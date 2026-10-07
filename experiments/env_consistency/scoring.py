"""Score an LLM-generated graph against an environment, using the reference engine.

Nodes are mapped to CVEs by the CVE IDs that appear anywhere in the node's text. A
node is "active" for a CVE unless its text contains a negation phrase ("patched",
"not vulnerable", ...); retention is reported both with and without that filter
because a keyword filter is only a rough signal.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from crystalball.postprocess import AttackGraph

from .engine import _single_step, classify_edge, enabled_cves, enabled_pairs
from .envs import Env

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
NEGATION_RE = re.compile(
    r"\b(patched|not\s+vulnerable|not\s+affected|unaffected|not\s+exploitable|"
    r"no\s+longer\s+(?:vulnerable|exploitable|affected)|mitigated|fixed|"
    r"cannot\s+be\s+exploited|not\s+applicable)\b",
    re.IGNORECASE,
)
RANK = {"supported": 3, "redundant": 2, "unsupported": 1}


def _node_text(node: dict) -> str:
    return json.dumps(node, ensure_ascii=False)


def node_cves(node: dict) -> set[str]:
    return {m.upper() for m in CVE_RE.findall(_node_text(node))}


def _node_id(node: dict) -> str | None:
    value = node.get("id")
    return None if value is None else str(value)


@dataclass
class GraphScore:
    referenced: set[str]
    referenced_active: set[str]
    enabled: set[str]
    edge_counts: dict[str, int] = field(default_factory=dict)

    @property
    def precision(self) -> float | None:
        if not self.referenced:
            return None
        return len(self.referenced & self.enabled) / len(self.referenced)

    @property
    def recall(self) -> float | None:
        if not self.enabled:
            return None
        return len(self.referenced & self.enabled) / len(self.enabled)

    def to_dict(self) -> dict:
        return {
            "referenced": sorted(self.referenced),
            "referenced_active": sorted(self.referenced_active),
            "enabled": sorted(self.enabled),
            "precision": self.precision,
            "recall": self.recall,
            "edge_counts": self.edge_counts,
        }


def score_graph(graph: AttackGraph, env: Env) -> GraphScore:
    by_id = {_node_id(n): n for n in graph.nodes if isinstance(n, dict)}
    referenced: set[str] = set()
    active: set[str] = set()
    for node in graph.nodes:
        if not isinstance(node, dict):
            continue
        cves = node_cves(node)
        referenced |= cves
        if not NEGATION_RE.search(_node_text(node)):
            active |= cves

    counts = {"supported": 0, "redundant": 0, "unsupported": 0, "unevaluable": 0}
    for edge in graph.edges:
        if not isinstance(edge, dict):
            counts["unevaluable"] += 1
            continue
        src = by_id.get(str(edge.get("from")))
        dst = by_id.get(str(edge.get("to")))
        if src is None or dst is None:
            counts["unevaluable"] += 1
            continue
        pairs = [(a, b) for a in node_cves(src) for b in node_cves(dst) if a != b]
        if not pairs:
            counts["unevaluable"] += 1
            continue
        best = max((classify_edge(env, a, b) for a, b in pairs), key=RANK.__getitem__)
        counts[best] += 1
    return GraphScore(referenced, active, enabled_cves(env), counts)


@dataclass
class CounterfactualScore:
    disabled: set[str]  # enabled in the base env, disabled after the intervention
    disabled_direct: set[str]  # ... because the changed fact itself blocks them
    retained_direct: set[str]  # direct ones still referenced (a version/config failure)
    retained: set[str]  # ... but still referenced in the intervened graph
    retained_active: set[str]  # ... and referenced without a negation phrase
    still_enabled_missing: set[str]  # still enabled, referenced in base graph, now absent
    still_enabled_total: int
    edges_touching_disabled: int

    @property
    def retention_rate(self) -> float | None:
        return len(self.retained) / len(self.disabled) if self.disabled else None

    @property
    def retention_rate_direct(self) -> float | None:
        if not self.disabled_direct:
            return None
        return len(self.retained_direct) / len(self.disabled_direct)

    @property
    def retention_rate_active(self) -> float | None:
        return len(self.retained_active) / len(self.disabled) if self.disabled else None

    @property
    def collateral_rate(self) -> float | None:
        if not self.still_enabled_total:
            return None
        return len(self.still_enabled_missing) / self.still_enabled_total

    def to_dict(self) -> dict:
        return {
            "disabled": sorted(self.disabled),
            "retained": sorted(self.retained),
            "retained_active": sorted(self.retained_active),
            "retention_rate": self.retention_rate,
            "retention_rate_active": self.retention_rate_active,
            "retention_rate_direct": self.retention_rate_direct,
            "still_enabled_missing": sorted(self.still_enabled_missing),
            "collateral_rate": self.collateral_rate,
            "edges_touching_disabled": self.edges_touching_disabled,
        }


def score_counterfactual(
    base_graph: AttackGraph, new_graph: AttackGraph, base_env: Env, new_env: Env
) -> CounterfactualScore:
    base_enabled = enabled_cves(base_env)
    new_enabled = enabled_cves(new_env)
    disabled = base_enabled - new_enabled
    # "Direct": still blocked even if the attacker keeps every foothold the base
    # environment gave them, i.e. the changed fact itself is the cause. The rest only
    # lost the footholds an earlier step used to provide (downstream effects).
    base_footholds = enabled_pairs(base_env)[1]
    disabled_direct = {c for c in disabled if not _single_step(new_env, c, base_footholds)}
    still = base_enabled & new_enabled

    new_score = score_graph(new_graph, new_env)
    base_score = score_graph(base_graph, base_env)

    by_id = {_node_id(n): n for n in new_graph.nodes if isinstance(n, dict)}
    touching = 0
    for edge in new_graph.edges:
        if not isinstance(edge, dict):
            continue
        cves: set[str] = set()
        for key in ("from", "to"):
            node = by_id.get(str(edge.get(key)))
            if node is not None:
                cves |= node_cves(node)
        if cves & disabled:
            touching += 1

    present_before = still & base_score.referenced
    retained = disabled & new_score.referenced
    return CounterfactualScore(
        disabled=disabled,
        disabled_direct=disabled_direct,
        retained_direct=disabled_direct & new_score.referenced,
        retained=retained,
        retained_active=disabled & new_score.referenced_active,
        still_enabled_missing=present_before - new_score.referenced,
        still_enabled_total=len(present_before),
        edges_touching_disabled=touching,
    )
