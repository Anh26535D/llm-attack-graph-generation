"""List the CVE->CVE edges in saved responses, for labeling.

A graph edge counts as a CVE->CVE edge when both endpoint nodes mention at least one
CVE ID and the sets differ. Edges touching nodes with no CVE ID (e.g. an "attacker
start" node) are counted separately and are NOT part of the H1 denominator.

    python -m experiments.h1_edge_support.extract --responses DIR --out pairs.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from crystalball.postprocess import GraphParseError, parse_llm_json
from experiments.env_consistency.scoring import node_cves

# Fallback when a node carries no CVE ID: distinctive product/vulnerability tokens, matched
# against the node LABEL only, and accepted only if exactly one CVE matches. Added after the
# first pilot showed one run whose nodes dropped the IDs (see README).
LABEL_KEYWORDS = {
    "CVE-2019-20354": ("pisignage",),
    "CVE-2019-3562": ("oculus browser",),
    "CVE-2020-1885": ("ovrredir",),
    "CVE-2020-24572": ("raspap",),
    "CVE-2021-24038": ("ovrservicelauncher",),
    "CVE-2021-38545": ("glowworm",),
    "CVE-2021-38759": ("default password",),
    "CVE-2022-21819": ("jetson", "iommu"),
}


def map_node(node: dict) -> set[str]:
    ids = node_cves(node)
    if ids:
        return ids
    label = str(node.get("label", "")).lower()
    hits = {c for c, words in LABEL_KEYWORDS.items() if any(w in label for w in words)}
    return hits if len(hits) == 1 else set()


def graph_edges(graph) -> tuple[list[dict], int]:
    """Return (cve_edges, n_other_edges); each cve_edge has cve_from, cve_to, label."""
    by_id = {str(n.get("id")): n for n in graph.nodes if isinstance(n, dict)}
    cve_edges: list[dict] = []
    other = 0
    for edge in graph.edges:
        if not isinstance(edge, dict):
            other += 1
            continue
        src, dst = by_id.get(str(edge.get("from"))), by_id.get(str(edge.get("to")))
        if src is None or dst is None:
            other += 1
            continue
        pairs = [(a, b) for a in sorted(map_node(src)) for b in sorted(map_node(dst)) if a != b]
        if not pairs:
            other += 1
            continue
        for a, b in pairs:
            cve_edges.append({"cve_from": a, "cve_to": b, "label": str(edge.get("label", ""))})
    return cve_edges, other


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--responses", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    pairs: dict[str, dict] = defaultdict(lambda: {"count": 0, "runs": [], "examples": []})
    runs = {}
    for model_dir in sorted(p for p in Path(args.responses).iterdir() if p.is_dir()):
        for path in sorted(model_dir.glob("*.txt")):
            run = f"{model_dir.name}/{path.stem}"
            try:
                graph = parse_llm_json(path.read_text(encoding="utf-8"))
            except GraphParseError as exc:
                runs[run] = {"parse_error": str(exc)}
                continue
            edges, other = graph_edges(graph)
            runs[run] = {"nodes": len(graph.nodes), "edges": len(graph.edges), "cve_edges": len(edges), "other_edges": other}
            for e in edges:
                key = f"{e['cve_from']}->{e['cve_to']}"
                pairs[key]["count"] += 1
                pairs[key]["runs"].append(run)
                if len(pairs[key]["examples"]) < 3:
                    pairs[key]["examples"].append(e["label"])
    Path(args.out).write_text(json.dumps({"runs": runs, "pairs": pairs}, indent=2), encoding="utf-8")
    print(json.dumps(runs, indent=1))
    print(f"{len(pairs)} unique directed CVE pairs -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
