"""Small helpers shared by the paired experiment runner and its tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Mapping


CVE_CONDITIONS_REQUIRING_PRE_POST = frozenset({
    "c1",
    "c2",
    "retriever_context",
    "appendix_a_full_8_cves",
    "x0",
    "s54_cutoff_initial",
    "s54_cutoff_continuation",
    "s54_edge_detail",
})


def prompt_sha256(prompt_bytes: bytes) -> str:
    return hashlib.sha256(prompt_bytes).hexdigest()


def _identifier_key(value: object) -> str | None:
    if value is None or isinstance(value, (bool, dict, list)):
        return None
    key = str(value)
    return key if key.strip() else None


def _has_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def graph_schema_metrics(
    nodes: list[object],
    edges: list[object],
    *,
    condition_id: str | None = None,
) -> dict[str, object]:
    """Measure raw graph compliance with the schema requested by a condition.

    The original two-argument call remains valid and uses the basic schema.
    CVE-context conditions and the matched-schema X0 baseline require non-empty
    precondition and postcondition text; other conditions require node id/label.
    """
    require_pre_post = (
        condition_id is not None
        and condition_id.casefold() in CVE_CONDITIONS_REQUIRING_PRE_POST
    )
    required_node_keys = ("id", "label") + (
        ("precondition", "postcondition") if require_pre_post else ()
    )
    node_ids: set[str] = set()
    seen_node_ids: set[str] = set()
    missing_node_fields = 0
    invalid_node_ids = 0
    duplicate_node_ids = 0
    invalid_node_labels = 0
    missing_node_condition_fields = 0
    for node in nodes:
        if not isinstance(node, dict):
            missing_node_fields += 1
            invalid_node_ids += 1
            invalid_node_labels += 1
            if require_pre_post:
                missing_node_condition_fields += 1
            continue

        if any(key not in node for key in required_node_keys):
            missing_node_fields += 1

        node_id = _identifier_key(node.get("id"))
        if node_id is None:
            invalid_node_ids += 1
        elif node_id in seen_node_ids:
            duplicate_node_ids += 1
        else:
            seen_node_ids.add(node_id)
            node_ids.add(node_id)

        if not _has_text(node.get("label")):
            invalid_node_labels += 1

        if require_pre_post and not all(
            _has_text(node.get(key)) for key in ("precondition", "postcondition")
        ):
            missing_node_condition_fields += 1

    missing_edge_fields = 0
    canonical_edges = 0
    alternate_endpoint_edges = 0
    valid_edges = 0
    invalid_edge_labels = 0
    for edge in edges:
        if not isinstance(edge, dict):
            missing_edge_fields += 1
            continue
        if all(key in edge for key in ("from", "to", "label")):
            canonical_edges += 1
        elif "source" in edge and "target" in edge and not ("from" in edge and "to" in edge):
            alternate_endpoint_edges += 1
        if any(key not in edge for key in ("from", "to", "label")):
            missing_edge_fields += 1
        if not _has_text(edge.get("label")):
            invalid_edge_labels += 1
        source_id = _identifier_key(edge.get("from"))
        target_id = _identifier_key(edge.get("to"))
        if source_id in node_ids and target_id in node_ids:
            valid_edges += 1
    non_empty_graph = bool(nodes or edges)
    return {
        "schema_valid": (
            non_empty_graph
            and missing_node_fields == 0
            and invalid_node_ids == 0
            and duplicate_node_ids == 0
            and invalid_node_labels == 0
            and missing_node_condition_fields == 0
            and missing_edge_fields == 0
            and invalid_edge_labels == 0
            and valid_edges == len(edges)
        ),
        "non_empty_graph": non_empty_graph,
        "missing_node_required_fields_count": missing_node_fields,
        "invalid_node_ids_count": invalid_node_ids,
        "duplicate_node_ids_count": duplicate_node_ids,
        "invalid_node_labels_count": invalid_node_labels,
        "missing_node_condition_fields_count": missing_node_condition_fields,
        "missing_edge_required_fields_count": missing_edge_fields,
        "invalid_edge_labels_count": invalid_edge_labels,
        "edge_schema_compliance": canonical_edges / len(edges) if edges else None,
        "alternate_source_target_edges_count": alternate_endpoint_edges,
        "valid_edges": valid_edges,
        "invalid_edges": len(edges) - valid_edges,
        "edge_endpoint_integrity": valid_edges / len(edges) if edges else None,
    }


def edges_for_visualization(edges: list[object]) -> tuple[list[dict[str, object]], bool]:
    """Copy edge objects and map source/target aliases for display only."""
    normalized = []
    aliased = False
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if ("from" not in edge or "to" not in edge) and "source" in edge and "target" in edge:
            aliased = True
        normalized.append({
            **edge,
            "from": edge.get("from", edge.get("source")),
            "to": edge.get("to", edge.get("target")),
        })
    return normalized, aliased


def decode_frozen_prompt(prompt_bytes: bytes) -> str:
    """Decode a saved prompt without changing its UTF-8 bytes."""
    prompt = prompt_bytes.decode("utf-8")
    if prompt.encode("utf-8") != prompt_bytes:
        raise ValueError("Frozen prompt is not a reversible UTF-8 byte sequence.")
    return prompt


@dataclass
class PairedCallResult:
    client_name: str
    prompt_sha256: str
    response: str | None = None
    error: Exception | None = None


def dispatch_paired_prompt(
    prompt_bytes: bytes,
    clients: Mapping[str, object],
    before_call: Callable[[str, str], None] | None = None,
) -> list[PairedCallResult]:
    """Send one exact saved prompt to each client, continuing after call errors."""
    digest = prompt_sha256(prompt_bytes)
    prompt = decode_frozen_prompt(prompt_bytes)
    results = []
    for name, client in clients.items():
        if before_call is not None:
            before_call(name, digest)
        result = PairedCallResult(client_name=name, prompt_sha256=digest)
        try:
            result.response = client.complete(prompt)
        except Exception as exc:  # noqa: BLE001
            result.error = exc
        results.append(result)
    return results
