"""Descriptive ablations and optional, independently annotated candidate-edge metrics."""

from __future__ import annotations

from collections import Counter

from .config import STATUSES


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def token_usage(reviews: list[dict]) -> dict:
    """Provider usage stays raw per request. Missing usage is never reported as zero."""
    totals = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "requests_with_usage": 0,
              "requests_missing_usage": 0}
    aliases = {"input_tokens": ("prompt_tokens", "prompt_token_count", "input_tokens"),
               "output_tokens": ("completion_tokens", "candidates_token_count", "output_tokens"),
               "total_tokens": ("total_tokens", "total_token_count")}
    field_counts = {key: 0 for key in aliases}
    requests = sum(r["api_calls"] for r in reviews)
    for review in reviews:
        if not review["api_calls"]:
            continue
        usage = review.get("usage")
        if not isinstance(usage, dict):
            totals["requests_missing_usage"] += 1
            continue
        values = {}
        for key, options in aliases.items():
            value = next((usage[o] for o in options if isinstance(usage.get(o), int)), None)
            values[key] = value
            if value is not None:
                totals[key] += value
                field_counts[key] += 1
        if all(v is None for v in values.values()):
            totals["requests_missing_usage"] += 1
        else:
            totals["requests_with_usage"] += 1
    for key in aliases:
        if requests and not field_counts[key]:
            totals[key] = None
    totals["totals_are_partial"] = bool(requests and any(count < requests for count in field_counts.values()))
    return totals


def validate_gold(gold: dict | None, edge_ids: set[str], graph_hash: str) -> dict[str, bool] | None:
    if gold is None:
        return None
    if (not isinstance(gold, dict) or gold.get("independent") is not True
            or gold.get("graph_sha256") != graph_hash or not isinstance(gold.get("provenance"), str)
            or not gold["provenance"].strip()):
        raise ValueError("Gold requires independent=true, matching graph_sha256 and annotation provenance")
    if gold.get("label_source") not in {"human", "independent_dataset"}:
        raise ValueError("Gold label_source must be human or independent_dataset, never LLM review/H1 pilot labels")
    labels = gold.get("labels")
    if not isinstance(labels, dict) or not set(labels) <= edge_ids or any(type(v) is not bool for v in labels.values()):
        raise ValueError("Gold labels must map known edge instance IDs to booleans")
    return labels


def candidate_metrics(retained: set[str], labels: dict[str, bool] | None) -> dict:
    result = {"precision": None, "recall": None, "f1": None, "false_removals": None,
              "false_retentions": None, "gold_annotated_edges": len(labels or {}),
              "scope": "independently labeled edge instances in the original candidate graph"}
    if not labels:
        result["reason"] = "No independent gold labels; N/A. LLM review labels are not ground truth."
        return result
    tp = sum(valid and edge in retained for edge, valid in labels.items())
    fp = sum(not valid and edge in retained for edge, valid in labels.items())
    fn = sum(valid and edge not in retained for edge, valid in labels.items())
    result.update(precision=_ratio(tp, tp + fp), recall=_ratio(tp, tp + fn),
                  f1=_ratio(2 * tp, 2 * tp + fp + fn), false_removals=fn, false_retentions=fp,
                  true_positives=tp, false_positives=fp, false_negatives=fn)
    return result


def ablation_metrics(rows: list[dict], offline_seconds: float, review_seconds: float,
                     labels: dict[str, bool] | None = None, *, all_node_mappings: dict | None = None,
                     review_enabled: bool = False) -> dict:
    n = len(rows)
    node_mappings = {}
    for row in rows:
        for role in ("source", "target"):
            node = row[f"{role}_node"]
            if node:
                node_mappings[str(node["id"])] = row["offline"][f"{role}_mapping"]
    mapped_edges = sum(all(row["offline"][f"{r}_mapping"]["status"] == "mapped" for r in ("source", "target")) for row in rows)
    mapping = {"mapped_edges": mapped_edges, "edge_mapping_coverage": _ratio(mapped_edges, n),
               "incident_nodes": len(node_mappings),
               "incident_node_mapping_coverage": _ratio(sum(m["status"] == "mapped" for m in node_mappings.values()), len(node_mappings))}
    if all_node_mappings is not None:
        mapping.update(nodes=len(all_node_mappings), mapped_nodes=sum(m["status"] == "mapped" for m in all_node_mappings.values()),
                       node_mapping_coverage=_ratio(sum(m["status"] == "mapped" for m in all_node_mappings.values()), len(all_node_mappings)))
    reviews = [r["review"] for r in rows]
    output = {}
    for name, stage in (("A_original", None), ("B_offline", "offline"), ("C_hybrid", "final")):
        distribution = Counter({s: 0 for s in STATUSES})
        if stage is None:
            distribution["unvalidated"] = n
            retained = {r["edge_id"] for r in rows}
            strict = set(retained)
        else:
            distribution.update(r[stage]["status"] for r in rows)
            retained = {r["edge_id"] for r in rows if r[stage]["status"] not in {"unsupported", "contradicted"}}
            strict = {r["edge_id"] for r in rows if r[stage]["status"] == "supported"}
        output[name] = {**mapping, "edges": n, "label_distribution": dict(distribution),
                        "unknown_rate": _ratio(distribution["unknown"], n) if stage else None,
                        "retained_edge_fraction": _ratio(len(retained), n),
                        "strict_retained_edge_fraction": _ratio(len(strict), n),
                        "retained_policy": "all original candidates" if stage is None else "exclude only unsupported/contradicted",
                        "strict_policy": "original unvalidated candidates" if stage is None else "supported only",
                        "edge_metrics": candidate_metrics(retained, labels),
                        "strict_edge_metrics": candidate_metrics(strict, labels),
                        "processing_seconds": 0.0 if stage is None else offline_seconds + (review_seconds if stage == "final" else 0),
                        "additional_api_calls": sum(r["api_calls"] for r in reviews) if stage == "final" else 0,
                        "token_usage": token_usage(reviews) if stage == "final" else token_usage([])}
    output["C_hybrid"]["review_states"] = dict(Counter(r["state"] for r in reviews))
    output["C_hybrid"]["disagreements"] = sum(r["final"]["disagreement"] for r in rows)
    output["C_hybrid"]["llm_review_enabled"] = review_enabled
    output["C_hybrid"]["ablation_state"] = "review_requested" if review_enabled else "not_run_offline_fallback"
    return output
