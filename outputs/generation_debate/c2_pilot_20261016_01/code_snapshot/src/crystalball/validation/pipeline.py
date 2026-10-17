"""A/B/C comparison using one immutable original graph and one offline baseline."""

from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy
from pathlib import Path

from ..postprocess import AttackGraph, parse_llm_json
from .config import ValidatorConfig
from .evidence import EnvironmentState, EvidenceStore, digest
from .metrics import ablation_metrics, validate_gold
from .offline import OfflineValidator
from .review import ReviewAdapter, recheck


def validate_graph(graph: AttackGraph, store: EvidenceStore, config: ValidatorConfig | None = None,
                   *, environment: EnvironmentState | None = None,
                   adapter: ReviewAdapter | None = None, gold: dict | None = None) -> dict:
    config = config or ValidatorConfig()
    before = deepcopy(graph.to_dict())
    graph_hash = digest(before)
    # Gold is checked before any potentially billable review.
    labels = validate_gold(gold, {f"edge-{i:04d}" for i in range(1, len(graph.edges) + 1)}, graph_hash)
    validator = OfflineValidator(store, environment)
    started = time.perf_counter()
    baseline = validator.validate(graph)
    offline_seconds = time.perf_counter() - started
    adapter = adapter or ReviewAdapter(config)
    if adapter.config != config:
        raise ValueError("Adapter config must match pipeline config")
    provenance = validator.provenance()
    provenance["environment_state"] = deepcopy(validator.environment.data)
    node_mappings = {str(n["id"]): store.mapping(n) for n in graph.nodes}
    rows = []
    started = time.perf_counter()
    for row in baseline:
        review = adapter.review(deepcopy(row), provenance)
        final = recheck(row, review)
        rows.append({"edge_id": row["edge_id"], "original_edge_id": row["original_edge_id"],
                     "index": row["index"], "edge": row["edge"],
                     "source_node": row["source_node"], "target_node": row["target_node"],
                     "offline": row, "review": review, "final": final})
    review_seconds = time.perf_counter() - started
    if graph.to_dict() != before:
        raise AssertionError("Original graph was mutated")
    return {"schema_version": 1, "graph_sha256": graph_hash, "config": config.public_dict(),
            "provenance": provenance, "node_mappings": node_mappings, "edges": rows,
            "metrics": ablation_metrics(rows, offline_seconds, review_seconds, labels,
                                        all_node_mappings=node_mappings, review_enabled=config.review_enabled),
            "review_enabled": config.review_enabled,
            "limitations": ["Static evidence consistency does not demonstrate exploit execution.",
                            "Lower edge count or Unknown rate does not establish improved accuracy.",
                            "Recall is over annotated original candidates; omitted real-world edges are not measured."]}


def reconstruct(original: dict, report: dict, *, strict: bool = False) -> dict:
    """Keep every node. Audit view keeps every edge; strict view records omissions."""
    if digest({"nodes": original["nodes"], "edges": original["edges"]}) != report["graph_sha256"] or len(original["edges"]) != len(report["edges"]):
        raise ValueError("Report does not belong to this original graph")
    result = deepcopy(original)
    result["edges"] = []
    excluded = []
    for edge, row in zip(original["edges"], report["edges"]):
        item = {**deepcopy(edge), "validation": {"edge_id": row["edge_id"],
                "original_edge_id": row["original_edge_id"], "status": row["final"]["status"],
                "offline_status": row["offline"]["status"], "reason": row["final"]["reason"]}}
        if strict and row["final"]["status"] != "supported":
            excluded.append(item)
        else:
            result["edges"].append(item)
    result["validation"] = {"source_graph_sha256": report["graph_sha256"], "strict": strict,
                            "excluded_edges": excluded}
    return result


def write_artifacts(graph_path: Path, out: Path, store: EvidenceStore, config: ValidatorConfig,
                    *, environment: EnvironmentState | None = None, adapter: ReviewAdapter | None = None,
                    gold: dict | None = None, render: bool = True) -> dict:
    source = graph_path.resolve()
    out = out.resolve()
    if out == source.parent or source in (out / name for name in (
            "original_graph.json", "validated_graph.json", "strict_graph.json", "validation_results.json")):
        raise ValueError("Choose a separate output directory to preserve historical artifacts")
    raw = source.read_bytes()
    # Deliberately no best-effort repair here; saved graph JSON must be complete.
    original = json.loads(raw)
    graph = parse_llm_json(json.dumps(original))
    if graph.container != "top_level":
        raise ValueError("Saved graph JSON must contain top-level nodes and edges")
    original_graph = original
    report = validate_graph(graph, store, config, environment=environment, adapter=adapter, gold=gold)
    report["input_file"] = {"path": str(source), "sha256": hashlib.sha256(raw).hexdigest()}
    out.mkdir(parents=True, exist_ok=True)
    (out / "original_graph.json").write_bytes(raw)
    for name, value in (("validated_graph.json", reconstruct(original_graph, report)),
                        ("strict_graph.json", reconstruct(original_graph, report, strict=True)),
                        ("validation_results.json", report), ("metrics.json", report["metrics"])):
        (out / name).write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    for stage in ("offline", "review", "final"):
        values = [{"edge_id": r["edge_id"], stage: r[stage]} for r in report["edges"]]
        (out / f"{stage}_results.json").write_text(json.dumps(values, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # Blank human-label table contains no validator/LLM suggestions (less anchoring).
    template = {"independent": True, "label_source": "human", "provenance": "",
                "graph_sha256": report["graph_sha256"],
                "labels": {r["edge_id"]: None for r in report["edges"]},
                "candidates": [{"edge_id": r["edge_id"], "original_edge_id": r["original_edge_id"],
                                "edge": r["edge"], "source_node": r["source_node"],
                                "target_node": r["target_node"], "evidence": r["offline"]["evidence"]} for r in report["edges"]]}
    (out / "annotation_template.json").write_text(json.dumps(template, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if render:
        from .visualization import render_comparison
        render_comparison(graph, report, out)
    if source.read_bytes() != raw:
        raise AssertionError("Source graph file changed during validation")
    return report
