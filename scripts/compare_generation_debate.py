"""Read-only paired analysis and common-layout figures for a generation pilot."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
from html import escape
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from crystalball.postprocess import AttackGraph
from crystalball.validation.metrics import token_usage
from crystalball.validation.visualization import _panel, fixed_layout


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def key(edge):
    return edge["from"], edge["to"]


def usage(calls):
    value = token_usage(calls)
    thoughts = [call.get("usage", {}).get("thoughts_token_count")
                if isinstance(call.get("usage"), dict) else None for call in calls]
    value["gemini_thoughts_tokens"] = sum(thoughts) if thoughts and all(type(item) is int for item in thoughts) else None
    value["note"] = "Gemini output_tokens here counts text candidates; provider total_tokens includes thoughts."
    return value


def describe_repeat(base: Path, strategies: list[str]) -> dict:
    result = {"repeat": base.name, "strategies": {}, "pairs": []}
    draft_path = base / "draft.json"
    if not draft_path.exists():
        return result
    draft = read(draft_path)
    original = {key(edge): edge for edge in draft["graph"]["edges"]}
    original_nodes = {node["id"]: node for node in draft["graph"]["nodes"]}
    union = set(original)
    for strategy in strategies:
        folder = base / strategy
        status = read(folder / "generation_audit.json") if (folder / "generation_audit.json").exists() else {"status": "not_run"}
        calls = [read(path) for path in sorted((base / "calls").glob("*.json"))
                 if path.stem == "draft" or path.stem.startswith(strategy + ".")]
        row = {"status": status["status"], "calls_including_common_draft": len(calls),
               "usage": usage(calls), "request_seconds": sum(call.get("seconds", 0) for call in calls),
               "accuracy": None}
        if (folder / "candidate.json").exists():
            candidate = read(folder / "candidate.json")
            graph = candidate["graph"]
            edges = {key(edge): edge for edge in graph["edges"]}
            union |= set(edges)
            row.update(nodes=len(graph["nodes"]), edges=len(graph["edges"]),
                       added=[list(pair) for pair in sorted(set(edges) - set(original))],
                       removed=[list(pair) for pair in sorted(set(original) - set(edges))],
                       changed_edge_claims=[list(pair) for pair in sorted(set(edges) & set(original))
                                            if edges[pair] != original[pair]],
                       changed_nodes=[node["id"] for node in graph["nodes"]
                                      if node != original_nodes.get(node["id"])],
                       evidence=candidate["edge_evidence"], decisions=candidate["decisions"],
                       candidate=deepcopy(candidate))
        validation = folder / "validation/validation_results.json"
        row["offline_tags"] = (dict(Counter(item["final"]["status"] for item in read(validation)["edges"]))
                               if validation.exists() else None)
        result["strategies"][strategy] = row
    for pair in sorted(union):
        record = {"from": pair[0], "to": pair[1], "in_draft": pair in original, "strategies": {}}
        for strategy, row in result["strategies"].items():
            candidate = row.get("candidate", {"graph": {"edges": []}, "edge_evidence": []})
            edge = next((edge for edge in candidate["graph"]["edges"] if key(edge) == pair), None)
            evidence = next((entry for entry in candidate["edge_evidence"] if key(entry) == pair), None)
            record["strategies"][strategy] = {"present": edge is not None, "claim": edge, "evidence": evidence}
        result["pairs"].append(record)
    return result


def render_repeat(base: Path, target: Path, record: dict, strategies: list[str]) -> str | None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    graph_paths = [base / strategy / "graph.json" for strategy in strategies]
    if not all(path.exists() for path in graph_paths):
        return None
    graphs = {strategy: read(path) for strategy, path in zip(strategies, graph_paths)}
    nodes = {node["id"]: node for graph in graphs.values() for node in graph["nodes"]}
    edges = {key(edge): edge for graph in graphs.values() for edge in graph["edges"]}
    positions = fixed_layout(AttackGraph(list(nodes.values()), list(edges.values())))
    fig, axes = plt.subplots(1, len(strategies), figsize=(7.6 * len(strategies), 8.5), squeeze=False)
    titles = {"grounded": "Single agent (grounded)", "self_refine": "Single agent + self-refine", "debate": "Multi-agent debate"}
    for ax, strategy in zip(axes[0], strategies):
        graph = graphs[strategy]
        report = read(base / strategy / "validation/validation_results.json")
        _panel(ax, AttackGraph(graph["nodes"], graph["edges"]), report, positions, True)
        ax.set_title("", loc="left")
        ax.set_title(f"{titles[strategy]}\n{len(graph['nodes'])} nodes / {len(graph['edges'])} edges", fontsize=13, pad=15)
    fig.suptitle(f"C2 {base.name}: same draft, sources and node positions", fontsize=17, y=.98)
    handles = [Line2D([0], [0], color="#c37409", linestyle="--", label="conditional"),
               Line2D([0], [0], color="#747b83", linestyle=":", label="unknown"),
               Line2D([0], [0], color="#16824b", label="supported")]
    fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(.5, .025))
    fig.text(.5, .015, "Colors are fixed offline-validator labels, not independent accuracy. Edge numbers are local to each panel.", ha="center", fontsize=10)
    fig.subplots_adjust(left=.025, right=.98, top=.88, bottom=.11, wspace=.10)
    filename = f"{base.name}_comparison.png"
    fig.savefig(target / filename, dpi=170)
    fig.savefig(target / f"{base.name}_comparison.svg")
    plt.close(fig)
    save(target / f"{base.name}_layout.json", positions)
    return filename


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    out = args.out.resolve()
    manifest = read(out / "manifest.json")
    inputs = [out / "manifest.json", out / "sources.json"]
    inputs += [path for path in (out / "runs").rglob("*.json") if "analysis" not in path.parts]
    before = {str(path.relative_to(out)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(inputs)}
    target = out / "analysis"
    target.mkdir(exist_ok=True)
    records = []
    for index in range(1, manifest["repeats"] + 1):
        base = out / "runs" / f"r{index:02d}"
        record = describe_repeat(base, manifest["strategies"])
        if record["strategies"]:
            record["figure"] = render_repeat(base, target, record, manifest["strategies"])
        records.append(record)
    calls = [read(path) for path in (out / "runs").glob("r*/calls/*.json")]
    totals = {}
    for strategy in manifest["strategies"]:
        rows = [record["strategies"][strategy] for record in records if strategy in record["strategies"]]
        valid = [row for row in rows if row["status"] == "ready_for_independent_validation"]
        totals[strategy] = {"scheduled_repeats": manifest["repeats"], "ready_repeats": len(valid),
            "candidate_edges_in_ready_repeats": sum(row["edges"] for row in valid),
            "added_in_ready_repeats": sum(len(row["added"]) for row in valid),
            "removed_in_ready_repeats": sum(len(row["removed"]) for row in valid),
            "changed_claims_in_ready_repeats": sum(len(row["changed_edge_claims"]) for row in valid),
            "offline_tags": dict(sum((Counter(row["offline_tags"] or {}) for row in valid), Counter())),
            "accuracy": None}
    result = {"repeats": records, "totals": totals, "unique_api_calls": len(calls),
              "unique_usage": usage(calls), "independent_gold": "absent", "accuracy": None}
    save(target / "paired_analysis.json", result)
    lines = ["# So sánh C2 theo cặp", "", "Cùng graph nháp; cùng tám CVE; cùng model cho các vai trò: "
             + str(manifest["same_model_for_all_roles"]) + ".", "",
             "Nhãn bên dưới là validator offline. Chưa có gold độc lập; accuracy = N/A.", "",
             "| Round | Nhánh | Trạng thái | Node | Cạnh | Thêm / bỏ so với draft | Nhãn offline | Calls gồm draft |",
             "|---|---|---|---:|---:|---|---|---:|"]
    for record in records:
        for strategy in manifest["strategies"]:
            row = record["strategies"].get(strategy, {"status": "not_run"})
            lines.append(f"| {record['repeat']} | {strategy} | {row['status']} | {row.get('nodes', 'N/A')} | "
                         f"{row.get('edges', 'N/A')} | {len(row.get('added', []))} / {len(row.get('removed', []))} | "
                         f"{row.get('offline_tags')} | {row.get('calls_including_common_draft', 0)} |")
    lines += ["", f"Tổng số request riêng biệt: **{len(calls)}**. Usage: `{json.dumps(result['unique_usage'])}`.",
              "Draft chung được tính vào từng nhánh khi so sánh, nhưng chỉ gọi/bị tính phí một lần.", ""]
    for record in records:
        lines += [f"## {record['repeat']}", ""]
        if record.get("figure"):
            lines += [f"![Ba graph dùng chung vị trí node]({record['figure']})", ""]
        for pair in record["pairs"]:
            lines += [f"### {pair['from']} → {pair['to']}", ""]
            for strategy, item in pair["strategies"].items():
                lines.append(f"- **{strategy}:** " + (item["claim"]["label"] if item["present"] else "Không có cạnh"))
                if item["evidence"]:
                    lines.append("  - Bridge: " + item["evidence"]["bridge"])
                    lines.append("  - Điều kiện chưa quan sát: " + "; ".join(item["evidence"]["missing_conditions"]))
            lines.append("")
    (target / "PAIRED_COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    images = "".join(f'<h2>{escape(record["repeat"])}</h2><img src="{record["figure"]}" style="max-width:100%">'
                     for record in records if record.get("figure"))
    page = '<!doctype html><meta charset="utf-8"><title>C2 generation comparison</title><style>body{font:16px system-ui;margin:30px;line-height:1.5}pre{white-space:pre-wrap}</style>'
    page += '<h1>C2: single / self-refine / debate</h1><p>Chưa có gold độc lập: accuracy = N/A. Màu cạnh là nhãn offline.</p>' + images
    page += '<h2>Số liệu và thay đổi từng cạnh</h2><pre>' + escape("\n".join(lines)) + '</pre>'
    (target / "index.html").write_text(page, encoding="utf-8")
    after = {str(path.relative_to(out)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(inputs)}
    if before != after:
        raise AssertionError("Input artifacts changed during analysis")
    save(target / "INPUT_AUDIT.json", {"input_files_unchanged": True, "input_sha256": before,
         "analysis_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "api_calls_by_analysis": 0})
    print(f"Saved paired comparison: {target / 'PAIRED_COMPARISON.md'}")


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    main()
