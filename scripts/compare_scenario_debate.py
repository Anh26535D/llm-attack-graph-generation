"""Read-only comparison of the explicitly synthetic state/action C2 pilot."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from html import escape
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from crystalball.scenario_debate import score
from crystalball.validation.metrics import token_usage

STRATEGIES = ("grounded", "self_refine", "debate")
NAMES = {"grounded": "Single-agent", "self_refine": "Single-agent + self-refine", "debate": "Multi-agent debate"}
LABELS = {
    "S01": "piSignage login", "A01": "File-download CVE", "S02": "File-read access",
    "A02": "Read RaspAP login", "S03": "RaspAP credential", "A03": "RaspAP commands",
    "S04": "pi-lab user process", "A04": "Read win-a login", "S05": "win-a credential",
    "S06": "win-a reachable", "A05": "Login win-a / AND", "S07": "win-a user process",
    "A06": "Hard-link elevation", "A07": "Handle elevation", "S08": "win-a admin",
    "A08": "Read win-b secret", "S09": "win-b credential", "S10": "Route from win-a",
    "A09": "Login win-b / AND", "S11": "win-b user process", "A10": "Handle elevation",
    "S12": "win-b admin / GOAL", "A11": "Patched hard-link", "A12": "No physical access",
    "S13": "Audio information", "A13": "Password changed", "A14": "No victim visit",
}
POSITIONS = {
    "S01": (0, 0), "A01": (2.8, 0), "S02": (5.6, 0), "A02": (8.4, 0), "S03": (11.2, 0),
    "S06": (0, -2), "S05": (2.8, -2), "A04": (5.6, -2), "S04": (8.4, -2), "A03": (11.2, -2),
    "A05": (2.8, -4), "S07": (5.6, -4), "A06": (8.4, -3.3), "A07": (8.4, -4.7), "S08": (11.2, -4),
    "S10": (5.6, -6.2), "S09": (8.4, -6.2), "A08": (11.2, -6.2),
    "S12": (0, -8.4), "A10": (2.8, -8.4), "S11": (5.6, -8.4), "A09": (8.4, -8.4),
    "A11": (0, -10.8), "A12": (2.8, -10.8), "S13": (5.6, -10.8), "A13": (8.4, -10.8), "A14": (11.2, -10.8),
}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def relation(edge):
    return edge["from"], edge["to"], edge.get("relation")


def usage(calls):
    value = token_usage(calls)
    thoughts = [call.get("usage", {}).get("thoughts_token_count") if isinstance(call.get("usage"), dict) else None for call in calls]
    value["gemini_thoughts_tokens"] = sum(thoughts) if thoughts and all(type(n) is int for n in thoughts) else None
    return value


def render(graphs, evaluations, public, reference, target, prefix):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
    from matplotlib.lines import Line2D
    from matplotlib.path import Path as DrawingPath

    catalog = {node["id"]: node for node in public["nodes"]}
    if set(catalog) != set(POSITIONS):
        raise ValueError("This renderer is for the frozen 27-node C2 extension")
    expected = {relation(edge) for edge in reference["edges"]}
    def panel(ax, graph, evaluation, title):
        ax.set_axis_off()
        ax.set_xlim(-1.5, 12.7)
        ax.set_ylim(-11.9, 1.0)
        ax.set_aspect("equal")
        predicted = {relation(edge) for edge in graph["edges"]}
        for source, target_id, rel in sorted(predicted | expected, key=str):
            if source not in POSITIONS or target_id not in POSITIONS:
                continue
            item = (source, target_id, rel)
            x1, y1 = POSITIONS[source]
            x2, y2 = POSITIONS[target_id]
            if item in predicted & expected:
                color, style, width = "#2a745e", "-", 1.5
            elif item in predicted:
                color, style, width = "#c43c3e", "-", 2.0
            else:
                color, style, width = "#cb8a22", ":", 1.5
            scale = max(abs(x2 - x1) / 1.14, abs(y2 - y1) / .43, 1)
            start = (x1 + (x2 - x1) / scale, y1 + (y2 - y1) / scale)
            end = (x2 - (x2 - x1) / scale, y2 - (y2 - y1) / scale)
            if source == "S08" and target_id == "A09":
                # Route between the secret-read node and the credential node;
                # a direct chord would pass behind the secret-read box.
                route = DrawingPath([(x1 - 1.14, y1), (9.8, -4), (10.05, -7.7), (9.53, -8.4)],
                                    [DrawingPath.MOVETO, DrawingPath.CURVE4, DrawingPath.CURVE4, DrawingPath.CURVE4])
                arrow = FancyArrowPatch(path=route, arrowstyle="-|>", mutation_scale=12,
                                        linewidth=width, linestyle=style, color=color, zorder=1)
            else:
                arrow = FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=12,
                                        linewidth=width, linestyle=style, color=color, zorder=1)
            ax.add_patch(arrow)
        for node in public["nodes"]:
            node_id = node["id"]
            x, y = POSITIONS[node_id]
            control = node_id in reference["isolated_controls"]
            face = "#f1f1f1" if control else "#edf4fc" if node["kind"] == "state" else "#fff3e1"
            border = "#999999" if control else "#4d6a87" if node["kind"] == "state" else "#b2823a"
            ax.add_patch(FancyBboxPatch((x - 1.08, y - .39), 2.16, .78,
                         boxstyle="round,pad=.035,rounding_size=.09", facecolor=face, edgecolor=border,
                         linewidth=.9, zorder=3))
            ax.text(x, y + .18, node_id + (" / AND" if node_id in {"A05", "A09"} else ""),
                    ha="center", va="center", fontsize=7.7, fontweight="bold", zorder=4)
            ax.text(x, y - .02, LABELS[node_id].replace(" / AND", ""), ha="center", va="center", fontsize=7.0, zorder=4)
            ax.text(x, y - .23, node["host"], ha="center", va="center", fontsize=6.7, color="#59616b", zorder=4)
        ax.text(5.6, -9.75, "Unavailable actions / isolated information control", ha="center", fontsize=8.3, color="#6c7075")
        ax.set_title(f"{title}\n{len(graph['nodes'])} nodes / {len(graph['edges'])} edges; "
                     f"{evaluation['matched_edges']} match / {evaluation['extra_or_wrong_edges']} extra / {evaluation['missing_edges']} missing",
                     fontsize=12, pad=15)
    handles = [Line2D([0], [0], color="#2a745e", label="Matches synthetic reference"),
               Line2D([0], [0], color="#c43c3e", label="Extra / wrong relation"),
               Line2D([0], [0], color="#cb8a22", linestyle=":", label="Reference relation omitted")]
    fig, axes = plt.subplots(1, len(graphs), figsize=(10 * len(graphs), 10.8), squeeze=False)
    for ax, (strategy, graph) in zip(axes[0], graphs.items()):
        panel(ax, graph, evaluations[strategy], NAMES[strategy])
        single, single_ax = plt.subplots(figsize=(12, 11.5))
        panel(single_ax, graph, evaluations[strategy], NAMES[strategy])
        single.legend(handles=handles, loc="lower center", ncol=1, frameon=False, fontsize=9, bbox_to_anchor=(.5, .015))
        single.subplots_adjust(top=.92, bottom=.13, left=.03, right=.97)
        single.savefig(target / f"{prefix}_{strategy}.png", dpi=180)
        single.savefig(target / f"{prefix}_{strategy}.svg")
        plt.close(single)
    fig.suptitle("Synthetic C2 extension — same 27-node inventory, source facts and positions", fontsize=17, y=.99)
    fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(.5, .055), fontsize=10)
    fig.text(.5, .035, "Reference agreement on an authored lab fixture; not independent or real-world CVE accuracy. Multiple inputs to an action are AND prerequisites.", ha="center", fontsize=10)
    fig.subplots_adjust(top=.88, bottom=.12, left=.015, right=.985, wspace=.06)
    filename = f"{prefix}_comparison.png"
    fig.savefig(target / filename, dpi=150)
    fig.savefig(target / f"{prefix}_comparison.svg")
    plt.close(fig)
    save(target / f"{prefix}_layout.json", POSITIONS)
    return filename


def analyze(out):
    manifest, public, reference = (read(out / name) for name in ("manifest.json", "scenario.json", "reference.synthetic.json"))
    inputs = [path for path in out.rglob("*") if path.is_file() and "analysis" not in path.relative_to(out).parts]
    input_hashes = {str(path.relative_to(out)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    target = out / "analysis"
    target.mkdir(exist_ok=True)
    records = []
    for index in range(1, manifest["repeats"] + 1):
        base = out / "runs" / f"r{index:02d}"
        graphs, evaluations = {}, {}
        record = {"repeat": index, "strategies": {}}
        initial = read(base / "draft.json") if (base / "draft.json").exists() else None
        for strategy in STRATEGIES:
            folder = base / strategy
            row = read(folder / "generation_audit.json") if (folder / "generation_audit.json").exists() else {"status": "not_run"}
            calls = [read(path) for path in sorted((base / "calls").glob("*.json"))
                     if path.stem == "draft" or path.stem.startswith(strategy + ".")]
            row.update(api_calls_including_common_draft=len(calls), usage=usage(calls),
                       request_seconds=sum(call.get("seconds", 0) for call in calls))
            if (folder / "candidate.json").exists():
                candidate = read(folder / "candidate.json")
                evaluation = score(candidate, reference)
                row.update(nodes=len(candidate["graph"]["nodes"]), edges=len(candidate["graph"]["edges"]),
                           synthetic_evaluation=evaluation, decisions=candidate["decisions"])
                if initial:
                    original = {relation(edge) for edge in initial["graph"]["edges"]}
                    current = {relation(edge) for edge in candidate["graph"]["edges"]}
                    original_nodes = {node["id"]: node for node in initial["graph"]["nodes"]}
                    original_edges = {relation(edge): edge for edge in initial["graph"]["edges"]}
                    row.update(added_relations=[list(e) for e in sorted(current - original, key=str)],
                               removed_relations=[list(e) for e in sorted(original - current, key=str)],
                               changed_node_bodies=[node["id"] for node in candidate["graph"]["nodes"]
                                                    if node != original_nodes.get(node["id"])],
                               changed_retained_edge_bodies=[list(relation(edge)) for edge in candidate["graph"]["edges"]
                                                            if relation(edge) in original_edges and edge != original_edges[relation(edge)]])
                if row["status"] == "ready_for_independent_validation":
                    graphs[strategy] = candidate["graph"]
                    evaluations[strategy] = evaluation
            record["strategies"][strategy] = row
        if graphs:
            record["figure"] = render(graphs, evaluations, public, reference, target, f"r{index:02d}")
        records.append(record)
    all_calls = [read(path) for path in out.glob("runs/r*/calls/*.json")]
    continuation = read(out / "CONTINUATION.json") if (out / "CONTINUATION.json").exists() else None
    recovery = read(out / "FORMAT_RECOVERY.json") if (out / "FORMAT_RECOVERY.json").exists() else None
    normalized = [str(path.relative_to(out)) for path in sorted(out.glob("runs/r*/format_normalization/*.audit.json"))]
    result = {"scope": manifest["scope"], "results": records, "unique_api_calls": len(all_calls),
              "unique_usage": usage(all_calls), "request_states": dict(Counter(call["status"] for call in all_calls)),
              "actual_models": dict(Counter(str((call.get("metadata") or {}).get("actual_model")) for call in all_calls)),
              "continuation": continuation, "format_recovery": recovery, "normalized_stages": normalized,
              "independent_human_gold": False, "real_world_accuracy": None}
    save(target / "paired_analysis.json", result)
    lines = ["# C2 mở rộng: 27 node trạng thái/hành động", "",
             "Dữ liệu lab mô phỏng, cùng inventory và graph nháp cho ba nhánh. "
             "Tham chiếu 23 quan hệ định nghĩa trước, không gửi cho model. "
             "Đây là mức khớp tham chiếu mô phỏng; không phải accuracy trên hệ thống thật.", "",
             "| Round | Nhánh | Node | Cạnh | Khớp / Thừa / Thiếu | Precision tham chiếu | Recall tham chiếu | F1 tham chiếu | Tokens gồm reasoning |",
             "|---|---|---:|---:|---|---:|---:|---:|---:|"]
    for record in records:
        for strategy, row in record["strategies"].items():
            evaluation = row.get("synthetic_evaluation")
            if evaluation:
                precision = evaluation["reference_precision"]
                lines.append(f"| {record['repeat']} | {strategy} | {row['nodes']} | {row['edges']} | "
                             f"{evaluation['matched_edges']} / {evaluation['extra_or_wrong_edges']} / {evaluation['missing_edges']} | "
                             f"{precision:.1%} | {evaluation['reference_recall']:.1%} | {evaluation['reference_f1']:.1%} | "
                             f"{row['usage']['total_tokens']} |" if precision is not None else f"| {strategy}: no edges |")
            else:
                lines.append(f"| {record['repeat']} | {strategy} — {row['status']} | N/A | N/A | N/A | N/A | N/A | N/A | {row['usage']['total_tokens']} |")
    lines += ["", f"Lượt hiện tại: {len(all_calls)} request riêng biệt, tổng {result['unique_usage']['total_tokens']} token theo provider.",
              "Draft dùng chung tính vào mỗi nhánh để so sánh nhưng chỉ thực hiện một lần. "
              "Output text không gồm toàn bộ reasoning; total_tokens theo provider có tính reasoning.", ""]
    if continuation:
        lines += ["Các lượt trước được giữ riêng: một draft JSON lỗi (12.130 token), "
                  "một request bị ngắt chưa có response/usage. Không coi chúng là kết quả hợp lệ; "
                  "tổng chi phí cả lịch sử chưa đầy đủ.", ""]
    if recovery:
        lines += ["Đây là bản phục hồi định dạng sau khi strict parser dừng ở Markdown fence của Defender. "
                  f"Đã dùng lại {recovery['requests_reused']} request; không gửi lại chúng. "
                  "Chỉ chấp nhận một lớp Markdown bao trọn JSON ở mọi stage; nội dung, duplicate-key/schema, "
                  "quote và decision checks giữ nguyên. Kết quả không được coi là pass giao thức strict ban đầu.",
                  "Các stage đã bóc Markdown: " + ", ".join(normalized), ""]
    for record in records:
        if record.get("figure"):
            lines += [f"![So sánh ba graph]({record['figure']})", ""]
        for strategy, row in record["strategies"].items():
            lines += [f"## {strategy}", "", f"Trạng thái: `{row['status']}`.", ""]
            if row.get("synthetic_evaluation"):
                e = row["synthetic_evaluation"]
                lines += [f"- Cạnh thêm so với draft: `{row.get('added_relations', [])}`",
                          f"- Cạnh bỏ so với draft: `{row.get('removed_relations', [])}`",
                          f"- Quan hệ thừa/sai: `{e['extra_relations']}`", f"- Quan hệ thiếu: `{e['omitted_relations']}`",
                          f"- Đủ hai nhóm AND: `{e['and_groups_complete']}`",
                          f"- Cạnh liên quan đối chứng âm: {e['control_incident_edges']}",
                          f"- Thời gian API gồm draft: {row['request_seconds']:.1f} giây", ""]
    lines += ["Node đã được cho sẵn để cố định độ hạt; thí nghiệm đo dựng quan hệ, "
              "không đo khả năng tự khám phá node. Label, điều kiện, bridge và bằng chứng "
              "vẫn cần người đọc kiểm tra. Chỉ một repeat: chưa đo độ ổn định hoặc chứng minh lợi ích tổng quát của debate."]
    lines += ["Ảnh dùng cùng tên ngắn và vị trí node từ fixture để thấy khác biệt về cạnh. "
              "Label/pre/postcondition nguyên bản model sinh vẫn nằm trong candidate.json/graph.json của từng nhánh."]
    (target / "COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    images = "".join(f'<img src="{r["figure"]}" style="width:100%;min-width:1200px">' for r in records if r.get("figure"))
    html = '<!doctype html><meta charset="utf-8"><title>C2 mở rộng</title><style>body{font:16px system-ui;margin:24px}pre{white-space:pre-wrap;line-height:1.5}</style>'
    html += '<h1>C2 mở rộng — so sánh graph</h1><p>Tham chiếu mô phỏng, không phải accuracy thực tế.</p>' + images
    html += '<pre>' + escape("\n".join(lines)) + '</pre>'
    (target / "index.html").write_text(html, encoding="utf-8")
    assert all(hashlib.sha256((out / name).read_bytes()).hexdigest() == expected for name, expected in input_hashes.items())
    save(target / "INPUT_AUDIT.json", {"inputs_unchanged": True, "sha256": input_hashes,
         "analysis_api_calls": 0, "analysis_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    print(target / "COMPARISON.md")


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    analyze(parser.parse_args().out.resolve())
