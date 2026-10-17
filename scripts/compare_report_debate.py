"""Read-only SolarWinds report comparisons with shared-layout graph figures."""
from __future__ import annotations

import argparse
import csv
import hashlib
from html import escape
import json
from pathlib import Path
import sys
import textwrap

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from crystalball.report_debate import STRATEGIES, parse_graph, checked_changes
from crystalball.generation_debate_runner import read, save
from crystalball.paper_graph import render_paper_graph
from crystalball.postprocess import AttackGraph

TITLES = {"single": "Single-agent / paper prompt", "self_refine": "Single-agent + self-refine", "debate": "Multi-agent debate"}


def render_readable_paper(graph, target, title, subtitle):
    """Choose display layout by label collisions only; never change graph data."""
    attack_graph = AttackGraph(graph["nodes"], graph["edges"])
    record = render_paper_graph(attack_graph, target, title=title, subtitle=subtitle)
    trials = [{"seed": 42, "aspect": 1.78, "collisions": record["label_collisions"]}]
    best = (record["label_collisions"], 42, 1.78)
    for seed, aspect in [(5, 1.3), (119, 1.9), (13, 1.0), (45, 1.2)]:
        if best[0] == 0:
            break
        trial = render_paper_graph(attack_graph, target / "layout_trials" / str(seed),
                                  title=title, subtitle=subtitle, seed=seed, aspect=aspect)
        trials.append({"seed": seed, "aspect": aspect, "collisions": trial["label_collisions"]})
        if trial["label_collisions"] < best[0]:
            best = (trial["label_collisions"], seed, aspect)
    if best[1] != 42:
        record = render_paper_graph(attack_graph, target, title=title, subtitle=subtitle, seed=best[1], aspect=best[2])
    save(target / "layout_selection.json", {"trials": trials, "selected": {"requested_seed": best[1], "aspect": best[2]},
                                            "selection_criterion": "fewer displayed label collisions only", "graph_changed": False})
    return record


def graph_layout(graphs):
    import networkx as nx
    net = nx.Graph()
    for graph in graphs.values():
        net.add_nodes_from(str(node["id"]) for node in graph["nodes"])
        net.add_edges_from((str(edge["from"]), str(edge["to"])) for edge in graph["edges"])
    stable = nx.Graph()
    stable.add_nodes_from(sorted(net.nodes))
    stable.add_edges_from(sorted(net.edges))
    points = nx.spring_layout(stable, seed=42, iterations=350, k=2.5 / max(len(stable), 1)**.5)
    return {key: [float(value[0]), float(value[1])] for key, value in points.items()}


def render_png(graphs, points, aliases, target, prefix):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch
    from matplotlib.lines import Line2D

    baseline = graphs.get("single", {"nodes": [], "edges": []})
    baseline_nodes = {str(node["id"]) for node in baseline["nodes"]}
    baseline_pairs = {(str(e["from"]), str(e["to"])) for e in baseline["edges"]}
    def panel(ax, strategy, graph):
        ax.set_axis_off()
        ax.set_xlim(-1.23, 1.23)
        ax.set_ylim(-1.23, 1.23)
        ax.set_aspect("equal")
        for edge in graph["edges"]:
            a, b = str(edge["from"]), str(edge["to"])
            color = "#137753" if (a, b) not in baseline_pairs else "#8593a1"
            ax.add_patch(FancyArrowPatch(points[a], points[b], arrowstyle="-|>",
                         mutation_scale=10, shrinkA=11, shrinkB=11, color=color,
                         connectionstyle="arc3,rad=.06", linewidth=1.2, zorder=1, alpha=.85))
        for node in graph["nodes"]:
            key = str(node["id"])
            x, y = points[key]
            ax.scatter([x], [y], s=330, c="#d6eee1" if key not in baseline_nodes else "#e5edf6",
                       edgecolors="#38634e" if key not in baseline_nodes else "#53718b", linewidths=.8, zorder=3)
            ax.text(x, y, aliases[key], ha="center", va="center", fontsize=7.0, zorder=4)
        ax.set_title(f"{TITLES[strategy]}\n{len(graph['nodes'])} nodes / {len(graph['edges'])} edges", fontsize=12, pad=14)
    fig, axes = plt.subplots(1, len(graphs), figsize=(8 * len(graphs), 8.3), squeeze=False)
    for ax, (strategy, graph) in zip(axes[0], graphs.items()):
        panel(ax, strategy, graph)
        individual, individual_ax = plt.subplots(figsize=(11, 10))
        panel(individual_ax, strategy, graph)
        individual.text(.5, .035, "Node codes: see node_legend.csv / interactive index.html. Green = added pair/node, not validated correctness.", ha="center", fontsize=9)
        individual.subplots_adjust(bottom=.07, top=.92, left=.02, right=.98)
        individual.savefig(target / f"{prefix}_{strategy}.png", dpi=180)
        individual.savefig(target / f"{prefix}_{strategy}.svg")
        plt.close(individual)
    fig.suptitle("SolarWinds Appendix C.1 — identical source and shared node positions", fontsize=16, y=.98)
    fig.legend(handles=[Line2D([0], [0], color="#8593a1", label="Pair already in baseline"),
                        Line2D([0], [0], color="#137753", label="Added pair (not a correctness label)")],
               loc="lower center", ncol=2, frameon=False, bbox_to_anchor=(.5, .025))
    fig.subplots_adjust(left=.015, right=.985, bottom=.08, top=.87, wspace=.02)
    name = f"{prefix}_comparison.png"
    fig.savefig(target / name, dpi=170)
    fig.savefig(target / f"{prefix}_comparison.svg")
    plt.close(fig)
    return name


def svg_graph(graph, points, aliases, baseline):
    baseline_pairs = {(str(e["from"]), str(e["to"])) for e in baseline["edges"]}
    def position(key):
        x, y = points[str(key)]
        return 600 + 470 * x, 600 - 470 * y
    pieces = ['<svg viewBox="0 0 1200 1200" role="img"><defs><marker id="arrow" markerWidth="7" markerHeight="7" refX="15" refY="3" orient="auto"><path d="M0,0 L0,6 L6,3 z" fill="context-stroke"/></marker></defs><g class="viewport">']
    for i, edge in enumerate(graph["edges"], 1):
        a, b = str(edge["from"]), str(edge["to"])
        x1, y1 = position(a)
        x2, y2 = position(b)
        color = "#147752" if (a, b) not in baseline_pairs else "#8a98a6"
        label = str(edge["label"])
        tooltip = f"edge-{i:04d}: {a} → {b}\n{label}"
        pieces.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="3" marker-end="url(#arrow)" class="edge"><title>{escape(tooltip)}</title></line>')
    for node in graph["nodes"]:
        key, label = str(node["id"]), str(node["label"])
        x, y = position(key)
        tooltip = json.dumps(node, ensure_ascii=False, indent=2)
        short = label if len(label) <= 65 else label[:62] + "..."
        pieces.append(f'<g class="node"><title>{escape(tooltip)}</title><circle cx="{x}" cy="{y}" r="19" fill="#e3edf7" stroke="#486b8c" stroke-width="2"/><text x="{x}" y="{y+4}" text-anchor="middle" font-size="12">{aliases[key]}</text><text x="{x}" y="{y+34}" text-anchor="middle" font-size="11" fill="#26384a">{escape(short)}</text></g>')
    return "".join(pieces) + '</g></svg>'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    out = args.out.resolve()
    frozen = [p for p in out.rglob("*") if p.is_file() and "analysis" not in p.relative_to(out).parts]
    before = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest() for p in frozen}
    manifest, report = read(out / "manifest.json"), read(out / "comparison.json")
    target = out / "analysis"
    target.mkdir(exist_ok=True)
    corpus = {row["id"]: row["text"] for row in read(out / "paragraphs.json")}
    lines = ["# SolarWinds: prompt bài gốc + multi-agent debate", "",
             f"Case {manifest['case']}, Figure {manifest['paper_figure']}. Baseline nhận đúng bytes prompt đã trích và chuẩn hóa từ bài gốc.",
             "Không bổ sung data mô phỏng, node inventory hoặc ép số lượng cạnh. Model hiện tại khác GPT-4 trong bài; không kỳ vọng ảnh giống từng node/cạnh.", "",
             "| Round | Cách sinh | Trạng thái | Node | Cạnh | Node thêm/bỏ | Cặp cạnh thêm/bỏ | Token provider |",
             "|---|---|---|---:|---:|---|---|---:|"]
    for row in report["rows"]:
        diff = row.get("diff", {})
        lines.append(f"| {row['repeat']} | {row['strategy']} | {row['status']} | {row.get('nodes','N/A')} | {row.get('edges','N/A')} | "
                     f"{len(diff.get('added_node_ids',[]))}/{len(diff.get('removed_node_ids',[]))} | "
                     f"{len(diff.get('added_pairs',[]))}/{len(diff.get('removed_pairs',[]))} | {row['usage']['total_tokens']} |")
    lines += ["", f"Tổng request riêng biệt: **{report['unique_api_calls']}**. Tổng token theo provider: **{report['unique_usage']['total_tokens']}**.",
              "Các nhánh dùng chung draft. Bảng tính draft vào mỗi nhánh để so sánh, API chỉ thực hiện draft một lần. "
              "Tự sửa và debate cùng bốn calls/cap nhưng khác input length/actual usage.", "",
              "**Chưa có gold độc lập: accuracy/precision/recall/F1 = N/A.** Số cạnh tăng, trích dẫn đúng hoặc reviewer đồng ý không chứng minh graph đúng hơn.", ""]
    all_records = []
    browser_panels = []
    with (target / "node_legend.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["repeat", "strategy", "display_code", "original_id", "model_label"])
        for repeat in range(1, manifest["repeats"] + 1):
            base = out / "runs" / f"r{repeat:02d}"
            candidates = {s: read(base / s / "candidate.json") for s in STRATEGIES if (base / s / "candidate.json").exists()}
            graphs = {s: c["graph"] for s, c in candidates.items()}
            if not graphs:
                continue
            points = graph_layout(graphs)
            baseline = graphs.get("single", next(iter(graphs.values())))
            ids = list(dict.fromkeys(str(node["id"]) for graph in graphs.values() for node in graph["nodes"]))
            aliases = {key: f"N{i:02d}" for i, key in enumerate(ids, 1)}
            save(target / f"r{repeat:02d}_layout.json", {"positions": points, "aliases": aliases})
            figure = render_png(graphs, points, aliases, target, f"r{repeat:02d}")
            lines += [f"## Round {repeat}", "", f"![Graph dùng chung vị trí node]({figure})", ""]
            for strategy, candidate in candidates.items():
                graph = candidate["graph"]
                for node in graph["nodes"]:
                    writer.writerow([repeat, strategy, aliases[str(node["id"])], node["id"], node["label"]])
                lines += [f"### {TITLES[strategy]}", "", "Thay đổi dựa trên ID/pair (cần người đối chiếu nếu tách/gộp/đổi tên node):", "",
                          "```json", json.dumps(candidate["diff"], ensure_ascii=False, indent=2), "```", ""]
                checked = candidate.get("change_citations", [])
                if strategy == "self_refine":
                    history = []
                    for revision in range(1, 4):
                        raw_path = base / "calls" / f"self_refine.revision{revision}.response.txt"
                        if raw_path.exists():
                            parsed, audit = parse_graph(raw_path.read_text(encoding="utf-8"), revision=True)
                            history.append({"revision": revision, "parsing": audit,
                                            "changes": checked_changes(parsed["changes"], corpus)})
                    save(target / f"r{repeat:02d}_self_refine_history.json", history)
                    lines += [f"Sidecar bên dưới là lượt tự sửa cuối; [lịch sử đủ ba lượt](r{repeat:02d}_self_refine_history.json) giữ các sửa đổi trước đó. Diff phía trên luôn so graph cuối với baseline.", ""]
                for change in checked:
                    lines += [f"- **{change['action']} {change['kind']} `{change['id']}`:** {change['reason']}"]
                    for citation in change["citations"]:
                        lines += [f"  - {citation['paragraph_id']} ({citation['verification']}): " + (citation["quote"] or "unverified quote withheld")]
                lines.append("")
                if strategy == "debate":
                    lines += ["Audit trích dẫn của hai reviewer: `" + json.dumps(candidate.get("review_audits", {})) + "`.",
                              "Đây là selective review tối đa 12 findings + 6 omissions mỗi bên; không phải audit toàn bộ graph.", ""]
                paper_style = target / "paper_style" / f"r{repeat:02d}_{strategy}"
                render_record = render_readable_paper(graph, paper_style,
                                title=f"SolarWinds {manifest['case']}: {TITLES[strategy]}",
                                subtitle="Original paper report; current model; no synthetic data")
                if render_record["graph_changed"]:
                    raise AssertionError("Renderer changed the model graph")
                lines += [f"[Ảnh nhãn đầy đủ kiểu paper](paper_style/r{repeat:02d}_{strategy}/graph.png) · "
                          f"[Bản xem tương tác](paper_style/r{repeat:02d}_{strategy}/graph.html)", ""]
                browser_panels.append(f'<section><h2>r{repeat:02d}: {escape(TITLES[strategy])}</h2><p>{len(graph["nodes"])} nodes / {len(graph["edges"])} edges. Cuộn để zoom, kéo để di chuyển, rê chuột vào node/cạnh để đọc.</p>'
                                      + svg_graph(graph, points, aliases, baseline) + '<button class="reset">Reset view</button>'
                                      + f'<p><a href="paper_style/r{repeat:02d}_{strategy}/graph.html">Ảnh nhãn đầy đủ kiểu paper</a></p></section>')
            all_records.append({"repeat": repeat, "figure": figure, "candidates": candidates})
    lines += ["## Cách đọc", "",
              "Màu xanh lá biểu thị pair/node thêm so với baseline, không phải nhãn đúng. Ảnh giữ chung vị trí và mã node; tên đầy đủ trong node_legend.csv và index.html.",
              "So sánh Figure 2 trong paper_references để tham khảo mức trừu tượng của bài; không dùng toàn bộ hình như nhãn chuẩn đầy đủ.",
              "Chấm cạnh bằng nguồn: supported/conditional/unknown/unsupported/contradicted, giữ uncertainty/alternative/scope. Đây là khung chấm cho người đọc, không chạy validator tám CVE.",
              "annotation_source_blind.json dành cho chuẩn coverage trước khi nhìn graph; runs/rNN/<strategy>/annotation_blind.json dành cho cạnh. Các ô nhãn đều để trống."]
    (target / "COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    save(target / "paired_analysis.json", {"manifest": manifest, "metrics": report, "records": all_records,
                                          "independent_gold": False, "accuracy": None})
    source_details = "".join(f'<details><summary>{escape(key)}</summary><p>{escape(text)}</p></details>' for key, text in corpus.items())
    reference = f'../paper_references/figure_{manifest["paper_figure"]:02d}.png'
    page = '''<!doctype html><html lang="vi"><meta charset="utf-8"><title>SolarWinds: paper source + debate</title>
<style>body{font:16px system-ui;margin:24px;color:#243344;background:#f5f7fa}section{background:white;margin:24px 0;padding:20px;border-radius:10px}svg{width:100%;height:780px;border:1px solid #d8e0e7;touch-action:none;cursor:grab}svg:active{cursor:grabbing}.node,.edge{cursor:help}pre{white-space:pre-wrap;line-height:1.5}details{margin:8px 0}</style>
<h1>SolarWinds — Appendix C.1 / Figure 2</h1><p>Nguồn trong bài gốc; không data mô phỏng, không cho trước node/cạnh. Màu xanh lá = pair thêm, không phải nhãn đúng. Chưa có gold độc lập: accuracy = N/A.</p>'''
    page += '<details><summary>Hình tham chiếu trong bài gốc</summary><img style="max-width:100%" src="' + reference + '"></details>'
    page += "".join(browser_panels) + '<h2>Bảng và thay đổi chi tiết</h2><pre>' + escape("\n".join(lines)) + '</pre><h2>Báo cáo nguồn theo đoạn</h2>' + source_details
    page += '''<script>for(const svg of document.querySelectorAll('svg')){const g=svg.querySelector('.viewport');let s=1,x=0,y=0,drag=null;function apply(){g.setAttribute('transform',`translate(${x},${y}) scale(${s})`)}svg.addEventListener('wheel',e=>{e.preventDefault();const rect=svg.getBoundingClientRect(),px=(e.clientX-rect.left)/rect.width*1200,py=(e.clientY-rect.top)/rect.height*1200;const n=Math.min(6,Math.max(.4,s*Math.exp(-e.deltaY*.001)));x=px-(px-x)*n/s;y=py-(py-y)*n/s;s=n;apply()},{passive:false});svg.addEventListener('pointerdown',e=>{drag=[e.clientX,e.clientY,x,y];svg.setPointerCapture(e.pointerId)});svg.addEventListener('pointermove',e=>{if(!drag)return;const r=svg.getBoundingClientRect();x=drag[2]+(e.clientX-drag[0])/r.width*1200;y=drag[3]+(e.clientY-drag[1])/r.height*1200;apply()});svg.addEventListener('pointerup',()=>drag=null);svg.parentElement.querySelector('.reset').onclick=()=>{s=1;x=0;y=0;apply()}};</script></html>'''
    (target / "index.html").write_text(page, encoding="utf-8")
    assert all(hashlib.sha256((out / name).read_bytes()).hexdigest() == expected for name, expected in before.items())
    save(target / "INPUT_AUDIT.json", {"source_artifacts_unchanged": True, "api_calls_by_analysis": 0,
         "sha256": before, "analysis_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    print(target / "COMPARISON.md")


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    main()
