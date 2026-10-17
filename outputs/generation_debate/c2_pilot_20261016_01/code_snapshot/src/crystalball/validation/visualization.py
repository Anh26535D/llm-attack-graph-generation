"""Publication-size audit views; both panels share one saved deterministic layout."""

from __future__ import annotations

import json
import textwrap
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.lines import Line2D
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.path import Path as DrawingPath

from ..cve_mapping import identity_candidates
from ..postprocess import AttackGraph
from .evidence import digest

STYLES = {
    "supported": ("#16824b", "-"),
    "conditional": ("#c37409", "--"),
    "unknown": ("#747b83", ":"),
    "unsupported": ("#c62828", "--"),
    "contradicted": ("#c62828", "-"),
    "original": ("#355675", "-"),
}
NAMES = {
    "CVE-2019-20354": "piSignage\nfile download",
    "CVE-2019-3562": "Oculus Browser\nHTML injection",
    "CVE-2020-1885": "OVRRedir\nfile write / LPE",
    "CVE-2020-24572": "RaspAP\nOS commands",
    "CVE-2021-24038": "Oculus Desktop\nhandle exposure",
    "CVE-2021-38545": "Glowworm\noptical recovery",
    "CVE-2021-38759": "Raspberry Pi\nOS default login",
    "CVE-2022-21819": "Jetson Linux\nIOMMU access",
}


def fixed_layout(graph: AttackGraph) -> dict[str, list[float]]:
    net = nx.DiGraph()
    net.add_nodes_from(str(n["id"]) for n in graph.nodes)
    for edge in graph.edges:
        a, b = str(edge.get("from", edge.get("source"))), str(edge.get("to", edge.get("target")))
        if a in net and b in net:
            net.add_edge(a, b)
    positions = {}
    heights = [0.0] * 3
    for component in sorted(nx.weakly_connected_components(net), key=lambda c: (-len(c), sorted(c))):
        sub = net.subgraph(component)
        if nx.is_directed_acyclic_graph(sub):
            layers = [sorted(layer) for layer in nx.topological_generations(sub)]
        else:
            # Condensation preserves cyclic component nodes rather than deleting edges.
            condensed = nx.condensation(sub)
            layers = [sorted(n for scc in layer for n in condensed.nodes[scc]["members"])
                      for layer in nx.topological_generations(condensed)]
        width = min(3, max(len(layer) for layer in layers))
        start = min(range(4 - width), key=lambda i: (max(heights[i:i + width]), i))
        top = max(heights[start:start + width])
        level = 0
        for layer in layers:
            for offset in range(0, len(layer), width):
                chunk = layer[offset:offset + width]
                for j, node in enumerate(chunk):
                    positions[node] = [(start + (width - len(chunk)) / 2 + j) * 3.2, -(top + level * 1.8)]
                level += 1
        for i in range(start, start + width):
            heights[i] = top + level * 1.8 + 0.5
    return positions


def _node_label(node: dict) -> tuple[str, str]:
    ids, _ = identity_candidates(node)
    if len(ids) == 1 and ids[0] in NAMES:
        return NAMES[ids[0]], ids[0]
    text = str(node.get("label", node["id"]))
    lines = textwrap.wrap(text, 17)
    return "\n".join(lines[:2]) + ("..." if len(lines) > 2 else ""), str(node["id"])


def _panel(ax, graph, report, positions, validated):
    ax.set_axis_off()
    xs, ys = [p[0] for p in positions.values()] or [0], [p[1] for p in positions.values()] or [0]
    ax.set_xlim(-2.15, max(max(xs) + 1.45, 7.85))
    ax.set_ylim(min(ys) - 0.9, 1.25)
    ax.set_aspect("equal")
    ax.apply_aspect()
    ax.set_title("(b) Evidence-validated graph" if validated else "(a) Original CrystalBall graph",
                 fontsize=11, fontweight="bold", pad=13, loc="left")
    groups = defaultdict(list)
    for i, edge in enumerate(graph.edges):
        a, b = str(edge.get("from", edge.get("source"))), str(edge.get("to", edge.get("target")))
        groups[(a, b)].append(i)
    for (a, b), indexes in groups.items():
        if a not in positions or b not in positions:
            continue
        x1, y1 = positions[a]
        x2, y2 = positions[b]
        for ordinal, i in enumerate(indexes):
            status = report["edges"][i]["final"]["status"] if validated else "original"
            color, style = STYLES[status]
            distance = abs(y1 - y2)
            radius = (0.40 if distance > 2 else 0.0) + (ordinal - (len(indexes) - 1) / 2) * 0.48
            if (b, a) in groups:
                radius += 0.65
            # Shrink endpoints to the fixed node boxes; arcs separate skip edges.
            if a == b:
                start, end = (x1 - .45, y1 + .38), (x1 + .45, y1 + .38)
                radius = -2.0 - ordinal * .5
            else:
                dx, dy = x2 - x1, y2 - y1
                scale = max(abs(dx) / 1.17, abs(dy) / .51)
                start, end = (x1 + dx / scale, y1 + dy / scale), (x2 - dx / scale, y2 - dy / scale)
            if a != b and x1 == x2 and distance > 2:
                # Skip edges route around the intervening boxes. Alternating sides
                # avoid crossing chords in a four-node chain.
                side = -1 if i % 2 == 0 else 1
                border, outer = x1 + side * 1.15, x1 + side * (2.05 + ordinal * .35)
                route = DrawingPath([(border, y1), (outer, y1), (outer, y2), (border, y2)],
                                    [DrawingPath.MOVETO, DrawingPath.CURVE4, DrawingPath.CURVE4, DrawingPath.CURVE4])
                patch = FancyArrowPatch(path=route, arrowstyle="-|>", mutation_scale=11,
                                        linewidth=1.45, linestyle=style, color=color, zorder=1)
                mx, my = border + (outer - border) * .75, (y1 + y2) / 2
            else:
                patch = FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=11,
                                        connectionstyle=f"arc3,rad={radius}", linewidth=1.45,
                                        linestyle=style, color=color, zorder=1)
                mx, my = ((start[0] + end[0]) / 2 + radius * (end[1] - start[1]) / 2,
                          (start[1] + end[1]) / 2 - radius * (end[0] - start[0]) / 2)
            ax.add_patch(patch)
            # The quadratic Bezier midpoint for arc3 is offset by rad/2.
            tag = f"e{i + 1}"
            if status in {"unsupported", "contradicted"}:
                tag += " X"
            horizontal = abs(x2 - x1) > abs(y2 - y1)
            ax.text(mx if horizontal else mx + .12, my, tag, fontsize=8, color=color,
                    ha="center" if horizontal else "left", va="center", zorder=4,
                    bbox={"facecolor": "white", "edgecolor": "none", "pad": .4})
    for node in graph.nodes:
        x, y = positions[str(node["id"])]
        ax.add_patch(FancyBboxPatch((x - 1.12, y - .48), 2.24, .96,
                                    boxstyle="round,pad=0.035,rounding_size=0.09", linewidth=.85,
                                    edgecolor="#597184", facecolor="#f2f6f8", zorder=3))
        name, identity = _node_label(node)
        title = ax.text(x, y + .11, name, ha="center", va="center", fontsize=8.3, linespacing=1.1, zorder=4)
        identifier = ax.text(x, y - .31, identity, ha="center", va="center", fontsize=7.3, color="#43576a", zorder=4)
        # Fit actual font glyphs rather than estimating with character counts.
        renderer = ax.figure.canvas.get_renderer()
        available = ax.transData.transform((x + 1.04, y))[0] - ax.transData.transform((x - 1.04, y))[0]
        for text in (title, identifier):
            width = text.get_window_extent(renderer).width
            if width > available:
                text.set_fontsize(text.get_fontsize() * available / width)


def render_comparison(graph: AttackGraph, report: dict, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    positions = fixed_layout(graph)
    layout = {"graph_sha256": report["graph_sha256"], "positions": positions,
              "layout_sha256": digest(positions), "identical_in_both_panels": True}
    (out / "layout.json").write_text(json.dumps(layout, indent=2) + "\n", encoding="utf-8")
    with plt.rc_context({"font.family": "DejaVu Sans", "svg.fonttype": "none", "svg.hashsalt": "crystalball-validator-v1"}):
        fig, axes = plt.subplots(1, 2, figsize=(8, 5.3))
        fig.subplots_adjust(left=.025, right=.985, top=.81, bottom=.20, wspace=.12)
        _panel(axes[0], graph, report, positions, False)
        _panel(axes[1], graph, report, positions, True)
        fig.suptitle("Static attack graph evidence audit", fontsize=13, fontweight="bold", y=.97)
        counts = report["metrics"]["C_hybrid"]["label_distribution"]
        summary = " | ".join(f"{s}: {counts[s]}" for s in ("supported", "conditional", "unknown", "unsupported", "contradicted"))
        fig.text(.5, .92, summary, ha="center", fontsize=8)
        handles = [Line2D([0], [0], color=STYLES[s][0], linestyle=STYLES[s][1], linewidth=1.8,
                          label=s.capitalize() + (" (X)" if s in {"unsupported", "contradicted"} else ""))
                   for s in ("supported", "conditional", "unknown", "unsupported", "contradicted")]
        fig.legend(handles=handles, loc="lower center", bbox_to_anchor=(.5, .055), ncol=3,
                   fontsize=8, frameon=False, columnspacing=1.5)
        state = "enabled" if report["review_enabled"] else "disabled; offline labels shown"
        fig.text(.5, .041, f"LLM review: {state}. Same nodes, edge instances and layout in both panels.", ha="center", fontsize=7.5)
        fig.text(.5, .015, "All edges remain visible. eN identifies edge-NNNN in validation_results.json. Static consistency is not exploit success.",
                 ha="center", fontsize=6.8)
        for suffix in ("png", "svg"):
            fig.savefig(out / f"comparison.{suffix}", dpi=600, facecolor="white",
                        metadata={"Date": None} if suffix == "svg" else None)
        plt.close(fig)
        for validated, stem in ((False, "original_graph"), (True, "validated_graph")):
            fig, ax = plt.subplots(figsize=(4.2, 5.8))
            fig.subplots_adjust(left=.04, right=.96, top=.90, bottom=.16)
            _panel(ax, graph, report, positions, validated)
            fig.text(.5, .07, "Edge IDs and evidence: validation_results.json\nAll original edge instances remain visible.",
                     fontsize=8, ha="center")
            for suffix in ("png", "svg"):
                fig.savefig(out / f"{stem}.{suffix}", dpi=600, facecolor="white",
                            metadata={"Date": None} if suffix == "svg" else None)
            plt.close(fig)
    return layout
