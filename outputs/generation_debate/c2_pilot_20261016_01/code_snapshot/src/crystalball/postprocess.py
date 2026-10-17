"""Post-Processor (Section 3.4): "extracts the attack graph from the answer,
saves it in database and shows the graph to the user."

Handles the common failure mode noted in Section 5.4: LLM answers wrapped in
prose/markdown fences, or occasionally truncated mid-JSON due to token
limits (best-effort recovery by trimming to the last complete node/edge).
"""

from __future__ import annotations

import json
import math
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class GraphParseError(ValueError):
    pass


@dataclass
class AttackGraph:
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    truncated: bool = False
    container: str = "top_level"
    missing_keys: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": self.nodes, "edges": self.edges}

    @property
    def explicitly_empty(self) -> bool:
        """True only when both graph keys were present and both lists were empty."""
        return not self.missing_keys and not self.nodes and not self.edges


def _strip_to_json_object(text: str) -> str:
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        return fence.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1:
        raise GraphParseError("No JSON object found in LLM response.")
    if end == -1 or end <= start:
        # Truncated response: no closing brace at all.
        return text[start:]
    return text[start : end + 1]


def _attempt_repair(candidate: str) -> tuple[dict[str, Any], bool]:
    """Try to salvage a truncated JSON object by trimming back to the last
    complete list element, then closing all open brackets/braces."""
    try:
        return json.loads(candidate), False
    except json.JSONDecodeError:
        pass

    # Trim back to the last comma at top-of-array level and close things up.
    for cutoff in (candidate.rfind("},"), candidate.rfind("],")):
        if cutoff == -1:
            continue
        trimmed = candidate[: cutoff + 1]
        open_braces = trimmed.count("{") - trimmed.count("}")
        open_brackets = trimmed.count("[") - trimmed.count("]")
        trimmed = trimmed.rstrip(",")
        trimmed += "]" * max(open_brackets, 0) + "}" * max(open_braces, 0)
        try:
            return json.loads(trimmed), True
        except json.JSONDecodeError:
            continue

    raise GraphParseError("Could not parse or repair JSON from LLM response.")


def parse_llm_json(raw_text: str) -> AttackGraph:
    candidate = _strip_to_json_object(raw_text)
    data, truncated = _attempt_repair(candidate)

    container = "top_level"
    graph_data = data
    if not {"nodes", "edges"}.issubset(data) and "attack_graph" in data:
        graph_data = data["attack_graph"]
        container = "attack_graph"
        if not isinstance(graph_data, dict):
            raise GraphParseError("Parsed JSON 'attack_graph' value is not an object.")

    missing_keys = tuple(key for key in ("nodes", "edges") if key not in graph_data)
    if len(missing_keys) == 2 or (missing_keys and not truncated):
        missing = ", ".join(missing_keys)
        raise GraphParseError(f"Parsed JSON graph is missing required key(s): {missing}.")

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise GraphParseError("Parsed JSON does not contain 'nodes'/'edges' lists.")

    return AttackGraph(
        nodes=nodes,
        edges=edges,
        truncated=truncated,
        container=container,
        missing_keys=missing_keys,
    )


def merge_graphs(
    graphs: list[AttackGraph],
    conflict_log: list[dict[str, Any]] | None = None,
) -> AttackGraph:
    """Combine partial graphs from chunked context (Section 5.4, first
    bullet: "we merged all the nodes and edges from the partial graphs".

    Exact duplicate nodes are deduplicated.  If two chunks reuse an id for
    different node bodies, the later id is namespaced and its local edge
    endpoints are rewritten.  This avoids silently collapsing distinct
    events and deliberately does not invent cross-chunk edges.
    """
    seen_nodes: dict[str, dict[str, Any]] = {}
    merged_nodes: list[dict[str, Any]] = []
    merged_edges: list[dict[str, Any]] = []
    for chunk_number, g in enumerate(graphs, start=1):
        aliases: dict[str, str] = {}
        for node in g.nodes:
            node_id = node.get("id", node.get("label"))
            key = str(node_id)
            if key in seen_nodes and seen_nodes[key] == node:
                continue
            output_node = dict(node)
            if key in seen_nodes:
                renamed = f"chunk-{chunk_number}::{key}"
                suffix = 2
                while renamed in seen_nodes:
                    renamed = f"chunk-{chunk_number}::{key}::{suffix}"
                    suffix += 1
                aliases[key] = renamed
                output_node["id"] = renamed
                if conflict_log is not None:
                    conflict_log.append({
                        "chunk_number": chunk_number,
                        "original_id": str(node_id),
                        "renamed_id": renamed,
                        "reason": "same id with different node body",
                    })
                key = renamed
            seen_nodes[key] = output_node
            merged_nodes.append(output_node)
        for edge in g.edges:
            output_edge = dict(edge)
            for endpoint in ("from", "to", "source", "target"):
                value = output_edge.get(endpoint)
                if value is not None and str(value) in aliases:
                    output_edge[endpoint] = aliases[str(value)]
            merged_edges.append(output_edge)
    return AttackGraph(nodes=merged_nodes, edges=merged_edges)


def save_graph_json(graph: AttackGraph, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(graph.to_dict(), indent=2), encoding="utf-8")


def _node_label(node: dict[str, Any]) -> str:
    return str(node.get("label") or node.get("id") or "?")


def visualize_graph(graph: AttackGraph, out_path: Path) -> Path:
    """Renders the graph with networkx + matplotlib (Section 4:
    "networkx package is used to show the graph graphically")."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx

    g = nx.DiGraph()
    id_to_label = {}
    for node in graph.nodes:
        node_id = node.get("id") or node.get("label")
        label = _node_label(node)
        id_to_label[node_id] = label
        g.add_node(node_id, label=label)

    for edge in graph.edges:
        src, dst = edge.get("from"), edge.get("to")
        if src is None or dst is None:
            continue
        g.add_edge(src, dst, label=edge.get("label", ""))

    out_path.parent.mkdir(parents=True, exist_ok=True)

    n_nodes = max(len(g.nodes), 1)
    fig_width = max(10, n_nodes * 2.2)
    fig_height = max(8, n_nodes * 1.6)
    plt.figure(figsize=(fig_width, fig_height))
    pos = nx.spring_layout(g, seed=42, k=2.5 / n_nodes**0.5)

    nx.draw_networkx_nodes(g, pos, node_color="#4C78A8", node_size=1800)
    nx.draw_networkx_labels(
        g, pos, labels={n: id_to_label.get(n, n) for n in g.nodes}, font_size=8
    )
    nx.draw_networkx_edges(g, pos, edge_color="#B0413E", arrows=True, arrowsize=15)
    edge_labels = nx.get_edge_attributes(g, "label")
    nx.draw_networkx_edge_labels(g, pos, edge_labels=edge_labels, font_size=6.5)

    plt.margins(0.2)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path


def visualize_graph_report(graph: AttackGraph, out_path: Path, max_label_chars: int = 44) -> Path:
    """Render a report-friendly PNG with abbreviated nodes and no overlapping edge text.

    Full node and edge properties remain available in the adjacent graph.json.
    Common source/target aliases are mapped only for this visualization.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx

    g = nx.DiGraph()
    display_labels: dict[Any, str] = {}
    legend_nodes = []
    compact_nodes = len(graph.nodes) > 5
    for index, node in enumerate(graph.nodes, start=1):
        if not isinstance(node, dict):
            continue
        node_id = node.get("id") or node.get("label") or f"node-{index}"
        node_key = str(node_id)
        full_label = str(node.get("label") or node_id)
        cve = re.search(r"CVE-\d{4}-\d{4,}", f"{node_id} {full_label}", re.IGNORECASE)
        if cve:
            display_label = cve.group(0)
        elif compact_nodes:
            display_label = f"N{index}"
        else:
            raw_id = str(node_id)
            short_core = re.sub(r"\s+", " ", full_label).strip()
            if len(raw_id) <= 12:
                display_label = raw_id
            else:
                available = max(8, min(max_label_chars, 34) - len(f"N{index}: "))
                if len(short_core) > available:
                    short_core = short_core[: available - 1].rstrip() + "…"
                display_label = f"N{index}: {short_core}"
        g.add_node(node_key)
        display_labels[node_key] = display_label
        legend_nodes.append({
            "display_label": display_label,
            "id": str(node_id),
            "full_label": full_label,
        })

    for edge in graph.edges:
        if not isinstance(edge, dict):
            continue
        source = edge.get("from", edge.get("source"))
        target = edge.get("to", edge.get("target"))
        if source is not None and target is not None:
            g.add_edge(str(source), str(target))

    n_nodes = max(len(g.nodes), 1)
    root = max(14.0, min(24.0, 2.0 * n_nodes**0.5))
    plt.figure(figsize=(root, max(10.0, root * 0.72)))
    pos = nx.spring_layout(g, seed=42, k=2.5 / n_nodes**0.5, iterations=100)
    nx.draw_networkx_nodes(g, pos, node_color="#4C78A8", node_size=1900)
    nx.draw_networkx_labels(g, pos, labels=display_labels, font_size=8)
    nx.draw_networkx_edges(g, pos, edge_color="#B0413E", arrows=True, arrowsize=14, alpha=0.72)
    plt.margins(0.18)
    plt.axis("off")
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=170, bbox_inches="tight")
    plt.close()
    legend_path = out_path.with_name("graph_report_legend.json")
    legend_path.write_text(
        json.dumps({
            "nodes": legend_nodes,
            "edge_labels": "See the adjacent graph.json for full labels and properties.",
        }, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path


def visualize_graph_report_with_legend(
    graph: AttackGraph, out_path: Path, *, wrap_chars: int = 62
) -> Path:
    """Render a compact graph beside a readable N→full-label legend."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx

    g = nx.DiGraph()
    labels: dict[str, str] = {}
    legend_rows: list[str] = []
    compact_nodes = len(graph.nodes) > 5
    for index, node in enumerate(graph.nodes, start=1):
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or node.get("label") or f"node-{index}")
        full_label = str(node.get("label") or node_id)
        cve = re.search(r"CVE-\d{4}-\d{4,}", f"{node_id} {full_label}", re.IGNORECASE)
        display_label = cve.group(0) if cve else (f"N{index}" if compact_nodes else node_id)
        g.add_node(node_id)
        labels[node_id] = display_label
        wrapped = textwrap.wrap(
            re.sub(r"\s+", " ", full_label).strip(),
            width=wrap_chars,
            subsequent_indent="    ",
            break_long_words=False,
        ) or [""]
        legend_rows.append(f"{display_label}: {wrapped[0]}")
        legend_rows.extend(wrapped[1:])

    for edge in graph.edges:
        if not isinstance(edge, dict):
            continue
        source = edge.get("from", edge.get("source"))
        target = edge.get("to", edge.get("target"))
        if source is not None and target is not None:
            g.add_edge(str(source), str(target))

    n_nodes = max(len(g.nodes), 1)
    graph_width = max(14.0, min(24.0, 2.0 * n_nodes**0.5))
    height = max(12.0, graph_width * 0.72, (len(legend_rows) + 4) * 0.24)
    fig = plt.figure(figsize=(graph_width + 9.0, height))
    grid = fig.add_gridspec(1, 2, width_ratios=[graph_width, 9.0], wspace=0.03)
    graph_ax = fig.add_subplot(grid[0, 0])
    legend_ax = fig.add_subplot(grid[0, 1])
    pos = nx.spring_layout(g, seed=42, k=3.5 / n_nodes**0.5, iterations=200)
    pos = _spread_overlapping_positions(pos, minimum_distance=0.23, iterations=160)
    nx.draw_networkx_nodes(g, pos, node_color="#4C78A8", node_size=1700, ax=graph_ax)
    nx.draw_networkx_labels(g, pos, labels=labels, font_size=8, ax=graph_ax)
    nx.draw_networkx_edges(g, pos, edge_color="#B0413E", arrows=True, arrowsize=14, alpha=0.72, ax=graph_ax)
    graph_ax.margins(0.18)
    graph_ax.axis("off")

    legend_ax.axis("off")
    legend_ax.set_title("Node legend", loc="left", fontsize=12, pad=10)
    legend_ax.text(
        0.0,
        1.0,
        "\n".join(legend_rows) or "(no nodes)",
        transform=legend_ax.transAxes,
        va="top",
        ha="left",
        fontsize=8,
        linespacing=1.35,
        family="DejaVu Sans",
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=170, bbox_inches="tight")
    plt.close(fig)
    return out_path


def _spread_overlapping_positions(
    positions: dict[Any, Any], *, minimum_distance: float, iterations: int
) -> dict[Any, Any]:
    """Push near-coincident nodes apart while keeping a deterministic layout."""
    if len(positions) < 2:
        return positions
    nodes = list(positions)
    coords = {
        node: [float(positions[node][0]), float(positions[node][1])]
        for node in nodes
    }
    for _ in range(iterations):
        shifts = {node: [0.0, 0.0] for node in nodes}
        crowded = False
        for index, left in enumerate(nodes):
            for other_index in range(index + 1, len(nodes)):
                right = nodes[other_index]
                dx = coords[right][0] - coords[left][0]
                dy = coords[right][1] - coords[left][1]
                distance = math.hypot(dx, dy)
                if distance >= minimum_distance:
                    continue
                crowded = True
                if distance < 1e-9:
                    angle = math.pi * 2 * (index + 1) / (len(nodes) + 1)
                    dx, dy = math.cos(angle), math.sin(angle)
                    distance = 1.0
                correction = (minimum_distance - distance) * 0.52
                shift_x = dx / distance * correction
                shift_y = dy / distance * correction
                shifts[left][0] -= shift_x
                shifts[left][1] -= shift_y
                shifts[right][0] += shift_x
                shifts[right][1] += shift_y
        if not crowded:
            break
        for node in nodes:
            coords[node][0] += shifts[node][0]
            coords[node][1] += shifts[node][1]
    return {node: coords[node] for node in nodes}
