"""Post-Processor (Section 3.4): "extracts the attack graph from the answer,
saves it in database and shows the graph to the user."

Handles the common failure mode noted in Section 5.4: LLM answers wrapped in
prose/markdown fences, or occasionally truncated mid-JSON due to token
limits (best-effort recovery by trimming to the last complete node/edge).
"""

from __future__ import annotations

import json
import re
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

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": self.nodes, "edges": self.edges}


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

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise GraphParseError("Parsed JSON does not contain 'nodes'/'edges' lists.")

    return AttackGraph(nodes=nodes, edges=edges, truncated=truncated)


def merge_graphs(graphs: list[AttackGraph]) -> AttackGraph:
    """Combine partial graphs from chunked context (Section 5.4, first
    bullet: "we merged all the nodes and edges from the partial graphs")."""
    seen_node_ids: set[str] = set()
    merged_nodes: list[dict[str, Any]] = []
    merged_edges: list[dict[str, Any]] = []
    for g in graphs:
        for node in g.nodes:
            node_id = node.get("id", node.get("label"))
            if node_id in seen_node_ids:
                continue
            seen_node_ids.add(node_id)
            merged_nodes.append(node)
        merged_edges.extend(g.edges)
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

    fig_width = max(8, len(g.nodes) * 1.2)
    fig_height = max(6, len(g.nodes) * 0.8)
    plt.figure(figsize=(fig_width, fig_height))
    pos = nx.spring_layout(g, seed=42, k=1.5 / max(len(g.nodes), 1) ** 0.5)

    nx.draw_networkx_nodes(g, pos, node_color="#4C78A8", node_size=1400)
    nx.draw_networkx_labels(
        g, pos, labels={n: id_to_label.get(n, n) for n in g.nodes}, font_size=7
    )
    nx.draw_networkx_edges(g, pos, edge_color="#B0413E", arrows=True, arrowsize=15)
    edge_labels = nx.get_edge_attributes(g, "label")
    nx.draw_networkx_edge_labels(g, pos, edge_labels=edge_labels, font_size=6)

    plt.margins(0.15)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    return out_path
