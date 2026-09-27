import json

import pytest

from crystalball.postprocess import AttackGraph, GraphParseError, merge_graphs, parse_llm_json

GRAPH = {
    "nodes": [
        {"id": "n1", "label": "OVRRedir privilege escalation", "precondition": "local access", "postcondition": "SYSTEM"},
        {"id": "n2", "label": "Oculus Browser HTML injection", "precondition": "web page", "postcondition": "UI spoof"},
    ],
    "edges": [{"from": "n2", "to": "n1", "label": "chain"}],
}


def test_parse_clean_json():
    graph = parse_llm_json(json.dumps(GRAPH))
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert not graph.truncated


def test_parse_json_wrapped_in_markdown_fence_and_prose():
    raw = "Sure, here is the graph:\n```json\n" + json.dumps(GRAPH) + "\n```\nLet me know if you need more."
    graph = parse_llm_json(raw)
    assert len(graph.nodes) == 2


def test_parse_extracts_attack_graph_wrapper_without_changing_raw_fields():
    wrapped = {"attack_graph": GRAPH, "metadata": {"source": "fixture"}}

    graph = parse_llm_json(json.dumps(wrapped))

    assert graph.container == "attack_graph"
    assert graph.nodes == GRAPH["nodes"]
    assert graph.edges == GRAPH["edges"]
    assert not graph.explicitly_empty


def test_parse_rejects_valid_json_with_missing_graph_keys():
    with pytest.raises(GraphParseError, match="missing required key.*edges"):
        parse_llm_json('{"nodes": []}')


def test_parse_distinguishes_explicit_empty_graph():
    graph = parse_llm_json('{"nodes": [], "edges": []}')

    assert graph.explicitly_empty
    assert graph.missing_keys == ()


def test_parse_truncated_json_is_repaired():
    full = json.dumps(GRAPH)
    # Simulate a response cut off mid-second-node.
    cutoff = full.index('{"from"')
    truncated = full[: cutoff - 2]  # drop the trailing "]," before edges too
    graph = parse_llm_json(truncated)
    assert graph.truncated
    assert len(graph.nodes) >= 1


def test_parse_raises_when_no_json_object_present():
    with pytest.raises(GraphParseError):
        parse_llm_json("no json here at all")


def test_merge_graphs_deduplicates_nodes():
    g1 = AttackGraph(nodes=[{"id": "a", "label": "A"}], edges=[])
    g2 = AttackGraph(nodes=[{"id": "a", "label": "A"}, {"id": "b", "label": "B"}], edges=[{"from": "a", "to": "b", "label": "x"}])

    merged = merge_graphs([g1, g2])

    assert [n["id"] for n in merged.nodes] == ["a", "b"]
    assert len(merged.edges) == 1


def test_merge_graphs_namespaces_conflicting_ids_and_rewrites_local_edges():
    g1 = AttackGraph(nodes=[{"id": "a", "label": "First A"}], edges=[])
    g2 = AttackGraph(
        nodes=[{"id": "a", "label": "Different A"}, {"id": "b", "label": "B"}],
        edges=[{"from": "a", "to": "b", "label": "local"}],
    )

    conflicts = []
    merged = merge_graphs([g1, g2], conflict_log=conflicts)

    assert [node["id"] for node in merged.nodes] == ["a", "chunk-2::a", "b"]
    assert merged.edges == [{"from": "chunk-2::a", "to": "b", "label": "local"}]
    assert conflicts == [{
        "chunk_number": 2,
        "original_id": "a",
        "renamed_id": "chunk-2::a",
        "reason": "same id with different node body",
    }]
