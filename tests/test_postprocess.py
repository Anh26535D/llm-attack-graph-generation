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
