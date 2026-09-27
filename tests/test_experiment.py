import json

from crystalball.experiment import (
    dispatch_paired_prompt,
    edges_for_visualization,
    graph_schema_metrics,
    prompt_sha256,
)
from crystalball.postprocess import (
    AttackGraph,
    _spread_overlapping_positions,
    visualize_graph_report,
    visualize_graph_report_with_legend,
)


class FakeClient:
    def __init__(self):
        self.received = []

    def complete(self, prompt):
        self.received.append(prompt.encode("utf-8"))
        return '{"nodes": [], "edges": []}'


def test_frozen_prompt_bytes_are_identical_for_both_model_clients():
    frozen = "Create graph\n\nCVE-2020-1885: mô tả mẫu".encode("utf-8")
    gemini = FakeClient()
    openrouter = FakeClient()

    results = dispatch_paired_prompt(frozen, {"gemini": gemini, "openrouter": openrouter})

    assert gemini.received == [frozen]
    assert openrouter.received == [frozen]
    assert prompt_sha256(gemini.received[0]) == prompt_sha256(openrouter.received[0])
    assert {result.client_name: result.prompt_sha256 for result in results} == {
        "gemini": prompt_sha256(frozen),
        "openrouter": prompt_sha256(frozen),
    }


def test_edge_schema_metric_keeps_source_target_violation_visible():
    nodes = [{"id": "a", "label": "A"}, {"id": "b", "label": "B"}]
    raw_edges = [{"source": "a", "target": "b", "description": "edge"}]

    metrics = graph_schema_metrics(nodes, raw_edges)
    visual_edges, aliased = edges_for_visualization(raw_edges)

    assert metrics["schema_valid"] is False
    assert metrics["edge_schema_compliance"] == 0
    assert metrics["alternate_source_target_edges_count"] == 1
    assert metrics["edge_endpoint_integrity"] == 0
    assert aliased is True
    assert visual_edges[0]["from"] == "a"
    assert visual_edges[0]["to"] == "b"
    assert "from" not in raw_edges[0] and "to" not in raw_edges[0]


def test_empty_graph_does_not_pass_schema_validation():
    metrics = graph_schema_metrics([], [])

    assert metrics["non_empty_graph"] is False
    assert metrics["schema_valid"] is False
    assert metrics["edge_schema_compliance"] is None


def test_schema_rejects_empty_or_duplicate_node_ids_and_blank_labels():
    metrics = graph_schema_metrics(
        [
            {"id": " ", "label": "Blank id"},
            {"id": "n1", "label": "Node one"},
            {"id": "n1", "label": "Duplicate id"},
            {"id": "n2", "label": " "},
        ],
        [{"from": "n1", "to": "missing", "label": " "}],
    )

    assert metrics["schema_valid"] is False
    assert metrics["invalid_node_ids_count"] == 1
    assert metrics["duplicate_node_ids_count"] == 1
    assert metrics["invalid_node_labels_count"] == 1
    assert metrics["invalid_edge_labels_count"] == 1
    assert metrics["edge_endpoint_integrity"] == 0


def test_cve_conditions_require_nonempty_pre_and_postconditions():
    nodes = [{"id": "n1", "label": "Vulnerability"}]

    basic = graph_schema_metrics(nodes, [], condition_id="baseline_no_context")
    c1 = graph_schema_metrics(nodes, [], condition_id="C1")
    c2 = graph_schema_metrics(nodes, [], condition_id="C2")
    cve = graph_schema_metrics(nodes, [], condition_id="retriever_context")
    x0 = graph_schema_metrics(nodes, [], condition_id="X0")
    section54 = [
        graph_schema_metrics(nodes, [], condition_id=condition_id)
        for condition_id in (
            "S54_CUTOFF_INITIAL",
            "S54_CUTOFF_CONTINUATION",
            "S54_EDGE_DETAIL",
        )
    ]

    assert basic["schema_valid"] is True
    assert c1["schema_valid"] is False
    assert c2["schema_valid"] is False
    assert cve["schema_valid"] is False
    assert cve["missing_node_condition_fields_count"] == 1
    assert x0["schema_valid"] is False
    assert all(metrics["schema_valid"] is False for metrics in section54)


def test_cve_schema_passes_when_pre_and_postconditions_are_present():
    nodes = [
        {
            "id": "n1",
            "label": "Vulnerability",
            "precondition": "Local access",
            "postcondition": "Elevated access",
        },
        {
            "id": "n2",
            "label": "Target",
            "precondition": "Elevated access",
            "postcondition": "System compromise",
        },
    ]
    edges = [{"from": "n1", "to": "n2", "label": "Grants access"}]

    metrics = graph_schema_metrics(nodes, edges, condition_id="appendix_a_full_8_cves")

    assert metrics["schema_valid"] is True
    assert metrics["valid_edges"] == 1
    assert metrics["missing_node_condition_fields_count"] == 0


def test_schema_rejects_missing_edge_fields_and_unknown_endpoints():
    nodes = [{"id": "n1", "label": "A"}, {"id": "n2", "label": "B"}]

    missing_field = graph_schema_metrics(nodes, [{"from": "n1", "to": "n2"}])
    unknown_endpoint = graph_schema_metrics(
        nodes, [{"from": "n1", "to": "n3", "label": "No such node"}]
    )

    assert missing_field["schema_valid"] is False
    assert missing_field["missing_edge_required_fields_count"] == 1
    assert unknown_endpoint["schema_valid"] is False
    assert unknown_endpoint["invalid_edges"] == 1


def test_report_graph_png_keeps_full_graph_in_sidecar(tmp_path):
    graph = AttackGraph(
        nodes=[
            {"id": "n1", "label": "CVE-2020-1885: a very long vulnerability description " * 2},
            {"id": "n2", "label": "Gain access"},
        ],
        edges=[{"source": "n1", "target": "n2", "description": "full edge label"}],
    )
    out_path = tmp_path / "graph_report.png"

    visualize_graph_report(graph, out_path, max_label_chars=42)

    assert out_path.exists()
    legend = json.loads((tmp_path / "graph_report_legend.json").read_text())
    assert legend["nodes"][0]["full_label"].startswith("CVE-2020-1885")
    assert graph.edges[0]["source"] == "n1"


def test_combined_report_png_includes_node_legend(tmp_path):
    graph = AttackGraph(
        nodes=[
            {"id": f"n{i}", "label": f"CVE-202{i}-1234: node label {i}"}
            for i in range(1, 9)
        ],
        edges=[{"from": f"n{i}", "to": f"n{i + 1}", "label": "edge"} for i in range(1, 8)],
    )
    out_path = tmp_path / "graph_report_with_legend.png"

    visualize_graph_report_with_legend(graph, out_path)

    assert out_path.is_file()
    assert out_path.stat().st_size > 1000


def test_report_layout_spreads_overlapping_nodes_deterministically():
    initial = {"N10": [0.73, -0.50], "N11": [0.85, -0.47], "N1": [-0.8, 0.7]}

    spread = _spread_overlapping_positions(initial, minimum_distance=0.23, iterations=160)

    distance = ((spread["N10"][0] - spread["N11"][0]) ** 2 + (spread["N10"][1] - spread["N11"][1]) ** 2) ** 0.5
    assert distance >= 0.229
    assert spread == _spread_overlapping_positions(initial, minimum_distance=0.23, iterations=160)
