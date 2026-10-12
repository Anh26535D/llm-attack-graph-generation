import json
import re

import pytest

from crystalball.demo_graph import render_demo_graph
from crystalball.postprocess import AttackGraph


def test_renderer_preserves_graph_and_escapes_model_text(tmp_path):
    label = '</script><script>alert("model text")</script>'
    graph = AttackGraph(
        nodes=[{"id": "a", "label": label, "source_refs": ["P001"]},
               {"id": "b", "label": "Observed action"}],
        edges=[{"from": "a", "to": "b", "label": "enables", "source_refs": ["P001"]}],
    )
    render_demo_graph(graph, tmp_path, title="Test", sources={"P001": "Evidence"})
    html = (tmp_path / "graph.html").read_text(encoding="utf-8")
    embedded = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S)[1]
    data = json.loads(embedded)
    assert data["nodes"] == graph.nodes
    assert data["edges"] == graph.edges
    assert label not in html
    assert data["sources"]["P001"] == "Evidence"
    svg = (tmp_path / "graph.svg").read_text(encoding="utf-8")
    assert svg.count('class="node"') == 2
    assert svg.count('class="edge"') == 1
    assert (tmp_path / "graph.png").stat().st_size > 1000


@pytest.mark.parametrize("nodes,edges", [
    ([{"id": "a", "label": "One"}, {"id": "a", "label": "Two"}], []),
    ([{"id": "a", "label": "One"}], [{"from": "a", "to": "missing", "label": "invalid"}]),
])
def test_renderer_rejects_duplicate_ids_and_unknown_endpoints(tmp_path, nodes, edges):
    with pytest.raises(ValueError):
        render_demo_graph(AttackGraph(nodes=nodes, edges=edges), tmp_path, title="Invalid")
