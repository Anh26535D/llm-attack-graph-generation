"""Tests for the H1 edge-support tooling (offline)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crystalball.postprocess import AttackGraph  # noqa: E402
from experiments.h1_edge_support import prepare, score  # noqa: E402
from experiments.h1_edge_support.extract import graph_edges, map_node  # noqa: E402

LABELS = Path(__file__).resolve().parents[1] / "experiments" / "h1_edge_support" / "labels.json"


def test_prompt_is_appendix_a_with_ids_only():
    text = prepare.build_prompt()
    original = prepare.APPENDIX_A.read_text(encoding="utf-8")
    import re

    stripped = re.sub(r"^CVE-\d{4}-\d+: ", "", text, flags=re.M)
    assert stripped.strip() == original.strip()


def test_map_node_prefers_ids_then_unique_label_keyword():
    assert map_node({"id": 1, "label": "x", "pre": "CVE-2020-1885"}) == {"CVE-2020-1885"}
    assert map_node({"id": 1, "label": "RaspAP web console command execution"}) == {"CVE-2020-24572"}
    assert map_node({"id": 1, "label": "RaspAP and piSignage combined"}) == set()  # ambiguous
    assert map_node({"id": 1, "label": "Initial attacker state"}) == set()


def test_graph_edges_counts_non_cve_edges_separately():
    g = AttackGraph(
        nodes=[
            {"id": "a", "label": "piSignage path traversal"},
            {"id": "b", "label": "RaspAP console"},
            {"id": "s", "label": "Attacker start"},
        ],
        edges=[{"from": "a", "to": "b", "label": "x"}, {"from": "s", "to": "a", "label": "y"}],
    )
    edges, other = graph_edges(g)
    assert [(e["cve_from"], e["cve_to"]) for e in edges] == [("CVE-2019-20354", "CVE-2020-24572")]
    assert other == 1


def test_score_pools_labels_and_applies_borderline_sensitivity(tmp_path, capsys):
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    pairs = {
        "pairs": {
            "CVE-2019-20354->CVE-2021-38759": {"runs": ["m/r1", "m/r2"]},  # borderline unsupported
            "CVE-2019-3562->CVE-2020-1885": {"runs": ["m/r1"]},  # conditional
        }
    }
    p = tmp_path / "pairs.json"
    p.write_text(json.dumps(pairs), encoding="utf-8")
    assert score.main(["--pairs", str(p), "--labels", str(LABELS)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["pooled"]["unsupported"] == 2 and result["pooled"]["conditional"] == 1
    assert result["sensitivity_borderline_as_conditional"]["unsupported"] == 0


def test_every_label_is_valid():
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    for key, value in labels.items():
        if key == "_meta":
            continue
        assert value["label"] in {"supported", "conditional", "unsupported", "contradicted"}
        assert value["evidence"] and value["reason"]
