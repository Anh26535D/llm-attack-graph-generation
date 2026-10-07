"""Tests for the E1 environment-consistency experiment (offline, no LLM calls)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crystalball.postprocess import AttackGraph  # noqa: E402
from experiments.env_consistency import run as e1_run  # noqa: E402
from experiments.env_consistency.conditions import CONDITIONS, VersionRange  # noqa: E402
from experiments.env_consistency.engine import classify_edge, enabled_cves  # noqa: E402
from experiments.env_consistency.envs import INTERVENTIONS, build_env  # noqa: E402
from experiments.env_consistency.prompts import (  # noqa: E402
    ENV_AWARE_SENTENCE,
    build_cases,
    load_cve_descriptions,
)
from experiments.env_consistency.scoring import (  # noqa: E402
    node_cves,
    score_counterfactual,
    score_graph,
)

ALL_CVES = set(CONDITIONS)


def node(node_id, text):
    return {"id": node_id, "label": text}


def graph(nodes, edges=()):
    return AttackGraph(nodes=list(nodes), edges=list(edges))


def test_conditions_cover_exactly_the_eight_official_cves():
    descriptions = load_cve_descriptions()
    assert set(descriptions) == ALL_CVES
    assert len(ALL_CVES) == 8


@pytest.mark.parametrize(
    "rng,version,expected",
    [
        (VersionRange(max_excl="2.6.4"), "2.6.3", True),
        (VersionRange(max_excl="2.6.4"), "2.6.4", False),
        (VersionRange(min_incl="5.2.7", max_incl="5.7.11"), "5.2.7", True),
        (VersionRange(min_incl="5.2.7", max_incl="5.7.11"), "5.7.11", True),
        (VersionRange(min_incl="5.2.7", max_incl="5.7.11"), "5.7.12", False),
        (VersionRange(min_excl="1.39", max_excl="31.1.0.67.507"), "1.39", False),
        (VersionRange(min_excl="1.39", max_excl="31.1.0.67.507"), "1.39.0.1", True),
        (VersionRange(min_excl="1.39", max_excl="31.1.0.67.507"), "31.1.0.67.507", False),
        (VersionRange(min_incl="32.0", max_excl="32.7.1"), "32.7.0", True),
        (VersionRange(min_incl="32.0", max_excl="32.7.1"), "32.7.1", False),
        (VersionRange(min_incl="32.0", max_excl="32.7.1"), "33.0", False),
    ],
)
def test_version_ranges(rng, version, expected):
    assert rng.contains(version) is expected


BASE_ENABLED = {
    "signage": {"CVE-2019-20354", "CVE-2020-24572", "CVE-2021-38545", "CVE-2021-38759"},
    "vr": {"CVE-2019-3562", "CVE-2020-1885", "CVE-2021-24038"},
    "edge": {"CVE-2020-24572", "CVE-2021-38759", "CVE-2022-21819"},
}


@pytest.mark.parametrize("env_id", sorted(BASE_ENABLED))
def test_base_environments(env_id):
    assert enabled_cves(build_env(env_id)) == BASE_ENABLED[env_id]


@pytest.mark.parametrize(
    "env_id,intervention,disabled",
    [
        ("signage", "patch_pisignage", {"CVE-2019-20354"}),
        ("signage", "change_pi_password", {"CVE-2021-38759"}),
        ("signage", "remove_credential", {"CVE-2019-20354", "CVE-2020-24572"}),
        ("signage", "no_audio_output", {"CVE-2021-38545"}),
        ("vr", "patch_oculus_desktop", {"CVE-2020-1885", "CVE-2021-24038"}),
        # Without the browser foothold the local escalations lose their only way in.
        ("vr", "update_browser", {"CVE-2019-3562", "CVE-2020-1885", "CVE-2021-24038"}),
        ("edge", "block_jetson_to_pi", {"CVE-2020-24572", "CVE-2021-38759"}),
        ("edge", "patch_jetson", ALL_CVES & BASE_ENABLED["edge"]),
    ],
)
def test_interventions_disable_expected_cves(env_id, intervention, disabled):
    now = enabled_cves(build_env(env_id, intervention))
    assert BASE_ENABLED[env_id] - now == disabled
    assert now <= BASE_ENABLED[env_id]  # an intervention here never enables anything new


def test_build_env_does_not_mutate_shared_state():
    build_env("signage", "patch_pisignage")
    assert build_env("signage").hosts["signage-pi"].services["pisignage"] == "2.6.1"


@pytest.mark.parametrize(
    "env_id,a,b,expected",
    [
        ("vr", "CVE-2019-3562", "CVE-2020-1885", "supported"),  # browser foothold -> local LPE
        ("vr", "CVE-2020-1885", "CVE-2019-3562", "redundant"),  # browser needs no foothold
        ("edge", "CVE-2022-21819", "CVE-2020-24572", "supported"),  # jetson -> pi via link
        ("signage", "CVE-2019-20354", "CVE-2020-24572", "redundant"),  # info leak, not a foothold
        ("signage", "CVE-2021-38759", "CVE-2022-21819", "unsupported"),  # Jetson not present
    ],
)
def test_classify_edge(env_id, a, b, expected):
    assert classify_edge(build_env(env_id), a, b) == expected


def test_info_effect_never_supports_a_chain():
    # The file-read CVE grants no foothold, so it cannot make a local CVE possible.
    assert classify_edge(build_env("vr"), "CVE-2019-20354", "CVE-2020-1885") == "unsupported"


def test_node_cve_extraction_is_case_insensitive_and_scans_all_fields():
    n = {"id": 1, "label": "x", "precondition": "cve-2020-1885 applies", "d": {"k": "CVE-2021-24038"}}
    assert node_cves(n) == {"CVE-2020-1885", "CVE-2021-24038"}


def test_score_graph_precision_recall_and_edges():
    env = build_env("vr")
    g = graph(
        [
            node(1, "CVE-2019-3562 browser injection"),
            node(2, "CVE-2020-1885 local escalation"),
            node(3, "CVE-2022-21819 Jetson physical access"),  # not applicable here
        ],
        [{"from": 1, "to": 2, "label": "x"}, {"from": 2, "to": 3, "label": "y"}, {"from": 9, "to": 1}],
    )
    s = score_graph(g, env)
    assert s.precision == pytest.approx(2 / 3)
    assert s.recall == pytest.approx(2 / 3)
    assert s.edge_counts == {"supported": 1, "redundant": 0, "unsupported": 1, "unevaluable": 1}


def test_counterfactual_retention_and_direct_split():
    base_env, new_env = build_env("vr"), build_env("vr", "patch_oculus_desktop")
    base_graph = graph([node(1, "CVE-2019-3562"), node(2, "CVE-2020-1885"), node(3, "CVE-2021-24038")])

    stale = score_counterfactual(base_graph, base_graph, base_env, new_env)  # nothing changes
    assert stale.disabled == {"CVE-2020-1885", "CVE-2021-24038"}
    assert stale.disabled_direct == stale.disabled  # patch itself blocks both
    assert stale.retention_rate == 1.0 and stale.retention_rate_direct == 1.0
    assert stale.collateral_rate == 0.0

    updated = graph([node(1, "CVE-2019-3562")])
    good = score_counterfactual(base_graph, updated, base_env, new_env)
    assert good.retention_rate == 0.0
    assert good.collateral_rate == 0.0


def test_downstream_disabled_cves_are_not_counted_as_direct():
    base_env, new_env = build_env("vr"), build_env("vr", "update_browser")
    base_graph = graph([node(1, "CVE-2019-3562"), node(2, "CVE-2020-1885")])
    s = score_counterfactual(base_graph, base_graph, base_env, new_env)
    assert s.disabled_direct == {"CVE-2019-3562"}  # 1885 only lost its foothold
    assert s.retention_rate == pytest.approx(2 / 3)  # 24038 is disabled but not in the graph
    assert s.retention_rate_direct == 1.0


def test_negated_mentions_are_retained_but_not_active():
    base_env, new_env = build_env("signage"), build_env("signage", "patch_pisignage")
    base_graph = graph([node(1, "CVE-2019-20354 file read")])
    new_graph = graph([node(1, "CVE-2019-20354 is patched in piSignage 2.6.5, not exploitable")])
    s = score_counterfactual(base_graph, new_graph, base_env, new_env)
    assert s.retention_rate == 1.0
    assert s.retention_rate_active == 0.0


def test_collateral_loss_is_counted():
    base_env, new_env = build_env("signage"), build_env("signage", "patch_pisignage")
    base_graph = graph([node(1, "CVE-2019-20354"), node(2, "CVE-2020-24572")])
    new_graph = graph([])  # drops the still-valid CVE as well
    s = score_counterfactual(base_graph, new_graph, base_env, new_env)
    assert s.still_enabled_missing == {"CVE-2020-24572"}
    assert s.collateral_rate == 1.0


def test_prompts_contain_every_cve_and_variant_sentence_only_when_asked():
    descriptions = load_cve_descriptions()
    cases = build_cases(descriptions)
    expected_states = sum(1 + len(v) for v in INTERVENTIONS.values())
    assert len(cases) == expected_states * 2
    for case in cases:
        assert all(cve in case.prompt for cve in ALL_CVES)
        assert (ENV_AWARE_SENTENCE in case.prompt) == (case.variant == "env_aware")
        assert "Return only the json" in case.prompt  # CrystalBall instruction is kept verbatim
    patched = next(c for c in cases if c.case_id == "signage.patch_pisignage.plain")
    assert "piSignage has been upgraded to version 2.6.5" in patched.prompt
    assert "pisignage version 2.6.5" in patched.prompt


def _write_response(path: Path, cves):
    nodes = [{"id": i + 1, "label": cve} for i, cve in enumerate(sorted(cves))]
    path.write_text(json.dumps({"nodes": nodes, "edges": []}), encoding="utf-8")


def _run_pipeline(tmp_path, monkeypatch, responder):
    monkeypatch.setattr(e1_run, "OUT_ROOT", tmp_path / "out")
    assert e1_run.main(["emit", "--run-id", "t", "--envs", "vr", "--variants", "plain"]) == 0
    cases = json.loads((tmp_path / "out" / "t" / "cases.json").read_text())
    assert {c["case_id"] for c in cases} == {
        "vr.base.plain",
        "vr.patch_oculus_desktop.plain",
        "vr.update_browser.plain",
        "vr.block_untrusted_pages.plain",
    }
    responses = tmp_path / "resp" / "fake"
    responses.mkdir(parents=True)
    for case in cases:
        _write_response(responses / f"{case['case_id']}.r01.txt", responder(case))
    assert e1_run.main(["score", "--run-id", "t", "--responses", str(tmp_path / "resp")]) == 0
    summary = json.loads((tmp_path / "out" / "t" / "summary.json").read_text())
    return summary["by_model_variant"]["fake/plain"]


def test_pipeline_flags_a_model_that_ignores_the_environment(tmp_path, monkeypatch):
    result = _run_pipeline(tmp_path, monkeypatch, lambda case: BASE_ENABLED["vr"])
    assert result["mean_retention_rate"] == 1.0
    assert result["verdict"].startswith("GO")


def test_pipeline_accepts_a_model_that_tracks_the_environment(tmp_path, monkeypatch):
    result = _run_pipeline(tmp_path, monkeypatch, lambda case: case["expected_enabled"])
    assert result["mean_retention_rate"] == 0.0
    assert result["mean_collateral_rate"] == 0.0
    assert result["mean_base_precision"] == 1.0
    assert result["verdict"].startswith("STOP")


def test_emit_refuses_to_overwrite(tmp_path, monkeypatch):
    monkeypatch.setattr(e1_run, "OUT_ROOT", tmp_path / "out")
    assert e1_run.main(["emit", "--run-id", "t", "--envs", "vr"]) == 0
    assert e1_run.main(["emit", "--run-id", "t", "--envs", "vr"]) == 1
