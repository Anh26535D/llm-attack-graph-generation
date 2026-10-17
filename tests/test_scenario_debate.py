from copy import deepcopy
import json

import pytest

from crystalball.config import Settings
from crystalball.generation_debate import DebateConfig, create_draft, run_strategy
from crystalball.scenario_debate import TASK, audit, execute, fixture, prepare, read, score, verify


def oracle_candidate(public, reference, *, revised=False):
    nodes = [{"id": node["id"], "kind": node["kind"], "host": node["host"], "cve_id": node["cve_id"],
              "label": node["id"], "precondition": "fixture prerequisite", "postcondition": "fixture outcome",
              **({"prerequisite_logic": "AND"} if node["kind"] == "action" else {})} for node in public["nodes"]]
    sources = {node["id"]: node["description"] for node in public["nodes"]}
    edges = [{**edge, "label": edge["relation"]} for edge in reference["edges"]]
    return {"graph": {"nodes": nodes, "edges": edges},
            "edge_evidence": [{"from": edge["from"], "to": edge["to"],
                               "source_quote": sources[edge["from"]][:100], "target_quote": sources[edge["to"]][:100],
                               "bridge": "fixture relation", "missing_conditions": []} for edge in edges],
            "decisions": [{"from": edge["from"], "to": edge["to"], "action": "keep", "reason": "fixture reason"}
                          for edge in edges] if revised else []}


def test_fixture_contains_all_eight_cves_and_reaches_goal_with_and_requirements():
    public, reference = fixture()
    assert len(public["nodes"]) == 27
    assert len(reference["edges"]) == 23
    assert {node["cve_id"] for node in public["nodes"] if node["cve_id"]} == set(public["official_cve_descriptions"])
    edges = {(edge["from"], edge["to"]) for edge in reference["edges"]}
    assert not any(a in reference["isolated_controls"] or b in reference["isolated_controls"] for a, b in edges)
    states = set(reference["initial_states"])
    activated = set()
    while True:
        previous = states.copy()
        for node in public["nodes"]:
            if node["kind"] != "action":
                continue
            prerequisites = {a for a, b in edges if b == node["id"]}
            if prerequisites and prerequisites <= states:
                activated.add(node["id"])
                states |= {b for a, b in edges if a == node["id"]}
        if states == previous:
            break
    assert "S12" in states
    assert not {"A11", "A12", "A13", "A14"} & activated
    assert {a for a, b in edges if b == "A09"} == {"S08", "S09", "S10"}


def test_missing_and_input_and_false_physical_bridge_are_scored_separately():
    public, reference = fixture()
    value = oracle_candidate(public, reference)
    assert score(value, reference)["reference_f1"] == 1
    value["graph"]["edges"] = [edge for edge in value["graph"]["edges"] if (edge["from"], edge["to"]) != ("S08", "A09")]
    value["graph"]["edges"].append({"from": "S13", "to": "A12", "relation": "requires", "label": "invalid audio to physical"})
    result = score(value, reference)
    assert result["matched_edges"] == 22
    assert result["extra_or_wrong_edges"] == 1
    assert result["missing_edges"] == 1
    assert result["and_groups_complete"] == {"A05": True, "A09": False}
    assert result["control_incident_edges"] == 1
    assert result["independent_gold"] is False
    assert result["real_world_accuracy"] is None


def test_scenario_audit_checks_quotes_identities_and_and_without_promoting_truth():
    public, reference = fixture()
    value = oracle_candidate(public, reference)
    sources = {node["id"]: node["description"] for node in public["nodes"]}
    assert audit(public, value, sources)["mechanical_checks_passed"]
    value["graph"]["nodes"][1]["host"] = "wrong-host"
    value["graph"]["nodes"][1]["prerequisite_logic"] = "OR"
    value["edge_evidence"][0]["source_quote"] = "invented proof"
    result = audit(public, value, sources)
    assert not result["mechanical_checks_passed"]
    assert result["semantic_accuracy"] is None
    assert any("AND" in issue for issue in result["issues"])
    assert any("quote_unverified" in issue for issue in result["issues"])


def test_custom_task_used_in_all_roles_without_leaking_reference():
    public, reference = fixture()
    initial = oracle_candidate(public, reference)
    revised = oracle_candidate(public, reference, revised=True)
    sources = {node["id"]: node["description"] for node in public["nodes"]}
    calls = []
    def complete(stage, role, prompt):
        calls.append(prompt)
        assert prompt.startswith(TASK)
        assert "Use one vulnerability node for EACH supplied CVE" not in prompt
        assert "isolated_controls" not in prompt
        assert "and_requirements" not in prompt
        if role in {"defender", "skeptic"}:
            return json.dumps({"arguments": [{"edge_id": f"edge-{index:04d}", "position": "keep", "reason": "source states prerequisite",
                "source_quote": sources[edge["from"]][:90], "target_quote": sources[edge["to"]][:90], "missing_conditions": []}
                for index, edge in enumerate(initial["graph"]["edges"], 1)]})
        return json.dumps(initial if stage == "draft" else revised)
    start = create_draft(sources, complete, task=TASK)
    result = run_strategy(start, "debate", sources, complete, DebateConfig(), task=TASK,
                          auditor=lambda value, texts: audit(public, value, texts))
    assert len(calls) == 4
    assert result["status"] == "ready_for_independent_validation"


def test_prepare_and_execution_use_frozen_separate_reference_and_reuse_calls(tmp_path, monkeypatch):
    import crystalball.scenario_debate as module
    monkeypatch.setattr(module, "hashes", lambda: {"pyproject.toml": "fixed-test-sentinel"})
    settings = Settings(gemini_model="fake", gemini_api_key="secret")
    out = tmp_path / "scenario"
    manifest = prepare(out, settings, repeats=1, backend="gemini", config=DebateConfig())
    assert manifest["max_api_calls_total"] == 7
    assert not manifest["reference_visible_to_model"]
    public = read(out / "scenario.json")
    reference = read(out / "reference.synthetic.json")
    initial = oracle_candidate(public, reference)
    revised = oracle_candidate(public, reference, revised=True)
    sources = {node["id"]: node["description"] for node in public["nodes"]}
    calls = []
    class Fake:
        last_usage = {"prompt_token_count": 1, "candidates_token_count": 2, "total_token_count": 3}
        last_response_metadata = {"finish_reason": "STOP", "actual_model": "fake"}
        def complete(self, prompt, **kwargs):
            calls.append(prompt)
            assert "isolated_controls" not in prompt
            assert "reference_precision" not in prompt
            if "Do not output a graph" in prompt:
                return json.dumps({"arguments": [{"edge_id": f"edge-{i:04d}", "position": "keep", "reason": "given relation",
                    "source_quote": sources[e["from"]][:80], "target_quote": sources[e["to"]][:80], "missing_conditions": []}
                    for i, e in enumerate(initial["graph"]["edges"], 1)]})
            return json.dumps(initial if len(calls) == 1 else revised)
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: Fake())
    result = execute(out, settings)
    assert len(calls) == 7
    assert all(row["synthetic_evaluation"]["reference_f1"] == 1 for row in result["rows"])
    assert all(row["accuracy"] is None for row in result["rows"])
    execute(out, settings)
    assert len(calls) == 7
    assert not (out / ".execute.lock").exists()
    changed = read(out / "reference.synthetic.json")
    changed["edges"].pop()
    (out / "reference.synthetic.json").write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="Frozen"):
        verify(out, settings)
