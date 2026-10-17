from copy import deepcopy
import json

import pytest

from crystalball.config import Settings
from crystalball.generation_debate import (DebateConfig, audit_candidate, check_decisions,
    create_draft, parse_candidate, run_strategy, strict_object)
from crystalball.generation_debate_runner import (Journal, execute, identity, prepare, read,
                                                 report, save, verify)

SOURCES = {"CVE-2000-0001": "The source permits local code execution.",
           "CVE-2000-0002": "The target requires a local unprivileged process."}


def candidate(sources=SOURCES):
    ids = list(sources)
    return {"graph": {"nodes": [{"id": cve, "label": cve, "precondition": "unknown",
                                "postcondition": "unknown"} for cve in ids],
                       "edges": [{"from": ids[0], "to": ids[1], "label": "Conditional bridge"}]},
            "edge_evidence": [{"from": ids[0], "to": ids[1], "source_quote": sources[ids[0]][:100],
                               "target_quote": sources[ids[1]][:100], "bridge": "Potential execution bridge",
                               "missing_conditions": ["Same host and compatible deployment"]}], "decisions": []}


def revision(value):
    value = deepcopy(value)
    value["decisions"] = [{**{key: edge[key] for key in ("from", "to")},
                           "action": "keep", "reason": "Keep as explicitly conditional"}
                          for edge in value["graph"]["edges"]]
    return value


def argument(quote="The source permits local code execution."):
    return {"arguments": [{"edge_id": "edge-0001", "position": "revise", "reason": "Deployment is unobserved",
        "source_quote": quote, "target_quote": SOURCES["CVE-2000-0002"], "missing_conditions": ["same host"]}]}


def test_debate_uses_same_draft_independent_current_round_and_withholds_fake_quotes():
    initial = candidate()
    before = deepcopy(initial)
    prompts = {}
    def complete(stage, role, prompt):
        prompts[stage] = prompt
        if role in ("defender", "skeptic"):
            return json.dumps(argument("forged quotation"))
        return json.dumps(revision(initial))
    result = run_strategy(initial, "debate", SOURCES, complete, DebateConfig(rounds=2), defender_first=False)
    assert initial == before
    assert len(prompts) == 5
    assert "forged quotation" not in prompts["debate.r1.skeptic"]
    assert '"previous_rounds": []' in prompts["debate.r1.defender"]
    assert '"previous_rounds": []' in prompts["debate.r1.skeptic"]
    assert '"round": 1' in prompts["debate.r2.defender"]
    assert "forged quotation" not in prompts["debate.synthesis"]
    assert '"unverified"' in prompts["debate.synthesis"]
    assert prompts["debate.synthesis"].index('"role": "skeptic"') < prompts["debate.synthesis"].index('"role": "defender"')
    assert result["status"] == "ready_for_independent_validation"
    assert result["audit"]["semantic_accuracy"] is None


def test_self_refinement_matches_debate_call_count_and_keeps_draft():
    initial = candidate()
    calls = []
    def complete(stage, role, prompt):
        calls.append((stage, role))
        return json.dumps(revision(initial))
    run_strategy(initial, "self_refine", SOURCES, complete, DebateConfig(rounds=2))
    assert len(calls) == 5
    assert {role for _, role in calls} == {"generator"}
    assert initial["decisions"] == []


@pytest.mark.parametrize("raw", ['{"graph": {}, "graph": {}}', '{"x":NaN}', '```json\n{}\n```', '[]'])
def test_no_silent_json_repairs(raw):
    with pytest.raises(ValueError):
        strict_object(raw)


def test_identity_or_quote_failures_cannot_be_published_as_checked_graph():
    value = candidate()
    value["edge_evidence"][0]["source_quote"] = "fabricated fact"
    result = run_strategy(value, "grounded", SOURCES, lambda *_: pytest.fail("No calls"), DebateConfig())
    assert result["status"] == "mechanical_checks_failed"
    assert "evidence_0_source_quote_not_verified" in result["audit"]["issues"]
    value = candidate()
    value["graph"]["nodes"][0]["id"] = "CVE-9999-9999"
    assert not audit_candidate(value, SOURCES)["mechanical_checks_passed"]


def test_deletions_and_additions_must_have_consistent_decisions():
    old = candidate()
    new = deepcopy(old)
    new["graph"]["edges"] = []
    new["edge_evidence"] = []
    with pytest.raises(ValueError, match="account"):
        check_decisions(old, new)
    decision = {"from": "CVE-2000-0001", "to": "CVE-2000-0002", "action": "remove", "reason": "No bridge"}
    new["decisions"] = [decision]
    check_decisions(old, new)
    new["decisions"][0]["action"] = "keep"
    with pytest.raises(ValueError, match="conflicts"):
        check_decisions(old, new)
    added = deepcopy(old)
    added["decisions"] = [{**decision, "action": "add"}]
    check_decisions({"graph": {"nodes": [], "edges": []}}, added)


def setup_run(tmp_path, monkeypatch, *, strategies=("grounded", "self_refine", "debate")):
    import crystalball.generation_debate_runner as runner
    settings = Settings(gemini_model="fake-model", gemini_api_key="test-secret")
    # Pin to a deterministic sentinel so tests do not depend on unrelated source edits.
    monkeypatch.setattr(runner, "code_hashes", lambda: {"sentinel": "same"})
    out = tmp_path / "pilot"
    manifest = prepare(out, settings, repeats=1, config=DebateConfig(),
                       backends=dict.fromkeys(("generator", "defender", "skeptic", "judge"), "gemini"),
                       strategies=strategies)
    return out, settings, manifest


def test_prepare_is_offline_freezes_budget_and_all_pairs(tmp_path, monkeypatch):
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: pytest.fail("Offline prepare"))
    out, settings, manifest = setup_run(tmp_path, monkeypatch)
    assert manifest["max_api_calls_total"] == 7
    assert manifest["same_model_for_all_roles"]
    assert len(read(out / "pair_annotation_blind.json")["pairs"]) == 56
    assert "test-secret" not in (out / "manifest.json").read_text()
    verify(out, settings)
    snapshot = read(out / "sources.json")
    snapshot[next(iter(snapshot))] += "new fact"
    save(out / "sources.json", snapshot)
    with pytest.raises(ValueError, match="snapshot changed"):
        verify(out, settings)


def test_paired_pilot_runs_seven_calls_reuses_responses_and_never_uses_env_validator(tmp_path, monkeypatch):
    out, settings, _ = setup_run(tmp_path, monkeypatch)
    sources = read(out / "sources.json")
    initial = candidate(sources)
    calls = []
    class Fake:
        last_usage = {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30}
        last_response_metadata = {"finish_reason": "stop"}
        def complete(self, prompt, **kwargs):
            calls.append(prompt)
            if "Do not output a graph" in prompt:
                row = argument()["arguments"][0]
                row["source_quote"] = initial["edge_evidence"][0]["source_quote"]
                row["target_quote"] = initial["edge_evidence"][0]["target_quote"]
                return json.dumps({"arguments": [row]})
            return json.dumps(initial if len(calls) == 1 else revision(initial))
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: Fake())
    monkeypatch.setenv("VALIDATOR_LLM_ENABLED", "true")
    first = execute(out, settings)
    assert len(calls) == 7
    assert [row["api_calls_including_shared_draft"] for row in first["runs"]] == [1, 4, 4]
    assert all(row["accuracy"] is None for row in first["runs"])
    assert all(row["status"] == "ready_for_independent_validation" for row in first["runs"])
    execute(out, settings)
    assert len(calls) == 7
    assert not (out / ".execute.lock").exists()
    for strategy in ("grounded", "self_refine", "debate"):
        validation = read(out / f"runs/r01/{strategy}/validation/validation_results.json")
        assert validation["config"]["mode"] == "offline"
        assert validation["review_enabled"] is False
        assert (out / f"runs/r01/{strategy}/graph.json").exists()


def test_journal_preserves_raw_before_parse_and_refuses_failed_or_uncertain_calls(tmp_path, monkeypatch):
    out, settings, manifest = setup_run(tmp_path, monkeypatch)
    class Bad:
        last_usage = None
        last_response_metadata = None
        def complete(self, *_args, **_kwargs):
            return "invalid JSON"
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: Bad())
    journal = Journal(out / "runs/r01", settings, manifest)
    with pytest.raises(ValueError):
        create_draft(read(out / "sources.json"), journal.complete)
    assert (journal.folder / "calls/draft.response.txt").read_text() == "invalid JSON"
    assert read(journal.folder / "calls/draft.json")["status"] == "received"
    # A received response may be re-parsed, but it must never trigger a duplicate request.
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: pytest.fail("No retry"))
    assert Journal(journal.folder, settings, manifest).complete("draft", "generator",
        (journal.folder / "calls/draft.prompt.txt").read_text(encoding="utf-8")) == "invalid JSON"
    record = read(journal.folder / "calls/draft.json")
    record["status"] = "started"
    save(journal.folder / "calls/draft.json", record)
    with pytest.raises(RuntimeError, match="uncertain"):
        journal.complete("draft", "generator", (journal.folder / "calls/draft.prompt.txt").read_text(encoding="utf-8"))


def test_changed_model_provider_and_raw_tampering_are_rejected(tmp_path, monkeypatch):
    from dataclasses import replace
    out, settings, manifest = setup_run(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="Model/provider changed"):
        verify(out, replace(settings, gemini_model="another-model"))
    assert identity(replace(settings, openrouter_model_v2="fake", openrouter_provider_config_v2='{"only":["x"]}'),
                    "openrouter_v2")["provider_config"] == {"only": ["x"]}
    journal = Journal(out / "runs/r01", settings, manifest)
    class Fake:
        last_usage = None
        last_response_metadata = None
        def complete(self, *_args, **_kwargs):
            return "{}"
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: Fake())
    journal.complete("draft", "generator", "same prompt")
    (journal.folder / "calls/draft.response.txt").write_text("changed")
    with pytest.raises(ValueError, match="raw response changed"):
        journal.complete("draft", "generator", "same prompt")


def test_bad_critique_stops_before_synthesis():
    calls = []
    def complete(stage, role, prompt):
        calls.append(stage)
        return '{"arguments":[]}'
    with pytest.raises(ValueError, match="cover every"):
        run_strategy(candidate(), "debate", SOURCES, complete, DebateConfig())
    assert calls == ["debate.r1.defender"]


def test_output_limit_is_not_hidden_by_a_complete_json_object(tmp_path, monkeypatch):
    out, settings, _ = setup_run(tmp_path, monkeypatch)
    initial = candidate(read(out / "sources.json"))
    calls = []
    class Truncated:
        last_usage = None
        last_response_metadata = {"finish_reason": "MAX_TOKENS"}
        def complete(self, *_args, **_kwargs):
            calls.append(1)
            return json.dumps(initial)
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: Truncated())
    with pytest.raises(RuntimeError, match="output limit"):
        execute(out, settings)
    assert len(calls) == 1
    assert read(out / "runs/r01/calls/draft.json")["output_truncated"]
    assert all(row["status"] == "draft_failed" for row in read(out / "comparison.json")["runs"])
    with pytest.raises(RuntimeError, match="output limit"):
        execute(out, settings)
    assert len(calls) == 1


def test_request_errors_stop_pilot_and_are_not_silently_retried(tmp_path, monkeypatch):
    out, settings, _ = setup_run(tmp_path, monkeypatch)
    calls = []
    class Broken:
        last_usage = None
        last_response_metadata = None
        def complete(self, *_args, **_kwargs):
            calls.append(1)
            raise RuntimeError("test-secret")
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: Broken())
    with pytest.raises(RuntimeError) as error:
        execute(out, settings)
    assert "test-secret" not in str(error.value)
    assert len(calls) == 1
    assert read(out / "runs/r01/calls/draft.json")["status"] == "error"
    assert not (out / ".execute.lock").exists()
    with pytest.raises(RuntimeError, match="uncertain"):
        execute(out, settings)
    assert len(calls) == 1


def test_frozen_manifest_and_request_budget_are_enforced(tmp_path, monkeypatch):
    out, settings, manifest = setup_run(tmp_path, monkeypatch, strategies=("grounded",))
    journal = Journal(out / "runs/r01", settings, manifest)
    save(journal.folder / "calls/uncertain.json", {"status": "started"})
    with pytest.raises(RuntimeError, match="budget"):
        journal.complete("draft", "generator", "prompt")
    changed = deepcopy(manifest)
    changed["max_api_calls_total"] = 100
    save(out / "manifest.json", changed)
    with pytest.raises(ValueError, match="manifest changed"):
        verify(out, settings)


def test_same_exact_id_with_another_cve_in_label_stays_ambiguous():
    value = candidate()
    value["graph"]["nodes"][0]["label"] = "CVE-2000-0002"
    assert "ambiguous_or_conflicting_node_CVE_identity" in audit_candidate(value, SOURCES)["issues"]
