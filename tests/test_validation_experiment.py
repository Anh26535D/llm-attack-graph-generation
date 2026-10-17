from dataclasses import replace
import json

import pytest

from crystalball.config import Settings
from crystalball.validation import experiment_runner as pilot
from crystalball.validation.config import ValidatorConfig
from crystalball.validation.review import ReviewAdapter


class Generation:
    name = "gemini"
    model = "fixed-test-model"
    last_usage = {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    last_response_metadata = {"finish_reason": "STOP"}

    def __init__(self):
        self.calls = []

    def complete(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return json.dumps({"nodes": [
            {"id": "a", "label": "CVE-2020-24572", "precondition": "auth", "postcondition": "execution"},
            {"id": "b", "label": "CVE-2021-24038", "precondition": "local user", "postcondition": "privileges"}],
            "edges": [{"from": "a", "to": "b", "label": "Code execution may supply local access"}]})


class Reviewer(Generation):
    def complete(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        row = json.loads(prompt.split("\nINPUT:\n")[1])["offline_result"]
        return json.dumps({"edge_id": row["edge_id"], "source_cve_id": row["source_mapping"]["cve_id"],
                           "target_cve_id": row["target_mapping"]["cve_id"], "suggested_status": "conditional",
                           "reason": "Host assignment remains unknown", "missing_conditions": [], "assumptions": [],
                           "evidence_quotes": [{"cve_id": e["cve_id"], "quote": e["description"][:40]} for e in row["evidence"].values()]})


def prepared(tmp_path, repeats=2):
    settings = replace(Settings(), gemini_model="fixed-test-model")
    out = tmp_path / "pilot"
    pilot.prepare(out, repeats=repeats, settings=settings, backend="gemini", review_backend="gemini",
                  generation_reasoning="medium", generation_tokens=8192, review_reasoning="low",
                  review_tokens=4096, max_reviews=5)
    return out, settings


def test_fresh_repeats_freeze_same_prompt_and_resume_without_paid_repeats(tmp_path):
    out, settings = prepared(tmp_path)
    generator = Generation()
    pilot.generate(out, settings, client=generator)
    assert len(generator.calls) == 2
    assert generator.calls[0] == generator.calls[1]
    original = (out / "runs/r01/graph.json").read_bytes()
    pilot.generate(out, settings, client=generator)
    assert len(generator.calls) == 2
    assert (out / "runs/r01/graph.json").read_bytes() == original
    annotation = pilot.read(out / "runs/r01/annotation_blind.json")
    assert annotation["labels"] == {"edge-0001": None}
    assert "status" not in annotation["candidates"][0]
    assert annotation["provenance"] == ""
    (out / "prompt.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="prompt"):
        pilot.generate(out, settings, client=generator)
    assert len(generator.calls) == 2


def test_paired_inputs_are_immutable_and_accuracy_is_not_invented(tmp_path):
    out, settings = prepared(tmp_path)
    pilot.generate(out, settings, client=Generation())
    reviewer = Reviewer()
    factory = lambda config: ReviewAdapter(config, client=reviewer, settings=settings)
    pilot.validate(out, settings, render=False, adapter_factory=factory)
    summary = pilot.report(out)
    assert summary["parsed_graphs"] == summary["completed_validations"] == 2
    assert summary["api_calls"] == {"generation": 2, "review": 2}
    assert summary["all_originals_preserved"]
    assert summary["accuracy_state"] == "not_estimable_without_independent_gold"
    assert summary["statistics"]["a_precision"]["mean"] is None
    assert summary["statistics"]["c_precision"]["mean"] is None
    pilot.validate(out, settings, render=False, adapter_factory=factory)
    assert len(reviewer.calls) == 2
    result = pilot.read(out / "runs/r01/validation/validation_results.json")
    gold = {"independent": True, "label_source": "human", "provenance": "independently adjudicated fixture",
            "graph_sha256": result["graph_sha256"], "labels": {"edge-0001": True}}
    pilot.save(out / "gold/r01.json", gold)
    rescored = pilot.report(out)
    assert rescored["statistics"]["a_precision"]["mean"] == 1.0
    assert len(reviewer.calls) == 2  # Adding human gold never requests another review.
    assert pilot.read(out / "runs/r01/validation/validation_results.json") == result


def test_generation_failures_persist_and_need_explicit_retry(tmp_path):
    out, settings = prepared(tmp_path, repeats=1)

    class Failed(Generation):
        def complete(self, *args, **kwargs):
            self.calls.append(args)
            raise RuntimeError("fake secret that must not be recorded")

    failed = Failed()
    pilot.generate(out, settings, client=failed)
    pilot.generate(out, settings, client=failed)
    assert len(failed.calls) == 1
    text = (out / "runs/r01/generation.json").read_text(encoding="utf-8")
    assert "fake secret" not in text
    pilot.generate(out, settings, client=Generation(), retry_errors=True)
    summary = pilot.report(out)
    assert summary["api_calls"]["generation"] == 2
    assert summary["token_usage"]["generation"]["totals_are_partial"]


def test_model_change_is_rejected_before_call(tmp_path):
    out, settings = prepared(tmp_path, repeats=1)
    generator = Generation()
    with pytest.raises(ValueError, match="model"):
        pilot.generate(out, replace(settings, gemini_model="different-model"), client=generator)
    assert generator.calls == []


def test_forked_review_freezes_new_options_but_preserves_generation(tmp_path):
    source, settings = prepared(tmp_path, repeats=1)
    generator = Generation()
    pilot.generate(source, settings, client=generator)
    out = tmp_path / "new_review"
    cfg = ValidatorConfig(llm_enabled=True, max_output_tokens=9999, reasoning_level="high",
                          cache_dir=tmp_path / "shared_cache")
    plan = pilot.fork_review(source, out, settings, cfg)
    assert plan["review"]["max_output_tokens"] == 9999
    assert plan["review"]["reasoning"] == "high"
    assert (source / "runs/r01/graph.json").read_bytes() == (out / "runs/r01/graph.json").read_bytes()
    assert len(generator.calls) == 1
    reviewer = Reviewer()

    def factory(config):
        adapter = pilot.JournaledReviewAdapter(config, out / "runs/r01/validation/call_journal", settings)
        adapter.client = reviewer
        return adapter

    pilot.validate(out, settings, render=False, adapter_factory=factory)
    summary = pilot.report(out)
    assert summary["api_calls"] == {"generation": 0, "review": 1}
    assert summary["unsettled_review_requests"] == 0
    assert summary["first_pass_review"]["passed_recheck"] == 1
    assert reviewer.calls[0][1] == {"max_output_tokens": 9999, "reasoning_level": "high"}
    assert not (source / "runs/r01/validation").exists()


def test_disabled_env_cannot_start_forked_live_review(tmp_path):
    source, settings = prepared(tmp_path, repeats=1)
    with pytest.raises(ValueError, match="Enable hybrid"):
        pilot.fork_review(source, tmp_path / "disabled", settings, ValidatorConfig(llm_enabled=False))
    assert not (tmp_path / "disabled").exists()


def test_larger_retry_cap_reuses_success_and_keeps_first_pass_failures(tmp_path):
    out, settings = prepared(tmp_path, repeats=1)

    class TwoEdges(Generation):
        def complete(self, prompt, **kwargs):
            graph = json.loads(super().complete(prompt, **kwargs))
            graph["edges"].append({**graph["edges"][0], "label": "Another bounded conditional bridge"})
            return json.dumps(graph)

    class OneBad(Reviewer):
        def complete(self, prompt, **kwargs):
            row = json.loads(prompt.split("\nINPUT:\n")[1])["offline_result"]
            if row["edge_id"] == "edge-0002":
                self.calls.append((prompt, kwargs))
                return "not json"
            return super().complete(prompt, **kwargs)

    pilot.generate(out, settings, client=TwoEdges())
    journal = out / "runs/r01/validation/call_journal"

    def factory(client, retry=None):
        def build(config):
            adapter = pilot.JournaledReviewAdapter(config, journal, settings, retry_output_tokens=retry)
            adapter.client = client
            return adapter
        return build

    initial = OneBad()
    pilot.validate(out, settings, render=False, adapter_factory=factory(initial))
    assert len(initial.calls) == 2
    retry = Reviewer()
    pilot.validate(out, settings, render=False, retry_incomplete=True, retry_output_tokens=16384,
                   adapter_factory=factory(retry, 16384))
    assert len(retry.calls) == 1
    assert retry.calls[0][1]["max_output_tokens"] == 16384
    final = pilot.report(out)
    assert final["api_calls"] == {"generation": 1, "review": 3}
    assert final["first_pass_review"]["passed_recheck"] == 1
    assert final["first_pass_review"]["candidates"] == 2
    assert final["completed_validations"] == 1
    report = pilot.read(out / "runs/r01/validation/validation_results.json")
    assert report["edges"][0]["review"]["state"] == "cache_hit"
    assert report["edges"][1]["review"]["request_overrides"]["max_output_tokens"] == 16384


def test_retry_cannot_reset_total_api_budget(tmp_path):
    out, settings = prepared(tmp_path, repeats=1)
    plan = pilot.read(out / "manifest.json")
    plan["review"]["max_calls_per_repeat"] = 1
    pilot.save(out / "manifest.json", plan)
    pilot.generate(out, settings, client=Generation())

    class Invalid(Reviewer):
        def complete(self, prompt, **kwargs):
            self.calls.append((prompt, kwargs))
            return "invalid json"

    client = Invalid()

    def factory(config):
        adapter = pilot.JournaledReviewAdapter(config, out / "runs/r01/validation/call_journal", settings)
        adapter.client = client
        return adapter

    pilot.validate(out, settings, render=False, adapter_factory=factory)
    pilot.validate(out, settings, render=False, retry_incomplete=True, adapter_factory=factory)
    assert len(client.calls) == 1
    result = pilot.read(out / "runs/r01/validation/validation_results.json")
    assert not result["edges"][0]["final"]["review_complete"]
    assert pilot.report(out)["api_calls"]["review"] == 1


def test_reviewer_comparison_rejects_changed_input_and_preserves_raw_labels(tmp_path):
    from crystalball.reviewer_comparison import compare

    source, settings = prepared(tmp_path, repeats=1)
    settings = replace(settings, openrouter_model="other-test-model")
    pilot.generate(source, settings, client=Generation())
    other = tmp_path / "other"
    pilot.fork_review(source, other, settings, ValidatorConfig(llm_enabled=True, llm_backend="openrouter",
                                                            cache_dir=tmp_path / "comparison_cache"))
    for root in (source, other):
        def factory(config):
            adapter = pilot.JournaledReviewAdapter(config, root / "runs/r01/validation/call_journal", settings)
            adapter.client = Reviewer()
            return adapter
        pilot.validate(root, settings, render=False, adapter_factory=factory)
        pilot.save(root / "runs/r01/validation/layout.json", {"layout_sha256": "same-layout"})
    result = compare([source, other], tmp_path / "comparison")
    assert all(result["input_invariants"].values())
    assert result["models"][0]["llm_suggested_distribution"] == {"conditional": 1}
    assert result["models"][0]["accuracy"] is None
    assert result["raw_suggestion_agreement"][0]["agreement_rate"] == 1
    graph = pilot.read(other / "runs/r01/graph.json")
    graph["edges"][0]["label"] = "changed claim"
    pilot.save(other / "runs/r01/graph.json", graph)
    with pytest.raises(ValueError, match="Original graph differs"):
        compare([source, other], tmp_path / "bad_comparison")


def test_api_failure_defers_remaining_requests(tmp_path):
    out, settings = prepared(tmp_path, repeats=2)
    pilot.generate(out, settings, client=Generation())

    class Failed(Reviewer):
        def complete(self, prompt, **kwargs):
            self.calls.append((prompt, kwargs))
            raise RuntimeError("provider unavailable")

    client = Failed()

    def factory(config):
        adapter = pilot.JournaledReviewAdapter(config, out / "runs/r01/validation/call_journal", settings)
        adapter.client = client
        return adapter

    pilot.validate(out, settings, render=False, adapter_factory=factory)
    assert len(client.calls) == 1
    assert (out / "runs/r01/validation/validation_results.json").exists()
    assert not (out / "runs/r02/validation/validation_results.json").exists()


def test_second_openrouter_profile_cache_identity_is_stable(tmp_path):
    _, settings = prepared(tmp_path, repeats=1)
    config = ValidatorConfig(llm_enabled=True, llm_backend="openrouter_v2")
    adapter = pilot.JournaledReviewAdapter(config, tmp_path / "journal", settings)
    before = adapter._model_identity()

    class ActualClient:
        name = "openrouter"
        model = settings.openrouter_model_v2

    adapter.client = ActualClient()
    assert adapter._model_identity() == before


def test_review_provider_cannot_drift_after_freezing(tmp_path):
    source, settings = prepared(tmp_path, repeats=1)
    pilot.generate(source, settings, client=Generation())
    settings = replace(settings, openrouter_provider_config_v2='{"only":["baidu/fp8"]}')
    out = tmp_path / "deepseek"
    pilot.fork_review(source, out, settings, ValidatorConfig(llm_enabled=True, llm_backend="openrouter_v2",
                                                          cache_dir=tmp_path / "provider_cache"))
    with pytest.raises(ValueError, match="provider"):
        pilot.verify(out, replace(settings, openrouter_provider_config_v2="{}"))


def test_legacy_openrouter_cache_is_reused_without_another_request(tmp_path):
    source, settings = prepared(tmp_path, repeats=1)
    settings = replace(settings, openrouter_model_v2="fixed-test-model")
    pilot.generate(source, settings, client=Generation())
    out = tmp_path / "second_profile"
    pilot.fork_review(source, out, settings, ValidatorConfig(llm_enabled=True, llm_backend="openrouter_v2",
                                                          cache_dir=tmp_path / "legacy_cache"))

    class OpenRouterReviewer(Reviewer):
        name = "openrouter"

    old_client = OpenRouterReviewer()

    def old_factory(config):
        adapter = pilot.JournaledReviewAdapter(config, out / "runs/r01/validation/call_journal", settings)
        adapter.client = old_client
        adapter._model_identity = lambda: ReviewAdapter._model_identity(adapter)
        return adapter

    pilot.validate(out, settings, render=False, adapter_factory=old_factory)
    assert len(old_client.calls) == 1
    result_file = out / "runs/r01/validation/validation_results.json"
    result = pilot.read(result_file)
    result["edges"][0]["final"]["review_complete"] = False
    pilot.save(result_file, result)  # Force resume to exercise the cache compatibility path.
    new_client = OpenRouterReviewer()

    def new_factory(config):
        adapter = pilot.JournaledReviewAdapter(config, out / "runs/r01/validation/call_journal", settings,
                                              retry_output_tokens=16384)
        adapter.client = new_client
        return adapter

    pilot.validate(out, settings, render=False, retry_incomplete=True, retry_output_tokens=16384,
                   adapter_factory=new_factory)
    assert new_client.calls == []
    assert pilot.read(result_file)["edges"][0]["review"]["state"] == "cache_hit"
