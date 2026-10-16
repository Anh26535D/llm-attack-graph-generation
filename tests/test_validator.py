from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import json

import pytest

from crystalball.postprocess import AttackGraph
from crystalball.validation.config import ValidatorConfig
from crystalball.validation.evidence import EnvironmentState, EvidenceStore, digest
from crystalball.validation.offline import OfflineValidator
from crystalball.validation.pipeline import reconstruct, validate_graph, write_artifacts
from crystalball.validation.review import ReviewAdapter, parse_review, recheck
from crystalball.validation.metrics import candidate_metrics, token_usage

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def store():
    return EvidenceStore.load(ROOT / "data/cve_official/manifest.json")


def pair(source="CVE-2020-24572", target="CVE-2021-24038", **edge):
    return AttackGraph(nodes=[{"id": "s", "label": source}, {"id": "t", "label": target}],
                       edges=[{"from": "s", "to": "t", "label": "Source enables target", **edge}])


def test_missing_information_is_unknown(store):
    graph = pair(source="no known CVE")
    assert OfflineValidator(store).validate(graph)[0]["status"] == "unknown"
    graph = pair(source="CVE-2019-20354", target="CVE-2021-38759")
    assert OfflineValidator(store).validate(graph)[0]["status"] == "unknown"


def test_ambiguous_mapping_never_selects_favorable_cve(store):
    graph = pair(source="CVE-2020-24572 CVE-2019-20354")
    result = OfflineValidator(store).validate(graph)[0]
    assert result["status"] == "unknown"
    assert result["source_mapping"]["status"] == "ambiguous"
    assert "target" in result["evidence"]  # Preserve the evidence that is known.


def test_default_pi_account_identity_is_mapped_without_guessing_edge_truth(store):
    node = {"id": "V7", "label": "Raspberry Pi OS through 5.10 default pi account password unchanged"}
    assert store.mapping(node)["cve_id"] == "CVE-2021-38759"


def test_generation_preconditions_are_not_evidence(store):
    graph = pair()
    graph.nodes[0]["postcondition"] = "SYSTEM on all hosts with physical access and passwords"
    row = OfflineValidator(store).validate(graph)[0]
    assert row["status"] == "conditional"
    assert "SYSTEM" not in str(row["evidence"])


def test_hard_rule_conflict(store):
    env = EnvironmentState({"node_hosts": {"s": "a", "t": "b"}, "hosts": {
        "a": {"services": {"raspap": "2.5"}},
        "b": {"services": {"oculus_desktop": "32.0"}}}}, {"kind": "test"})
    row = OfflineValidator(store, env).validate(pair())[0]
    assert row["status"] == "contradicted"
    assert any("version" in c for c in row["hard_conflicts"])


def test_parallel_edges_and_original_unchanged(store):
    graph = pair()
    graph.edges *= 2
    before = deepcopy(graph.to_dict())
    rows = OfflineValidator(store).validate(graph)
    assert len({r["edge_id"] for r in rows}) == 2
    assert graph.to_dict() == before
    assert digest(graph.to_dict()) == digest(before)


def test_no_host_relationship_is_inferred_from_generated_host_field(store):
    graph = pair()
    for node in graph.nodes:
        node["host"] = "same-host"
    row = OfflineValidator(store).validate(graph)[0]
    assert row["status"] == "conditional"
    assert "externally_verified_source_target_host_relationship" in row["missing_conditions"]


def test_config_controls_require_explicit_opt_in():
    with pytest.raises(ValueError, match="allow_control_review"):
        ValidatorConfig(review_statuses=("supported",))
    assert not ValidatorConfig(mode="offline", llm_enabled=True).review_enabled


class MockLLM:
    name = "mock"
    model = "fixed-model"

    def __init__(self, status="conditional", raw=None, error=None, quotes=True):
        self.calls = []
        self.status, self.raw, self.error, self.quotes = status, raw, error, quotes
        self.last_usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}

    def complete(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        if self.error:
            raise self.error
        if self.raw is not None:
            return self.raw
        row = json.loads(prompt.split("\nINPUT:\n")[1])["offline_result"]
        return json.dumps({"edge_id": row["edge_id"],
            "source_cve_id": row["source_mapping"]["cve_id"],
            "target_cve_id": row["target_mapping"]["cve_id"],
            "suggested_status": self.status, "reason": "Bounded review",
            "evidence_quotes": [{"cve_id": e["cve_id"], "quote": e["description"][:50]}
                                for e in row["evidence"].values()] if self.quotes else [],
            "missing_conditions": [], "assumptions": [], "confidence": 0.7})


def hybrid(tmp_path, **kwargs):
    return ValidatorConfig(llm_enabled=True, cache_dir=tmp_path / "cache", **kwargs)


@pytest.mark.parametrize("mode,enabled", [("offline", False), ("offline", True), ("hybrid", False)])
def test_disabled_never_initializes_or_calls_llm(store, mode, enabled):
    config = ValidatorConfig(mode=mode, llm_enabled=enabled)
    def forbidden(_):
        pytest.fail("Client must not even be initialized")
    adapter = ReviewAdapter(config, client_factory=forbidden)
    report = validate_graph(pair(), store, config, adapter=adapter)
    assert report["edges"][0]["review"]["state"] == "disabled"
    assert report["metrics"]["C_hybrid"]["additional_api_calls"] == 0


def test_hybrid_selective_calls_and_cap(store, tmp_path):
    graph = pair()
    graph.edges *= 3
    config = hybrid(tmp_path, max_llm_calls=1, cache_enabled=False)
    client = MockLLM()
    report = validate_graph(graph, store, config, adapter=ReviewAdapter(config, client=client))
    assert [r["review"]["state"] for r in report["edges"]] == ["completed", "budget_exhausted", "budget_exhausted"]
    assert len(client.calls) == 1
    assert client.calls[0][1] == {"max_output_tokens": 1024, "reasoning_level": "low"}
    row = deepcopy(report["edges"][0]["offline"])
    row["status"] = "unsupported"
    assert ReviewAdapter(config, client=client).review(row, {})["state"] == "not_selected"


@pytest.mark.parametrize("raw", ["not json", '```json\n{}\n```', '{}', '[]', '{"edge_id":"a","edge_id":"b"}',
                                '{"confidence":NaN}', '{"suggested_status":true}'])
def test_strict_json_invalid_responses(raw):
    with pytest.raises(ValueError):
        parse_review(raw)


def test_invalid_response_and_api_error_preserve_offline(store, tmp_path):
    config = hybrid(tmp_path)
    for client, state in [(MockLLM(raw="bad"), "invalid_response"),
                          (MockLLM(error=RuntimeError("secret request headers")), "api_error")]:
        report = validate_graph(pair(), store, config, adapter=ReviewAdapter(config, client=client))
        row = report["edges"][0]
        assert row["review"]["state"] == state
        assert row["final"]["status"] == row["offline"]["status"]
        assert not row["final"]["review_complete"]
        assert "secret request" not in json.dumps(report)


def test_quote_and_identity_recheck(store, tmp_path):
    offline = OfflineValidator(store).validate(pair())[0]
    config = hybrid(tmp_path)
    review = ReviewAdapter(config, client=MockLLM()).review(offline, {})
    assert recheck(offline, review)["review_complete"]
    for key, value, issue in [("edge_id", "foreign", "edge_id_mismatch"),
                              ("source_cve_id", "CVE-2099-9999", "source_cve_id_mismatch")]:
        tampered = deepcopy(review)
        tampered["response"][key] = value
        assert issue in recheck(offline, tampered)["issues"]
    review["response"]["evidence_quotes"][0]["quote"] = "Hallucinated credentials extracted successfully"
    final = recheck(offline, review)
    assert "unverified_evidence_quote" in final["issues"]
    assert not final["review_complete"]


def test_llm_supported_suggestion_cannot_override_evidence(store, tmp_path):
    config = hybrid(tmp_path)
    report = validate_graph(pair(), store, config, adapter=ReviewAdapter(config, client=MockLLM("supported")))
    row = report["edges"][0]
    assert row["final"]["status"] == "conditional"
    assert row["final"]["disagreement"]
    assert not row["final"]["suggestion_accepted"]


def test_review_cannot_override_hard_conflict(store, tmp_path):
    config = hybrid(tmp_path, review_statuses=("contradicted",), allow_control_review=True)
    env = EnvironmentState({"node_hosts": {"s": "a", "t": "b"}, "hosts": {"a": {}, "b": {}}}, {})
    report = validate_graph(pair(), store, config, environment=env,
                            adapter=ReviewAdapter(config, client=MockLLM("supported")))
    assert report["edges"][0]["final"]["status"] == "contradicted"
    assert "hard_rules_preserved" in report["edges"][0]["final"]["issues"]


def test_cache_hit_and_input_config_invalidation(store, tmp_path):
    config = hybrid(tmp_path)
    client = MockLLM()
    first = validate_graph(pair(), store, config, adapter=ReviewAdapter(config, client=client))
    second = validate_graph(pair(), store, config, adapter=ReviewAdapter(config, client=client))
    assert len(client.calls) == 1
    assert second["edges"][0]["review"]["state"] == "cache_hit"
    assert second["metrics"]["C_hybrid"]["token_usage"]["total_tokens"] == 0
    changed = replace(config, reasoning_level="high")
    validate_graph(pair(), store, changed, adapter=ReviewAdapter(changed, client=client))
    assert len(client.calls) == 2
    graph = pair(label="A different claim")
    validate_graph(graph, store, config, adapter=ReviewAdapter(config, client=client))
    assert len(client.calls) == 3
    assert first["graph_sha256"] == second["graph_sha256"]


def test_same_input_same_baseline_even_when_llm_disagrees(store, tmp_path):
    original = pair()
    before = deepcopy(original.to_dict())
    offline = validate_graph(original, store, ValidatorConfig(mode="offline"))
    config = hybrid(tmp_path)
    reviewed = validate_graph(original, store, config, adapter=ReviewAdapter(config, client=MockLLM("unknown")))
    assert offline["edges"][0]["offline"] == reviewed["edges"][0]["offline"]
    assert reviewed["edges"][0]["final"]["status"] == "unknown"
    assert original.to_dict() == before
    assert reconstruct(before, reviewed)["edges"][0]["validation"]["status"] == "unknown"
    strict = reconstruct(before, reviewed, strict=True)
    assert strict["nodes"] == before["nodes"]
    assert len(strict["validation"]["excluded_edges"]) == 1


def test_backend_selection_does_not_mutate_generation_settings(store, tmp_path):
    from crystalball.config import Settings
    settings = Settings(llm_backend="openrouter", gemini_api_key="mock-key")
    captured = []
    config = hybrid(tmp_path, llm_backend="gemini", cache_enabled=False)
    def factory(chosen):
        captured.append(chosen)
        return MockLLM()
    validate_graph(pair(), store, config, adapter=ReviewAdapter(config, settings=settings, client_factory=factory))
    assert settings.llm_backend == "openrouter"
    assert captured[0].llm_backend == "gemini"
    assert captured[0].llm_max_output_tokens == 1024


def test_metrics_with_independent_labels_and_without():
    assert candidate_metrics(set(), None)["precision"] is None
    values = candidate_metrics({"a", "b"}, {"a": True, "b": False, "c": True})
    assert values["precision"] == values["recall"] == values["f1"] == .5
    assert values["false_removals"] == values["false_retentions"] == 1
    usage = token_usage([{"api_calls": 1, "usage": {"prompt_token_count": 12,
                         "candidates_token_count": 4, "total_token_count": 20}}])
    assert usage["total_tokens"] == 20  # Gemini total may include reasoning tokens.


def test_gold_rejects_llm_labels_and_wrong_graph(store):
    with pytest.raises(ValueError, match="Gold"):
        validate_graph(pair(), store, gold={"independent": False})


def test_real_graph_artifacts_preserve_bytes_nodes_parallel_edges_and_hash(store, tmp_path):
    graph = pair()
    graph.edges *= 2
    graph.edges[0]["id"] = "duplicate-id"
    source = tmp_path / "graph.json"
    raw = json.dumps(graph.to_dict(), indent=3).encode()
    source.write_bytes(raw)
    report = write_artifacts(source, tmp_path / "out", store, ValidatorConfig(mode="offline"), render=False)
    assert source.read_bytes() == (tmp_path / "out/original_graph.json").read_bytes() == raw
    validated = json.loads((tmp_path / "out/validated_graph.json").read_text())
    assert validated["nodes"] == graph.nodes
    assert len(validated["edges"]) == len(graph.edges)
    assert len({e["validation"]["edge_id"] for e in validated["edges"]}) == 2
    assert report["metrics"]["B_offline"]["edge_metrics"]["f1"] is None
    with pytest.raises(ValueError, match="separate"):
        write_artifacts(source, source.parent, store, ValidatorConfig(), render=False)


def test_supported_requires_canonical_claim_and_complete_observations(store):
    graph = pair(relation="local_execution_enables_local_exploit",
                 label="Local code execution enables local exploitation.")
    env = EnvironmentState({"node_hosts": {"s": "a", "t": "a"}, "hosts": {"a": {
        "platform": "raspberry_pi", "services": {"raspap": "2.5", "oculus_desktop": "1.40.0.1"},
        "network_access": True, "flags": {"attacker_has_low_priv_credential": True}}}}, {"kind": "test"})
    assert OfflineValidator(store, env).validate(graph)[0]["status"] == "supported"
    graph.edges[0]["label"] = "This also yields SYSTEM, credentials and all other hosts"
    assert OfflineValidator(store, env).validate(graph)[0]["status"] == "conditional"
    del env.data["hosts"]["a"]["services"]["oculus_desktop"]
    assert OfflineValidator(store, env).validate(graph)[0]["status"] == "conditional"
    env.data["hosts"]["a"]["services_complete"] = True
    assert OfflineValidator(store, env).validate(graph)[0]["status"] == "contradicted"


def test_canonical_execution_claim_not_supported_by_file_read(store):
    graph = pair(source="CVE-2019-20354", relation="local_execution_enables_local_exploit")
    assert OfflineValidator(store).validate(graph)[0]["status"] == "unsupported"


@pytest.mark.parametrize("target,flag", [("CVE-2022-21819", "physical_access"),
                                        ("CVE-2021-38545", "line_of_sight")])
def test_explicit_physical_optical_denial_is_conflict_but_missing_is_unknown(store, target, flag):
    graph = pair(target=target)
    env = EnvironmentState({"node_hosts": {"t": "h"}, "hosts": {"h": {flag: False}}}, {})
    assert OfflineValidator(store, env).validate(graph)[0]["status"] == "contradicted"
    del env.data["hosts"]["h"][flag]
    assert OfflineValidator(store, env).validate(graph)[0]["status"] in {"unknown", "conditional"}


def test_partial_environment_absence_does_not_imply_blocked_reachability(store):
    graph = pair(target="CVE-2019-20354")
    env = EnvironmentState({"node_hosts": {"s": "a", "t": "b"}, "hosts": {"a": {}, "b": {}}}, {})
    assert OfflineValidator(store, env).validate(graph)[0]["status"] != "contradicted"
    env.data["links_complete"] = True
    assert OfflineValidator(store, env).validate(graph)[0]["status"] != "contradicted"
    env.data["hosts"]["b"]["network_access"] = False
    assert OfflineValidator(store, env).validate(graph)[0]["status"] == "contradicted"


def test_verified_pivot_can_supply_target_network_access(store):
    graph = pair(target="CVE-2019-20354")
    env = EnvironmentState({"node_hosts": {"s": "a", "t": "b"}, "hosts": {
        "a": {}, "b": {"network_access": False}}, "links": [["a", "b"]]}, {})
    row = OfflineValidator(store, env).validate(graph)[0]
    assert row["status"] != "contradicted"
    assert any(c.get("vantage") == "source_host" for c in row["checks"])


def test_version_boundaries_normalize_trailing_zeroes():
    from crystalball.validation.conditions import VersionRange
    assert not VersionRange(min_excl="1.39").contains("1.39.0")
    assert VersionRange(max_incl="5.10").contains("5.10.0")
    with pytest.raises(ValueError):
        VersionRange().contains("unknown")


def test_cache_invalidates_on_evidence_model_and_environment_changes(store, tmp_path):
    config = hybrid(tmp_path)
    client = MockLLM()
    validate_graph(pair(), store, config, adapter=ReviewAdapter(config, client=client))
    client.model = "another-model"
    validate_graph(pair(), store, config, adapter=ReviewAdapter(config, client=client))
    assert len(client.calls) == 2
    altered = deepcopy(store)
    altered.records["CVE-2020-24572"]["description"] += " Additional supplied observation."
    validate_graph(pair(), altered, config, adapter=ReviewAdapter(config, client=client))
    env = EnvironmentState({"observation": "new state"}, {"kind": "test"})
    validate_graph(pair(), altered, config, environment=env, adapter=ReviewAdapter(config, client=client))
    assert len(client.calls) == 4


def test_missing_endpoint_quotes_cannot_complete_positive_review(store, tmp_path):
    config = hybrid(tmp_path)
    report = validate_graph(pair(), store, config, adapter=ReviewAdapter(config, client=MockLLM(quotes=False)))
    assert not report["edges"][0]["final"]["review_complete"]
    assert "missing_endpoint_evidence_quotes" in report["edges"][0]["final"]["issues"]


def test_pipeline_independent_gold_is_hash_bound_and_candidate_scoped(store):
    graph = pair()
    gold = {"independent": True, "label_source": "human", "provenance": "independent expert fixture",
            "graph_sha256": digest(graph.to_dict()), "labels": {"edge-0001": True}}
    report = validate_graph(graph, store, gold=gold)
    assert report["metrics"]["B_offline"]["edge_metrics"]["f1"] == 1.0
    assert report["metrics"]["B_offline"]["strict_edge_metrics"]["false_removals"] == 1
    gold["label_source"] = "llm"
    with pytest.raises(ValueError, match="label_source"):
        validate_graph(graph, store, gold=gold)


def test_token_usage_missing_provider_values_are_not_fabricated_zeroes():
    usage = token_usage([{"api_calls": 1, "usage": None}])
    assert usage["total_tokens"] is None and usage["totals_are_partial"]
    usage = token_usage([{"api_calls": 1, "usage": {"total_tokens": 12}}])
    assert usage["input_tokens"] is None and usage["output_tokens"] is None


def test_openai_validator_options_usage_and_no_hidden_retries(monkeypatch):
    import sys
    import types
    from types import SimpleNamespace
    captured = {}
    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured["init"] = kwargs
            def create(**request):
                captured["request"] = request
                return SimpleNamespace(model="gpt-4o-mini", usage={"total_tokens": 10},
                    choices=[SimpleNamespace(message=SimpleNamespace(content="result"), finish_reason="stop")])
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))
    module = types.ModuleType("openai")
    module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", module)
    from crystalball.llm.openai_client import OpenAILLMClient
    client = OpenAILLMClient("test-key")
    assert client.complete("hello", max_output_tokens=120, reasoning_level="low") == "result"
    assert captured["init"]["max_retries"] == 0
    assert captured["request"]["max_completion_tokens"] == 120
    assert "reasoning_effort" not in captured["request"]
    assert client.last_usage == {"total_tokens": 10}
    client.complete("generation payload")
    assert set(captured["request"]) == {"model", "messages"}


def test_layout_preserves_all_nodes_for_parallel_edges_cycles_and_isolated_nodes(store, tmp_path):
    from crystalball.validation.visualization import fixed_layout, render_comparison
    graph = pair()
    graph.nodes.append({"id": "isolated", "label": "CVE-2022-21819"})
    graph.edges *= 2
    graph.edges.extend([{"from": "t", "to": "s"}, {"from": "s", "to": "s"}])
    assert fixed_layout(graph) == fixed_layout(graph)
    assert set(fixed_layout(graph)) == {"s", "t", "isolated"}
    report = validate_graph(graph, store)
    layout = render_comparison(graph, report, tmp_path)
    assert layout["identical_in_both_panels"]
    for stem in ("original_graph", "validated_graph", "comparison"):
        for suffix in ("png", "svg"):
            assert (tmp_path / f"{stem}.{suffix}").stat().st_size > 100
    assert report["metrics"]["A_original"]["nodes"] == 3
    comparison = (tmp_path / "comparison.png").read_bytes()
    vector = (tmp_path / "comparison.svg").read_bytes()
    render_comparison(graph, report, tmp_path)
    assert (tmp_path / "comparison.png").read_bytes() == comparison
    assert (tmp_path / "comparison.svg").read_bytes() == vector
