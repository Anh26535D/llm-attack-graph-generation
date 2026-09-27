from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


RUNNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_paired_experiment.py"
SPEC = importlib.util.spec_from_file_location("reproduction_runner", RUNNER_PATH)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def test_cli_requires_official_dataset_before_starting(monkeypatch, capsys):
    monkeypatch.setattr(runner.sys, "argv", ["run_paired_experiment.py"])
    monkeypatch.setattr(
        runner, "run_experiment",
        lambda *args, **kwargs: pytest.fail("Missing dataset must not start a legacy run"),
    )
    with pytest.raises(SystemExit) as exc:
        runner.main()
    assert exc.value.code == 2
    assert "--dataset-manifest" in capsys.readouterr().err


def _make_retry_run(
    tmp_path, *, status="api_error", run_status="failed", retry_attempts=None
):
    run_id = "retry-fixture"
    run_dir = tmp_path / run_id
    for folder in ("calls", "call_prompts", "raw_responses"):
        (run_dir / folder).mkdir(parents=True, exist_ok=True)
    call_id = runner.graph_call_id("edge_context", "gemini", "S54_EDGE_CONTEXT", 1)
    prompt = "frozen transient retry prompt"
    prompt_file = f"call_prompts/{call_id}.txt"
    (run_dir / prompt_file).write_text(prompt, encoding="utf-8")
    record = {
        "call_id": call_id,
        "stage": "edge_context",
        "backend": "gemini",
        "model": "gemini-3.8-flash",
        "condition_id": "S54_EDGE_CONTEXT",
        "repeat_id": 1,
        "attempt_id": 1,
        "status": status,
        "prompt_sha256": runner.prompt_sha256(prompt.encode("utf-8")),
        "prompt_file": prompt_file,
        "generation_config": {"max_output_tokens": 2048, "reasoning_level": "low"},
        "request_cost_ceiling_vnd": 50,
    }
    if status != "api_error":
        record["response_file"] = f"raw_responses/{call_id}.txt"
        response_path = run_dir / record["response_file"]
        response_path.write_text("saved response", encoding="utf-8")
        record["response_sha256"] = runner.sha256_file(response_path)
    runner.atomic_json(run_dir / "calls" / f"{call_id}.json", record)
    original_result = {"call_id": call_id, "stage": "edge_context", "status": status}
    manifest = {
        "run_id": run_id,
        "status": run_status,
        "dataset": {"dataset_digest": "fixture-dataset"},
        "reproduction_source_sha256": {"fixture": "frozen"},
        "conditions": [
            {"condition_id": "C2", "provided_cve_ids": ["CVE-2020-0001"]},
        ],
        "calls": [call_id],
        "results": [original_result],
        "retry_attempts": retry_attempts or [],
    }
    runner.atomic_json(run_dir / "manifest.json", manifest)
    return run_id, run_dir, call_id, original_result


def test_main_call_matrix_has_five_paired_repeats_and_unique_ids():
    conditions = [
        {"condition_id": condition_id, "max_output_tokens": 8192 if condition_id == "T1" else 4096}
        for condition_id in ("C0", "C1", "C2", "T0", "T1", "T2", "X0")
    ]

    calls = runner.main_call_specs(conditions)

    assert len(calls) == 70
    assert len({call["call_id"] for call in calls}) == 70
    assert {call["repeat_id"] for call in calls} == {1, 2, 3, 4, 5}
    assert {call["model_name"] for call in calls} == {"gemini", "openrouter"}
    assert all(call["max_output_tokens"] == 8192 for call in calls if call["condition_id"] == "T1")


def test_call_ids_include_stage_model_condition_repeat_and_attempt():
    assert (
        runner.graph_call_id("graph", "gemini", "C1", 3, 2)
        == "graph.gemini.C1.r03.a02"
    )


def test_conservative_budget_reserve_is_positive_and_backend_specific():
    gemini = runner.conservative_request_ceiling_vnd("gemini", "prompt", 4096)
    openrouter = runner.conservative_request_ceiling_vnd("openrouter", "prompt", 4096)

    assert gemini > openrouter > 0


def test_missing_usage_falls_back_to_recorded_request_ceiling():
    ceiling_vnd = 1234.5

    estimated = runner.estimated_call_cost_usd({
        "backend": "gemini",
        "usage": None,
        "request_cost_ceiling_vnd": ceiling_vnd,
    })

    assert estimated == pytest.approx(ceiling_vnd / runner.USD_TO_VND)


def test_resume_verifies_prompt_parameters_and_response_hash(tmp_path):
    prompt = "frozen prompt"
    response_path = tmp_path / "raw_responses" / "call.txt"
    response_path.parent.mkdir()
    response_path.write_text('{"nodes": [], "edges": []}', encoding="utf-8")
    record = {
        "call_id": "graph.gemini.C1.r01.a01",
        "stage": "graph",
        "backend": "gemini",
        "model": "gemini-3.8-flash",
        "condition_id": "C1",
        "repeat_id": 1,
        "attempt_id": 1,
        "prompt_sha256": runner.prompt_sha256(prompt.encode("utf-8")),
        "generation_config": {"max_output_tokens": 4096, "reasoning_level": "low"},
        "status": "strict_success",
        "response_file": "raw_responses/call.txt",
        "response_sha256": runner.sha256_file(response_path),
    }

    assert runner.verify_saved_call(
        run_dir=tmp_path,
        record=record,
        call_id=record["call_id"],
        stage="graph",
        backend="gemini",
        model="gemini-3.8-flash",
        condition_id="C1",
        repeat_id=1,
        attempt_id=1,
        prompt=prompt,
        max_output_tokens=4096,
    ) == response_path

    with pytest.raises(RuntimeError, match="prompt_sha256"):
        runner.verify_saved_call(
            run_dir=tmp_path,
            record=record,
            call_id=record["call_id"],
            stage="graph",
            backend="gemini",
            model="gemini-3.8-flash",
            condition_id="C1",
            repeat_id=1,
            attempt_id=1,
            prompt="changed",
            max_output_tokens=4096,
        )


def test_resume_refuses_unknown_send_without_response(tmp_path):
    prompt = "frozen prompt"
    record = {
        "call_id": "graph.gemini.C1.r01.a01",
        "stage": "graph",
        "backend": "gemini",
        "model": "gemini-3.8-flash",
        "condition_id": "C1",
        "repeat_id": 1,
        "attempt_id": 1,
        "prompt_sha256": runner.prompt_sha256(prompt.encode("utf-8")),
        "generation_config": {"max_output_tokens": 4096, "reasoning_level": "low"},
        "status": "attempted",
    }

    assert runner.verify_saved_call(
        run_dir=tmp_path,
        record=record,
        call_id=record["call_id"],
        stage="graph",
        backend="gemini",
        model="gemini-3.8-flash",
        condition_id="C1",
        repeat_id=1,
        attempt_id=1,
        prompt=prompt,
        max_output_tokens=4096,
    ) is None


@pytest.mark.parametrize("run_status", ["failed", "results_ready_for_review_3"])
def test_operator_confirmed_transient_retry_keeps_original_failure_and_mocks_provider(
    tmp_path, monkeypatch, run_status
):
    run_id, run_dir, failed_call_id, original_result = _make_retry_run(
        tmp_path, run_status=run_status
    )
    monkeypatch.setattr(runner, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setattr(runner, "ACTIVE_DATASET", type("Dataset", (), {"digest": "fixture-dataset"})())
    monkeypatch.setattr(runner, "reproduction_source_hashes", lambda: {"fixture": "frozen"})
    monkeypatch.setattr(runner, "rebuild_summary", lambda *args: None)
    artifact_refreshes = []
    monkeypatch.setattr(
        runner,
        "write_reproduction_artifacts",
        lambda *args: artifact_refreshes.append(args),
    )

    settings = runner.Settings(
        llm_backend="gemini",
        extractor_backend="llm",
        embedding_backend="sentence-transformers",
        embedding_model="facebook/contriever-msmarco",
        gemini_model="gemini-3.8-flash",
        openrouter_model="openai/gpt-5.6-luna",
        gemini_api_key="test-only",
        openrouter_api_key="test-only",
    )
    monkeypatch.setattr(runner, "get_settings", lambda: settings)
    monkeypatch.setattr(runner, "check_settings", lambda *args, **kwargs: None)

    class MockProvider:
        def __init__(self):
            self.calls = []

        def complete(self, prompt, *, max_output_tokens=None, reasoning_level=None):
            self.calls.append((prompt, max_output_tokens, reasoning_level))
            return "Context does not establish a prerequisite."

    provider = MockProvider()
    monkeypatch.setattr(runner, "get_llm_client", lambda provider_settings: provider)

    row = runner.retry_confirmed_transient_call(
        run_id,
        failed_call_id,
        operator_confirmed_transient=True,
    )

    retry_call_id = "edge_context.gemini.S54_EDGE_CONTEXT.r01.a02"
    assert row["call_id"] == retry_call_id
    assert row["status"] == "response_saved"
    assert provider.calls == [("frozen transient retry prompt", 2048, "low")]
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["results"] == [original_result]
    assert manifest["results"][0]["status"] == "api_error"
    assert manifest["calls"][-1] == retry_call_id
    assert manifest["retry_attempts"][0]["retry_of_call_id"] == failed_call_id
    assert manifest["retry_attempts"][0]["operator_confirmed_transient"] is True
    assert manifest["retry_attempts"][0]["status"] == "response_saved"
    retry_record = json.loads((run_dir / "calls" / f"{retry_call_id}.json").read_text(encoding="utf-8"))
    assert retry_record["attempt_id"] == 2
    assert retry_record["retry_of_call_id"] == failed_call_id
    assert retry_record["operator_confirmed_transient"] is True
    assert bool(artifact_refreshes) is (run_status == "results_ready_for_review_3")


@pytest.mark.parametrize("status", ["attempted", "response_saved"])
def test_operator_retry_rejects_unknown_send_and_saved_response(tmp_path, monkeypatch, status):
    run_id, _, failed_call_id, _ = _make_retry_run(tmp_path, status=status)
    monkeypatch.setattr(runner, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setattr(runner, "ACTIVE_DATASET", type("Dataset", (), {"digest": "fixture-dataset"})())
    monkeypatch.setattr(runner, "reproduction_source_hashes", lambda: {"fixture": "frozen"})

    with pytest.raises(RuntimeError, match="Only a saved api_error"):
        runner.retry_confirmed_transient_call(
            run_id,
            failed_call_id,
            operator_confirmed_transient=True,
        )


def test_operator_retry_enforces_four_run_wide_attempts(tmp_path, monkeypatch):
    retry_attempts = [
        {
            "call_id": f"graph.gemini.C{index}.r01.a02",
            "stage": "graph",
            "backend": "gemini",
            "condition_id": f"C{index}",
            "repeat_id": 1,
            "attempt_id": 2,
        }
        for index in range(4)
    ]
    run_id, _, failed_call_id, _ = _make_retry_run(tmp_path, retry_attempts=retry_attempts)
    monkeypatch.setattr(runner, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setattr(runner, "ACTIVE_DATASET", type("Dataset", (), {"digest": "fixture-dataset"})())
    monkeypatch.setattr(runner, "reproduction_source_hashes", lambda: {"fixture": "frozen"})

    with pytest.raises(RuntimeError, match=r"retry limit reached \(4\)"):
        runner.retry_confirmed_transient_call(
            run_id,
            failed_call_id,
            operator_confirmed_transient=True,
        )


def test_review_3_approval_closes_complete_run_without_api_call(tmp_path, monkeypatch):
    run_id = "review-3-fixture"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    manifest = {
        "run_id": run_id,
        "status": "results_ready_for_review_3",
        "call_plan": {"total_calls": 1},
        "results": [{"call_id": "fixture-call"}],
        "review_checkpoints": {"review_3": {"status": "ready_for_user_review"}},
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    refreshes = []
    monkeypatch.setattr(runner, "OUTPUTS_DIR", tmp_path)
    monkeypatch.setattr(
        runner,
        "write_reproduction_artifacts",
        lambda path, saved_manifest, rows: refreshes.append((path, saved_manifest, rows)),
    )
    monkeypatch.setattr(runner, "rebuild_summary", lambda *args: None)

    approved = runner.approve_reproduction_review_3(run_id, "Tôi duyệt Review 3")

    saved = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert approved["status"] == saved["status"] == "completed"
    assert saved["completed_at"] == saved["review_checkpoints"]["review_3"]["approved_at"]
    assert saved["review_checkpoints"]["review_3"]["approved_by"] == "user"
    assert saved["review_checkpoints"]["review_3"]["approval_message"] == "Tôi duyệt Review 3"
    assert len(refreshes) == 1


def test_event_coverage_tracks_representation_not_edge_count():
    graph = {
        "nodes": [
            {"id": "a", "label": "Enumerate PostgreSQL server"},
            {"id": "b", "label": "Exploit trust authentication"},
        ],
        "edges": [],
    }

    coverage = runner._event_coverage(graph, runner.KUBERNETES_COVERAGE_EVENTS)

    assert coverage["PostgreSQL_trust_authentication_path"] is True
    assert coverage["vulnerable_container_image_RCE_path"] is False


def test_parse_mode_distinguishes_raw_markdown_extracted_and_repaired():
    graph = runner.AttackGraph(nodes=[], edges=[])

    assert runner.classify_parse_mode('{"nodes": [], "edges": []}', graph) == "raw_json"
    assert runner.classify_parse_mode(
        '```json\n{"nodes": [], "edges": []}\n```', graph
    ) == "markdown_stripped"
    assert runner.classify_parse_mode(
        'Result: {"nodes": [], "edges": []}', graph
    ) == "object_extracted"
    assert runner.classify_parse_mode(
        '{"nodes": [', runner.AttackGraph(nodes=[], edges=[], truncated=True)
    ) == "repaired_truncated"


def test_wrapper_extraction_does_not_upgrade_raw_schema():
    raw = json.dumps({
        "attack_graph": {
            "nodes": [{"id": "a", "label": "A"}, {"id": "b", "label": "B"}],
            "edges": [{"from": "a", "to": "b", "label": "next"}],
        }
    })
    graph = runner.parse_llm_json(raw)

    metrics = runner.response_graph_metrics(raw, graph, [], "fixture", condition_id="T0")

    assert metrics["response_json_valid"] is True
    assert metrics["graph_wrapper_extracted"] is True
    assert metrics["extracted_graph_schema_valid"] is True
    assert metrics["schema_valid"] is False
    assert metrics["true_empty_graph"] is False


def test_refresh_reparses_raw_response_and_preserves_repaired_state(tmp_path):
    run_dir = tmp_path / "run"
    for folder in ("calls", "call_prompts", "raw_responses"):
        (run_dir / folder).mkdir(parents=True, exist_ok=True)
    call_id = "graph.openrouter.T1.r01.a01"
    prompt = "fixture prompt"
    full = json.dumps({
        "nodes": [{"id": "n1", "label": "A"}, {"id": "n2", "label": "B"}],
        "edges": [{"from": "n1", "to": "n2", "label": "next"}],
    })
    raw = full[: full.index('{"from"') - 2]
    prompt_path = run_dir / "call_prompts" / f"{call_id}.txt"
    response_path = run_dir / "raw_responses" / f"{call_id}.txt"
    prompt_path.write_text(prompt, encoding="utf-8")
    response_path.write_text(raw, encoding="utf-8")
    runner.atomic_json(run_dir / "calls" / f"{call_id}.json", {
        "call_id": call_id,
        "prompt_file": prompt_path.relative_to(run_dir).as_posix(),
        "prompt_sha256": runner.sha256_file(prompt_path),
        "response_file": response_path.relative_to(run_dir).as_posix(),
        "response_sha256": runner.sha256_file(response_path),
        "response_metadata": {"finish_reason": "length"},
    })
    row = {
        "call_id": call_id,
        "stage": "graph",
        "condition_id": "T1",
        "status": "repaired_success",
        "parse_mode": "object_extracted",
    }
    manifest = {"conditions": [], "results": [row]}

    runner.refresh_saved_graph_metrics(run_dir, manifest, [row])

    assert row["status"] == "repaired_success"
    assert row["parse_mode"] == "repaired_truncated"
    assert row["truncated_repair"] is True
    assert row["parser_repaired_truncation"] is True
    assert row["finish_reason_indicates_truncation"] is True


def test_edge_context_detector_recognizes_markdown_negation_in_all_ten_pairs(tmp_path):
    rows = []
    phrases = [
        "The source **does **not** explicitly establish** the local execution prerequisite.",
        "The source does **not** explicitly establish the local execution prerequisite.",
        "The source does not establish the local execution prerequisite.",
        "The source does not explicitly establish the local execution prerequisite.",
        "The source does not directly establish the local execution prerequisite.",
        "The source does not clearly establish the local execution prerequisite.",
        "The source does not adequately establish the local execution prerequisite.",
        "The source has **not established** the local execution prerequisite.",
        "The local execution prerequisite is not established by the source.",
        "Nguồn không thiết lập điều kiện local execution.",
    ]
    for repeat_id in range(1, 6):
        for model_index, backend in enumerate(("gemini", "openrouter")):
            call_id = f"edge_context.{backend}.r{repeat_id:02d}"
            response = tmp_path / f"{call_id}.txt"
            response.write_text(phrases[(repeat_id - 1) * 2 + model_index], encoding="utf-8")
            rows.extend([
                {
                    "stage": "edge_detail", "backend": backend, "repeat_id": repeat_id,
                    "call_id": f"edge_detail.{backend}.r{repeat_id:02d}",
                    "raw_response_file": "unused.txt", "schema_valid": True,
                },
                {
                    "stage": "edge_context", "backend": backend, "repeat_id": repeat_id,
                    "call_id": call_id, "raw_response_file": response.name,
                },
            ])

    review = runner.write_edge_expansion_review(tmp_path, rows)

    assert review["summary"]["context_extractions"] == 10
    assert review["summary"]["contexts_flagging_missing_prerequisite"] == 10
    assert all(
        item["context_explicitly_flags_missing_prerequisite"]
        for item in review["repeat_reviews"]
    )


def test_source_excerpt_cites_endpoint_passages_with_line_positions():
    source = (
        "Prompt instructions unrelated to the selected edge.\n\n"
        "A remote page can inject HTML into the Oculus Browser UI.\n\n---\n\n"
        "OVRRedir.exe can write arbitrary files through a hard link and cause local privilege escalation.\n\n"
        "A separate unrelated Glowworm description."
    )

    location, excerpt = runner._source_excerpt(
        source,
        [
            "Leverages local execution from Oculus Browser to OVRRedir.exe",
            "Oculus Browser compromise",
            "OVRRedir local privilege escalation",
        ],
    )

    assert "lines 3–3 (source endpoint)" in location
    assert "lines 7–7 (target endpoint)" in location
    assert "Oculus Browser UI" in excerpt
    assert "OVRRedir.exe" in excerpt
    assert "Glowworm" not in excerpt


def test_unidentified_bridge_remains_unclear_and_names_the_unknown():
    label, reason, missing_condition = runner._preliminary_edge_label(
        "C2",
        "Alpha service accepts requests. Beta component writes a report.",
        "Alpha service",
        "Beta component",
        "Alpha leads to Beta",
    )

    assert label == "chưa rõ"
    assert "cầu nối" in reason
    assert missing_condition.startswith("Chưa rõ")


def test_named_oculus_bridge_can_be_labeled_conditional():
    label, _, missing_condition = runner._preliminary_edge_label(
        "C2",
        "A remote page can inject HTML into the Oculus Browser UI. "
        "OVRRedir.exe can write arbitrary files through a hard link and cause local privilege escalation.",
        "Oculus Browser compromise",
        "OVRRedir local privilege escalation",
        "Browser compromise enables OVRRedir exploitation",
    )

    assert label == "có điều kiện"
    assert "local execution" in missing_condition


def test_ovrredir_internal_step_is_not_mislabeled_as_browser_bridge():
    label, _, missing_condition = runner._preliminary_edge_label(
        "S54_EDGE_DETAIL",
        "A remote page can inject HTML into the Oculus Browser UI. "
        "OVRRedir.exe can write arbitrary files through a hard link and cause local privilege escalation.",
        "Unprivileged local execution on Windows",
        "Identify OVRRedir.exe log-file target",
        "Locate the unprivileged log path before preparing a hard link",
    )

    assert label == "chưa rõ"
    assert missing_condition.startswith("Chưa rõ")
