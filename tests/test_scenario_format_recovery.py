import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("scenario_format_recovery", Path(__file__).parents[1] / "scripts/resume_scenario_format.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_fence_only_recovery_does_not_edit_json_content():
    raw = '\n```json\n{"graph":{"nodes":[],"edges":[]},"text":"literal value"}\n```\n'
    normalized, changed = module.unwrap(raw)
    assert changed
    assert normalized == '{"graph":{"nodes":[],"edges":[]},"text":"literal value"}'


@pytest.mark.parametrize("raw", [
    'Prose before\n```json\n{"x":1}\n```',
    '```json\n{"x":1}\n```\nProse after',
    '```json\n{"x":1}\n```\n```json\n{"x":2}\n```',
    '```json\n{"x":1,"x":2}\n```',
    '```json\n{"x":\n```',
])
def test_recovery_rejects_prose_duplicate_keys_and_truncation(raw):
    try:
        normalized, changed = module.unwrap(raw)
        # An unrecognized wrapper must remain untouched and fail the normal parser.
        assert not changed
        module.strict_object(normalized)
    except ValueError:
        return
    pytest.fail("Malformed response was accepted")


def test_plain_json_is_unchanged():
    raw = '{"x":1}'
    assert module.unwrap(raw) == (raw, False)


def test_recovery_reuses_five_requests_and_preserves_strict_failure(tmp_path, monkeypatch):
    from crystalball.config import Settings
    from crystalball.generation_debate import DebateConfig
    from test_scenario_debate import oracle_candidate
    public, reference = module.runner.fixture()
    initial = oracle_candidate(public, reference)
    revised = oracle_candidate(public, reference, revised=True)
    sources = {node["id"]: node["description"] for node in public["nodes"]}
    calls = []
    class Fake:
        last_usage = {"total_token_count": 10}
        last_response_metadata = {"finish_reason": "STOP"}
        def complete(self, prompt, **kwargs):
            calls.append(prompt)
            if "Do not output a graph" in prompt:
                value = {"arguments": [{"edge_id": f"edge-{i:04d}", "position": "keep", "reason": "source relation",
                    "source_quote": sources[e["from"]][:80], "target_quote": sources[e["to"]][:80], "missing_conditions": []}
                    for i, e in enumerate(initial["graph"]["edges"], 1)]}
                return "```json\n" + json.dumps(value) + "\n```"
            return json.dumps(initial if len(calls) == 1 else revised)
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: Fake())
    # main's temporary journal substitution must be restored at test teardown.
    monkeypatch.setattr(module.runner, "Journal", module.runner.Journal)
    settings = Settings()
    source, recovered = tmp_path / "strict", tmp_path / "recovered"
    module.runner.prepare(source, settings, repeats=1, backend="gemini", config=DebateConfig())
    with pytest.raises(ValueError):
        module.runner.execute(source, settings)
    assert len(calls) == 5
    before = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    module.main(["--source", str(source), "--out", str(recovered)])
    assert len(calls) == 7
    assert before == {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    result = module.read(recovered / "comparison.json")
    assert all(row["status"] == "ready_for_independent_validation" for row in result["rows"])
    assert len(list(recovered.glob("runs/r01/calls/*.json"))) == 7
    assert len(list(recovered.glob("runs/r01/format_normalization/*.audit.json"))) == 2
    assert module.read(recovered / "FORMAT_RECOVERY.json")["requests_reused"] == 5
