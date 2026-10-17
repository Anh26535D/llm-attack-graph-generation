from copy import deepcopy
import json

import pytest

from crystalball.config import PROJECT_ROOT, Settings
from crystalball.paper_cases import BY_FIGURE, load_prompt
from crystalball.report_debate import (check_citations, execute, graph_diff, paragraphs,
                                      parse_graph, parse_review, prepare, read,
                                      run_branches, verify)

GRAPH = {"nodes": [{"id": "update", "label": "Trojanized update"},
                   {"id": "dll", "label": "SUNBURST DLL"}],
         "edges": [{"from": "update", "to": "dll", "label": "distributes"}]}
SOURCE = [{"id": "P001", "text": "Trojanized updates distribute the SUNBURST DLL."}]


def review(quote="Trojanized updates distribute the SUNBURST DLL."):
    return {"findings": [{"kind": "edge", "id": "edge-0001", "position": "keep",
            "reason": "The report states the distribution relationship.",
            "citations": [{"paragraph_id": "P001", "quote": quote}]}], "omissions": []}


def test_report_prompt_and_paragraphs_are_exact_paper_text(tmp_path):
    out = tmp_path / "t1"
    settings = Settings()
    manifest = prepare(out, settings)
    assert (out / "paper_prompt.txt").read_bytes() == load_prompt(PROJECT_ROOT, BY_FIGURE[2]).encode()
    body = (out / "report.txt").read_text(encoding="utf-8")
    rows = read(out / "paragraphs.json")
    assert len(rows) == 56
    assert all(body[row["start_char"]:row["end_char"]] == row["text"] for row in rows)
    assert manifest["synthetic_data"] is False
    assert manifest["fixed_node_inventory"] is False
    assert manifest["max_api_calls_total"] == 7
    assert (out / "paper_references/figure_02.png").exists()
    verify(out, settings)
    (out / "report.txt").write_text(body + "changed", encoding="utf-8")
    with pytest.raises(ValueError, match="Frozen"):
        verify(out, settings)


def test_no_cve_schema_or_fixed_node_count_for_report_graph():
    value, audit = parse_graph(json.dumps(GRAPH), revision=False)
    assert value["graph"] == GRAPH
    assert audit["strict_json_without_fence"]
    fenced = "```json\n" + json.dumps(GRAPH) + "\n```"
    assert parse_graph(fenced, revision=False)[1]["markdown_fence_removed"]
    broken = deepcopy(GRAPH)
    broken["edges"][0]["to"] = "absent"
    with pytest.raises(ValueError, match="schema"):
        parse_graph(json.dumps(broken), revision=False)
    with pytest.raises(ValueError):
        parse_graph('{"nodes":[],"nodes":[],"edges":[]}', revision=False)


def test_unverified_review_quotes_are_withheld_and_references_checked():
    parsed, audit = parse_review(json.dumps(review("invented quote")), GRAPH, {"P001": SOURCE[0]["text"]})
    assert parsed["findings"][0]["citations"][0]["quote"] is None
    assert audit["unverified_citations"] == 1
    broken = review()
    broken["findings"][0]["id"] = "edge-9999"
    with pytest.raises(ValueError, match="nonexistent"):
        parse_review(json.dumps(broken), GRAPH, {"P001": SOURCE[0]["text"]})
    assert check_citations([{"paragraph_id": "P999", "quote": SOURCE[0]["text"]}], {"P001": SOURCE[0]["text"]})[0]["verification"] == "unverified"


def test_branches_share_original_and_freeze_opposing_prompts():
    prompts = {}
    initial = deepcopy(GRAPH)
    def complete(stage, role, prompt):
        prompts[stage] = prompt
        if role in {"defender", "skeptic"}:
            return json.dumps(review("invented quote"))
        return json.dumps({"graph": GRAPH, "changes": []})
    results = dict(run_branches(initial, SOURCE, complete, defender_first=False))
    assert initial == GRAPH
    assert len(prompts) == 6
    assert "invented quote" not in prompts["debate.synthesis"]
    assert '"role": "skeptic"' not in prompts["debate.defender"]
    assert '"role": "defender"' not in prompts["debate.skeptic"]
    assert prompts["debate.synthesis"].index('"role": "skeptic"') < prompts["debate.synthesis"].index('"role": "defender"')
    assert all(value["graph"] == GRAPH for value in results.values())
    assert results["debate"]["review_audits"]["skeptic"]["unverified_citations"] == 1


def test_graph_diff_preserves_parallel_relations_and_flags_granularity():
    changed = deepcopy(GRAPH)
    changed["nodes"].append({"id": "beacon", "label": "BEACON"})
    changed["edges"].append({"from": "update", "to": "dll", "label": "contains"})
    changed["edges"].append({"from": "dll", "to": "beacon", "label": "may deliver"})
    result = graph_diff(GRAPH, changed)
    assert result["added_node_ids"] == ["beacon"]
    assert result["added_pairs"] == [["dll", "beacon"]]
    assert result["changed_retained_pairs"] == [["update", "dll"]]
    assert result["id_based_alignment_only"]


def test_execute_calls_exact_baseline_once_and_resumes_without_new_requests(tmp_path, monkeypatch):
    out = tmp_path / "pilot"
    settings = Settings()
    prepare(out, settings)
    prompt = (out / "paper_prompt.txt").read_text(encoding="utf-8")
    rows = read(out / "paragraphs.json")
    citation = {"paragraph_id": rows[1]["id"], "quote": rows[1]["text"][:100]}
    calls = []
    class Fake:
        last_usage = {"total_token_count": 20}
        last_response_metadata = {"finish_reason": "STOP"}
        def complete(self, text, **kwargs):
            calls.append(text)
            if len(calls) == 1:
                assert text == prompt
                return json.dumps(GRAPH)
            if "Do not output a graph" in text:
                value = review()
                value["findings"][0]["citations"] = [citation]
                return "```json\n" + json.dumps(value) + "\n```"
            return json.dumps({"graph": GRAPH, "changes": []})
    monkeypatch.setattr("crystalball.generation_debate_runner.get_llm_client", lambda *_: Fake())
    result = execute(out, settings)
    assert len(calls) == 7
    assert all(row["status"] == "completed" and row["accuracy"] is None for row in result["rows"])
    assert [row["calls_including_shared_draft"] for row in result["rows"]] == [1, 4, 4]
    assert result["unique_usage"]["total_tokens"] == 140
    execute(out, settings)
    assert len(calls) == 7
    assert not (out / ".execute.lock").exists()
    blind = read(out / "runs/r01/debate/annotation_blind.json")
    assert all(row["status"] is None and row["source_citations"] == [] for row in blind["edges"])
    assert "reviews" not in json.dumps(blind)
