import json
from datetime import datetime, timezone

from crystalball.config import Settings
from crystalball.db import Database
from crystalball.run_artifacts import experiment_metadata, new_run_id


def test_new_run_id_does_not_reuse_a_timestamp_with_existing_artifacts(tmp_path):
    prompts = tmp_path / "prompts"
    graphs = tmp_path / "graphs"
    prompts.mkdir()
    graphs.mkdir()
    started = datetime(2026, 9, 24, 1, 2, 3, tzinfo=timezone.utc)

    first = new_run_id(prompts, graphs, now=started)
    (prompts / f"response_{first}.txt").write_text("already used")
    second = new_run_id(prompts, graphs, now=started)

    assert second == f"{first}_01"


def test_successful_graph_result_and_experiment_metadata_persist_in_sqlite(tmp_path):
    db = Database(tmp_path / "graphs.sqlite3")
    metadata = experiment_metadata(
        Settings(llm_backend="openrouter", openrouter_model="openai/gpt-5.6-luna"),
        run_id="20260924T010203000000Z",
        timestamp="2026-09-24T01:02:03+00:00",
        input_mode="products",
        context_mode="cve_retrieval",
        retrieved_cve_ids=["CVE-2020-1885"],
        parse_status="pending",
    )
    row_id = db.save_graph("Oculus Desktop", "prompt text", "response text", None, metadata)
    graph = {"nodes": [{"id": "n1", "label": "Example"}], "edges": []}
    metadata["parse_status"] = "success"
    db.update_graph_result(row_id, graph, metadata)

    import sqlite3

    with sqlite3.connect(db.db_path) as conn:
        row = conn.execute(
            "SELECT graph_json, metadata_json FROM graphs WHERE id = ?", (row_id,)
        ).fetchone()

    assert json.loads(row[0]) == graph
    saved = json.loads(row[1])
    assert saved["backend"] == "openrouter"
    assert saved["model"] == "openai/gpt-5.6-luna"
    assert saved["context_mode"] == "cve_retrieval"
    assert saved["retrieved_cve_ids"] == ["CVE-2020-1885"]
    assert saved["parse_status"] == "success"
