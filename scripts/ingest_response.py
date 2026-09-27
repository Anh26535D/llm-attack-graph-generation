#!/usr/bin/env python
"""Step 3 (manual LLM_BACKEND only): feed back the answer you pasted from
ChatGPT/Gemini/etc, and get the parsed graph + PNG visualization.

Usage:
    python scripts/ingest_response.py --response outputs/prompts/response_pasted.txt

The response file can contain stray prose/markdown fences around the JSON;
it will be extracted automatically. If the LLM's answer was cut off by a
token limit, a best-effort repair is attempted (see Section 5.4 of the
paper for why this happens).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crystalball.config import GRAPHS_DIR, PROMPTS_DIR, ensure_dirs, get_settings  # noqa: E402
from crystalball.db import Database  # noqa: E402
from crystalball.postprocess import parse_llm_json, save_graph_json, visualize_graph  # noqa: E402
from crystalball.run_artifacts import experiment_metadata, new_run_id  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--response", type=Path, required=True, help="File containing the pasted LLM answer.")
    parser.add_argument("--query", default=None, help="Optional label to store alongside the saved graph.")
    parser.add_argument("--prompt-file", type=Path, default=None, help="Optional matching prompt file, for the DB record.")
    parser.add_argument("--backend", choices=("manual", "openai", "openrouter", "gemini"), default=None,
                        help="Actual LLM backend used for the pasted response (recorded as metadata).")
    parser.add_argument("--model", default=None, help="Actual model name/slug used for the pasted response.")
    args = parser.parse_args()

    ensure_dirs()
    raw_response = args.response.read_text(encoding="utf-8")
    settings = get_settings()
    started = datetime.now(timezone.utc)
    timestamp = started.isoformat()
    run_id = new_run_id(PROMPTS_DIR, GRAPHS_DIR, now=started)
    response_path = PROMPTS_DIR / f"response_{run_id}.txt"
    response_path.write_text(raw_response, encoding="utf-8")
    prompt_text = args.prompt_file.read_text(encoding="utf-8") if args.prompt_file else ""
    prompt_path = PROMPTS_DIR / f"prompt_{run_id}.txt"
    prompt_path.write_text(prompt_text, encoding="utf-8")

    metadata = None
    source_metadata_path = args.prompt_file.with_suffix(".meta.json") if args.prompt_file else None
    if source_metadata_path and source_metadata_path.exists():
        try:
            metadata = json.loads(source_metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metadata = None
    metadata = metadata or experiment_metadata(
        settings,
        run_id=run_id,
        timestamp=timestamp,
        input_mode="manual_response",
        context_mode="unknown",
    )
    metadata.update({
        "run_id": run_id,
        "timestamp": timestamp,
        "backend": args.backend or metadata.get("backend", "manual"),
        "model": args.model or metadata.get("model"),
        "parse_status": "pending",
        "source_prompt_file": str(args.prompt_file) if args.prompt_file else None,
        "response_file": str(response_path),
    })
    metadata["query"] = args.query or (args.prompt_file.stem if args.prompt_file else str(args.response))
    metadata_path = prompt_path.with_suffix(".meta.json")

    graph = None
    parse_error = None
    try:
        graph = parse_llm_json(raw_response)
        metadata["parse_status"] = "repaired" if graph.truncated else "success"
    except Exception as exc:  # noqa: BLE001
        parse_error = exc
        metadata["parse_status"] = "failed"
        metadata["parse_error"] = str(exc)

    db = Database()
    metadata["graph_file"] = str(GRAPHS_DIR / f"graph_{run_id}.json") if graph else None
    row_id = db.save_graph(
        metadata["query"],
        prompt_text,
        raw_response,
        graph.to_dict() if graph else None,
        metadata=metadata,
    )
    metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Raw response saved to: {response_path} (graphs row id={row_id})")
    print(f"Prompt copy saved to: {prompt_path}")
    print(f"Run metadata saved to: {metadata_path}")
    if parse_error:
        print(f"Could not parse a graph out of the response ({parse_error}).")
        return

    graph_json_path = GRAPHS_DIR / f"graph_{run_id}.json"
    save_graph_json(graph, graph_json_path)
    png_path = visualize_graph(graph, GRAPHS_DIR / f"graph_{run_id}.png")
    print(f"Parsed {len(graph.nodes)} nodes and {len(graph.edges)} edges.")
    print(f"Graph saved to: {graph_json_path}")
    print(f"Visualization saved to: {png_path}")
    if graph.truncated:
        print("Note: the response looked truncated; the graph was repaired best-effort.")


if __name__ == "__main__":
    main()
