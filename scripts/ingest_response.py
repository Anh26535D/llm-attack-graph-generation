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
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crystalball.config import GRAPHS_DIR, ensure_dirs  # noqa: E402
from crystalball.db import Database  # noqa: E402
from crystalball.postprocess import parse_llm_json, save_graph_json, visualize_graph  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--response", type=Path, required=True, help="File containing the pasted LLM answer.")
    parser.add_argument("--query", default=None, help="Optional label to store alongside the saved graph.")
    parser.add_argument("--prompt-file", type=Path, default=None, help="Optional matching prompt file, for the DB record.")
    args = parser.parse_args()

    ensure_dirs()
    raw_response = args.response.read_text(encoding="utf-8")

    graph = parse_llm_json(raw_response)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    graph_json_path = GRAPHS_DIR / f"graph_{timestamp}.json"
    save_graph_json(graph, graph_json_path)
    png_path = visualize_graph(graph, GRAPHS_DIR / f"graph_{timestamp}.png")

    db = Database()
    prompt_text = args.prompt_file.read_text(encoding="utf-8") if args.prompt_file else ""
    db.save_graph(args.query or str(args.response), prompt_text, raw_response, graph.to_dict())

    print(f"Parsed {len(graph.nodes)} nodes and {len(graph.edges)} edges.")
    print(f"Graph saved to: {graph_json_path}")
    print(f"Visualization saved to: {png_path}")
    if graph.truncated:
        print("Note: the response looked truncated; the graph was repaired best-effort.")


if __name__ == "__main__":
    main()
