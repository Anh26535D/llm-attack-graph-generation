#!/usr/bin/env python
"""Step 2: build the attack-graph generation prompt (Algorithm 3 / Appendix C).

This is the script you run to get something to paste into ChatGPT, Gemini,
Claude, etc. By default (LLM_BACKEND=manual in .env) it just writes the
prompt to a file and prints it to stdout for copy/paste. If you set
LLM_BACKEND=openai or LLM_BACKEND=gemini (with the matching API key), it
also calls the LLM automatically and produces the graph + a PNG
visualization in outputs/graphs/, skipping the copy/paste step entirely.

Examples:
    # CVE-context mode, using the sample system from the paper (Section 5)
    python scripts/build_prompt.py --products "Oculus Desktop" "Jetson TX1" "Raspberry Pi"

    # Baseline "no context" mode (reproduces Figure 6)
    python scripts/build_prompt.py --products "Raspberry Pi" "Oculus Desktop" "NVIDIA Jetson Nano" --no-context

    # Threat-report mode (reproduces Figure 2 / Appendix C)
    python scripts/build_prompt.py --report data/threat_reports/solarwinds_full.txt
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crystalball.config import PROMPTS_DIR, ensure_dirs, get_settings  # noqa: E402
from crystalball.db import Database  # noqa: E402
from crystalball.generator import (  # noqa: E402
    build_prompt_from_products,
    build_prompt_from_report,
    call_llm_and_save,
)
from crystalball.llm.factory import get_llm_client  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--products", nargs="+", help="Product/package names making up the target system.")
    group.add_argument("--report", type=Path, help="Path to a threat report text file.")
    parser.add_argument(
        "--no-context",
        action="store_true",
        help="Skip the retriever entirely (baseline experiment, --products only).",
    )
    args = parser.parse_args()

    ensure_dirs()
    settings = get_settings()
    db = Database()

    if args.report:
        built = build_prompt_from_report(args.report)
    else:
        built = build_prompt_from_products(args.products, db, settings=settings, use_context=not args.no_context)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prompt_path = PROMPTS_DIR / f"prompt_{timestamp}.txt"
    prompt_path.write_text(built.prompt, encoding="utf-8")

    print(f"Prompt written to: {prompt_path}")
    if built.retrieval is not None:
        print(f"Retrieved {len(built.retrieval.relevant_cve_ids)} relevant CVE(s): "
              f"{', '.join(built.retrieval.relevant_cve_ids) or '(none)'}")
    print("\n----- PROMPT (copy everything below into ChatGPT / Gemini / etc.) -----\n")
    print(built.prompt)
    print("\n----- END PROMPT -----\n")

    llm_client = get_llm_client(settings)
    if llm_client is None:
        print(
            f"LLM_BACKEND=manual: paste the LLM's JSON answer into a file and run\n"
            f"  python scripts/ingest_response.py --response <file> --query {prompt_path.stem!r}"
        )
        return

    print(f"LLM_BACKEND={settings.llm_backend}: calling the API automatically...")
    raw_response, row_id = call_llm_and_save(built, llm_client, db)

    response_path = PROMPTS_DIR / f"response_{timestamp}.txt"
    response_path.write_text(raw_response, encoding="utf-8")
    print(f"Raw response saved to: {response_path} (graphs row id={row_id})")

    from crystalball.config import GRAPHS_DIR
    from crystalball.postprocess import parse_llm_json, save_graph_json, visualize_graph

    try:
        graph = parse_llm_json(raw_response)
    except Exception as exc:  # noqa: BLE001
        print(f"Could not parse a graph out of the response ({exc}). "
              f"Inspect {response_path} manually.")
        return

    graph_json_path = GRAPHS_DIR / f"graph_{timestamp}.json"
    save_graph_json(graph, graph_json_path)
    png_path = visualize_graph(graph, GRAPHS_DIR / f"graph_{timestamp}.png")
    print(f"Graph saved to: {graph_json_path}")
    print(f"Visualization saved to: {png_path}")
    if graph.truncated:
        print("Note: the response looked truncated; the graph was repaired best-effort.")


if __name__ == "__main__":
    main()
