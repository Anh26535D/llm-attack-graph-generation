#!/usr/bin/env python
"""One-shot, zero-API-key smoke test of the whole pipeline.

Ingests the bundled sample CVEs, runs the retriever for the paper's example
system (Oculus Desktop, Jetson TX1/Nano, Raspberry Pi), and prints both the
"no context" baseline prompt (Figure 6) and the retrieved-context prompt
(Figure 7) so you can see the retriever actually narrowing things down.

This does NOT call any LLM. It exists to prove steps 1-2 of the pipeline
(ingestion + retrieval + prompt construction) work before you spend API
credits or copy/paste into a chat UI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crystalball.config import DATA_DIR, ensure_dirs, get_settings  # noqa: E402
from crystalball.db import Database  # noqa: E402
from crystalball.generator import build_prompt_from_products  # noqa: E402
from crystalball.preprocess import preprocess_directory  # noqa: E402

SAMPLE_SYSTEM = ["Oculus Desktop", "Jetson TX1", "Raspberry Pi"]


def main() -> None:
    ensure_dirs()
    settings = get_settings()
    db = Database()

    print("== Step 1: ingesting sample CVEs (data/cve_samples) ==")
    results = preprocess_directory(DATA_DIR / "cve_samples", db, settings=settings)
    print(f"Ingested {sum(1 for r in results if not r.skipped)} CVE(s).\n")

    print("== Baseline: no-context prompt (reproduces Figure 6) ==")
    baseline = build_prompt_from_products(SAMPLE_SYSTEM, db, settings=settings, use_context=False)
    print(baseline.prompt)

    print("\n== Retriever-augmented prompt (reproduces Figure 7) ==")
    augmented = build_prompt_from_products(SAMPLE_SYSTEM, db, settings=settings, use_context=True)
    print(f"Relevant CVEs found: {augmented.retrieval.relevant_cve_ids}")
    print(f"Matches (cve_id, matched_on, cosine_similarity):")
    for m in augmented.retrieval.matches:
        print(f"  {m[0]:<20} {m[1]:<40} {m[2]:.3f}")
    print("\n--- Full prompt ---\n")
    print(augmented.prompt)

    print(
        "\nNext step: paste the prompt above into ChatGPT/Gemini/etc, save the "
        "reply to a file, then run:\n"
        "  python scripts/ingest_response.py --response <file>\n"
        "...or set LLM_BACKEND=openai/gemini in .env and use scripts/build_prompt.py "
        "for full automation."
    )


if __name__ == "__main__":
    main()
