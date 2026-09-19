#!/usr/bin/env python
"""Step 1: ingest CVE JSON records into the database (Algorithm 1).

Usage:
    python scripts/ingest_cves.py                       # ingest data/cve_samples
    python scripts/ingest_cves.py --input path/to/dir    # ingest a custom directory

Set EXTRACTOR_BACKEND=llm (and LLM_BACKEND=openai/gemini with the matching
API key in .env) to use a real LLM for property extraction as in the paper;
defaults to a dependency-free heuristic extractor.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crystalball.config import DATA_DIR, ensure_dirs, get_settings  # noqa: E402
from crystalball.db import Database  # noqa: E402
from crystalball.preprocess import preprocess_directory  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=DATA_DIR / "cve_samples",
        help="Directory of CVE Record Format v5 JSON files.",
    )
    args = parser.parse_args()

    ensure_dirs()
    settings = get_settings()
    db = Database()

    print(f"Ingesting CVE records from {args.input} "
          f"(extractor={settings.extractor_backend}, embeddings={settings.embedding_backend})")

    results = preprocess_directory(args.input, db, settings=settings)

    ingested = [r for r in results if not r.skipped]
    skipped = [r for r in results if r.skipped]

    for r in ingested:
        print(f"  [ok]      {r.cve_id}")
    for r in skipped:
        print(f"  [skipped] {r.cve_id} ({r.reason})")

    print(f"\nDone. {len(ingested)} ingested, {len(skipped)} skipped. "
          f"Total CVEs in DB: {db.count_cves()}")


if __name__ == "__main__":
    main()
