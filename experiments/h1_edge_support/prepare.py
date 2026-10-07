"""Build the H1 prompt: the paper's own Appendix A (C2) prompt, with each CVE
description tagged by its CVE ID so graph nodes can be mapped back reliably.

This is the one deliberate deviation from the paper's prompt; it is applied to the
wrapper-plus-descriptions text in data/reproduction/appendix_a_context.txt without
changing any other word.

    python -m experiments.h1_edge_support.prepare --run-id h1_pilot
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from experiments.env_consistency.prompts import load_cve_descriptions

REPO = Path(__file__).resolve().parents[2]
OUT_ROOT = REPO / "outputs" / "experiments"
APPENDIX_A = REPO / "data" / "reproduction" / "appendix_a_context.txt"


def build_prompt() -> str:
    text = APPENDIX_A.read_text(encoding="utf-8")
    by_description = {desc: cve for cve, desc in load_cve_descriptions().items()}
    wrapper, *paragraphs = text.rstrip("\n").split("\n\n")
    out = [wrapper]
    seen = set()
    for paragraph in paragraphs:
        paragraph = paragraph.strip()
        cve = by_description.get(paragraph)
        if cve is None:
            raise ValueError(f"Paragraph does not match any official CVE description: {paragraph[:60]}")
        seen.add(cve)
        out.append(f"{cve}: {paragraph}")
    if len(seen) != 8:
        raise ValueError(f"Expected 8 CVE paragraphs, found {len(seen)}")
    return "\n\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    out = OUT_ROOT / args.run_id
    (out / "prompts").mkdir(parents=True, exist_ok=True)
    (out / "prompts" / "c2ids.txt").write_text(build_prompt(), encoding="utf-8")
    (out / "cases.json").write_text(
        json.dumps([{"case_id": "c2ids", "env_id": "none", "state": "base", "variant": "plain"}], indent=2),
        encoding="utf-8",
    )
    print(f"Wrote prompt to {out / 'prompts' / 'c2ids.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
