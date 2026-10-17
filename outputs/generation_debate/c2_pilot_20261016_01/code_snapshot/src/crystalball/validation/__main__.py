"""python -m crystalball.validation --help"""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

from ..config import PROJECT_ROOT
from .config import ValidatorConfig
from .evidence import EnvironmentState, EvidenceStore
from .pipeline import write_artifacts

DEFAULT_GRAPH = PROJECT_ROOT / "outputs/paper_nine/paper9_20261013_original/figures/figure_07_r01/graph.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evidence-grounded static attack graph audit; never executes exploits.")
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--manifest", type=Path, default=PROJECT_ROOT / "data/cve_official/manifest.json")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs/validator/figure_07_offline")
    parser.add_argument("--mode", choices=("offline", "hybrid"))
    parser.add_argument("--enable-llm", action="store_true", help="Explicitly enable billable review; also select --mode hybrid")
    parser.add_argument("--backend", choices=("gemini", "openai", "openrouter", "openrouter_v2"))
    parser.add_argument("--max-llm-calls", type=int)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--review-controls", action="store_true", help="Explicitly review all statuses as a control experiment")
    parser.add_argument("--environment", type=Path, help="External environment observations; missing data stays unknown")
    parser.add_argument("--gold", type=Path, help="Independent human/dataset labels; never LLM review labels")
    parser.add_argument("--no-render", action="store_true")
    args = parser.parse_args(argv)
    config = ValidatorConfig.from_env(allow_control_review=args.review_controls)
    updates = {key: value for key, value in {
        "mode": args.mode, "llm_backend": args.backend, "max_llm_calls": args.max_llm_calls,
        "cache_dir": args.cache_dir}.items() if value is not None}
    if args.enable_llm:
        updates["llm_enabled"] = True
    if args.no_cache:
        updates["cache_enabled"] = False
    if args.review_controls:
        from .config import STATUSES
        updates.update(allow_control_review=True, review_statuses=STATUSES)
    config = replace(config, **updates)
    report = write_artifacts(args.graph, args.out, EvidenceStore.load(args.manifest), config,
                             environment=EnvironmentState.load(args.environment) if args.environment else None,
                             gold=json.loads(args.gold.read_text(encoding="utf-8")) if args.gold else None,
                             render=not args.no_render)
    print(json.dumps({"output": str(args.out), "review_enabled": report["review_enabled"],
                      "metrics": report["metrics"]}, indent=2))
    if any(r["review"]["state"] in {"initialization_error", "api_error", "invalid_response"}
           or r["review"]["state"] in {"completed", "cache_hit"} and not r["final"]["review_complete"]
           for r in report["edges"]):
        return 2  # Offline artifacts are still complete and usable.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
