"""Retry only failed reviews; retain initial attempts and successful cached reviews."""

import json
import shutil
from dataclasses import replace
from pathlib import Path

from crystalball.validation.config import ValidatorConfig
from crystalball.validation.evidence import EvidenceStore
from crystalball.validation.pipeline import write_artifacts
from crystalball.validation.review import ReviewAdapter

base = Path(__file__).resolve().parent
config = replace(ValidatorConfig.from_env(), mode="hybrid", llm_enabled=True)
store = EvidenceStore.load(Path("data/cve_official/manifest.json"))
warmup = json.loads((base / "warmup_07/validation_results.json").read_text(encoding="utf-8"))
initial = {n: json.loads((base / f"figure_{n:02d}/validation_results.json").read_text(encoding="utf-8"))
           for n in (7, 9, 10)}
spent = warmup["metrics"]["C_hybrid"]["additional_api_calls"] + sum(
    r["metrics"]["C_hybrid"]["additional_api_calls"] for r in initial.values())
remaining = max(0, config.max_llm_calls - spent)
retry_config = replace(config, max_output_tokens=8192, max_llm_calls=remaining)
retry_adapter = ReviewAdapter(retry_config)
retry_log = {"initial_api_calls_including_warmup": spent, "remaining_call_budget": remaining,
             "retry_config": retry_config.public_dict(), "figures": []}


class SelectiveRetryAdapter(ReviewAdapter):
    def __init__(self, number, failed):
        super().__init__(config)
        self.number, self.failed = number, failed
        self.cache_reader = ReviewAdapter(replace(config, max_llm_calls=0))

    def review(self, row, provenance):
        if row["edge_id"] in self.failed:
            print(f"Figure {self.number} {row['edge_id']}: retry, output limit 8192", flush=True)
            result = retry_adapter.review(row, provenance)
            result["request_overrides"] = {"max_output_tokens": 8192,
                                           "reasoning_level": retry_config.reasoning_level}
            print(f"Figure {self.number} {row['edge_id']}: {result['state']}", flush=True)
            return result
        return self.cache_reader.review(row, provenance)


for number, previous in initial.items():
    failed = {r["edge_id"] for r in previous["edges"] if not r["final"]["review_complete"]}
    if not failed:
        continue
    folder = base / f"figure_{number:02d}"
    archive = base / "attempts" / f"figure_{number:02d}_initial"
    shutil.copytree(folder, archive)
    report = write_artifacts(
        Path(f"outputs/paper_nine/paper9_20261013_original/figures/figure_{number:02d}_r01/graph.json"),
        folder, store, config, adapter=SelectiveRetryAdapter(number, failed))
    retry_log["figures"].append({"figure": number, "retried_edges": sorted(failed),
                                 "api_calls": report["metrics"]["C_hybrid"]["additional_api_calls"],
                                 "all_reviews_complete": all(r["final"]["review_complete"] for r in report["edges"])})
    (base / "retry_summary.json").write_text(json.dumps(retry_log, indent=2) + "\n", encoding="utf-8")
    print(f"Figure {number}: completed {sum(r['final']['review_complete'] for r in report['edges'])}/{len(report['edges'])}", flush=True)

print(f"Additional retry API calls: {retry_adapter.calls}", flush=True)
