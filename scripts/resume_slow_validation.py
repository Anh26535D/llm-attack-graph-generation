"""Resume frozen reviews with at most one new request per paced step."""
from dataclasses import replace
import argparse
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dotenv import load_dotenv
from crystalball.config import PROJECT_ROOT, Settings
from crystalball.validation import experiment_runner as pilot


class OneCallAdapter(pilot.JournaledReviewAdapter):
    def review(self, row, provenance):
        original = self.config
        try:
            self.config = replace(original, max_llm_calls=min(1, original.max_llm_calls))
            return super().review(row, provenance)
        finally:
            self.config = original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=60)
    parser.add_argument("--repeat-ids", type=int, nargs="+")
    args = parser.parse_args()
    if args.interval < 60:
        parser.error("Slow resume requires at least 60 seconds between new requests")
    load_dotenv(PROJECT_ROOT / ".env", override=True)
    settings = Settings()
    out = args.out.resolve()
    plan, _ = pilot.verify(out, settings)
    numbers = args.repeat_ids or list(range(1, plan["repeats"] + 1))
    next_allowed = 0
    for number in numbers:
        target = out / "runs" / f"r{number:02d}" / "validation"
        journal = target / "call_journal"

        def calls():
            return sum((pilot.read(f).get("result") or {}).get("api_calls", 0)
                       for f in journal.glob("*.json"))

        def factory(config):
            return OneCallAdapter(config, journal, settings, retry_output_tokens=16384)

        for _ in range(plan["review"]["max_calls_per_repeat"] + 1):
            result_file = target / "validation_results.json"
            if result_file.exists() and all(e["final"]["review_complete"] for e in pilot.read(result_file)["edges"]):
                break
            before = calls()
            delay = max(0, next_allowed - time.monotonic())
            if delay:
                print(f"Pacing: wait {delay:.0f}s", flush=True)
                time.sleep(delay)
            started = time.monotonic()
            pilot.validate(out, settings, repeat_ids=[number], retry_incomplete=True,
                           retry_output_tokens=16384, adapter_factory=factory)
            after = calls()
            if after == before:
                print(f"r{number:02d}: no further request within frozen budget/retry limits", flush=True)
                break
            if after - before != 1:
                raise RuntimeError("Pacing step unexpectedly made multiple requests")
            next_allowed = started + args.interval
    pilot.report(out)
    print("Slow resume complete within frozen call/retry limits", flush=True)


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    main()
