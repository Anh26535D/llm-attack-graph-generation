"""Score H1 from pairs.json (extract.py) and labels.json."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

GO_AT_LEAST = 0.30
STOP_BELOW = 0.10


def rates(counter: Counter) -> dict:
    total = sum(counter.values())
    if not total:
        return {"n": 0}
    return {
        "n": total,
        **{k: counter.get(k, 0) for k in ("supported", "conditional", "unsupported", "contradicted")},
        "not_supported_rate": (total - counter.get("supported", 0)) / total,
        "unsupported_or_contradicted_rate": (counter.get("unsupported", 0) + counter.get("contradicted", 0)) / total,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", required=True)
    parser.add_argument("--labels", required=True)
    args = parser.parse_args(argv)

    pairs = json.loads(Path(args.pairs).read_text(encoding="utf-8"))
    labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    missing = [k for k in pairs["pairs"] if k not in labels]
    if missing:
        print(f"Unlabeled pairs: {missing}", file=sys.stderr)
        return 1

    per_run: dict[str, Counter] = defaultdict(Counter)
    pooled: Counter = Counter()
    relaxed: Counter = Counter()  # borderline 'unsupported' pairs counted as 'conditional'
    for key, info in pairs["pairs"].items():
        label = labels[key]["label"]
        softened = "conditional" if labels[key].get("borderline") and label == "unsupported" else label
        for run in info["runs"]:
            per_run[run][label] += 1
            pooled[label] += 1
            relaxed[softened] += 1

    result = {
        "per_run": {run: rates(c) for run, c in sorted(per_run.items())},
        "pooled": rates(pooled),
        "sensitivity_borderline_as_conditional": rates(relaxed),
    }
    rate = result["pooled"]["not_supported_rate"]
    result["verdict_primary"] = (
        "GO" if rate >= GO_AT_LEAST else "STOP" if rate < STOP_BELOW else "INCONCLUSIVE"
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
