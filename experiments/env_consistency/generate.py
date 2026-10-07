"""Generate E1 responses with an OpenAI-compatible API under a hard request cap.

The API key is read only from the OPENAI_API_KEY environment variable (never from an
argument or file). Responses are saved where `run.py score` expects them, with a
sidecar `.meta.json` per response (model actually served, finish reason, token usage).

    OPENAI_API_KEY=... python -m experiments.env_consistency.generate \\
        --run-id e1_pilot --label gpt-4o-mini --model gpt-4o-mini \\
        --out-dir outputs/experiments/e1_pilot/responses --max-requests 12
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import run as e1_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--label", required=True, help="model label = subdirectory name")
    parser.add_argument("--model", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--max-requests", type=int, required=True, help="hard cap on API calls")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--max-output-tokens", type=int, default=4096)
    parser.add_argument("--envs", nargs="*")
    parser.add_argument("--variants", nargs="*")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--pause", type=float, default=1.0, help="seconds between requests")
    args = parser.parse_args(argv)

    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        print("Set OPENAI_API_KEY in the environment.", file=sys.stderr)
        return 1
    from openai import OpenAI

    client = OpenAI(api_key=key, base_url=args.base_url, max_retries=0)

    cases = json.loads((e1_run.run_dir(args.run_id) / "cases.json").read_text(encoding="utf-8"))
    cases = [
        c
        for c in cases
        if (not args.envs or c["env_id"] in args.envs)
        and (not args.variants or c["variant"] in args.variants)
    ]
    jobs = [(c, r) for r in range(1, args.repeats + 1) for c in cases]
    out_dir = Path(args.out_dir) / args.label
    out_dir.mkdir(parents=True, exist_ok=True)

    sent = 0
    for case, repeat in jobs:
        target = out_dir / f"{case['case_id']}.r{repeat:02d}.txt"
        if target.exists():
            continue
        if sent >= args.max_requests:
            print(f"Request cap ({args.max_requests}) reached; stopping.")
            break
        prompt = (e1_run.run_dir(args.run_id) / "prompts" / f"{case['case_id']}.txt").read_text(
            encoding="utf-8"
        )
        sent += 1
        try:
            response = client.chat.completions.create(
                model=args.model,
                messages=[{"role": "user", "content": prompt}],
                max_completion_tokens=args.max_output_tokens,
            )
        except Exception as exc:  # stop on any API error rather than burning the cap
            print(f"API error on {case['case_id']} r{repeat:02d}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        choice = response.choices[0]
        target.write_text(choice.message.content or "", encoding="utf-8")
        target.with_suffix(".meta.json").write_text(
            json.dumps(
                {
                    "requested_model": args.model,
                    "served_model": response.model,
                    "finish_reason": choice.finish_reason,
                    "usage": response.usage.model_dump() if response.usage else None,
                    "created": response.created,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"ok {case['case_id']} r{repeat:02d} finish={choice.finish_reason}")
        time.sleep(args.pause)
    print(f"Sent {sent} request(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
