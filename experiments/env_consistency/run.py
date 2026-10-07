"""E1 command line: emit prompts, then score saved responses. No API calls here.

    # 1. write prompts + manifest (what the engine expects for every case)
    python -m experiments.env_consistency.run emit --run-id e1_pilot

    # 2. generate responses yourself (paste into a chat UI, or any API you choose) and
    #    save each as  <responses>/<model_label>/<case_id>.r01.txt  (r02 ... for repeats)

    # 3. score
    python -m experiments.env_consistency.run score --run-id e1_pilot --responses DIR
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

from crystalball.postprocess import GraphParseError, parse_llm_json

from .engine import enabled_cves
from .envs import INTERVENTIONS, build_env
from .prompts import VARIANTS, build_cases, load_cve_descriptions
from .scoring import score_counterfactual, score_graph

REPO = Path(__file__).resolve().parents[2]
OUT_ROOT = REPO / "outputs" / "experiments"

# Pre-registered decision thresholds (see README). Applied to pooled retention.
GO_AT_LEAST = 0.30
STOP_BELOW = 0.10


def run_dir(run_id: str) -> Path:
    return OUT_ROOT / run_id


def cmd_emit(args: argparse.Namespace) -> int:
    out = run_dir(args.run_id)
    if out.exists() and not args.force:
        print(f"{out} already exists; choose a new --run-id or pass --force.", file=sys.stderr)
        return 1
    descriptions = load_cve_descriptions()
    cases = build_cases(
        descriptions,
        env_ids=args.envs or None,
        variants=args.variants or None,
    )
    (out / "prompts").mkdir(parents=True, exist_ok=True)
    manifest = []
    for case in cases:
        (out / "prompts" / f"{case.case_id}.txt").write_text(case.prompt, encoding="utf-8")
        env = build_env(case.env_id, None if case.state == "base" else case.state)
        manifest.append(
            {
                "case_id": case.case_id,
                "env_id": case.env_id,
                "state": case.state,
                "variant": case.variant,
                "expected_enabled": sorted(enabled_cves(env)),
            }
        )
    (out / "cases.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(cases)} prompts and cases.json to {out}")
    return 0


def _load_graph(path: Path):
    try:
        return parse_llm_json(path.read_text(encoding="utf-8")), None
    except (GraphParseError, OSError) as exc:
        return None, str(exc)


def _mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def cmd_score(args: argparse.Namespace) -> int:
    out = run_dir(args.run_id)
    cases = json.loads((out / "cases.json").read_text(encoding="utf-8"))
    responses = Path(args.responses)
    models = sorted(p.name for p in responses.iterdir() if p.is_dir())
    if not models:
        print(f"No model subdirectories found in {responses}", file=sys.stderr)
        return 1

    rows: list[dict] = []
    for model in models:
        for case in cases:
            for path in sorted((responses / model).glob(f"{case['case_id']}.r*.txt")):
                repeat = path.name.rsplit(".r", 1)[1].removesuffix(".txt")
                graph, error = _load_graph(path)
                row = {
                    "model": model,
                    "case_id": case["case_id"],
                    "env_id": case["env_id"],
                    "state": case["state"],
                    "variant": case["variant"],
                    "repeat": repeat,
                    "parse_error": error or "",
                }
                if graph is not None:
                    env = build_env(case["env_id"], None if case["state"] == "base" else case["state"])
                    score = score_graph(graph, env)
                    row.update(
                        precision=score.precision,
                        recall=score.recall,
                        referenced=len(score.referenced),
                        edges_supported=score.edge_counts["supported"],
                        edges_redundant=score.edge_counts["redundant"],
                        edges_unsupported=score.edge_counts["unsupported"],
                        edges_unevaluable=score.edge_counts["unevaluable"],
                    )
                    if case["state"] != "base":
                        base_path = responses / model / f"{case['env_id']}.base.{case['variant']}.r{repeat}.txt"
                        if not base_path.exists():
                            candidates = sorted(
                                (responses / model).glob(f"{case['env_id']}.base.{case['variant']}.r*.txt")
                            )
                            base_path = candidates[0] if candidates else None
                        base_graph = _load_graph(base_path)[0] if base_path else None
                        if base_graph is not None:
                            cf = score_counterfactual(
                                base_graph,
                                graph,
                                build_env(case["env_id"]),
                                env,
                            )
                            row.update(
                                disabled=len(cf.disabled),
                                retention_rate=cf.retention_rate,
                                retention_rate_active=cf.retention_rate_active,
                                retention_rate_direct=cf.retention_rate_direct,
                                collateral_rate=cf.collateral_rate,
                                edges_touching_disabled=cf.edges_touching_disabled,
                            )
                rows.append(row)

    if not rows:
        print("No response files matched any case in cases.json.", file=sys.stderr)
        return 1

    fields = sorted({k for r in rows for k in r})
    with (out / "metrics.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    summary: dict = {"n_graphs": len(rows), "by_model_variant": {}}
    for model in models:
        for variant in VARIANTS:
            sel = [r for r in rows if r["model"] == model and r["variant"] == variant]
            if not sel:
                continue
            retention = [r["retention_rate"] for r in sel if r.get("retention_rate") is not None]
            retention_active = [
                r["retention_rate_active"] for r in sel if r.get("retention_rate_active") is not None
            ]
            base_prec = [
                r["precision"] for r in sel if r["state"] == "base" and r.get("precision") is not None
            ]
            mean_ret = _mean(retention)
            if mean_ret is None:
                verdict = "no intervention graphs scored"
            elif mean_ret >= GO_AT_LEAST:
                verdict = f"GO (H5 supported, indicative): mean retention >= {GO_AT_LEAST}"
            elif mean_ret < STOP_BELOW:
                verdict = f"STOP (H5 weak): mean retention < {STOP_BELOW}"
            else:
                verdict = "INCONCLUSIVE: between thresholds"
            summary["by_model_variant"][f"{model}/{variant}"] = {
                "n_graphs": len(sel),
                "n_parse_failures": sum(1 for r in sel if r["parse_error"]),
                "n_intervention_graphs": len(retention),
                "mean_retention_rate": mean_ret,
                "mean_retention_rate_active": _mean(retention_active),
                "mean_retention_rate_direct": _mean(
                    [r["retention_rate_direct"] for r in sel if r.get("retention_rate_direct") is not None]
                ),
                "mean_collateral_rate": _mean(
                    [r["collateral_rate"] for r in sel if r.get("collateral_rate") is not None]
                ),
                "mean_base_precision": _mean(base_prec),
                "verdict": verdict,
            }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"\nPer-graph rows: {out / 'metrics.csv'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    emit = sub.add_parser("emit", help="write prompts and the expected-state manifest")
    emit.add_argument("--run-id", required=True)
    emit.add_argument("--envs", nargs="*", choices=sorted(INTERVENTIONS))
    emit.add_argument("--variants", nargs="*", choices=VARIANTS)
    emit.add_argument("--force", action="store_true")
    emit.set_defaults(func=cmd_emit)

    score = sub.add_parser("score", help="score saved responses")
    score.add_argument("--run-id", required=True)
    score.add_argument("--responses", required=True, help="dir with one subdir per model label")
    score.set_defaults(func=cmd_score)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
