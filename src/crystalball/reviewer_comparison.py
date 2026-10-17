"""Read-only reviewer ablation over identical original graph/edge instances."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from html import escape
from itertools import combinations
import json
from pathlib import Path
import statistics

from .validation.evidence import digest
from .validation.experiment_runner import read, save
from .validation.metrics import token_usage
from .paper_cases import digest as byte_digest


def _fraction(a, b):
    return a / b if b else None


def compare(runs: list[Path], out: Path) -> dict:
    if len(runs) < 2:
        raise ValueError("At least two reviewer runs are required")
    runs = [p.resolve() for p in runs]
    plans = [read(p / "manifest.json") for p in runs]
    if len({p["review"]["model"] for p in plans}) != len(plans):
        raise ValueError("Reviewer models must be distinct")
    if len({(p["repeats"], p["prompt_sha256"], p["dataset_digest"]) for p in plans}) != 1:
        raise ValueError("Reviewer runs use different experiments or evidence")
    if any(p["code_sha256"] != plans[0]["code_sha256"] for p in plans):
        raise ValueError("Reviewer runs use different validator implementations")
    base = runs[0]
    records, model_rows, paired = [], [], []
    invariants = {"same_original_graph_bytes": True, "same_offline_baselines": True,
                  "same_review_prompt_bytes": True, "same_layout": True}
    for root, plan in zip(runs, plans):
        journal_results, reports_saved, unsettled = [], 0, 0
        raw_counts, final_counts, first_counts, valid_labels = Counter(), Counter(), Counter(), {}
        final_review_states, incomplete_issues = Counter(), Counter()
        first_passed = final_passed = candidates = changes = disagreements = 0
        latencies, costs, actual_models, actual_providers = [], [], Counter(), Counter()
        for number in range(1, plan["repeats"] + 1):
            folder = root / "runs" / f"r{number:02d}"
            reference = base / "runs" / f"r{number:02d}"
            graph_file = folder / "graph.json"
            if graph_file.read_bytes() != (reference / "graph.json").read_bytes():
                raise ValueError(f"Original graph differs in repeat {number}")
            result_file = folder / "validation/validation_results.json"
            if not result_file.exists():
                raise ValueError(f"Incomplete reviewer run: {root.name}/r{number:02d}")
            result = read(result_file)
            reports_saved += 1
            if result["graph_sha256"] != digest(read(graph_file)):
                raise ValueError("Report is not tied to its original graph")
            reference_report = read(reference / "validation/validation_results.json")
            if [r["offline"] for r in result["edges"]] != [r["offline"] for r in reference_report["edges"]]:
                raise ValueError(f"Offline baseline differs in repeat {number}")
            if read(folder / "validation/layout.json")["layout_sha256"] != read(reference / "validation/layout.json")["layout_sha256"]:
                raise ValueError("Reviewers use different layouts")
            journals = [read(p) for p in sorted((folder / "validation/call_journal").glob("*.json"))]
            journal_results.extend(j["result"] for j in journals if j.get("result") is not None)
            unsettled += sum(j.get("result") is None for j in journals)
            first = {}
            for j in journals:
                if j.get("result") is None or j["result"].get("api_calls"):
                    first.setdefault(j["edge_id"], j)
                r = j.get("result") or {}
                if r.get("api_calls"):
                    latencies.append(r.get("latency_seconds", 0))
                    metadata = r.get("response_metadata") or {}
                    if metadata.get("actual_model"):
                        actual_models[metadata["actual_model"]] += 1
                    if metadata.get("actual_provider"):
                        actual_providers[metadata["actual_provider"]] += 1
                    cost = (r.get("usage") or {}).get("cost")
                    if isinstance(cost, (int, float)):
                        costs.append(cost)
            first_passed += sum(bool(j.get("recheck_complete")) for j in first.values())
            first_counts.update((j.get("result") or {}).get("state", j["state"]) for j in first.values())
            for row in result["edges"]:
                edge_id = row["edge_id"]
                prompt = folder / "validation" / f"review_prompt_{edge_id}.txt"
                reference_prompt = reference / "validation" / f"review_prompt_{edge_id}.txt"
                if prompt.read_bytes() != reference_prompt.read_bytes():
                    raise ValueError(f"Semantic review prompt differs: r{number:02d}/{edge_id}")
                candidates += 1
                final_counts[row["final"]["status"]] += 1
                complete = bool(row["final"]["review_complete"])
                final_review_states[row["review"]["state"]] += 1
                if not complete:
                    incomplete_issues.update(row["final"]["issues"])
                final_passed += complete
                changes += row["offline"]["status"] != row["final"]["status"]
                disagreements += row["final"]["disagreement"]
                response = row["review"].get("response")
                suggested = response["suggested_status"] if response and complete else None
                if suggested:
                    raw_counts[suggested] += 1
                    valid_labels[(number, edge_id)] = suggested
                records.append({"model": plan["review"]["model"], "repeat": number, "edge_id": edge_id,
                                "graph_sha256": result["graph_sha256"], "prompt_sha256": byte_digest(prompt.read_bytes()),
                                "offline_status": row["offline"]["status"], "llm_suggested_status": suggested,
                                "review_complete": complete, "final_status": row["final"]["status"],
                                "final_issues": "; ".join(row["final"]["issues"])})
        row = {"model": plan["review"]["model"], "backend": plan["review"]["backend"],
               "repeats": plan["repeats"], "graph_reports": reports_saved,
               "candidate_edges": candidates, "first_pass_valid": first_passed,
               "first_pass_valid_rate": _fraction(first_passed, candidates), "first_pass_states": dict(first_counts),
               "final_review_valid": final_passed, "final_review_valid_rate": _fraction(final_passed, candidates),
               "final_review_states": dict(final_review_states), "incomplete_review_issues": dict(incomplete_issues),
               "llm_suggested_distribution": dict(raw_counts), "final_distribution": dict(final_counts),
               "llm_disagreements_with_offline": disagreements, "accepted_label_changes": changes,
               "review_api_calls": sum(r.get("api_calls", 0) for r in journal_results),
               "usage": token_usage(journal_results), "requests_with_unknown_outcome": unsettled,
               "mean_request_seconds": statistics.mean(latencies) if latencies else None,
               "provider_reported_cost": sum(costs) if costs else None,
               "provider_reported_cost_is_partial": bool(unsettled) or any(
                   r.get("api_calls") and not isinstance((r.get("usage") or {}).get("cost"), (int, float))
                   for r in journal_results),
               "provider_config": plan["review"].get("provider_config"),
               "observed_actual_models": dict(actual_models), "observed_actual_providers": dict(actual_providers),
               "primary_max_output_tokens": plan["review"]["max_output_tokens"],
               "reasoning": plan["review"]["reasoning"], "max_calls_per_repeat": plan["review"]["max_calls_per_repeat"],
               "accuracy": None, "accuracy_reason": "No independent gold labels", "run_directory": str(root)}
        model_rows.append(row)
        paired.append(valid_labels)
    agreements = []
    for a, b in combinations(range(len(model_rows)), 2):
        common = set(paired[a]) & set(paired[b])
        agree = sum(paired[a][k] == paired[b][k] for k in common)
        agreements.append({"model_a": model_rows[a]["model"], "model_b": model_rows[b]["model"],
                           "common_valid_reviews": len(common), "same_suggested_status": agree,
                           "agreement_rate": _fraction(agree, len(common)),
                           "scope": "LLM suggestions on common verified review outputs; not accuracy"})
    protocol = {(p["review"]["reasoning"], p["review"]["max_output_tokens"], tuple(p["review"]["statuses"])) for p in plans}
    out.mkdir(parents=True, exist_ok=True)
    result = {"input_invariants": invariants, "same_primary_review_protocol": len(protocol) == 1,
              "models": model_rows, "raw_suggestion_agreement": agreements,
              "limitations": ["No independent gold: no accuracy ranking", "Provider tokenizers and reasoning effort differ",
                              "First-pass results kept separate from technical retries; final labels include offline fallbacks"]}
    save(out / "comparison.json", result)
    if records:
        with (out / "edge_comparison.csv").open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)
    lines = ["# So sánh reviewer trên cùng graph C2", "",
             f"Cùng {plans[0]['repeats']} graph C2, cùng edge instances, evidence, offline baseline, prompt review và layout. Không gọi lại generation.", "",
             "| Model | First pass hợp lệ | Sau retry | LLM: supported / conditional / unsupported / contradicted / unknown | Nhãn cuối C/U | Đổi nhãn B→C | API calls |", "|---|---:|---:|---|---|---:|---:|"]
    for m in model_rows:
        raw = m["llm_suggested_distribution"]
        labels = " / ".join(str(raw.get(s, 0)) for s in ("supported", "conditional", "unsupported", "contradicted", "unknown"))
        final = m["final_distribution"]
        lines.append(f"| {m['model']} | {m['first_pass_valid']}/{m['candidate_edges']} | {m['final_review_valid']}/{m['candidate_edges']} | {labels} | {final.get('conditional',0)}/{final.get('unknown',0)} | {m['accepted_label_changes']} | {m['review_api_calls']} |")
    lines += ["", "First pass hợp lệ / sau retry đo parse, identity và quote recheck, không đo độ đúng ngữ nghĩa. Phân bố đề xuất chỉ tính review qua recheck; tổng có thể thấp hơn 58. Nhãn cuối gồm fallback offline khi review lỗi.",
              "", "Primary protocol giống nhau: " + str(result["same_primary_review_protocol"]) + ". Token cap/call budget từng model và usage thực tế nằm trong comparison.json. Tokenizers và lượng reasoning khác nhau nên cùng high không đồng nghĩa cùng compute.",
              "", "Call budget mỗi round: " + "; ".join(f"{m['model']}: {m['max_calls_per_repeat']}" for m in model_rows) + ". Kết quả sau retry chịu giới hạn ngân sách từng round; đọc riêng kết quả lần đầu.",
              "", "Chưa có gold độc lập: không kết luận model nào chính xác hơn. Xem edge_comparison.csv để đối chiếu từng cạnh."]
    (out / "COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    table = '<table><tr><th>Reviewer</th><th>Lần đầu hợp lệ</th><th>Sau retry</th><th>LLM đề xuất C/U/không hỗ trợ</th><th>Nhãn cuối C/U</th><th>Đổi nhãn</th></tr>'
    for m in model_rows:
        final = m["final_distribution"]
        raw = m["llm_suggested_distribution"]
        label = m["model"]
        if m["observed_actual_providers"]:
            label += " (" + ", ".join(m["observed_actual_providers"]) + ")"
        table += f'<tr><td>{escape(label)}</td><td>{m["first_pass_valid"]}/{m["candidate_edges"]}</td><td>{m["final_review_valid"]}/{m["candidate_edges"]}</td><td>{raw.get("conditional",0)}/{raw.get("unknown",0)}/{raw.get("unsupported",0)}</td><td>{final.get("conditional",0)}/{final.get("unknown",0)}</td><td>{m["accepted_label_changes"]}</td></tr>'
    page = '<!doctype html><html lang="vi"><meta charset="utf-8"><title>So sánh reviewer C2</title><style>body{font:16px Arial;margin:28px;color:#17334c}table{border-collapse:collapse}td,th{padding:12px;border:1px solid #ccd7df;text-align:left}</style><h1>Cùng graph C2, các reviewer khác nhau</h1><p>Cùng graph bytes, evidence và prompt review. Review hợp lệ đo schema, ID và trích dẫn; độ đúng của cạnh cần gold độc lập. C/U = có điều kiện / chưa đủ bằng chứng.</p>' + table + '</table><p><a href="COMPARISON.md">Báo cáo</a> · <a href="comparison.json">Số liệu</a> · <a href="edge_comparison.csv">So sánh từng cạnh</a></p></html>'
    (out / "index.html").write_text(page, encoding="utf-8")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, nargs="+", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    compare(args.runs, args.out.resolve())
    print(f"Saved comparison: {args.out.resolve()}")
    return 0
