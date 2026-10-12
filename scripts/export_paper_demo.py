"""Export saved paper scenarios as PNG/SVG/interactive HTML, without API calls."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html import escape
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crystalball.demo_graph import render_demo_graph
from crystalball.postprocess import parse_llm_json, save_graph_json

SCENARIOS = {
    "C0": ("Không có CVE context", "Figure 6", "No-context baseline"),
    "C1": ("CVE context do Contriever truy hồi", "Algorithm 2; bổ sung", "Retrieved CVE context"),
    "C2": ("Đủ tám mô tả CVE — Appendix A", "Figures 7, 9, 10", "Appendix A CVE context"),
    "T0": ("PostgreSQL / container — Appendix B", "Figures 11, 12, 13", "Appendix B threat report"),
    "T1": ("SolarWinds đầy đủ — Appendix C.1", "Figure 2", "Full SolarWinds report"),
    "T2": ("SolarWinds evasion — Appendix C.2", "Figure 8", "SolarWinds evasion report"),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path,
                        default=ROOT / "outputs/experiments/20260927_full_reproduction")
    parser.add_argument("--output", type=Path, help="New destination directory; must not already exist.")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--include-rag", action="store_true", help="Also export C1 retrieval outputs.")
    args = parser.parse_args()
    run = args.run_dir.resolve()
    metric_path = run / "offline_reevaluation/metrics.json"
    if not metric_path.is_file():
        parser.error(f"Missing corrected metrics: {metric_path}. Historical artifacts are local, outside Git.")
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    metrics = json.loads(metric_path.read_text(encoding="utf-8"))["results"]
    conditions = ["C0", *(["C1"] if args.include_rag else []), "C2", "T0", "T1", "T2"]
    selected = []
    # Validate all inputs before creating any output. No API client is imported.
    for condition in conditions:
        for backend in ("gemini", "openrouter"):
            candidates = [row for row in metrics if row.get("stage") == "graph"
                          and row.get("condition_id") == condition and row.get("backend") == backend
                          and row.get("repeat_id") == args.repeat]
            if len(candidates) != 1:
                parser.error(f"Expected one saved result for {condition}/{backend}/r{args.repeat:02d}")
            row = candidates[0]
            raw_path = run / row["raw_response_file"]
            prompt_path = run / "prompts" / f"{condition}.txt"
            journal_path = run / "calls" / f"{row['call_id']}.json"
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            response_hash = sha256(raw_path)
            prompt_hash = sha256(prompt_path)
            if response_hash != journal.get("response_sha256"):
                parser.error(f"Saved response hash mismatch: {row['call_id']}")
            if prompt_hash != row.get("prompt_sha256"):
                parser.error(f"Saved prompt hash mismatch: {row['call_id']}")
            graph = parse_llm_json(raw_path.read_text(encoding="utf-8"))
            if (len(graph.nodes), len(graph.edges)) != (row.get("node_count"), row.get("edge_count")):
                parser.error(f"Current parser differs from corrected metrics: {row['call_id']}")
            selected.append((row, graph, raw_path, prompt_path, response_hash, prompt_hash))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = (args.output or ROOT / "outputs/paper_demo" / stamp).resolve()
    if output.exists():
        parser.error(f"Destination exists; choose a new directory: {output}")
    output.mkdir(parents=True)
    entries = []
    for row, graph, raw_path, prompt_path, response_hash, prompt_hash in selected:
        condition, backend = row["condition_id"], row["backend"]
        relative_folder = f"{condition}_{backend}_r{args.repeat:02d}"
        folder = output / relative_folder
        folder.mkdir()
        warnings = []
        if graph.truncated:
            warnings.append("JSON bị cắt đã được repair; graph có thể thiếu nội dung.")
        if row.get("finish_reason_indicates_truncation"):
            warnings.append("Provider của request gốc báo chạm output cap.")
        if not row.get("schema_valid"):
            warnings.append("Không đạt schema đầy đủ của repo; xem yêu cầu trong prompt tương ứng.")
        entry = {
            "source_run": run.name, "condition_id": condition, "backend": backend,
            "model": row["model"], "repeat_id": args.repeat, "source_call_id": row["call_id"],
            "related_paper_figures": SCENARIOS[condition][1],
            "source_response": str(raw_path), "source_prompt": str(prompt_path),
            "response_sha256": response_hash, "prompt_sha256": prompt_hash,
            "nodes": len(graph.nodes), "edges": len(graph.edges),
            "parse_mode": row.get("parse_mode"), "graph_container": graph.container,
            "repaired": graph.truncated, "provider_finish_reason": row.get("provider_finish_reason"),
            "finish_reason_indicates_truncation": row.get("finish_reason_indicates_truncation"),
            "extracted_graph_schema_valid": row.get("schema_valid"),
            "warnings": warnings, "api_calls_during_export": 0, "folder": relative_folder,
            "semantic_validation": "Not established by export, schema, or figure similarity.",
        }
        save_graph_json(graph, folder / "graph.json")
        (folder / "response.txt").write_bytes(raw_path.read_bytes())
        (folder / "prompt.txt").write_bytes(prompt_path.read_bytes())
        (folder / "metadata.json").write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding="utf-8")
        title = f"{condition} | {SCENARIOS[condition][2]} | {backend} r{args.repeat:02d}"
        render_demo_graph(graph, folder, title=title,
                          subtitle="Saved model output; inspect prompt and review relationships")
        entries.append(entry)
        print(f"EXPORTED {condition}/{backend}: {len(graph.nodes)} nodes, {len(graph.edges)} edges", flush=True)

    sections = []
    for condition in conditions:
        title, figures, _ = SCENARIOS[condition]
        cards = []
        for item in (e for e in entries if e["condition_id"] == condition):
            prefix = item["folder"]
            notes = " ".join(item["warnings"]) or "Không có cảnh báo cấu trúc/truncation trong dữ liệu kiểm tra."
            cards.append(f'<article><h3>{escape(item["model"])}</h3>'
                         f'<p>{item["nodes"]} nút · {item["edges"]} cạnh · repeat {args.repeat}</p>'
                         f'<a href="{prefix}/graph.html"><img src="{prefix}/graph.png" alt="{escape(title)}"></a>'
                         f'<p class="note">{escape(notes)}</p><nav>'
                         f'<a href="{prefix}/graph.html">Graph tương tác</a>'
                         f'<a href="{prefix}/graph.svg">SVG</a><a href="{prefix}/graph.png">PNG</a>'
                         f'<a href="{prefix}/graph.json">JSON</a><a href="{prefix}/prompt.txt">Prompt</a>'
                         f'<a href="{prefix}/metadata.json">Metadata</a></nav></article>')
        sections.append(f'<section><h2>{condition}: {escape(title)}</h2>'
                        f'<p>Tương ứng kịch bản {escape(figures)} trong bài gốc; model thay thế được ghi bên dưới.</p>'
                        f'<div class="grid">{"".join(cards)}</div></section>')
    page = ('<!doctype html><html lang="vi"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>CrystalBall — bộ demo tái hiện</title><style>'
            'body{font:16px/1.6 Arial,sans-serif;background:#eef3f8;color:#173554;margin:0}'
            'header,main{max-width:1300px;margin:auto;padding:28px}'
            'h1{font-size:30px}h2{font-size:23px}h3{font-size:18px;margin-top:0}'
            '.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}'
            'article{background:white;border:1px solid #c5d6e4;border-radius:12px;padding:22px}'
            'img{width:100%;height:290px;object-fit:contain;border:1px solid #e1e8ef}'
            'nav{display:flex;gap:12px;flex-wrap:wrap}a{color:#176b91}.note{font-size:14px}'
            'section{margin-bottom:38px}.banner{background:#fff0d2;padding:16px;border-radius:10px}'
            '@media(max-width:800px){.grid{grid-template-columns:1fr}}</style>'
            f'<header><h1>CrystalBall — các graph tái hiện từ response đã lưu</h1>'
            f'<p>Run {escape(run.name)} · repeat {args.repeat} · {len(entries)} graph · xuất offline, 0 request API</p>'
            '<p class="banner">Dùng cùng repeat đã chỉ định cho mọi kịch bản, không chọn graph đẹp nhất. '
            'Đây là output của hai model thay thế. PNG/SVG/HTML được vẽ lại bằng parser hiện tại; '
            'cấu trúc hợp lệ chưa chứng minh đúng ngữ nghĩa. Xem cảnh báo của từng graph.</p></header>'
            f'<main>{"".join(sections)}</main></html>')
    (output / "index.html").write_text(page, encoding="utf-8")
    manifest = {"source_run": str(run), "repeat_id": args.repeat, "api_calls": 0,
                "selection_rule": "Same specified repeat for every selected scenario/backend; no semantic ranking.",
                "source_metrics": str(metric_path), "entries": entries}
    (output / "export_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Gallery: {output / 'index.html'}")


if __name__ == "__main__":
    main()
