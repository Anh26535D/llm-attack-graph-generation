"""Nine-figure reproduction and online demo; one request per selected figure/repeat."""

import argparse
from dataclasses import replace
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import shutil
import networkx as nx

from .config import Settings
from .experiment import graph_schema_metrics
from .llm.factory import get_llm_client
from .paper_cases import BACKENDS, BY_FIGURE, CASES, digest, load_prompt, prepare_references
from .paper_graph import render_paper_graph, t0_overview
from .postprocess import parse_llm_json, save_graph_json


ROOT = Path(__file__).resolve().parents[2]
PRESENTATION = """Use the original task and source below. Return JSON nodes and edges.
Every node must have id and a concise, meaningful label. Every edge must have
from, to and a concise, meaningful label explaining the relationship.
Use short names (roughly 2-8 words); put explanatory details in description,
not label. Represent the main entities, techniques and their relationships,
not a chronological node for every internal analysis or implementation step.
For campaign reports, branch from the main malware/campaign entities to their
capabilities, operational techniques, impacted entities and detection/mitigation.
Do not serialize all capabilities into a single universal victim timeline.
Keep the overview granularity of an attack graph: combine repeated descriptions
of the same event, preserve distinct attack branches, and invent no facts or links.
Do not expand into implementation microsteps or add a generic node for every paragraph.
ORIGINAL TASK AND SOURCE:
"""


def write_json(path, record):
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")


def safe_error(exc):
    message = str(exc)
    for name, value in os.environ.items():
        if "API_KEY" in name and value:
            message = message.replace(value, "[REDACTED]")
    return message


def collect_gallery(destination: Path, sources: dict[int, Path]):
    """An explicitly selected presentation set, with original run provenance."""
    if set(sources) != set(BY_FIGURE):
        raise ValueError('The presentation collection must contain all nine figures')
    if destination.exists():
        raise ValueError('Destination exists; do not overwrite a reviewed set')
    validated = {}
    for figure, source in sources.items():
        meta = json.loads((source / 'metadata.json').read_text(encoding='utf-8'))
        if meta['figure'] != figure or not meta['status'].startswith('completed'):
            raise ValueError(f'Figure {figure} is not a completed matching result')
        for filename, field in [('prompt.txt', 'prompt_sha256'), ('response.txt', 'response_sha256')]:
            if digest((source / filename).read_bytes()) != meta[field]:
                raise ValueError(f'Figure {figure} source hash mismatch')
        validated[figure] = meta
    for condition in ('C2', 'T0'):
        cases = [validated[case.figure] for case in CASES if case.condition == condition]
        if len({case['prompt_sha256'] for case in cases}) != 1:
            raise ValueError(f'{condition} three-model comparisons must have identical prompts')
    destination.mkdir(parents=True)
    first = next(iter(sources.values())).parents[1]
    if (first / 'references').exists():
        shutil.copytree(first / 'references', destination / 'references')
    manifest = {'scope': 'selected_paper_gallery', 'prompt_style': 'per_figure_see_metadata',
                'max_output_tokens': 16384, 'entries': []}
    for figure, source in sorted(sources.items()):
        directory = f'figures/figure_{figure:02d}_r01'
        folder = destination / directory
        shutil.copytree(source, folder)
        meta = validated[figure]
        meta['selected_from'] = str(source.resolve())
        write_json(folder / 'metadata.json', meta)
        finish_graph(folder, meta, seed=42)
        manifest['entries'].append({'figure': figure, 'repeat': 1, 'directory': directory})
    write_json(destination / 'manifest.json', manifest)
    gallery(destination, manifest)
    return manifest


def gallery(output: Path, manifest: dict):
    cards = []
    for entry in manifest["entries"]:
        folder = output / entry["directory"]
        meta = json.loads((folder / "metadata.json").read_text(encoding="utf-8"))
        case = BY_FIGURE[entry["figure"]]
        ref = output / "references" / f"figure_{case.figure:02d}.png"
        left = f'<img src="../../references/{ref.name}" alt="Original Figure {case.figure}">' if ref.exists() else '<p>Chưa có ảnh nguồn PDF.</p>'
        preferred = 'overview/' if meta.get('preferred_view') == 'overview' else ''
        right = '<img src="'+preferred+'graph.svg" alt="Reproduced graph">' if (folder / "graph.svg").exists() else '<p>Chưa có graph: '+escape(meta["status"])+'.</p>'
        detail = f"Figure {case.figure} / {case.condition} / {meta['model']} / repeat {entry['repeat']}"
        warnings = " · ".join(meta.get("warnings", []))
        if preferred:
            warnings += f" · Ảnh tổng quan 4 nút/2 cạnh là bản gom nhóm để trình bày; output mô hình đầy đủ {meta['nodes']} nút/{meta['edges']} cạnh vẫn được giữ."
        compare = '<!doctype html><meta charset="utf-8"><title>'+escape(detail)+'</title>'+STYLE
        view_description = 'bản gom nhóm biên tập từ graph mô hình thay thế' if preferred else 'graph mô hình thay thế'
        compare += '<h1>'+escape(detail)+'</h1><p>Trái: bài gốc ('+escape(case.original_model)+'). Phải: '+view_description+'; cùng kịch bản, không phải cùng lần sinh.</p>'
        compare += '<p>'+escape(warnings)+'</p><div class="comparison"><section><h2>Bài gốc</h2>'+left+'</section><section><h2>Tái hiện</h2>'+right+'</section></div>'
        compare += '<p><a href="graph.html">Mở graph tương tác</a> · <a href="graph.png">PNG đầy đủ</a> · <a href="graph.svg">SVG</a> · <a href="prompt.txt">Prompt</a> · <a href="metadata.json">Metadata</a> · <a href="../../index.html">Toàn bộ</a></p>'
        if preferred:
            compare += '<p><a href="overview/graph.png">PNG tổng quan</a> · <a href="overview/graph.html">Tổng quan tương tác và ánh xạ về source_nodes/source_edges</a></p>'
        (folder / "comparison.html").write_text(compare, encoding="utf-8")
        caption = escape(f"Figure {case.figure} · {case.condition} · {meta['model']} · r{entry['repeat']:02d}")
        image = f'<img src="{entry["directory"]}/{preferred}graph.svg" alt="Figure {case.figure}">' if (folder / "graph.svg").exists() else ""
        cards.append(f'<article><h2>{caption}</h2><p>{escape(meta["status"])} · {meta.get("nodes", "—")} nodes / {meta.get("edges", "—")} edges</p>{image}<p>{escape(warnings)}</p><a href="{entry["directory"]}/comparison.html">So sánh riêng với hình gốc</a> · <a href="{entry["directory"]}/graph.html">Demo tương tác</a></article>')
    page = '<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Nine paper figures</title>'+STYLE
    page += '<h1>Chín attack graph theo bài báo</h1><p>Gemini / GPT-5.6 Luna / DeepSeek là các mô hình thay thế. Graph đầy đủ giữ nguyên node/edge từ response; ảnh gom nhóm được ghi rõ và có ánh xạ về graph đầy đủ. Nhãn, bố cục và nguồn gốc được lưu riêng.</p>'
    page += '<p>Chọn “So sánh riêng” để xem từng cặp ảnh; nhấn SVG hoặc graph tương tác để đọc tên nút/cạnh.</p><div class="cards">'+"".join(cards)+'</div></html>'
    (output / "index.html").write_text(page, encoding="utf-8")


STYLE = '<style>body{font:16px Arial;background:#f4f7fb;color:#19334b;margin:24px}a{color:#22578c}h1{font-size:25px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(450px,1fr));gap:20px}article,section{background:white;padding:20px;border:1px solid #ccd7e5;border-radius:9px}h2{font-size:18px}img{width:100%;height:auto}.comparison{display:grid;grid-template-columns:1fr 1fr;gap:20px}.comparison img{min-height:300px;object-fit:contain}@media(max-width:850px){.comparison,.cards{grid-template-columns:1fr}}</style>'


def finish_graph(folder: Path, meta: dict, *, seed: int):
    raw = (folder / "response.txt").read_text(encoding="utf-8")
    graph = parse_llm_json(raw)
    save_graph_json(graph, folder / "graph.json")
    warnings = []
    if graph.truncated:
        warnings.append("JSON đã repair; graph có thể thiếu")
    if any(word in json.dumps(meta.get("provider", {})).upper() for word in ("MAX_TOKENS", '"LENGTH"')):
        warnings.append("Response chạm token cap")
    schema = graph_schema_metrics(graph.nodes, graph.edges)
    if not schema["schema_valid"]:
        warnings.append("Khác schema đầy đủ của repo; xem metadata")
    aspect = 1.78
    references = folder.parents[1] / "references/references.json"
    if references.exists():
        width, height = json.loads(references.read_text(encoding="utf-8"))["images"][str(meta["figure"])]["size"]
        aspect = width / height
    view = render_paper_graph(graph, folder, title=f"Figure {meta['figure']} — {meta['condition']}",
                              subtitle=f"{meta['model']} / r{meta['repeat']:02d}", seed=seed, aspect=aspect)
    if view["label_collisions"]:
        warnings.append(f"Còn {view['label_collisions']} nhãn chồng; đổi seed hoặc bố cục")
    if "(unlabelled in response)" in view["edge_labels"]:
        warnings.append("Response có cạnh chưa đặt tên")
    net = nx.DiGraph()
    net.add_nodes_from(str(node["id"]) for node in graph.nodes)
    net.add_edges_from((str(edge.get("from", edge.get("source"))), str(edge.get("to", edge.get("target")))) for edge in graph.edges)
    meta.update(status="completed_with_warnings" if warnings else "completed", nodes=len(graph.nodes),
                edges=len(graph.edges), components=nx.number_weakly_connected_components(net),
                schema=schema, warnings=warnings, render=view, response_sha256=digest((folder / "response.txt").read_bytes()))
    if meta['figure'] == 13:
        overview = t0_overview(graph)
        if overview is not None:
            abstract, mapping = overview
            destination = folder / 'overview'
            destination.mkdir(exist_ok=True)
            save_graph_json(abstract, destination / 'graph.json')
            rendered = render_paper_graph(abstract, destination, title='Figure 13 — derived overview',
                                         subtitle='Editorial abstraction; full model graph is preserved', seed=seed, aspect=aspect)
            overview_html = destination / 'graph.html'
            overview_html.write_text(overview_html.read_text(encoding='utf-8').replace(
                'Đồ thị do LLM sinh từ nguồn bài báo',
                'Bản tổng quan gom nhóm từ graph LLM; graph đầy đủ được giữ riêng'), encoding='utf-8')
            write_json(destination / 'mapping.json', mapping)
            meta.update(preferred_view='overview', overview={'mapping': mapping, 'render': rendered})
    meta.pop("error", None)
    meta.pop("error_type", None)
    write_json(folder / "metadata.json", meta)


def _history(folder, meta, case, run):
    prefix = f"graph.{meta['backend']}.{case.condition}.r{meta['repeat']:02d}.a01"
    response = run / "raw_responses" / f"{prefix}.txt"
    journal = run / "calls" / f"{prefix}.json"
    prompt = run / "prompts" / f"{case.condition}.txt"
    if not response.is_file() or not journal.is_file():
        return False
    record = json.loads(journal.read_text(encoding="utf-8"))
    if digest(response.read_bytes()) != record["response_sha256"]:
        raise ValueError(f"Historical response hash mismatch: {prefix}")
    if record["model"] != meta["model"]:
        raise ValueError("Historical response used a different model")
    if prompt.read_text(encoding="utf-8") != (folder / "prompt.txt").read_text(encoding="utf-8"):
        raise ValueError("Historical and current prompts differ; use a separate run.")
    shutil.copyfile(response, folder / "response.txt")
    meta.update(status="response_saved", origin="historical_import", historical_call=str(journal),
                reasoning="low (historical run)", provider=record.get("response_metadata"), usage=record.get("usage"))
    return True


def main(argv=None, *, root: Path | None = None) -> int:
    root = root or ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--figures", type=int, nargs="+", choices=sorted(BY_FIGURE), default=sorted(BY_FIGURE))
    parser.add_argument("--backend", choices=BACKENDS, help="Override the backend of selected figures.")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--run-id")
    parser.add_argument("--resume", type=Path, help="Reuse this run; never regenerate saved responses.")
    parser.add_argument("--render-only", action="store_true")
    parser.add_argument("--retry-failed", action="store_true", help="Explicitly resend failed requests that have no response.")
    parser.add_argument("--check", action="store_true", help="Prepare nine prompts/configs without LLM calls.")
    parser.add_argument("--replay", type=Path, help="Render a saved response for one selected figure.")
    parser.add_argument("--import-history", type=Path, help="Import matching frozen prompts/responses for available figures.")
    parser.add_argument("--reuse-run", type=Path, help="Reuse matching responses from a previous nine-figure run.")
    parser.add_argument("--prompt-style", choices=("paper", "presentation"), default="paper")
    parser.add_argument("--max-output-tokens", type=int, default=16384)
    parser.add_argument("--layout-seed", type=int, default=42)
    parser.add_argument("--reference-pdf", type=Path)
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args(argv)
    if args.repeat < 1 or args.max_output_tokens < 1:
        parser.error("repeat and max-output-tokens must be positive")
    if args.replay and (len(set(args.figures)) != 1 or args.repeat != 1):
        parser.error("--replay requires exactly one --figures value and --repeat 1")
    if args.render_only and not args.resume:
        parser.error("--render-only requires --resume")
    from dotenv import load_dotenv
    load_dotenv(root / ".env", override=True)
    settings = Settings()
    if args.resume:
        output = args.resume.resolve()
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        if manifest['scope'] != 'nine_paper_figures' and not args.render_only:
            parser.error('A selected gallery can only be rendered; generate in a new experiment run')
        args.max_output_tokens = manifest["max_output_tokens"]
        args.prompt_style = manifest["prompt_style"]
    else:
        run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        if Path(run_id).name != run_id or run_id in (".", ".."):
            parser.error("--run-id must be a single directory name")
        output = root / "outputs/paper_nine" / run_id
        if output.exists():
            parser.error("Run exists; use --resume or another --run-id")
        # Freeze sources before preparing any request.
        prepared = [(BY_FIGURE[number], load_prompt(root, BY_FIGURE[number])) for number in sorted(set(args.figures))]
        output.mkdir(parents=True)
        manifest = {"scope": "nine_paper_figures", "prompt_style": args.prompt_style,
                    "max_output_tokens": args.max_output_tokens, "reasoning": "high", "entries": []}
        for repeat in range(1, args.repeat+1):
            for case, original_prompt in prepared:
                backend = args.backend or case.backend
                directory = f"figures/figure_{case.figure:02d}_r{repeat:02d}"
                folder = output / directory
                folder.mkdir(parents=True)
                prompt = (PRESENTATION if args.prompt_style == "presentation" else "") + original_prompt
                (folder / "prompt.txt").write_bytes(prompt.encode("utf-8"))
                model = getattr(settings, {"gemini": "gemini_model", "openrouter": "openrouter_model", "openrouter_v2": "openrouter_model_v2"}[backend])
                meta = {"figure": case.figure, "condition": case.condition, "backend": backend, "model": model,
                        "original_model": case.original_model, "repeat": repeat, "status": "prepared",
                        "origin": "online", "prompt_style": args.prompt_style,
                        "prompt_sha256": digest(prompt.encode("utf-8")), "reasoning": "high", "max_output_tokens": args.max_output_tokens}
                write_json(folder / "metadata.json", meta)
                manifest["entries"].append({"figure": case.figure, "repeat": repeat, "directory": directory})
        write_json(output / "manifest.json", manifest)
    print(f"Run: {output}\nPlan: {len(manifest['entries'])} figure/repeat entries; no C1/X0/section 5.4", flush=True)
    if not (output / "references/references.json").exists():
        prepare_references(root, output / "references", args.reference_pdf)
    clients = {}
    failed_backends = set()
    failures = 0
    for entry in manifest["entries"]:
        folder = output / entry["directory"]
        meta = json.loads((folder / "metadata.json").read_text(encoding="utf-8"))
        case = BY_FIGURE[entry["figure"]]
        prompt = (folder / "prompt.txt").read_bytes()
        if digest(prompt) != meta["prompt_sha256"]:
            raise ValueError("Frozen prompt hash mismatch; no request sent")
        try:
            if args.replay:
                shutil.copyfile(args.replay.resolve(), folder / "response.txt")
                meta.update(origin="offline_replay", replay_source=str(args.replay.resolve()), status="response_saved", reasoning="see original response metadata")
            if args.import_history and not (folder / "response.txt").exists():
                _history(folder, meta, case, args.import_history.resolve())
            if args.reuse_run and not (folder / "response.txt").exists():
                previous = args.reuse_run.resolve() / entry["directory"]
                if (previous / "response.txt").exists():
                    previous_meta = json.loads((previous / "metadata.json").read_text(encoding="utf-8"))
                    for field in ("prompt_sha256", "backend", "model", "reasoning", "max_output_tokens"):
                        if previous_meta[field] != meta[field]:
                            raise ValueError(f"Cannot reuse a different {field}; use a separate run")
                    if digest((previous / "response.txt").read_bytes()) != previous_meta["response_sha256"]:
                        raise ValueError("Previous response hash mismatch")
                    shutil.copyfile(previous / "response.txt", folder / "response.txt")
                    meta.update(origin="reused_run", reused_source=str(previous),
                                usage=previous_meta.get("usage"), provider=previous_meta.get("provider"), status="response_saved")
            if (folder / "response.txt").exists():
                if meta.get("response_sha256") and digest((folder / "response.txt").read_bytes()) != meta["response_sha256"]:
                    raise ValueError("Saved response hash mismatch; not calling API")
                finish_graph(folder, meta, seed=args.layout_seed)
                print(f"Figure {case.figure}: rendered saved response ({meta['nodes']} nodes / {meta['edges']} edges)", flush=True)
                continue
            if args.render_only:
                print(f"Figure {case.figure}: response missing; not calling API", flush=True)
                failures += 1
                continue
            backend = meta["backend"]
            if backend in failed_backends:
                failures += 1
                continue
            if meta["status"] in ("calling_api", "failed") and not args.retry_failed and not args.check:
                raise RuntimeError("Unfinished/failed request; inspect metadata, then explicitly use --retry-failed if appropriate")
            if backend not in clients:
                chosen = replace(settings, llm_backend=backend, llm_max_output_tokens=args.max_output_tokens, llm_reasoning_level="high")
                client = get_llm_client(chosen)
                if client.model != meta["model"]:
                    raise ValueError("Model changed since preparation; create a new run")
                clients[backend] = client
            client = clients[backend]
            if args.check:
                print(f"CHECK OK Figure {case.figure}: {case.condition} / {client.model}", flush=True)
                continue
            meta["status"] = "calling_api"
            meta["attempted_at"] = datetime.now(timezone.utc).isoformat()
            write_json(folder / "metadata.json", meta)
            print(f"Figure {case.figure}: calling {client.model} (1 API request)", flush=True)
            raw = client.complete(prompt.decode("utf-8"), max_output_tokens=args.max_output_tokens, reasoning_level="high")
            (folder / "response.txt").write_bytes(raw.encode("utf-8"))
            meta.update(status="response_saved", usage=client.last_usage, provider=client.last_response_metadata,
                        finished_at=datetime.now(timezone.utc).isoformat())
            write_json(folder / "metadata.json", meta)
            finish_graph(folder, meta, seed=args.layout_seed)
            print(f"Figure {case.figure}: {meta['nodes']} nodes / {meta['edges']} edges", flush=True)
        except Exception as exc:
            failures += 1
            if not (folder / "response.txt").exists():
                failed_backends.add(meta["backend"])
            meta.update(status="failed", error_type=type(exc).__name__, error=safe_error(exc))
            meta.setdefault("errors", []).append({"at": datetime.now(timezone.utc).isoformat(), "error_type": type(exc).__name__, "error": safe_error(exc)})
            write_json(folder / "metadata.json", meta)
            print(f"Figure {case.figure} failed: {safe_error(exc)}", flush=True)
        finally:
            gallery(output, manifest)
    gallery(output, manifest)
    states = [json.loads((output / entry["directory"] / "metadata.json").read_text(encoding="utf-8"))["status"] for entry in manifest["entries"]]
    manifest["summary"] = {"entries": len(states), "completed": sum(state.startswith("completed") for state in states),
                           "failed": states.count("failed"), "prepared": states.count("prepared")}
    write_json(output / "manifest.json", manifest)
    print(f"Gallery: {output / 'index.html'}", flush=True)
    if not args.no_open and os.name == "nt":
        os.startfile(output / "index.html")
    return 1 if failures else 0
