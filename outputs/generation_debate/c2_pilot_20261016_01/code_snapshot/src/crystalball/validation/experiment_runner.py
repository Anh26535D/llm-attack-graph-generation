"""A fixed-prompt pilot: fresh repeats, immutable inputs, paired A/B/C reporting.

No LLM output is used as independent gold. Human labels can be added later
without repeating generation; candidate recall never measures missing edges.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import replace
from datetime import datetime, timezone
import json
from itertools import combinations
from pathlib import Path
import statistics
import shutil
import time

from ..config import PROJECT_ROOT, Settings
from ..experiment import graph_schema_metrics
from ..llm.base import to_metadata_value
from ..llm.factory import get_llm_client
from ..paper_cases import BY_FIGURE, digest as byte_digest, load_prompt
from ..postprocess import parse_llm_json
from .config import ValidatorConfig
from .evidence import EvidenceStore, digest
from .metrics import ablation_metrics, token_usage, validate_gold
from .pipeline import write_artifacts
from .review import ReviewAdapter, build_prompt, recheck

BACKENDS = ("gemini", "openrouter", "openrouter_v2", "openai")


def save(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def model_name(settings: Settings, backend: str) -> str:
    return getattr(settings, {"gemini": "gemini_model", "openrouter": "openrouter_model",
                             "openrouter_v2": "openrouter_model_v2", "openai": "openai_model"}[backend])


PROTOCOL = """# Thí nghiệm C2 lặp 10 lần: generation → offline → hybrid

Một prompt Appendix A cố định, cùng model và cấu hình trong mọi repeat. Không
ép graph phải có số node/cạnh cụ thể. Không chọn lại graph đẹp hoặc lớn nhất.
Mỗi response mới được lưu trước khi parse; lỗi, truncation và repair ghi riêng.
Không coi JSON parse được là graph đúng về ngữ nghĩa. SDK không tự retry.

A = toàn bộ graph sinh ra; B = kiểm tra offline; C = offline + selective LLM
review + deterministic recheck. B và C nhận cùng bằng chứng, không có quan sát
môi trường trong pilot này. Rule/policy hiện có được giữ nguyên. Original JSON
giữ nguyên byte; ảnh original/validated dùng cùng renderer, layout và edge IDs.
Cache chỉ trong repeat để resume không gọi lại các review đã thành công.
Mỗi review prompt và raw response đều được lưu để kiểm toán.

## Thang đo đã xác định trước khi gọi API

Chỉ số chính nếu có nhãn độc lập là candidate-edge precision:
100 × số cạnh đúng được giữ / số cạnh được giữ đã gán nhãn. Báo cáo kèm
candidate recall, F1, số cạnh đúng bị loại nhầm và số cạnh sai còn giữ.
Recall chỉ xét các cạnh đúng có trong graph gốc, không đo cạnh generator bỏ sót.
Policy retained chỉ bỏ unsupported/contradicted; strict chỉ giữ supported.
Unknown/conditional không được tự chuyển thành gold false.

Nhãn chuyên gia chưa có: các chỉ số precision/recall/F1 để null (N/A), không
lấy nhãn offline, LLM review hoặc nhãn AI tự tạo thay gold độc lập. Có thể gán
nhãn bằng annotation_blind.json, lưu riêng gold/rNN.json theo schema hiện có.
Không thay đổi annotation sau khi xem quyết định của validator.

Khi chưa có gold vẫn đo được: tỷ lệ parse/schema thành công, coverage 8 CVE,
số node/cạnh, conditional/unknown/negative rates, retained/strict fractions,
thay đổi nhãn B→C, review completion/disagreement, latency và usage thực tế.
Các tỷ lệ trạng thái là mô tả hành vi, không phải điểm accuracy.

Tổng hợp từng repeat và mean/min/max; đơn vị lặp là graph, không xem các cạnh
trong cùng graph là các quan sát độc lập. Pilot cùng một prompt không đại diện
cho mọi case/project, không xác nhận exploit thực tế. 10 repeat chưa dùng để
xếp hạng model. Chi phí tiền chỉ báo khi provider trả số liệu, không ước giá.
"""


def prepare(out: Path, *, repeats: int, settings: Settings, backend: str, review_backend: str,
            generation_reasoning: str, generation_tokens: int, review_reasoning: str,
            review_tokens: int, max_reviews: int) -> dict:
    if out.exists():
        raise ValueError("Run directory exists; use its generate/validate/report commands.")
    if not 1 <= repeats <= 100 or generation_tokens < 1 or review_tokens < 1 or max_reviews < 1:
        raise ValueError("Invalid repeat/token/review budget")
    prompt = load_prompt(PROJECT_ROOT, BY_FIGURE[7])
    store = EvidenceStore.load(PROJECT_ROOT / "data/cve_official/manifest.json")
    out.mkdir(parents=True)
    (out / "prompt.txt").write_bytes(prompt.encode("utf-8"))
    (out / "PROTOCOL.md").write_text(PROTOCOL.replace("lặp 10 lần", f"lặp {repeats} lần"), encoding="utf-8")
    save(out / "evidence_snapshot.json", {"dataset_digest": store.dataset_digest, "records": store.records})
    manifest = {"schema_version": 1, "scope": "fresh_c2_paired_validation", "created_at": timestamp(),
                "condition": "C2", "repeats": repeats, "prompt_sha256": byte_digest(prompt.encode("utf-8")),
                "dataset_digest": store.dataset_digest, "environment": "absent",
                "generation": {"backend": backend, "model": model_name(settings, backend),
                               "reasoning": generation_reasoning, "max_output_tokens": generation_tokens},
                "review": {"backend": review_backend, "model": model_name(settings, review_backend),
                           "reasoning": review_reasoning, "max_output_tokens": review_tokens,
                           "max_calls_per_repeat": max_reviews, "statuses": ["conditional", "unknown"]},
                "code_sha256": {str(p.relative_to(PROJECT_ROOT)): byte_digest(p.read_bytes())
                                for p in sorted((PROJECT_ROOT / "src/crystalball/validation").glob("*.py"))
                                if p.name != "experiment_runner.py"},
                "gold_state": "not_available", "automatic_retries": False,
                "scoring": "independent candidate precision when gold supplied; otherwise descriptive metrics only"}
    save(out / "manifest.json", manifest)
    return manifest


def verify(out: Path, settings: Settings) -> tuple[dict, EvidenceStore]:
    plan = read(out / "manifest.json")
    if byte_digest((out / "prompt.txt").read_bytes()) != plan["prompt_sha256"]:
        raise ValueError("Frozen prompt changed")
    store = EvidenceStore.load(PROJECT_ROOT / "data/cve_official/manifest.json")
    if store.dataset_digest != plan["dataset_digest"]:
        raise ValueError("Evidence dataset changed")
    if read(out / "evidence_snapshot.json")["records"] != store.records:
        raise ValueError("Evidence snapshot changed")
    if any(byte_digest((PROJECT_ROOT / p).read_bytes()) != expected for p, expected in plan["code_sha256"].items()):
        raise ValueError("Frozen validator implementation changed")
    for role in ("generation", "review"):
        if model_name(settings, plan[role]["backend"]) != plan[role]["model"]:
            raise ValueError(f"Configured {role} model differs from frozen experiment model")
    if "provider_config" in plan["review"]:
        if json.loads(settings.openrouter_provider_config_v2) != plan["review"]["provider_config"]:
            raise ValueError("Configured provider differs from frozen review profile")
    return plan, store


def fork_review(source: Path, out: Path, settings: Settings, config: ValidatorConfig) -> dict:
    """Reuse immutable generations, freezing a new review configuration separately."""
    if not config.review_enabled:
        raise ValueError("Enable hybrid LLM review in the environment before forking this live review")
    old, _ = verify(source, settings)
    gen = old["generation"]
    plan = prepare(out, repeats=old["repeats"], settings=settings, backend=gen["backend"],
                   review_backend=config.llm_backend, generation_reasoning=gen["reasoning"],
                   generation_tokens=gen["max_output_tokens"], review_reasoning=config.reasoning_level,
                   review_tokens=config.max_output_tokens, max_reviews=config.max_llm_calls)
    plan["generation_reused_from"] = str(source.resolve())
    plan["review"].update(cache_enabled=config.cache_enabled, cache_root=str(config.cache_dir.resolve()),
                           statuses=list(config.review_statuses), enabled=config.review_enabled)
    if config.llm_backend == "openrouter_v2":
        plan["review"]["provider_config"] = json.loads(settings.openrouter_provider_config_v2)
    save(out / "manifest.json", plan)
    for number in range(1, old["repeats"] + 1):
        src, dst = source / "runs" / f"r{number:02d}", out / "runs" / f"r{number:02d}"
        meta = read(src / "generation.json")
        if meta.get("state") != "parsed" or byte_digest((src / "graph.json").read_bytes()) != meta["graph_file_sha256"]:
            raise ValueError("Source generation is incomplete or modified")
        dst.mkdir(parents=True)
        for name in ("graph.json", "response.txt", "annotation_blind.json"):
            shutil.copyfile(src / name, dst / name)
        shutil.copyfile(src / "generation.json", dst / "generation_source.json")
        meta.update(attempts=[], origin="reused_frozen_generation", source_directory=str(src.resolve()))
        save(dst / "generation.json", meta)
    with (out / "PROTOCOL.md").open("a", encoding="utf-8") as handle:
        handle.write(f"\n## Lượt review mới theo .env\n\nTái sử dụng nguyên byte {old['repeats']} graph từ `{source}`; không gọi lại generation. "
                     f"Reviewer {plan['review']['model']}, reasoning {config.reasoning_level}, output cap {config.max_output_tokens}, "
                     f"tối đa {config.max_llm_calls} calls/repeat. Nhãn review cũ không được nhập vào lượt mới. "
                     "API usage của lượt mới tách khỏi chi phí generation/lượt review trước. Không có dữ liệu môi trường host/version/reachability mới.\n")
    return plan


class JournaledReviewAdapter(ReviewAdapter):
    """Persist every individual request/result, even if the graph run is interrupted."""
    def __init__(self, config, journal: Path, settings: Settings, retry_output_tokens: int | None = None):
        super().__init__(config, settings=settings)
        self.journal = journal
        self.retry_output_tokens = retry_output_tokens
        self.api_error_seen = False

    def _model_identity(self):
        identity = super()._model_identity()
        # The second OpenRouter profile shares the first profile's client class.
        # Keep cache identity stable before and after lazy client initialization.
        if self.config.llm_backend == "openrouter_v2":
            identity["client_name"] = "openrouter_v2"
        return identity

    def _probe_cache(self, row, provenance):
        probe = JournaledReviewAdapter(replace(self.config, max_llm_calls=0), self.journal, self.settings)
        probe.client = self.client
        result = ReviewAdapter.review(probe, row, provenance)
        if result["state"] != "cache_hit" and self.config.llm_backend == "openrouter_v2":
            # Earlier requests used the shared client's name in cache identity.
            client = self.client or self.factory(self._settings())
            legacy = ReviewAdapter(replace(self.config, max_llm_calls=0), client=client, settings=self.settings)
            legacy_result = legacy.review(row, provenance)
            if legacy_result["state"] == "cache_hit":
                result = legacy_result
                result["cache_identity_profile"] = "legacy_shared_openrouter_client"
        return result

    def review(self, row: dict, provenance: dict) -> dict:
        self.journal.mkdir(parents=True, exist_ok=True)
        previous = [read(p) for p in self.journal.glob(f"{row['edge_id']}_*.json")]
        request_attempts = sum(j.get("result") is None or bool(j["result"].get("api_calls")) for j in previous)
        attempt = len(previous) + 1
        destination = self.journal / f"{row['edge_id']}_{attempt:02d}.json"
        entry = {"edge_id": row["edge_id"], "started_at": timestamp(), "state": "started",
                 "result": None, "api_calls": None}
        save(destination, entry)
        destination.with_suffix(".prompt.txt").write_text(build_prompt(row, provenance), encoding="utf-8")
        try:
            if self.api_error_seen:
                original_config = self.config
                try:
                    self.config = replace(original_config, max_llm_calls=0)
                    result = super().review(row, provenance)
                    if result["state"] != "cache_hit" and self.retry_output_tokens:
                        self.config = replace(self.config, max_output_tokens=self.retry_output_tokens)
                        result = super().review(row, provenance)
                    if result["state"] not in {"cache_hit", "not_selected", "disabled"}:
                        result["state"] = "deferred_after_api_error"
                finally:
                    self.config = original_config
            elif self.retry_output_tokens is None or request_attempts == 0:
                result = super().review(row, provenance)
            else:
                # Probe the original-profile cache without allowing an API request.
                result = self._probe_cache(row, provenance)
                if result["state"] not in {"cache_hit", "not_selected", "disabled"}:
                    original_config = self.config
                    try:
                        self.config = replace(original_config, max_output_tokens=self.retry_output_tokens,
                                              max_llm_calls=0 if request_attempts >= 2 else original_config.max_llm_calls)
                        cached_retry = self._probe_cache(row, provenance)
                        result = cached_retry if cached_retry["state"] == "cache_hit" else super().review(row, provenance)
                        if request_attempts >= 2 and result["state"] == "budget_exhausted":
                            result["state"] = "retry_limit_reached"
                        result["request_overrides"] = {"max_output_tokens": self.retry_output_tokens,
                                                       "reasoning_level": original_config.reasoning_level}
                    finally:
                        self.config = original_config
            if result["state"] == "api_error":
                self.api_error_seen = True
        except BaseException as exc:
            entry.update(state="interrupted", error_type=type(exc).__name__, finished_at=timestamp())
            save(destination, entry)
            raise
        entry.update(state="finished", result=result, api_calls=result["api_calls"],
                     recheck_complete=recheck(row, result)["review_complete"], finished_at=timestamp())
        save(destination, entry)
        print(f"{self.journal.parents[1].name} {row['edge_id']}: {result['state']}", flush=True)
        return result


def generate(out: Path, settings: Settings, *, retry_errors: bool = False, client=None) -> None:
    plan, _ = verify(out, settings)
    config = plan["generation"]
    prompt = (out / "prompt.txt").read_text(encoding="utf-8")
    for number in range(1, plan["repeats"] + 1):
        folder = out / "runs" / f"r{number:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        meta_file = folder / "generation.json"
        response_file = folder / "response.txt"
        meta = read(meta_file) if meta_file.exists() else {"repeat": number, "attempts": []}
        if (folder / "graph.json").exists():
            if byte_digest((folder / "graph.json").read_bytes()) != meta["graph_file_sha256"]:
                raise ValueError("Saved generation graph changed")
            print(f"r{number:02d} generation already saved", flush=True)
            continue
        if not response_file.exists():
            if meta["attempts"] and not retry_errors:
                print(f"r{number:02d} previous failure; explicit --retry-errors required", flush=True)
                continue
            client = client or get_llm_client(replace(settings, llm_backend=config["backend"]))
            if client is None:
                raise ValueError("A live generation backend is required")
            attempt = {"attempt": len(meta["attempts"]) + 1, "started_at": timestamp(), "api_calls": 1,
                       "state": "in_flight", "usage": None}
            meta["attempts"].append(attempt)
            save(meta_file, meta)  # Record intent before a potentially billable request.
            started = time.perf_counter()
            try:
                raw = client.complete(prompt, max_output_tokens=config["max_output_tokens"],
                                      reasoning_level=config["reasoning"])
                response_file.write_bytes(raw.encode("utf-8"))
                attempt.update(state="response_saved", usage=to_metadata_value(client.last_usage),
                               response_metadata=to_metadata_value(client.last_response_metadata),
                               response_sha256=byte_digest(raw.encode("utf-8")))
            except Exception as exc:
                attempt.update(state="api_error", error_type=type(exc).__name__)
                meta["state"] = "api_error"
            finally:
                attempt["seconds"] = time.perf_counter() - started
                save(meta_file, meta)
            if not response_file.exists():
                print(f"r{number:02d} generation error: {attempt.get('error_type', 'unknown')}", flush=True)
                continue
        try:
            payload = response_file.read_bytes()
            if payload and meta["attempts"][-1].get("response_sha256") != byte_digest(payload):
                raise ValueError("Raw generation response changed")
            graph = parse_llm_json(payload.decode("utf-8"))
            schema = graph_schema_metrics(graph.nodes, graph.edges, condition_id="C2")
            if any(not isinstance(node, dict) or "id" not in node for node in graph.nodes):
                raise ValueError("Unusable graph node")
            if len({str(n["id"]) for n in graph.nodes}) != len(graph.nodes):
                raise ValueError("Duplicate node identity")
            if not graph.nodes:
                raise ValueError("Empty graph")
            save(folder / "graph.json", graph.to_dict())
            meta.update(state="parsed", nodes=len(graph.nodes), edges=len(graph.edges), schema=schema,
                        repaired=graph.truncated, container=graph.container,
                        graph_file_sha256=byte_digest((folder / "graph.json").read_bytes()))
        except Exception as exc:
            meta.update(state="parse_error", error_type=type(exc).__name__)
        save(meta_file, meta)
        print(f"r{number:02d} {meta['state']}: {meta.get('nodes', '?')} nodes / {meta.get('edges', '?')} edges", flush=True)
    make_blind_annotations(out)


def make_blind_annotations(out: Path) -> None:
    """Freeze candidates before hybrid, with no rule/LLM labels or suggestions."""
    plan = read(out / "manifest.json")
    store = EvidenceStore.load(PROJECT_ROOT / "data/cve_official/manifest.json")
    for number in range(1, plan["repeats"] + 1):
        folder = out / "runs" / f"r{number:02d}"
        destination = folder / "annotation_blind.json"
        if not (folder / "graph.json").exists() or destination.exists():
            continue
        graph = read(folder / "graph.json")
        nodes = {str(n["id"]): n for n in graph["nodes"]}
        candidates = []
        for index, edge in enumerate(graph["edges"], 1):
            ends = [nodes.get(str(edge.get("from", edge.get("source")))),
                    nodes.get(str(edge.get("to", edge.get("target"))))]
            mappings = [store.mapping(n or {}) for n in ends]
            evidence = [store.records[m["cve_id"]] for m in mappings if m["status"] == "mapped"]
            candidates.append({"edge_id": f"edge-{index:04d}", "edge": edge,
                               "source_node": ends[0], "target_node": ends[1], "source_evidence": evidence})
        save(destination, {"independent": True, "label_source": "human", "provenance": "",
                           "graph_sha256": digest(graph), "labels": {c["edge_id"]: None for c in candidates},
                           "candidates": candidates,
                           "instructions": "Blank template only. Supply independent provenance and boolean labels only for adjudicated candidates; omit unresolved IDs."})


def validate(out: Path, settings: Settings, *, retry_incomplete: bool = False,
             render: bool = True, adapter_factory=None, repeat_ids: list[int] | None = None,
             retry_output_tokens: int | None = None) -> None:
    plan, store = verify(out, settings)
    review = plan["review"]
    numbers = repeat_ids if repeat_ids is not None else list(range(1, plan["repeats"] + 1))
    if len(set(numbers)) != len(numbers) or any(n < 1 or n > plan["repeats"] for n in numbers):
        raise ValueError("Invalid repeat selection")
    if retry_output_tokens is not None:
        if not retry_incomplete or retry_output_tokens <= review["max_output_tokens"]:
            raise ValueError("A larger token limit is only allowed for explicit incomplete-review retries")
        amendment = out / f"retry_profile_{retry_output_tokens}.json"
        if not amendment.exists():
            save(amendment, {"created_at": timestamp(), "original_output_limit": review["max_output_tokens"],
                             "retry_output_limit": retry_output_tokens, "reasoning": review["reasoning"],
                             "scope": "Only incomplete edge reviews; preserve successful original-profile reviews and first-pass failures",
                             "repeat_ids": numbers})
    make_blind_annotations(out)
    for number in numbers:
        folder = out / "runs" / f"r{number:02d}"
        graph_file = folder / "graph.json"
        if not graph_file.exists():
            continue
        generation = read(folder / "generation.json")
        if byte_digest(graph_file.read_bytes()) != generation["graph_file_sha256"]:
            raise ValueError("Generation input was modified")
        target = folder / "validation"
        report_file = target / "validation_results.json"
        if report_file.exists():
            old = read(report_file)
            complete = all(r["final"]["review_complete"] or r["review"]["state"] == "not_selected" for r in old["edges"])
            if complete or not retry_incomplete:
                print(f"r{number:02d} validation already recorded ({'complete' if complete else 'incomplete'})", flush=True)
                continue
            attempt_path = target / "previous_attempts" / f"attempt_{len(list((target / 'previous_attempts').glob('*.json'))) + 1:02d}.json"
            save(attempt_path, old)
        journal_entries = [read(p) for p in (target / "call_journal").glob("*.json")]
        spent_calls = sum((j.get("result") or {}).get("api_calls", 0) if j.get("result") is not None else 1
                          for j in journal_entries)  # Reserve requests whose outcome was lost on interruption.
        remaining_calls = max(0, review["max_calls_per_repeat"] - spent_calls)
        config = ValidatorConfig(mode="hybrid", llm_enabled=True, llm_backend=review["backend"],
                                 max_llm_calls=remaining_calls, max_output_tokens=review["max_output_tokens"],
                                 reasoning_level=review["reasoning"], cache_enabled=review.get("cache_enabled", True),
                                 review_statuses=tuple(review.get("statuses", ["conditional", "unknown"])),
                                 cache_dir=Path(review["cache_root"]) / out.name / folder.name if review.get("cache_root") else folder / "review_cache")
        adapter = adapter_factory(config) if adapter_factory else JournaledReviewAdapter(
            config, target / "call_journal", settings, retry_output_tokens=retry_output_tokens)
        gold_file = out / "gold" / f"r{number:02d}.json"
        # Existing artifacts are not silently rescored with different gold on resume.
        gold = read(gold_file) if gold_file.exists() else None
        result = write_artifacts(graph_file, target, store, config, adapter=adapter, gold=gold, render=render)
        for row in result["edges"]:
            if row["review"]["state"] != "not_selected":
                (target / f"review_prompt_{row['edge_id']}.txt").write_text(
                    build_prompt(row["offline"], result["provenance"]), encoding="utf-8")
        completed = sum(r["final"]["review_complete"] for r in result["edges"])
        print(f"r{number:02d} hybrid: {completed}/{len(result['edges'])} reviews complete", flush=True)
        if getattr(adapter, "api_error_seen", False):
            print("Stopped after API error; remaining reviews deferred without requests", flush=True)
            return


def stats(values: list) -> dict:
    numbers = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return {"n": len(numbers), "mean": statistics.mean(numbers) if numbers else None,
            "sample_sd": statistics.stdev(numbers) if len(numbers) > 1 else None,
            "min": min(numbers) if numbers else None, "max": max(numbers) if numbers else None}


def report(out: Path) -> dict:
    plan = read(out / "manifest.json")
    rows, generation_calls, review_calls, cards, topologies = [], [], [], [], []
    first_pass_reviews, journal_unknown_calls = [], 0
    for number in range(1, plan["repeats"] + 1):
        folder = out / "runs" / f"r{number:02d}"
        generation = read(folder / "generation.json") if (folder / "generation.json").exists() else {}
        generation_calls += generation.get("attempts", [])
        journals = [read(p) for p in sorted((folder / "validation/call_journal").glob("*.json"))]
        if journals:
            review_calls += [j["result"] for j in journals if j.get("result") is not None]
            journal_unknown_calls += sum(j.get("api_calls") is None for j in journals)
            first = {}
            for j in journals:
                if j.get("result") is None or j["result"].get("api_calls"):
                    first.setdefault(j["edge_id"], j)
            first_pass_reviews += list(first.values())
        row = {"repeat": number, "generation_state": generation.get("state", "not_run"),
               "nodes": generation.get("nodes"), "edges": generation.get("edges"),
               "schema_valid": generation.get("schema", {}).get("schema_valid"),
               "repaired": generation.get("repaired"), "review_complete": 0,
               "validation_state": "not_run"}
        if (folder / "graph.json").exists():
            graph = read(folder / "graph.json")
            store = EvidenceStore.load(PROJECT_ROOT / "data/cve_official/manifest.json")
            mapped = {store.mapping(n)["cve_id"] for n in graph["nodes"] if store.mapping(n)["status"] == "mapped"}
            row["cve_coverage"] = len(mapped) / len(store.records)
            node_identities = {str(n["id"]): store.mapping(n)["cve_id"] for n in graph["nodes"]}
            mapped_pairs = []
            for edge in graph["edges"]:
                a = node_identities.get(str(edge.get("from", edge.get("source"))))
                b = node_identities.get(str(edge.get("to", edge.get("target"))))
                if a and b:
                    mapped_pairs.append((a, b))
            row["topology_mapped_edge_fraction"] = len(mapped_pairs) / len(graph["edges"]) if graph["edges"] else None
            topologies.append((number, set(mapped_pairs)))
        result_file = folder / "validation/validation_results.json"
        if result_file.exists():
            result = read(result_file)
            stages = result["metrics"]
            edge_rows = result["edges"]
            gold_file = out / "gold" / f"r{number:02d}.json"
            if gold_file.exists():
                labels = validate_gold(read(gold_file), {r["edge_id"] for r in edge_rows}, result["graph_sha256"])
                offline_seconds = stages["B_offline"]["processing_seconds"]
                review_seconds = stages["C_hybrid"]["processing_seconds"] - offline_seconds
                stages = ablation_metrics(edge_rows, offline_seconds, review_seconds, labels,
                                          all_node_mappings=result["node_mappings"], review_enabled=result["review_enabled"])
                save(folder / "evaluation_with_gold.json", {"gold_sha256": byte_digest(gold_file.read_bytes()), "metrics": stages})
            row.update(validation_state="complete" if all(r["final"]["review_complete"] or r["review"]["state"] == "not_selected" for r in edge_rows) else "incomplete",
                       review_complete=sum(r["final"]["review_complete"] for r in edge_rows),
                       label_changes=sum(r["offline"]["status"] != r["final"]["status"] for r in edge_rows),
                       disagreements=sum(r["final"]["disagreement"] for r in edge_rows),
                       original_byte_match=byte_digest((folder / "graph.json").read_bytes()) == byte_digest((folder / "validation/original_graph.json").read_bytes()))
            row["review_fallback_edges"] = sum(not r["final"]["review_complete"] and r["review"]["state"] != "not_selected" for r in edge_rows)
            reviews = [r["review"] for r in edge_rows]
            for previous in sorted((folder / "validation/previous_attempts").glob("*.json")):
                reviews += [r["review"] for r in read(previous)["edges"]]
            if not journals:
                review_calls += reviews
            for stage, prefix in (("A_original", "a"), ("B_offline", "b"), ("C_hybrid", "c")):
                metric = stages[stage]
                for key in ("supported", "conditional", "unknown", "unsupported", "contradicted"):
                    row[f"{prefix}_{key}"] = metric["label_distribution"][key]
                row[f"{prefix}_retained"] = metric["retained_edge_fraction"]
                row[f"{prefix}_strict_retained"] = metric["strict_retained_edge_fraction"]
                for key in ("precision", "recall", "f1", "false_removals", "false_retentions", "gold_annotated_edges"):
                    row[f"{prefix}_{key}"] = metric["edge_metrics"][key]
            cards.append(f'<article><h2>Repeat {number:02d}: {row["nodes"]} nodes / {row["edges"]} edges</h2>'
                         f'<p>Review {row["review_complete"]}/{row["edges"]}; B→C label changes: {row["label_changes"]}</p>'
                         f'<a href="runs/r{number:02d}/validation/comparison.svg"><img src="runs/r{number:02d}/validation/comparison.png"></a>'
                         f'<p><a href="runs/r{number:02d}/graph.json">Original JSON</a> · '
                         f'<a href="runs/r{number:02d}/validation/validation_results.json">Evidence report</a> · '
                         f'<a href="runs/r{number:02d}/annotation_blind.json">Blank annotation</a></p></article>')
        rows.append(row)
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with (out / "metrics.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    totals = {"generation": token_usage(generation_calls), "review": token_usage(review_calls)}
    jaccards = [{"repeat_a": a, "repeat_b": b, "jaccard": len(x & y) / len(x | y) if x | y else None}
                for (a, x), (b, y) in combinations(topologies, 2)]
    summary = {"planned_repeats": plan["repeats"], "parsed_graphs": sum(r["generation_state"] == "parsed" for r in rows),
               "validation_reports_saved": sum(r["validation_state"] != "not_run" for r in rows),
               "completed_validations": sum(r["validation_state"] == "complete" for r in rows),
               "all_originals_preserved": all(r.get("original_byte_match", True) for r in rows),
               "api_calls": {"generation": sum(c["api_calls"] for c in generation_calls),
                             "review": sum(c["api_calls"] for c in review_calls)}, "token_usage": totals,
               "generation_reused_from": plan.get("generation_reused_from"),
               "unsettled_review_requests": journal_unknown_calls,
               "first_pass_review": {"candidates": len(first_pass_reviews),
                                     "passed_recheck": sum(bool(j.get("recheck_complete")) for j in first_pass_reviews),
                                     "result_states": dict(Counter((j.get("result") or {}).get("state", j["state"]) for j in first_pass_reviews)),
                                     "scope": "First invocation per edge, before any transport/schema retries; not semantic accuracy."},
               "review_attempt_states": dict(Counter(r["state"] for r in review_calls)),
               "retry_profiles": [read(p) for p in sorted(out.glob("retry_profile_*.json"))],
               "total_label_changes": sum(r.get("label_changes", 0) for r in rows),
               "total_llm_disagreements": sum(r.get("disagreements", 0) for r in rows),
               "gold_annotated_edges": sum(r.get("a_gold_annotated_edges", 0) for r in rows),
               "mapped_cve_topology_stability": {"unique_topologies": len({tuple(sorted(pairs)) for _, pairs in topologies}),
                                                "pairwise_jaccard": stats([p["jaccard"] for p in jaccards]),
                                                "scope": "Mapped CVE endpoint pairs only; ignores edge label claims, duplicates and unmapped endpoints. Not accuracy."},
               "accuracy_state": "not_estimable_without_independent_gold" if not any(r.get("a_gold_annotated_edges", 0) for r in rows) else "candidate_edges_only",
               "statistics": {key: stats([r.get(key) for r in rows]) for key in (
                   "nodes", "edges", "cve_coverage", "label_changes", "disagreements", "b_retained", "c_retained",
                   "a_precision", "b_precision", "c_precision", "a_recall", "b_recall", "c_recall")},
               "rows": rows}
    save(out / "summary.json", summary)
    save(out / "topology_comparison.json", jaccards)
    lines = ["# Kết quả pilot validation C2", "", f"Đã parse {summary['parsed_graphs']}/{plan['repeats']} graph; lưu {summary['validation_reports_saved']} report validation; toàn bộ review qua recheck ở {summary['completed_validations']}/{plan['repeats']} graph.",
             "", "Mỗi repeat dùng đúng prompt đã freeze, cùng model/config. Original giữ nguyên byte; before/after cùng renderer/layout.",
             "", "**Chưa có gold độc lập: precision/recall/F1 = N/A, không báo phần trăm accuracy.**" if not summary["gold_annotated_edges"] else "Metrics chỉ áp dụng các candidate được gán nhãn.",
             "", "| Repeat | Nodes | Edges | CVE coverage | Offline C/U | Hybrid C/U | B→C đổi nhãn |", "|---|---:|---:|---:|---|---|---:|"]
    if plan.get("generation_reused_from"):
        lines[3:3] = [f"\nDùng lại 10 generation đã lưu từ `{plan['generation_reused_from']}`. Lượt này chỉ gọi validation; "
                       f"reviewer {plan['review']['model']}, {plan['review']['reasoning']}, output cap {plan['review']['max_output_tokens']}.\n"]
    if summary["retry_profiles"]:
        limits = ", ".join(str(p["retry_output_limit"]) for p in summary["retry_profiles"])
        lines[3:3] = [f"\nCác review lỗi được phép retry với output cap {limits}; reasoning giữ nguyên. Review đã thành công được tái sử dụng từ cache. First-pass metrics vẫn giữ các lỗi lần đầu.\n"]
    for r in rows:
        lines.append(f"| {r['repeat']:02d} | {r.get('nodes', 'N/A')} | {r.get('edges', 'N/A')} | {r.get('cve_coverage', 0):.0%} | {r.get('b_conditional', '—')}/{r.get('b_unknown', '—')} | {r.get('c_conditional', '—')}/{r.get('c_unknown', '—')} | {r.get('label_changes', '—')} |")
    lines += ["", f"API calls: generation {summary['api_calls']['generation']}, review {summary['api_calls']['review']}. Usage tính cả attempt lỗi, cache hit không tính token lịch sử.",
              "", f"First-pass review qua parse/identity/quote recheck: {summary['first_pass_review']['passed_recheck']}/{summary['first_pass_review']['candidates']}. Review lỗi giữ nhãn offline (fallback), không xem đó là kết quả semantic review hoàn tất.",
              "", f"Topology CVE được ánh xạ: {summary['mapped_cve_topology_stability']['unique_topologies']} cấu trúc khác nhau. Jaccard trung bình giữa các cặp repeat: {summary['mapped_cve_topology_stability']['pairwise_jaccard']['mean']}. Chỉ đo ổn định các cặp CVE có mapping, không đo độ đúng và không xét nội dung claim.",
              "", "C/U = conditional/unknown. Đây là distribution của validator, không phải nhãn chuẩn về đúng/sai.",
              "", "Để chấm precision, dùng annotation_blind.json cho người đánh giá độc lập, chỉ gán true/false cho cạnh đã đủ căn cứ; bỏ qua cạnh chưa thể phân xử. Không dùng nhãn hybrid làm gold.",
              "", "Xem PROTOCOL.md, metrics.csv và summary.json. Một case lặp nhiều lần chỉ đo biến thiên của case đó."]
    (out / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    html = '<!doctype html><html lang="vi"><meta charset="utf-8"><title>C2 paired validation pilot</title><style>body{font:16px Arial;margin:24px;background:#f3f6fa;color:#172b40}article{background:white;padding:20px;margin:20px 0;border:1px solid #ccd5df;border-radius:8px}img{width:100%;max-width:1200px}a{color:#195695}</style>'
    html += f'<h1>C2: {plan["repeats"]} fresh generations → paired validation</h1><p>Original and validated use the same graph and layout. '
    html += 'No independent gold: accuracy N/A.</p>' if not summary["gold_annotated_edges"] else 'Candidate-edge metrics available for the annotated subset.</p>'
    html += '<p><a href="REPORT.md">Report</a> · <a href="PROTOCOL.md">Protocol</a> · <a href="metrics.csv">Metrics CSV</a> · <a href="summary.json">Summary</a></p>' + "".join(cards) + '</html>'
    (out / "index.html").write_text(html, encoding="utf-8")
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "generate", "validate", "report", "fork-review"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path, help="Source frozen generation run for fork-review")
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--backend", choices=BACKENDS, default="gemini")
    parser.add_argument("--review-backend", choices=BACKENDS)
    parser.add_argument("--generation-reasoning", choices=("low", "medium", "high"), default="medium")
    parser.add_argument("--generation-tokens", type=int, default=8192)
    parser.add_argument("--review-reasoning", choices=("low", "medium", "high"))
    parser.add_argument("--review-tokens", type=int)
    parser.add_argument("--review-provider-config", help="Explicit OpenRouter v2 routing JSON, without changing .env")
    parser.add_argument("--max-reviews-per-repeat", type=int, default=30)
    parser.add_argument("--retry-errors", action="store_true")
    parser.add_argument("--retry-incomplete", action="store_true")
    parser.add_argument("--retry-output-tokens", type=int, help="Record a higher output cap only for failed edge retries; keep successful cached reviews")
    parser.add_argument("--no-render", action="store_true")
    parser.add_argument("--repeat-ids", type=int, nargs="+", help="Validate selected already-generated repeats")
    parser.add_argument("--no-report", action="store_true", help="Skip shared report writes when validating disjoint repeat groups")
    args = parser.parse_args(argv)
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env", override=True)
    settings = Settings()
    if args.review_provider_config is not None:
        provider = json.loads(args.review_provider_config)
        if not isinstance(provider, dict):
            raise ValueError("Provider config must be an object")
        settings = replace(settings, openrouter_provider_config_v2=json.dumps(provider))
    out = args.out.resolve()
    try:
        if args.command == "fork-review":
            if not args.source:
                raise ValueError("fork-review requires --source")
            config = ValidatorConfig.from_env()
            overrides = {key: value for key, value in {
                "llm_backend": args.review_backend, "reasoning_level": args.review_reasoning,
                "max_output_tokens": args.review_tokens}.items() if value is not None}
            fork_review(args.source.resolve(), out, settings, replace(config, **overrides))
            report(out)
        elif args.command == "prepare":
            prepare(out, repeats=args.repeats, settings=settings, backend=args.backend, review_backend=args.review_backend or "gemini",
                    generation_reasoning=args.generation_reasoning, generation_tokens=args.generation_tokens,
                    review_reasoning=args.review_reasoning or "low", review_tokens=args.review_tokens or 4096,
                    max_reviews=args.max_reviews_per_repeat)
        elif args.command == "generate":
            generate(out, settings, retry_errors=args.retry_errors)
            if not args.no_report:
                report(out)
        elif args.command == "validate":
            validate(out, settings, retry_incomplete=args.retry_incomplete, render=not args.no_render,
                     repeat_ids=args.repeat_ids, retry_output_tokens=args.retry_output_tokens)
            if not args.no_report:
                report(out)
        else:
            report(out)
    except Exception as exc:
        print(f"Experiment error: {type(exc).__name__}", flush=True)
        return 2
    print(f"Saved experiment: {out}", flush=True)
    return 0
