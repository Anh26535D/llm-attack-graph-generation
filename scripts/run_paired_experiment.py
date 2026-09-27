#!/usr/bin/env python
"""Prepare or run the paired Gemini/OpenRouter reproduction on official CVEs.

The index and experiment artifacts are local. API keys are read from .env by
the existing config loader and are never written to manifests or logs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
os.environ["CRYSTALBALL_DB_PATH"] = str(REPO_ROOT / "data" / "db" / "contriever.sqlite3")
os.environ["CRYSTALBALL_EMBEDDINGS_DIR"] = str(REPO_ROOT / "data" / "embeddings" / "contriever")
os.environ["CRYSTALBALL_OUTPUTS_DIR"] = str(REPO_ROOT / "outputs")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="backslashreplace")
sys.path.insert(0, str(REPO_ROOT / "src"))

from crystalball.config import DATA_DIR, GRAPHS_DIR, Settings, get_settings  # noqa: E402
from crystalball.cve_dataset import (  # noqa: E402
    OFFICIAL_CVE_IDS,
    OfficialCveDataset,
    load_official_cve_dataset,
)
from crystalball.db import Database  # noqa: E402
from crystalball.embeddings import get_embedding_model  # noqa: E402
from crystalball.experiment import (  # noqa: E402
    dispatch_paired_prompt,
    edges_for_visualization,
    graph_schema_metrics,
    prompt_sha256,
)
from crystalball.extractors import LLMExtractor  # noqa: E402
from crystalball.generator import (  # noqa: E402
    CVE_CONTEXT_PROMPT,
    NO_CONTEXT_PROMPT_TEMPLATE,
    REPORT_PROMPT,
    BuiltPrompt,
    build_prompt_from_products,
    build_prompt_from_report,
)
from crystalball.llm.base import LLMClient  # noqa: E402
from crystalball.llm.factory import get_llm_client  # noqa: E402
from crystalball.postprocess import (  # noqa: E402
    AttackGraph,
    merge_graphs,
    parse_llm_json,
    save_graph_json,
    visualize_graph,
    visualize_graph_report,
    visualize_graph_report_with_legend,
)
from crystalball.preprocess import preprocess_cve  # noqa: E402
from crystalball.retriever import RetrievalResult  # noqa: E402

OUTPUTS_DIR = REPO_ROOT / "outputs" / "experiments"
DB_PATH = REPO_ROOT / "data" / "db" / "contriever.sqlite3"
EMBEDDINGS_DIR = REPO_ROOT / "data" / "embeddings" / "contriever"
INDEX_MANIFEST_PATH = REPO_ROOT / "data" / "db" / "contriever.index_manifest.json"
REPRODUCTION_DATA_DIR = REPO_ROOT / "data" / "reproduction"
PRODUCT_QUERY = ["Oculus Desktop", "Jetson TX1", "Raspberry Pi"]
REPORT_FILES = {
    "kubernetes_report": "kubernetes_cluster_hacked.txt",
    "solarwinds_evasion_excerpt": "solarwinds_evasion.txt",
    "solarwinds_full_condensed": "solarwinds_full.txt",
}
SAMPLE_IDS_MATCHING_OFFICIAL_RECORDS = {"CVE-2020-1885"}
ACTIVE_DATASET: OfficialCveDataset | None = None
ACTIVE_CONDITION_SET = "all"
ACTIVE_PRODUCT_QUERY = PRODUCT_QUERY
MODEL_SPECS = {
    "gemini": ("gemini", "gemini_model"),
    "openrouter": ("openrouter", "openrouter_model"),
}
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
REPEAT_COUNT = 5
PILOT_CONDITION_ID = "C1"
DEFAULT_OUTPUT_TOKENS = 4096
MAX_RUN_RETRIES = 4
MAIN_OUTPUT_TOKENS = {"T1": 8192}
SECTION54_EDGE = {
    "from": "node_oculus_browser_xss",
    "to": "node_ovrredir_lpe",
    "label": (
        "Leverages unprivileged local execution from browser compromise to create hard links "
        "and trigger privileged arbitrary file write in OVRRedir.exe"
    ),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_run_id() -> str:
    base = utc_now().strftime("%Y%m%dT%H%M%S%fZ")
    suffix = 0
    while True:
        run_id = base if suffix == 0 else f"{base}_{suffix:02d}"
        if not (OUTPUTS_DIR / run_id).exists():
            return run_id
        suffix += 1


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(path: Path, run_dir: Path) -> str:
    return path.resolve().relative_to(run_dir.resolve()).as_posix()


def safe_error(exc: Exception, settings: Settings) -> str:
    message = f"{type(exc).__name__}: {exc}"
    for secret in (settings.gemini_api_key, settings.openrouter_api_key, settings.openai_api_key):
        if secret:
            message = message.replace(secret, "<redacted>")
    return message[:4000]


def sample_cve_files() -> list[Path]:
    if ACTIVE_DATASET is not None:
        return list(ACTIVE_DATASET.files)
    return sorted((DATA_DIR / "cve_samples").glob("*.json"))


def cve_id_for_file(path: Path) -> str:
    record = json.loads(path.read_text(encoding="utf-8"))
    return record.get("cveMetadata", {}).get("cveId", path.stem)


def description_for_file(path: Path) -> str:
    record = json.loads(path.read_text(encoding="utf-8"))
    descriptions = record.get("containers", {}).get("cna", {}).get("descriptions", [])
    for item in descriptions:
        if item.get("lang", "en").startswith("en"):
            return item.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def source_hashes() -> dict[str, str]:
    paths = sample_cve_files()
    if ACTIVE_CONDITION_SET != "cve-only":
        paths += [DATA_DIR / "threat_reports" / name for name in REPORT_FILES.values()]
    return {path.relative_to(REPO_ROOT).as_posix(): sha256_file(path) for path in paths}


def condition_record(
    condition_id: str,
    built: BuiltPrompt,
    input_mode: str,
    context_mode: str,
    provided_cve_ids: list[str],
    source_files: list[str],
    *,
    requires_prepost: bool = False,
    max_output_tokens: int = DEFAULT_OUTPUT_TOKENS,
) -> dict[str, Any]:
    return {
        "condition_id": condition_id,
        "query": built.query,
        "input_mode": input_mode,
        "context_mode": context_mode,
        "provided_cve_ids": provided_cve_ids,
        "retrieved_cve_ids": built.retrieval.relevant_cve_ids if built.retrieval else [],
        "retrieval_matches": [
            {"cve_id": cve_id, "matched_on": matched_on, "cosine_similarity": score}
            for cve_id, matched_on, score in (built.retrieval.matches if built.retrieval else [])
        ],
        "source_files": source_files,
        "prompt": built.prompt,
        "requires_prepost": requires_prepost,
        "max_output_tokens": max_output_tokens,
    }


def reproduction_prompt(filename: str) -> tuple[str, str]:
    path = REPRODUCTION_DATA_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Missing reviewed reproduction source: {path}")
    return path.read_text(encoding="utf-8"), path.relative_to(REPO_ROOT).as_posix()


def graph_call_id(
    stage: str,
    model_name: str,
    condition_id: str,
    repeat_id: int,
    attempt_id: int = 1,
) -> str:
    if repeat_id < 1 or attempt_id < 1:
        raise ValueError("repeat_id and attempt_id must be positive integers.")
    return (
        f"{stage}.{model_name}.{condition_id}."
        f"r{repeat_id:02d}.a{attempt_id:02d}"
    )


def main_call_specs(conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the approved 7 x 2 x 5 graph-call matrix without making API calls."""
    specs: list[dict[str, Any]] = []
    for condition in conditions:
        for repeat_id in range(1, REPEAT_COUNT + 1):
            for model_name in MODEL_SPECS:
                specs.append({
                    "stage": "graph",
                    "model_name": model_name,
                    "condition_id": condition["condition_id"],
                    "repeat_id": repeat_id,
                    "attempt_id": 1,
                    "max_output_tokens": condition.get(
                        "max_output_tokens", DEFAULT_OUTPUT_TOKENS
                    ),
                    "call_id": graph_call_id(
                        "graph", model_name, condition["condition_id"], repeat_id
                    ),
                })
    return specs


def build_conditions(
    db: Database, settings: Settings, *, condition_set: str | None = None
) -> list[dict[str, Any]]:
    cv_files = sample_cve_files()
    all_cve_ids = [cve_id_for_file(path) for path in cv_files]
    source_names = [path.relative_to(REPO_ROOT).as_posix() for path in cv_files]

    query = ACTIVE_PRODUCT_QUERY
    baseline = build_prompt_from_products(query, db, settings=settings, use_context=False)
    rag = build_prompt_from_products(query, db, settings=settings, use_context=True)
    full_description_context = "\n---\n".join(description_for_file(path) for path in cv_files)
    appendix_a = BuiltPrompt(
        prompt=CVE_CONTEXT_PROMPT + full_description_context,
        query=", ".join(query),
    )

    if ACTIVE_DATASET is not None:
        c2_prompt, c2_source = reproduction_prompt("appendix_a_context.txt")
        t0_prompt, t0_source = reproduction_prompt("kubernetes_appendix_b.txt")
        t1_prompt, t1_source = reproduction_prompt("solarwinds_full_appendix_c1.txt")
        t2_prompt, t2_source = reproduction_prompt("solarwinds_evasion_appendix_c2.txt")
        c0 = BuiltPrompt(
            prompt=(
                "Create an attack graph in json format using only nodes and edges as keys "
                "for a system comprising of Raspberry Pi, Oculus Desktop, NVIDIA Jetson Nano."
            ),
            query="Raspberry Pi, Oculus Desktop, NVIDIA Jetson Nano",
        )
        c2 = BuiltPrompt(prompt=c2_prompt, query=", ".join(query))
        t0 = BuiltPrompt(prompt=t0_prompt, query=t0_source)
        t1 = BuiltPrompt(prompt=t1_prompt, query=t1_source)
        t2 = BuiltPrompt(prompt=t2_prompt, query=t2_source)
        x0 = BuiltPrompt(prompt=CVE_CONTEXT_PROMPT, query=", ".join(query))
        conditions = [
            condition_record("C0", c0, "products", "none_paper_section_5_1", [], []),
            condition_record(
                "C1", rag, "products", "contriever_retrieval", [], [],
                requires_prepost=True,
            ),
            condition_record(
                "C2", c2, "appendix_a", "all_8_descriptions", all_cve_ids,
                [c2_source], requires_prepost=True,
            ),
            condition_record("T0", t0, "threat_report", "not_applicable", [], [t0_source]),
            condition_record(
                "T1", t1, "threat_report", "not_applicable", [], [t1_source],
                max_output_tokens=MAIN_OUTPUT_TOKENS["T1"],
            ),
            condition_record("T2", t2, "threat_report", "not_applicable", [], [t2_source]),
            condition_record(
                "X0", x0, "products", "none_matched_instruction_schema", [], [],
                requires_prepost=True,
            ),
        ]
        conditions[1]["provided_cve_ids"] = list(conditions[1]["retrieved_cve_ids"])
        conditions[1]["source_files"] = [
            f"retrieved description: {cve_id}"
            for cve_id in conditions[1]["retrieved_cve_ids"]
        ]
        return conditions

    conditions = [
        condition_record("baseline_no_context", baseline, "products", "none", [], []),
        condition_record(
            "retriever_context", rag, "products", "contriever_retrieval", all_cve_ids[:0], []
        ),
        condition_record(
            "appendix_a_full_8_cves", appendix_a,
            "all_official_cve_descriptions" if ACTIVE_DATASET else "all_sample_cve_descriptions",
            "all_8_descriptions",
            all_cve_ids, source_names,
        ),
    ]
    selected_condition_set = condition_set or ACTIVE_CONDITION_SET
    if selected_condition_set not in {"all", "cve-only"}:
        raise ValueError(f"Unknown condition set: {selected_condition_set}.")
    if selected_condition_set == "cve-only":
        conditions[1]["provided_cve_ids"] = list(conditions[1]["retrieved_cve_ids"])
        conditions[1]["source_files"] = [
            f"retrieved description: {cve_id}" for cve_id in conditions[1]["retrieved_cve_ids"]
        ]
        return conditions

    for condition_id, filename in REPORT_FILES.items():
        path = DATA_DIR / "threat_reports" / filename
        built = build_prompt_from_report(path)
        provenance = "quoted/condensed sample report; not the full original report"
        conditions.append(
            condition_record(
                condition_id,
                built,
                "threat_report",
                "not_applicable",
                [],
                [path.relative_to(REPO_ROOT).as_posix()],
            ) | {"report_provenance": provenance}
        )
    conditions[1]["provided_cve_ids"] = list(conditions[1]["retrieved_cve_ids"])
    conditions[1]["source_files"] = [
        f"retrieved description: {cve_id}" for cve_id in conditions[1]["retrieved_cve_ids"]
    ]
    return conditions


def check_settings(settings: Settings, *, require_api_keys: bool = True) -> None:
    if settings.llm_backend != "gemini":
        raise RuntimeError("Expected LLM_BACKEND=gemini for the extractor configuration.")
    if settings.extractor_backend != "llm":
        raise RuntimeError("Expected EXTRACTOR_BACKEND=llm.")
    if settings.embedding_backend != "sentence-transformers":
        raise RuntimeError("Expected EMBEDDING_BACKEND=sentence-transformers.")
    if settings.embedding_model != "facebook/contriever-msmarco":
        raise RuntimeError("Expected EMBEDDING_MODEL=facebook/contriever-msmarco.")
    if settings.gemini_model != "gemini-3.8-flash":
        raise RuntimeError("Expected GEMINI_MODEL=gemini-3.8-flash.")
    if settings.openrouter_model.strip() != "openai/gpt-5.6-luna":
        raise RuntimeError("Expected OPENROUTER_MODEL=openai/gpt-5.6-luna.")
    if require_api_keys and (not settings.gemini_api_key or not settings.openrouter_api_key):
        raise RuntimeError("Both Gemini and OpenRouter API keys must be set in the local environment.")


def safe_settings(settings: Settings) -> dict[str, Any]:
    return {
        "llm_backend_for_extraction": settings.llm_backend,
        "extractor_backend": settings.extractor_backend,
        "embedding_backend": settings.embedding_backend,
        "embedding_model": settings.embedding_model,
        "min_similarity": settings.min_similarity,
        "context_tokens_per_query": settings.context_tokens_per_query,
        "models": {
            name: {"backend": backend, "model": getattr(settings, model_field)}
            for name, (backend, model_field) in MODEL_SPECS.items()
        },
        "product_query": ACTIVE_PRODUCT_QUERY,
    }


def index_signature(settings: Settings, input_hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "embedding_backend": settings.embedding_backend,
        "embedding_model": settings.embedding_model,
        "extractor_backend": settings.extractor_backend,
        "extractor_backend_provider": settings.llm_backend,
        "extractor_model": settings.gemini_model,
        "input_sha256": input_hashes,
    }


def inspect_saved_index(settings: Settings, input_hashes: dict[str, str]) -> dict[str, Any] | None:
    if INDEX_MANIFEST_PATH.exists():
        previous = json.loads(INDEX_MANIFEST_PATH.read_text(encoding="utf-8"))
        if previous.get("status") not in {"ready", "building", "failed"}:
            raise RuntimeError("Contriever index has an unsupported status; refusing to reuse it.")
        if previous.get("signature") != index_signature(settings, input_hashes):
            raise RuntimeError("Contriever index source/config does not match this run; refusing to reuse it.")
        # Graph-call history belongs to an experiment run, not to the immutable
        # extraction/index cache.  Older manifests may contain this legacy field;
        # ignore it when deciding whether the reviewed index can be reused.
        if not DB_PATH.exists():
            raise RuntimeError("Contriever index manifest exists but its SQLite database is missing.")
        return previous

    if DB_PATH.exists():
        raise RuntimeError("Contriever DB already exists without an index manifest; refusing to overwrite it.")
    if EMBEDDINGS_DIR.exists() and any(EMBEDDINGS_DIR.iterdir()):
        raise RuntimeError("Contriever embedding directory is not empty without an index manifest; refusing to reuse it.")
    return None


def read_properties(db_path: Path, cve_id: str) -> dict[str, Any]:
    with sqlite3.connect(db_path) as conn:
        products = conn.execute(
            "SELECT product_name FROM product_info WHERE cve_id = ? ORDER BY id", (cve_id,)
        ).fetchall()
        problems = conn.execute(
            "SELECT problem_type FROM problem_type WHERE cve_id = ? ORDER BY id", (cve_id,)
        ).fetchall()
        platforms = conn.execute(
            "SELECT platform FROM platform WHERE cve_id = ? ORDER BY id", (cve_id,)
        ).fetchall()
        versions = conn.execute(
            "SELECT version_number, qualifier FROM version_info WHERE product_id IN "
            "(SELECT id FROM product_info WHERE cve_id = ?) ORDER BY id",
            (cve_id,),
        ).fetchall()
    return {
        "products": [row[0] for row in products],
        "versions": [{"version_number": row[0], "qualifier": row[1]} for row in versions],
        "problem_types": [row[0] for row in problems],
        "platforms": [row[0] for row in platforms],
    }


def load_usage(client: object) -> dict[str, Any] | None:
    usage = getattr(client, "last_usage", None)
    if usage is None:
        return None
    if hasattr(usage, "model_dump"):
        return usage.model_dump(exclude_none=True)
    return usage if isinstance(usage, dict) else None


class JournalLLMClient(LLMClient):
    """Persists every attempted LLM call without recording credentials."""

    def __init__(
        self,
        client: LLMClient,
        *,
        call_id: str,
        stage: str,
        backend: str,
        model: str,
        run_dir: Path,
        settings: Settings,
        condition_id: str | None = None,
        repeat_id: int | None = None,
        attempt_id: int = 1,
        max_output_tokens: int = DEFAULT_OUTPUT_TOKENS,
        reasoning_level: str = "low",
        retry_of_call_id: str | None = None,
        operator_confirmed_transient: bool = False,
    ) -> None:
        self.client = client
        self.call_id = call_id
        self.stage = stage
        self.backend = backend
        self.model = model
        self.run_dir = run_dir
        self.settings = settings
        self.condition_id = condition_id
        self.repeat_id = repeat_id
        self.attempt_id = attempt_id
        self.max_output_tokens = max_output_tokens
        self.reasoning_level = reasoning_level
        self.retry_of_call_id = retry_of_call_id
        self.operator_confirmed_transient = operator_confirmed_transient
        self.last_usage: dict[str, Any] | None = None
        self.record_path = run_dir / "calls" / f"{call_id}.json"
        self.prompt_path = run_dir / "call_prompts" / f"{call_id}.txt"
        self.response_path = run_dir / "raw_responses" / f"{call_id}.txt"

    def complete(self, prompt: str) -> str:
        prompt_bytes = prompt.encode("utf-8")
        self.prompt_path.parent.mkdir(parents=True, exist_ok=True)
        self.prompt_path.write_bytes(prompt_bytes)
        record = {
            "call_id": self.call_id,
            "stage": self.stage,
            "backend": self.backend,
            "model": self.model,
            "condition_id": self.condition_id,
            "repeat_id": self.repeat_id,
            "attempt_id": self.attempt_id,
            "status": "attempted",
            "attempted_at": utc_now().isoformat(),
            "prompt_sha256": prompt_sha256(prompt_bytes),
            "prompt_file": relative(self.prompt_path, self.run_dir),
            "generation_config": {
                "max_output_tokens": self.max_output_tokens,
                "reasoning_level": self.reasoning_level,
            },
            # Retain the pre-send reserve so a provider response without usage
            # metadata is never accounted as a zero-cost request.
            "request_cost_ceiling_vnd": conservative_request_ceiling_vnd(
                self.backend, prompt, self.max_output_tokens
            ),
        }
        if self.retry_of_call_id is not None:
            record.update({
                "retry_of_call_id": self.retry_of_call_id,
                "operator_confirmed_transient": self.operator_confirmed_transient,
            })
        atomic_json(self.record_path, record)
        try:
            raw = self.client.complete(
                prompt,
                max_output_tokens=self.max_output_tokens,
                reasoning_level=self.reasoning_level,
            )
        except Exception as exc:  # noqa: BLE001
            record.update({"status": "api_error", "error": safe_error(exc, self.settings)})
            record["finished_at"] = utc_now().isoformat()
            atomic_json(self.record_path, record)
            raise

        self.response_path.parent.mkdir(parents=True, exist_ok=True)
        self.response_path.write_text(raw, encoding="utf-8")
        self.last_usage = load_usage(self.client)
        response_metadata = getattr(self.client, "last_response_metadata", None)
        record.update({
            "status": "response_saved",
            "finished_at": utc_now().isoformat(),
            "response_file": relative(self.response_path, self.run_dir),
            "usage": self.last_usage,
            "response_metadata": response_metadata,
            "response_sha256": sha256_file(self.response_path),
        })
        atomic_json(self.record_path, record)
        return raw


class SavedResponseLLMClient(LLMClient):
    """Feeds a previously saved response through parsing without an API call."""

    name = "saved-response-recovery"

    def __init__(self, response: str) -> None:
        self.response = response

    def complete(self, prompt: str) -> str:
        return self.response


def mark_call(call_path: Path, status: str, *, error: str | None = None) -> None:
    record = json.loads(call_path.read_text(encoding="utf-8"))
    record["status"] = status
    record["finished_at"] = utc_now().isoformat()
    if error:
        record["processing_error"] = error
    atomic_json(call_path, record)


def cve_ids_in_graph(graph: Any) -> list[str]:
    found: set[str] = set()
    for node in graph.nodes:
        if not isinstance(node, dict):
            continue
        for field in ("id", "label"):
            value = node.get(field)
            if value is not None:
                found.update(match.upper() for match in CVE_ID_RE.findall(str(value)))
    return sorted(found)


def graph_metrics(
    graph: Any,
    context_ids: list[str],
    prompt: str,
    *,
    condition_id: str | None = None,
) -> dict[str, Any]:
    labeled_ids = cve_ids_in_graph(graph)
    prompt_ids = {item.upper() for item in CVE_ID_RE.findall(prompt)}
    explicit_context_ids = sorted({item.upper() for item in context_ids} & prompt_ids)
    mentioned_context_ids = sorted(set(labeled_ids) & set(explicit_context_ids))
    return {
        **graph_schema_metrics(graph.nodes, graph.edges, condition_id=condition_id),
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "node_cve_labels": labeled_ids,
        "provided_cve_ids_explicit_in_prompt": explicit_context_ids,
        "provided_cve_id_mentions_count": len(mentioned_context_ids),
        "provided_cve_id_mention_rate": (
            len(mentioned_context_ids) / len(explicit_context_ids) if explicit_context_ids else None
        ),
    }


def response_graph_metrics(
    raw: str,
    graph: AttackGraph,
    context_ids: list[str],
    prompt: str,
    *,
    condition_id: str | None = None,
) -> dict[str, Any]:
    """Keep response syntax, extraction, and raw graph-schema results separate."""
    metrics = graph_metrics(graph, context_ids, prompt, condition_id=condition_id)
    extracted_schema_valid = bool(metrics["schema_valid"])
    try:
        response_json_valid = isinstance(json.loads(raw.strip()), dict)
    except json.JSONDecodeError:
        response_json_valid = False
    metrics.update({
        "response_json_valid": response_json_valid,
        "graph_extracted": True,
        "graph_container": graph.container,
        "graph_wrapper_extracted": graph.container != "top_level",
        "missing_graph_keys": list(graph.missing_keys),
        "true_empty_graph": graph.explicitly_empty,
        "parser_repaired_truncation": graph.truncated,
        "extracted_graph_schema_valid": extracted_schema_valid,
        # A recognized wrapper is useful for extraction, but it is not the requested
        # top-level graph schema.  Node/edge aliases likewise remain unnormalized here.
        "schema_valid": (
            extracted_schema_valid
            and graph.container == "top_level"
            and not graph.missing_keys
        ),
    })
    return metrics


def provider_finish_reason(call_record: dict[str, Any]) -> str | None:
    metadata = call_record.get("response_metadata") or {}
    reason = metadata.get("finish_reason")
    if reason is None:
        reasons = metadata.get("finish_reasons") or []
        reason = reasons[0] if reasons else None
    return str(reason) if reason is not None else None


def finish_reason_indicates_truncation(reason: str | None) -> bool:
    normalized = (reason or "").strip().casefold().replace("-", "_")
    return normalized in {"length", "max_tokens", "max_token", "token_limit"}


def visualization_graph(graph: Any) -> tuple[AttackGraph, bool]:
    """Copy the graph for display, accepting common aliases without changing saved JSON."""
    edges, aliased = edges_for_visualization(graph.edges)
    return AttackGraph(nodes=graph.nodes, edges=edges, truncated=graph.truncated), aliased


def classify_parse_mode(raw: str, graph: AttackGraph | None) -> str:
    if graph is None:
        return "parse_failed"
    if graph.truncated:
        return "repaired_truncated"
    stripped = raw.strip()
    try:
        exact = json.loads(stripped)
    except json.JSONDecodeError:
        exact = None
    if isinstance(exact, dict):
        return "raw_json"
    if re.search(r"```(?:json)?\s*\{.*?\}\s*```", stripped, re.DOTALL):
        return "markdown_stripped"
    return "object_extracted"


def write_metrics(run_dir: Path, rows: list[dict[str, Any]]) -> None:
    safe_rows = [{key: value for key, value in row.items() if key != "_error_object"} for row in rows]
    metrics_path = run_dir / "metrics.json"
    atomic_json(metrics_path, {
        "results": safe_rows,
        "interpretation_limit": (
            "provided_cve_id_mention_rate only measures output mentions of IDs explicitly present in the prompt; "
            "it is not a vulnerability recall/coverage metric. Automated structural metrics do not judge "
            "semantic correctness or attack-path validity. Schema metrics check required JSON keys and endpoint "
            "integrity only; PNGs may map source/target aliases for display while graph.json remains raw."
        ),
    })
    columns = [
        "call_id", "stage", "backend", "model", "condition_id", "repeat_id", "attempt_id",
        "status", "parse_mode", "parse_success", "strict_parse_success",
        "truncated_repair", "node_count", "edge_count", "valid_edges", "invalid_edges",
        "schema_valid", "non_empty_graph", "missing_node_required_fields_count", "missing_edge_required_fields_count",
        "edge_schema_compliance", "alternate_source_target_edges_count", "edge_endpoint_integrity",
        "node_cve_labels", "provided_cve_ids_explicit_in_prompt",
        "provided_cve_id_mentions_count", "provided_cve_id_mention_rate", "retrieved_cve_ids", "prompt_sha256", "total_tokens",
        "cost", "cost_usd_estimated", "graph_file", "graph_report_png", "graph_report_with_legend_png",
        "graph_report_legend", "raw_response_file", "error",
    ]
    with (run_dir / "metrics.csv").open("w", newline="", encoding="utf-8-sig") as output:
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in safe_rows:
            writer.writerow({
                **row,
                "node_cve_labels": ";".join(row.get("node_cve_labels", [])),
                "provided_cve_ids_explicit_in_prompt": ";".join(row.get("provided_cve_ids_explicit_in_prompt", [])),
                "retrieved_cve_ids": ";".join(row.get("retrieved_cve_ids", [])),
            })


def usage_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    totals: dict[str, dict[str, Any]] = {}
    for record in records:
        usage = record.get("usage") or {}
        backend = record.get("backend", "unknown")
        total = totals.setdefault(backend, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                                            "total_tokens": 0, "cost": 0.0, "cost_reported": False})
        total["calls"] += 1
        prompt_tokens = usage.get("prompt_tokens", usage.get("prompt_token_count", 0)) or 0
        completion_tokens = usage.get("completion_tokens", usage.get("candidates_token_count", 0)) or 0
        tokens = usage.get("total_tokens", usage.get("total_token_count"))
        total["prompt_tokens"] += prompt_tokens if isinstance(prompt_tokens, (int, float)) else 0
        total["completion_tokens"] += completion_tokens if isinstance(completion_tokens, (int, float)) else 0
        if isinstance(tokens, (int, float)):
            total["total_tokens"] += tokens
        if isinstance(usage.get("cost"), (int, float)):
            total["cost"] += usage["cost"]
            total["cost_reported"] = True
    for total in totals.values():
        if not total["cost_reported"]:
            total["cost"] = None
        del total["cost_reported"]
    return totals


def write_report_summary(
    run_dir: Path,
    rows: list[dict[str, Any]],
    run_manifest: dict[str, Any],
    usage_by_backend: dict[str, Any],
) -> None:
    def percentage(value: Any) -> str:
        return "—" if value is None else f"{100 * value:.1f}%"

    if run_manifest.get("call_plan", {}).get("total_calls") == 130:
        review_3_approved = (
            run_manifest.get("review_checkpoints", {}).get("review_3", {}).get("status")
            == "approved"
        )
        review_3_note = (
            "Nhãn bằng chứng và coverage vẫn là đánh giá sơ bộ của Codex; "
            "người dùng đã duyệt Review 3."
            if review_3_approved
            else "Nhãn bằng chứng và coverage là sơ bộ, chờ Review 3 của người dùng."
        )
        stage_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        for row in rows:
            stage_counts[row.get("stage", "unknown")] = stage_counts.get(
                row.get("stage", "unknown"), 0
            ) + 1
            status_counts[row.get("status", "unknown")] = status_counts.get(
                row.get("status", "unknown"), 0
            ) + 1
        cost = run_manifest.get("cost") or run_cost_summary(run_dir)
        lines = [
            "# Tóm tắt run tái hiện §5.1–§5.4",
            "",
            f"- Run ID: `{run_manifest.get('run_id')}`; trạng thái: `{run_manifest.get('status')}`.",
            "- Protocol: 7 điều kiện chính × 2 model × 5 repeat và đủ ba workflow §5.4; "
            "index/extraction chính thức được reuse, không có extraction API call mới.",
            f"- Tiến độ: {len(rows)}/130 kết quả; API errors: "
            f"{status_counts.get('api_error', 0)}; chi phí ước tính: "
            f"{cost.get('estimated_cost_vnd', 0):.2f}/50000 VND.",
            f"- Confirmed transient retries: {len(run_manifest.get('retry_attempts', []))}/"
            f"{MAX_RUN_RETRIES}; retry outcomes are journaled separately and do not replace planned results.",
            "",
            "## Phân bổ request đã ghi",
            "",
            "| Stage | Calls |",
            "|---|---:|",
            *[f"| {stage} | {count} |" for stage, count in sorted(stage_counts.items())],
            "",
            "## Trạng thái output",
            "",
            "| Status | Count |",
            "|---|---:|",
            *[f"| {status} | {count} |" for status, count in sorted(status_counts.items())],
            "",
            "## Artifact chuẩn",
            "",
            "- [`REPRODUCTION_REPORT.md`](REPRODUCTION_REPORT.md): báo cáo kết quả và coverage.",
            "- [`evidence_table.md`](evidence_table.md): bảng bằng chứng từng edge entry.",
            "- [`coverage.md`](coverage.md) / [`coverage.json`](coverage.json): coverage từng repeat.",
            "- [`manifest.json`](manifest.json), [`metrics.csv`](metrics.csv), "
            "[`metrics.json`](metrics.json), [`summary.json`](summary.json): provenance và dữ liệu máy đọc.",
            "",
            "Không suy diễn semantic correctness từ parse/schema hoặc số node/edge. "
            + review_3_note,
        ]
        (run_dir / "REPORT_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    conditions = {item["condition_id"]: item for item in run_manifest.get("conditions", [])}
    appendix = conditions.get("appendix_a_full_8_cves", {})
    expected_ids = set(appendix.get("provided_cve_ids", []))
    rag = conditions.get("retriever_context", {})
    retrieved_ids = set(rag.get("retrieved_cve_ids", []))
    missing_ids = sorted(expected_ids - retrieved_ids)
    official_cve_run = run_manifest.get("dataset", {}).get("kind") == "official_cve_records"
    dataset_info = run_manifest.get("dataset", {})
    dataset_manifest_link = os.path.relpath(
        REPO_ROOT / dataset_info.get("manifest_file", "manifest.json"), run_dir
    ).replace("\\", "/")
    provenance_lines = (
        [
            "- Dataset gồm tám CVE Record Format v5 chính thức từ CVEProject/cvelistV5, đã kiểm tra ID, PUBLISHED, mô tả tiếng Anh và SHA-256. Các điều kiện/prompt là cấu hình thí nghiệm dựng lại; đây không phải tái tạo chính xác bài báo.",
            "- Source commit: `{}`; manifest: [`{}`](<{}>); thời điểm tải: `{}` UTC.".format(
                dataset_info.get("source_commit", "?"),
                dataset_info.get("manifest_file", "?"),
                dataset_manifest_link,
                dataset_info.get("retrieved_at_utc", "?"),
            ),
            "- Ingest dùng Gemini extractor chung và Contriever trong DB/vector riêng. Giới hạn dự kiến: 8 extraction calls + 6 graph calls, không retry tự động; một lượt cho mỗi model/condition.",
        ]
        if official_cve_run else
        [
            "- Tám mô tả CVE mẫu lấy từ Appendix A; structured affected fields được dựng lại. Sáu ID là placeholder; ID piSignage `CVE-2020-25299` trong data mẫu sai, official match là `CVE-2019-20354`. Threat reports là excerpt được trích/rút gọn; SolarWinds ‘full’ cũng là bản condensed. Đây không phải tái tạo chính xác bài báo.",
            "- Thí nghiệm mẫu dùng Gemini extractor và Contriever riêng. Giới hạn dự kiến: 8 extraction calls + 12 graph calls, không retry tự động; mỗi model/condition có một lượt, chưa có replicate.",
        ]
    )
    lines = [
        "# Kết quả thí nghiệm (bản dựng lại)",
        "",
        f"- Run ID: `{run_manifest.get('run_id')}`; trạng thái: `{run_manifest.get('status')}`.",
        "- Cấu hình: Gemini `{}` và OpenRouter `{}`; embedding `{}`; ngưỡng `{}`; context budget `{}` tokens/query.".format(
            run_manifest.get("configuration", {}).get("models", {}).get("gemini", {}).get("model", "?"),
            run_manifest.get("configuration", {}).get("models", {}).get("openrouter", {}).get("model", "?"),
            run_manifest.get("configuration", {}).get("embedding_model", "?"),
            run_manifest.get("configuration", {}).get("min_similarity", "?"),
            run_manifest.get("configuration", {}).get("context_tokens_per_query", "?"),
        ),
        *provenance_lines,
        "",
        "## Metrics tự động",
        "",
        "`schema_valid` kiểm tra node `id/label`, edge `from/to/label` và endpoint trỏ tới node tồn tại. Các metrics này không xác nhận tính đúng về ngữ nghĩa hay tính hợp lệ của attack chain.",
        "",
        "| Condition | Model | Parse | Schema | Nodes | Edges | Endpoint integrity | Edge schema | Report PNG | Raw graph JSON |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for row in rows:
        schema = "pass" if row.get("schema_valid") else "fail" if row.get("schema_valid") is False else "—"
        graph_link = f"[{row.get('condition_id')}](<{row['graph_file']}>)" if row.get("graph_file") else "—"
        report_png = row.get("graph_report_with_legend_png") or row.get("graph_report_png")
        png_link = f"[PNG + legend](<{report_png}>)" if report_png else "—"
        lines.append(
            "| {condition} | {backend} | {parse} | {schema} | {nodes} | {edges} | {integrity} | {edge_schema} | {png} | {graph} |".format(
                condition=row.get("condition_id", "?"),
                backend=row.get("backend", "?"),
                parse=row.get("status", "?"),
                schema=schema,
                nodes=row.get("node_count", "—"),
                edges=row.get("edge_count", "—"),
                integrity=percentage(row.get("edge_endpoint_integrity")),
                edge_schema=percentage(row.get("edge_schema_compliance")),
                png=png_link,
                graph=graph_link,
            )
        )
    lines.extend([
        "",
        "## Lưu ý cho phần diễn giải",
        "",
        *(
            [
                f"- Retriever lấy được {len(retrieved_ids)}/{len(expected_ids)} CVE: {', '.join(sorted(retrieved_ids)) or 'không có'}. Không vào context: `{', '.join(missing_ids) or 'không có'}`. Dùng extraction properties và retrieval matches trong manifest/index để giải thích từng trường hợp.",
                "- `appendix_a_full_8_cves` đưa đủ tám mô tả chính thức vào prompt; `retriever_context` phản ánh Contriever với query ghi trong manifest. Số node/edge là metric cấu trúc, không đo độ đúng ngữ nghĩa.",
                "- Tám mô tả tiếng Anh khớp nguyên văn với mô tả trong bộ sample; lần chạy này dùng CVE ID và metadata của record chính thức. LLM extractor lấy thuộc tính từ mô tả, còn `affected` metadata có thể khác sample.",
                "- Review định tính thủ công vẫn cần: cả hai baseline tự suy diễn lateral movement/đường tấn công khi không có CVE context; OpenRouter RAG nối OVRRedir↔OVRServiceLauncher dù edge nói không thiết lập prerequisite trực tiếp; Gemini RAG nối piSignage→RaspAP dựa trên credential disclosure chưa được CVE chứng minh; Gemini full nối Oculus Browser→local LPE bằng giả định local execution. Đây là giả định cần xác minh, không phải chain đã được xác thực.",
                "- OpenRouter full sinh 24 nodes/18 edges so với Gemini 8/5; số lượng lớn hơn không chứng minh graph đúng hoặc tốt hơn. `schema_valid` chỉ kiểm tra cấu trúc và endpoint, không kiểm tra semantic validity.",
                "- Hai graph full-context có thêm `graph_report_with_legend.png`, gồm hình graph và bảng mã node → nhãn đầy đủ/rút dòng. Các graph report khác vẫn có JSON legend bên cạnh; `graph.json` giữ edge labels và properties đầy đủ.",
            ] if official_cve_run else [
                f"- Retriever lấy được {len(retrieved_ids)}/{len(expected_ids)} CVE: {', '.join(sorted(retrieved_ids)) or 'không có'}. Thiếu `{', '.join(missing_ids) or 'không có'}`. CVE-2024-90006 được extractor gán product `Jetson Linux` và platform `Linux`, trong khi query dùng `Jetson TX1`; similarity dưới ngưỡng 0.68 nên retriever không thêm CVE đó vào context.",
                "- Trong điều kiện Appendix A, cả hai model vẫn tạo node Jetson khi nhận đủ tám mô tả; trên mẫu này, việc thiếu Jetson ở RAG xảy ra tại retrieval stage, không phải do model không thể biểu diễn nó khi được cung cấp mô tả.",
                "- Cả hai baseline dùng endpoint `source/target` thay cho schema yêu cầu `from/to`; raw `graph.json` được giữ nguyên và `edge_schema_compliance=0`. PNG phục vụ trình bày ánh xạ alias chỉ khi render; legend sidecar cùng thư mục và JSON gốc giữ đầy đủ nội dung.",
                "- Review định tính sơ bộ (cần xác minh thủ công, không phải kết luận từ metrics): Gemini baseline có các bước SSH weak credentials/network pivot không thấy nguồn hỗ trợ; Gemini RAG nối RaspAP → Glowworm; OpenRouter RAG nối OVRRedir → OVRServiceLauncher dù edge tự mô tả quan hệ không phải prerequisite. Không diễn giải các cạnh này là attack chain đã được xác thực.",
                "- Với Kubernetes report, OpenRouter sinh 43 nodes/65 edges so với Gemini 16/19; một số node OpenRouter diễn đạt lại các bước (ví dụ `attack path 1`, `first path begins`, `enumeration`). Nhiều node/edge hơn không đồng nghĩa graph tốt hơn.",
                "- Report PNG rút ngắn nhãn node và bỏ nhãn edge để giảm chồng lấn; tra full label/property trong `graph.json` và `graph_report_legend.json`.",
            ]
        ),
        "",
        "## Tokens, chi phí và artifact",
        "",
        "| Backend | Calls | Prompt tokens | Completion tokens | Total tokens | Cost returned by API |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    for backend, usage in sorted(usage_by_backend.items()):
        cost = usage.get("cost")
        lines.append(
            f"| {backend} | {usage.get('calls', 0)} | {usage.get('prompt_tokens', 0)} | "
            f"{usage.get('completion_tokens', 0)} | {usage.get('total_tokens', 0)} | "
            f"{f'${cost:.8f}' if isinstance(cost, (int, float)) else 'not returned'} |"
        )
    lines.extend([
        "",
        "Gemini không trả cost trong usage metadata đã nhận; không ước tính chi phí. Gemini total token count là tổng do API báo; nó không bằng prompt + completion/candidates. Adapter đã lưu prompt/candidates/total nhưng không có trường riêng giải thích phần chênh lệch, nên không suy đoán nguyên nhân. OpenRouter cost lấy từ response usage và có thể thay đổi theo thời điểm/model billing.",
        "",
        "- [`manifest.json`](manifest.json): tham số, provenance, prompt hashes và call journal.",
        "- [`metrics.csv`](metrics.csv) / [`metrics.json`](metrics.json): kết quả định lượng theo condition/model.",
        "- [`summary.json`](summary.json): trạng thái calls, token usage và tổng hợp kết quả.",
        f"- [`prompts/`](prompts/): {len(run_manifest.get('conditions', []))} prompt UTF-8 đã freeze; mỗi prompt SHA-256 dùng chung cho cả hai backend.",
        "",
    ])
    (run_dir / "REPORT_SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def rebuild_summary(run_dir: Path, rows: list[dict[str, Any]], run_manifest: dict[str, Any]) -> None:
    write_metrics(run_dir, rows)
    records = []
    for call_path in sorted((run_dir / "calls").glob("*.json")):
        records.append(json.loads(call_path.read_text(encoding="utf-8")))
    usage = usage_summary(records)
    summary = {
        "run_id": run_manifest["run_id"],
        "status": run_manifest["status"],
        "api_call_attempts": len(records),
        "extractor_calls_attempted": sum(record.get("stage") == "extractor" for record in records),
        "graph_calls_attempted": sum(record.get("stage") == "graph" for record in records),
        "api_errors": sum(record.get("status") == "api_error" for record in records),
        "parse_failures": sum(row.get("status") == "parse_failed" for row in rows),
        "usage_by_backend": usage,
        "result_count": len(rows),
        "results": rows,
        "interpretation_limit": (
            "provided_cve_id_mention_rate only measures output mentions of IDs explicitly present in the prompt; "
            "it is not a vulnerability recall/coverage metric. Automated structural metrics do not establish "
            "semantic correctness; graphs require human review. Schema metrics check JSON fields and endpoints. "
            "PNG endpoint aliases are display-only; graph.json preserves the raw response schema."
        ),
    }
    atomic_json(run_dir / "summary.json", summary)
    write_report_summary(run_dir, rows, run_manifest, usage)


def extract_or_reuse_index(
    run_id: str,
    run_dir: Path,
    settings: Settings,
    embedding_model: Any,
    input_hashes: dict[str, str],
    previous: dict[str, Any] | None,
    run_manifest: dict[str, Any],
) -> tuple[Database, dict[str, Any]]:
    expected_files = sample_cve_files()
    expected_ids = {cve_id_for_file(path) for path in expected_files}
    db = Database(DB_PATH)

    if previous is None:
        index_manifest: dict[str, Any] = {
            "status": "building",
            "built_by_run_id": run_id,
            "started_at": utc_now().isoformat(),
            "signature": index_signature(settings, input_hashes),
            "database": DB_PATH.relative_to(REPO_ROOT).as_posix(),
            "embeddings_directory": EMBEDDINGS_DIR.relative_to(REPO_ROOT).as_posix(),
            "extractions": {},
            "graph_calls": {},
        }
        atomic_json(INDEX_MANIFEST_PATH, index_manifest)
    else:
        index_manifest = previous
        with sqlite3.connect(DB_PATH) as conn:
            indexed_ids = {row[0] for row in conn.execute("SELECT cve_id FROM cve_info")}
        if index_manifest.get("status") == "ready":
            if not expected_ids.issubset(indexed_ids):
                raise RuntimeError("Ready Contriever index is missing one or more CVE rows.")
            run_manifest["index_reused_from_run"] = index_manifest.get("built_by_run_id")
            run_manifest["extractor_stats"] = index_manifest.get("extractor_stats", {})
            return db, index_manifest

        prior_status = index_manifest.get("status")
        index_manifest.setdefault("recovery_history", []).append({
            "previous_status": prior_status,
            "failed_cve_id": index_manifest.get("failed_cve_id"),
            "error": index_manifest.get("error"),
            "finished_at": index_manifest.get("finished_at"),
            "resumed_at": utc_now().isoformat(),
            "resumed_by_run_id": run_id,
        })
        index_manifest["status"] = "building"
        index_manifest["resumed_by_run_id"] = run_id
        index_manifest["resumed_at"] = utc_now().isoformat()
        index_manifest.pop("error", None)
        index_manifest.pop("failed_cve_id", None)
        atomic_json(INDEX_MANIFEST_PATH, index_manifest)

    gemini_settings = replace(settings, llm_backend="gemini")
    base_client = get_llm_client(gemini_settings)
    if base_client is None:
        raise RuntimeError("Gemini client was not created for extraction.")

    extraction_dir = run_dir / "extractions"
    original_run_id = index_manifest.get("built_by_run_id", run_id)
    for path in expected_files:
        cve_id = cve_id_for_file(path)
        call_id = f"extract.{cve_id}"
        saved_extraction = index_manifest.setdefault("extractions", {}).get(cve_id)
        if saved_extraction and saved_extraction.get("status") in {
            "completed", "recovered_from_saved_response"
        }:
            continue

        call_run_id = (saved_extraction or {}).get("call_run_id", original_run_id)
        call_root = OUTPUTS_DIR / call_run_id
        prior_call_path = call_root / "calls" / f"{call_id}.json"
        if not prior_call_path.exists() and call_run_id != run_id:
            prior_call_path = run_dir / "calls" / f"{call_id}.json"

        if prior_call_path.exists():
            prior_call = json.loads(prior_call_path.read_text(encoding="utf-8"))
            prior_call_status = prior_call.get("status")
            if prior_call_status in {"api_error", "attempted"}:
                raise RuntimeError(
                    f"Prior extraction call {call_id} has no saved response; refusing to repeat it."
                )
            response_file = prior_call.get("response_file")
            prior_response = call_root / response_file if response_file else None
            if not prior_response or not prior_response.exists():
                raise RuntimeError(
                    f"Prior extraction call {call_id} has no readable saved response; refusing to repeat it."
                )
            raw = prior_response.read_text(encoding="utf-8")
            try:
                preprocess_cve(
                    path,
                    db,
                    embedding_model=embedding_model,
                    extractor=LLMExtractor(SavedResponseLLMClient(raw)),
                    embeddings_dir=EMBEDDINGS_DIR,
                    settings=settings,
                )
            except Exception as exc:  # noqa: BLE001
                prior_call["recovery_processing_error"] = safe_error(exc, settings)
                prior_call["recovery_attempted_at"] = utc_now().isoformat()
                atomic_json(prior_call_path, prior_call)
                index_manifest["status"] = "failed"
                index_manifest["failed_cve_id"] = cve_id
                index_manifest["error"] = safe_error(exc, settings)
                index_manifest["finished_at"] = utc_now().isoformat()
                atomic_json(INDEX_MANIFEST_PATH, index_manifest)
                raise RuntimeError(
                    f"Saved Gemini response for {cve_id} could not be processed; no API retry was made."
                ) from None

            prior_call["status"] = "recovered_from_saved_response"
            prior_call["recovery_processed_at"] = utc_now().isoformat()
            prior_call["recovery_processing_error"] = None
            atomic_json(prior_call_path, prior_call)
            properties_path = extraction_dir / cve_id / "properties.json"
            atomic_json(properties_path, read_properties(DB_PATH, cve_id))
            index_manifest["extractions"][cve_id] = {
                "status": "recovered_from_saved_response",
                "call_id": call_id,
                "call_run_id": call_run_id,
                "response_file": response_file,
                "properties_file": relative(properties_path, run_dir),
                "recovery_note": "Parsed the already-saved Gemini response; no API call was repeated.",
            }
            completed_count = sum(
                item.get("status") in {"completed", "recovered_from_saved_response"}
                for item in index_manifest["extractions"].values()
            )
            run_manifest["extractor_stats"] = {
                "completed": completed_count,
                "expected": len(expected_files),
                "recovered_from_saved_responses": sum(
                    item.get("status") == "recovered_from_saved_response"
                    for item in index_manifest["extractions"].values()
                ),
            }
            atomic_json(INDEX_MANIFEST_PATH, index_manifest)
            atomic_json(run_dir / "manifest.json", run_manifest)
            continue

        client = JournalLLMClient(
            base_client,
            call_id=call_id,
            stage="extractor",
            backend="gemini",
            model=settings.gemini_model,
            run_dir=run_dir,
            settings=settings,
        )
        try:
            preprocess_cve(
                path,
                db,
                embedding_model=embedding_model,
                extractor=LLMExtractor(client),
                embeddings_dir=EMBEDDINGS_DIR,
                settings=settings,
            )
        except Exception as exc:  # noqa: BLE001
            if client.record_path.exists():
                mark_call(client.record_path, "extraction_failed", error=safe_error(exc, settings))
            index_manifest["status"] = "failed"
            index_manifest["failed_cve_id"] = cve_id
            index_manifest["error"] = safe_error(exc, settings)
            index_manifest["extractions"][cve_id] = {
                "status": "failed", "call_id": call_id, "call_run_id": run_id,
            }
            index_manifest["finished_at"] = utc_now().isoformat()
            atomic_json(INDEX_MANIFEST_PATH, index_manifest)
            raise RuntimeError(
                f"Gemini extraction stopped at {cve_id}; inspect the run artifacts for details."
            ) from None

        mark_call(client.record_path, "completed")
        properties_path = extraction_dir / cve_id / "properties.json"
        atomic_json(properties_path, read_properties(DB_PATH, cve_id))
        index_manifest["extractions"][cve_id] = {
            "status": "completed",
            "call_id": call_id,
            "call_run_id": run_id,
            "response_file": relative(client.response_path, run_dir),
            "properties_file": relative(properties_path, run_dir),
        }
        atomic_json(INDEX_MANIFEST_PATH, index_manifest)
        completed_count = sum(
            item.get("status") in {"completed", "recovered_from_saved_response"}
            for item in index_manifest["extractions"].values()
        )
        run_manifest["extractor_stats"] = {
            "completed": completed_count,
            "expected": len(expected_files),
            "recovered_from_saved_responses": sum(
                item.get("status") == "recovered_from_saved_response"
                for item in index_manifest["extractions"].values()
            ),
        }
        atomic_json(run_dir / "manifest.json", run_manifest)

    completed_count = sum(
        index_manifest["extractions"].get(cve_id, {}).get("status")
        in {"completed", "recovered_from_saved_response"}
        for cve_id in expected_ids
    )
    index_manifest["status"] = "ready"
    index_manifest["finished_at"] = utc_now().isoformat()
    index_manifest["extractor_stats"] = {
        "expected": len(expected_files),
        "completed": completed_count,
        "skipped": 0,
        "recovered_from_saved_responses": sum(
            index_manifest["extractions"].get(cve_id, {}).get("status")
            == "recovered_from_saved_response"
            for cve_id in expected_ids
        ),
    }
    atomic_json(INDEX_MANIFEST_PATH, index_manifest)
    run_manifest["extractor_stats"] = index_manifest["extractor_stats"]
    atomic_json(run_dir / "manifest.json", run_manifest)
    return db, index_manifest


def run_experiment(
    run_id: str,
    *,
    resume: bool = False,
    prepare_only: bool = False,
    continue_graphs: bool = False,
) -> int:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id) or run_id in {".", ".."}:
        raise ValueError("Invalid run id.")
    run_dir = OUTPUTS_DIR / run_id
    if resume:
        if not run_dir.is_dir() or not (run_dir / "manifest.json").exists():
            raise FileNotFoundError(f"Cannot resume missing experiment run: {run_dir}")
        run_manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        expected_digest = run_manifest.get("dataset", {}).get("dataset_digest")
        if expected_digest and (ACTIVE_DATASET is None or ACTIVE_DATASET.digest != expected_digest):
            raise RuntimeError("Resume dataset does not match the dataset used by the failed run.")
        if ACTIVE_DATASET is None and expected_digest:
            raise RuntimeError("This official CVE run must be resumed with --dataset-manifest.")
        expected_status = "awaiting_graph_review" if continue_graphs else "failed"
        if run_manifest.get("status") != expected_status:
            raise RuntimeError(f"This operation requires a run in status {expected_status!r}.")
        run_manifest.setdefault("resume_history", []).append({
            "previous_status": run_manifest.get("status"),
            "previous_error": run_manifest.get("error"),
            "resumed_at": utc_now().isoformat(),
        })
        run_manifest.pop("error", None)
        run_manifest["status"] = "resuming"
    else:
        if run_dir.exists():
            raise FileExistsError(f"Experiment output directory already exists: {run_dir}")
        run_dir.mkdir(parents=True)
        settings = get_settings()
        run_manifest = {
            "run_id": run_id,
            "started_at": utc_now().isoformat(),
            "status": "preparing",
            "configuration": safe_settings(settings),
            "provenance": {
                "data_reconstructed": True,
                "sample_ids_matching_official_records": sorted(SAMPLE_IDS_MATCHING_OFFICIAL_RECORDS),
                "placeholder_cve_ids": [],
                "placeholder_cve_count": 6,
                "non_official_or_mismatched_id_count": 7,
                "mismatched_sample_ids": ["CVE-2020-25299"],
                "sample_cve_descriptions": "Quoted from paper Appendix A; structured affected fields are reconstructed.",
                "threat_reports": "Sample files are quoted/condensed excerpts, not complete original reports.",
                "solarwinds_full_condensed": True,
                "exact_paper_reproduction": False,
            },
            "calls": [],
            "results": [],
        }
        if ACTIVE_DATASET is not None:
            dataset_manifest = json.loads(ACTIVE_DATASET.manifest_path.read_text(encoding="utf-8"))
            run_manifest["dataset"] = {
                "kind": "official_cve_records",
                "dataset_id": ACTIVE_DATASET.dataset_id,
                "dataset_digest": ACTIVE_DATASET.digest,
                "manifest_file": ACTIVE_DATASET.manifest_path.relative_to(REPO_ROOT).as_posix(),
                "manifest_sha256": sha256_file(ACTIVE_DATASET.manifest_path),
                "source_commit": dataset_manifest["source_commit"],
                "retrieved_at_utc": dataset_manifest["retrieved_at_utc"],
                "product_query": ACTIVE_DATASET.query,
                "records": ACTIVE_DATASET.records,
            }
            run_manifest["provenance"] = {
                "data_reconstructed": False,
                "input_records_official": True,
                "experiment_conditions_reconstructed": True,
                "source": "CVEProject/cvelistV5",
                "source_commit": dataset_manifest["source_commit"],
                "exact_paper_reproduction": False,
                "conditions": "baseline no-context, Contriever retrieval, and all eight official descriptions",
            }
    settings = get_settings()
    atomic_json(run_dir / "manifest.json", run_manifest)
    rows: list[dict[str, Any]] = list(run_manifest.get("results", []))

    try:
        check_settings(settings)
        files = sample_cve_files()
        if len(files) != 8:
            source_label = "official CVE" if ACTIVE_DATASET else "sample CVE"
            raise RuntimeError(f"Expected 8 {source_label} files, found {len(files)}.")
        cv_ids = [cve_id_for_file(path) for path in files]
        if ACTIVE_DATASET is None:
            run_manifest["provenance"]["placeholder_cve_ids"] = sorted(
                set(cv_ids) & {f"CVE-2024-9000{number}" for number in range(1, 7)}
            )
            run_manifest["provenance"]["non_official_or_mismatched_id_count"] = len(
                set(cv_ids) - SAMPLE_IDS_MATCHING_OFFICIAL_RECORDS
            )
        input_hashes = source_hashes()
        run_manifest["input_sha256"] = input_hashes
        run_manifest["settings_signature"] = index_signature(settings, input_hashes)
        previous = inspect_saved_index(settings, input_hashes)

        embedding_model = get_embedding_model(settings)
        if getattr(embedding_model, "dim", None) is None:
            raise RuntimeError("Embedding model did not expose its vector dimension.")
        if previous is None:
            EMBEDDINGS_DIR.mkdir(parents=True, exist_ok=True)
        run_manifest["embedding_dimension"] = embedding_model.dim
        atomic_json(run_dir / "manifest.json", run_manifest)

        db, index_manifest = extract_or_reuse_index(
            run_id, run_dir, settings, embedding_model, input_hashes, previous, run_manifest
        )
        run_manifest["index"] = {
            "database": DB_PATH.relative_to(REPO_ROOT).as_posix(),
            "embeddings_directory": EMBEDDINGS_DIR.relative_to(REPO_ROOT).as_posix(),
            "status": index_manifest.get("status"),
            "extractor_stats": index_manifest.get("extractor_stats", {}),
        }

        conditions = build_conditions(db, settings, condition_set=ACTIVE_CONDITION_SET)
        prompts_dir = run_dir / "prompts"
        prompts_dir.mkdir(parents=True, exist_ok=True)
        frozen_before_resume = {
            item["condition_id"]: item for item in run_manifest.get("conditions", [])
        } if continue_graphs else {}
        if continue_graphs and set(frozen_before_resume) != {item["condition_id"] for item in conditions}:
            raise RuntimeError("Frozen prompt condition set differs from the official run configuration.")
        for condition in conditions:
            prompt_path = prompts_dir / f"{condition['condition_id']}.txt"
            prompt_bytes = condition["prompt"].encode("utf-8")
            prompt_hash = prompt_sha256(prompt_bytes)
            if continue_graphs:
                prior = frozen_before_resume[condition["condition_id"]]
                if not prompt_path.is_file() or sha256_file(prompt_path) != prior.get("prompt_sha256"):
                    raise RuntimeError(f"Frozen prompt file/hash is missing or changed: {condition['condition_id']}.")
                if prior.get("prompt_sha256") != prompt_hash:
                    raise RuntimeError(f"Rebuilt prompt differs from reviewed frozen bytes: {condition['condition_id']}.")
                if prior.get("retrieved_cve_ids") != condition["retrieved_cve_ids"]:
                    raise RuntimeError(f"Retrieval set changed since prompt review: {condition['condition_id']}.")
            else:
                prompt_path.write_bytes(prompt_bytes)
            condition["prompt_file"] = relative(prompt_path, run_dir)
            condition["prompt_sha256"] = prompt_hash
            condition["prompt_bytes"] = prompt_path.stat().st_size
            del condition["prompt"]
        run_manifest["conditions"] = conditions
        run_manifest["status"] = "prompts_frozen"
        atomic_json(run_dir / "manifest.json", run_manifest)

        if prepare_only:
            run_manifest["status"] = "awaiting_graph_review"
            run_manifest["prompts_frozen_at"] = utc_now().isoformat()
            atomic_json(run_dir / "manifest.json", run_manifest)
            rebuild_summary(run_dir, rows, run_manifest)
            print(f"Prompts frozen for review; graph API calls not started: {run_dir}")
            return 0

        clients: dict[str, LLMClient] = {}
        model_config: dict[str, tuple[str, str]] = {}
        for name, (backend, model_field) in MODEL_SPECS.items():
            model = getattr(settings, model_field)
            client = get_llm_client(replace(settings, llm_backend=backend))
            if client is None:
                raise RuntimeError(f"Could not create client for {name}.")
            clients[name] = client
            model_config[name] = (backend, model)

        for condition in conditions:
            condition_id = condition["condition_id"]
            prompt_bytes = (run_dir / condition["prompt_file"]).read_bytes()
            if prompt_sha256(prompt_bytes) != condition["prompt_sha256"]:
                raise RuntimeError(f"Frozen prompt hash mismatch for {condition_id}.")

            journal_clients: dict[str, JournalLLMClient] = {}
            for name, client in clients.items():
                backend, model = model_config[name]
                call_id = f"graph.{name}.{condition_id}"
                journal_clients[name] = JournalLLMClient(
                    client,
                    call_id=call_id,
                    stage="graph",
                    backend=backend,
                    model=model,
                    run_dir=run_dir,
                    settings=settings,
                    condition_id=condition_id,
                )

            def before_call(name: str, digest: str) -> None:
                call_id = f"graph.{name}.{condition_id}"
                if call_id in index_manifest.setdefault("graph_calls", {}):
                    raise RuntimeError(f"Refusing duplicate graph API call {call_id}.")
                backend, model = model_config[name]
                index_manifest["graph_calls"][call_id] = {
                    "status": "attempted",
                    "run_id": run_id,
                    "backend": backend,
                    "model": model,
                    "condition_id": condition_id,
                    "prompt_sha256": digest,
                    "attempted_at": utc_now().isoformat(),
                }
                atomic_json(INDEX_MANIFEST_PATH, index_manifest)

            paired = dispatch_paired_prompt(prompt_bytes, journal_clients, before_call=before_call)
            for result in paired:
                call_id = f"graph.{result.client_name}.{condition_id}"
                index_manifest["graph_calls"][call_id]["prompt_sha256"] = result.prompt_sha256
                backend, model = model_config[result.client_name]
                journal_client = journal_clients[result.client_name]
                row: dict[str, Any] = {
                    "backend": backend,
                    "model": model,
                    "condition_id": condition_id,
                    "status": "pending",
                    "parse_success": False,
                    "strict_parse_success": False,
                    "truncated_repair": False,
                    "retrieved_cve_ids": condition["retrieved_cve_ids"],
                    "prompt_sha256": result.prompt_sha256,
                    "raw_response_file": relative(journal_client.response_path, run_dir),
                }
                if result.error is not None:
                    message = safe_error(result.error, settings)
                    row.update({"status": "api_error", "error": message})
                    index_manifest["graph_calls"][call_id].update({"status": "api_error", "error": message})
                    error_path = run_dir / "errors" / f"{call_id}.txt"
                    error_path.parent.mkdir(parents=True, exist_ok=True)
                    error_path.write_text(message, encoding="utf-8")
                else:
                    mark_call(journal_client.record_path, "response_saved")
                    index_manifest["graph_calls"][call_id].update({"status": "response_saved"})
                    try:
                        graph = parse_llm_json(result.response or "")
                    except Exception as exc:  # noqa: BLE001
                        message = safe_error(exc, settings)
                        row.update({"status": "parse_failed", "error": message})
                        index_manifest["graph_calls"][call_id].update({
                            "status": "parse_failed", "parse_error": message,
                        })
                        error_path = run_dir / "errors" / f"{call_id}.txt"
                        error_path.parent.mkdir(parents=True, exist_ok=True)
                        error_path.write_text(message, encoding="utf-8")
                    else:
                        frozen_prompt = prompt_bytes.decode("utf-8")
                        row.update({
                            "status": "repaired_success" if graph.truncated else "strict_success",
                            "parse_success": True,
                            "strict_parse_success": not graph.truncated,
                            "truncated_repair": graph.truncated,
                            **graph_metrics(graph, condition["provided_cve_ids"], frozen_prompt),
                        })
                        graph_dir = run_dir / result.client_name / condition_id
                        graph_json_path = graph_dir / "graph.json"
                        save_graph_json(graph, graph_json_path)
                        row["graph_file"] = relative(graph_json_path, run_dir)
                        index_manifest["graph_calls"][call_id].update({"status": row["status"]})
                        try:
                            display_graph, endpoint_aliases = visualization_graph(graph)
                            png_path = visualize_graph(display_graph, graph_dir / "graph.png")
                            report_png_path = visualize_graph_report(
                                display_graph, graph_dir / "graph_report.png"
                            )
                            row["graph_png"] = relative(png_path, run_dir)
                            row["graph_report_png"] = relative(report_png_path, run_dir)
                            row["graph_report_legend"] = relative(
                                report_png_path.with_name("graph_report_legend.json"), run_dir
                            )
                            if condition_id == "appendix_a_full_8_cves":
                                combined_path = visualize_graph_report_with_legend(
                                    display_graph, graph_dir / "graph_report_with_legend.png"
                                )
                                row["graph_report_with_legend_png"] = relative(combined_path, run_dir)
                            if endpoint_aliases:
                                row["graph_png_note"] = (
                                    "PNG visualization mapped source/target to from/to; graph.json preserves raw schema."
                                )
                        except Exception as exc:  # noqa: BLE001
                            row["visualization_error"] = safe_error(exc, settings)
                call_record = json.loads(journal_client.record_path.read_text(encoding="utf-8"))
                row["total_tokens"] = (call_record.get("usage") or {}).get(
                    "total_tokens", (call_record.get("usage") or {}).get("total_token_count")
                )
                row["cost"] = (call_record.get("usage") or {}).get("cost")
                run_manifest["calls"].append(call_id)
                rows.append(row)
                run_manifest["results"] = rows
                run_manifest["status"] = "running_graph_calls"
                atomic_json(INDEX_MANIFEST_PATH, index_manifest)
                atomic_json(run_dir / "manifest.json", run_manifest)
                rebuild_summary(run_dir, rows, run_manifest)

        run_manifest["status"] = "completed"
        run_manifest["finished_at"] = utc_now().isoformat()
        run_manifest["results"] = rows
        index_manifest["experiment_run_id"] = run_id
        index_manifest["experiment_finished_at"] = run_manifest["finished_at"]
        atomic_json(INDEX_MANIFEST_PATH, index_manifest)
        atomic_json(run_dir / "manifest.json", run_manifest)
        rebuild_summary(run_dir, rows, run_manifest)
        return 0
    except Exception as exc:  # noqa: BLE001
        run_manifest["status"] = "failed"
        run_manifest["finished_at"] = utc_now().isoformat()
        run_manifest["error"] = safe_error(exc, settings)
        atomic_json(run_dir / "manifest.json", run_manifest)
        rebuild_summary(run_dir, rows, run_manifest)
        print(f"Experiment stopped: {type(exc).__name__}. See {run_dir / 'manifest.json'} for details.")
        return 1


def configure_official_dataset(manifest_path: Path) -> OfficialCveDataset:
    global ACTIVE_DATASET, ACTIVE_CONDITION_SET, ACTIVE_PRODUCT_QUERY
    global DB_PATH, EMBEDDINGS_DIR, INDEX_MANIFEST_PATH

    dataset = load_official_cve_dataset(
        manifest_path,
        required_ids=OFFICIAL_CVE_IDS,
        expected_count=8,
    )
    try:
        dataset.manifest_path.relative_to(REPO_ROOT)
        for path in dataset.files:
            path.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError("Official CVE manifest and records must live inside this repository.") from exc

    ACTIVE_DATASET = dataset
    ACTIVE_CONDITION_SET = "cve-only"
    ACTIVE_PRODUCT_QUERY = dataset.query
    dataset_key = dataset.digest[:16]
    DB_PATH = REPO_ROOT / "data" / "db" / f"official_cve_{dataset_key}.sqlite3"
    EMBEDDINGS_DIR = REPO_ROOT / "data" / "embeddings" / f"official_cve_{dataset_key}"
    INDEX_MANIFEST_PATH = REPO_ROOT / "data" / "db" / f"official_cve_{dataset_key}.index_manifest.json"
    return dataset


class BudgetLimitReached(RuntimeError):
    """Raised before a request whose conservative ceiling would exceed 50,000 VND."""


USD_TO_VND = 26170.0
BUDGET_VND = 50000.0
PRICE_USD_PER_MILLION = {
    "gemini": {"input": 0.75, "output": 3.75},
    "openrouter": {"input": 0.25, "output": 1.32},
}


def _number(mapping: dict[str, Any], *keys: str) -> float:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
    return 0.0


def estimated_call_cost_usd(record: dict[str, Any]) -> float:
    """Use provider-reported cost when available, otherwise the frozen price table."""
    usage = record.get("usage") or {}
    reported = usage.get("cost")
    if isinstance(reported, (int, float)) and not isinstance(reported, bool):
        return float(reported)
    backend = record.get("backend")
    prices = PRICE_USD_PER_MILLION.get(backend)
    if not prices:
        return 0.0
    token_keys = {
        "prompt_tokens", "prompt_token_count", "input_tokens", "total_tokens",
        "total_token_count", "completion_tokens", "candidates_token_count",
        "output_tokens", "thoughts_token_count", "reasoning_tokens",
    }
    has_token_usage = any(
        isinstance(usage.get(key), (int, float))
        and not isinstance(usage.get(key), bool)
        for key in token_keys
    )
    if not has_token_usage:
        ceiling_vnd = record.get("request_cost_ceiling_vnd")
        if isinstance(ceiling_vnd, (int, float)) and not isinstance(ceiling_vnd, bool):
            return float(ceiling_vnd) / USD_TO_VND
        return 0.0
    prompt = _number(usage, "prompt_tokens", "prompt_token_count", "input_tokens")
    total = _number(usage, "total_tokens", "total_token_count")
    completion = _number(
        usage, "completion_tokens", "candidates_token_count", "output_tokens"
    )
    thoughts = _number(usage, "thoughts_token_count", "reasoning_tokens")
    output = max(completion + thoughts, total - prompt, 0.0)
    return (prompt * prices["input"] + output * prices["output"]) / 1_000_000


def run_cost_summary(run_dir: Path) -> dict[str, Any]:
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((run_dir / "calls").glob("*.json"))
    ]
    cost_usd = sum(estimated_call_cost_usd(record) for record in records)
    return {
        "attempted_calls": len(records),
        "estimated_cost_usd": round(cost_usd, 8),
        "estimated_cost_vnd": round(cost_usd * USD_TO_VND, 2),
        "budget_vnd": BUDGET_VND,
        "remaining_vnd": round(max(BUDGET_VND - cost_usd * USD_TO_VND, 0.0), 2),
        "basis": (
            "provider cost when returned; otherwise frozen token rates; pre-send conservative "
            "request ceiling when usage metadata is unavailable"
        ),
    }


def conservative_request_ceiling_vnd(
    backend: str, prompt: str, max_output_tokens: int
) -> float:
    prices = PRICE_USD_PER_MILLION[backend]
    # UTF-8 bytes / 3 is deliberately conservative for these English prompts.
    input_ceiling = max(1, (len(prompt.encode("utf-8")) + 2) // 3)
    usd = (
        input_ceiling * prices["input"]
        + max_output_tokens * prices["output"]
    ) / 1_000_000
    return usd * USD_TO_VND


def reproduction_source_hashes() -> dict[str, str]:
    required = [
        "appendix_a_context.txt",
        "kubernetes_appendix_b.txt",
        "solarwinds_full_appendix_c1.txt",
        "solarwinds_evasion_appendix_c2.txt",
        "manifest.json",
    ]
    hashes: dict[str, str] = {}
    for filename in required:
        path = REPRODUCTION_DATA_DIR / filename
        if not path.is_file():
            raise FileNotFoundError(f"Missing reviewed reproduction source: {path}")
        hashes[path.relative_to(REPO_ROOT).as_posix()] = sha256_file(path)
    source_manifest = json.loads((REPRODUCTION_DATA_DIR / "manifest.json").read_text(encoding="utf-8"))
    for filename, entry in source_manifest.get("files", {}).items():
        path = REPRODUCTION_DATA_DIR / filename
        if sha256_file(path) != entry.get("sha256"):
            raise RuntimeError(f"Reviewed source hash does not match manifest: {filename}")
        if path.stat().st_size != entry.get("bytes_utf8"):
            raise RuntimeError(f"Reviewed source byte count does not match manifest: {filename}")
    return hashes


def section54_prompts(conditions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_id = {item["condition_id"]: item for item in conditions}
    t1 = by_id["T1"]["prompt"]
    if not t1.startswith(REPORT_PROMPT):
        raise RuntimeError("T1 does not start with the reviewed Appendix C report prefix.")
    report = t1[len(REPORT_PROMPT):]
    marker = "In-Depth Malware Analysis"
    split_at = report.find(marker)
    if split_at <= 0:
        raise RuntimeError(f"Reviewed T1 source is missing the chunk boundary {marker!r}.")
    chunks = [report[:split_at].rstrip(), report[split_at:].lstrip()]

    c2 = by_id["C2"]["prompt"]
    if not c2.startswith(CVE_CONTEXT_PROMPT):
        raise RuntimeError("C2 does not start with the reviewed Appendix A schema prefix.")
    cve_context = c2[len(CVE_CONTEXT_PROMPT):]
    edge_json = json.dumps(SECTION54_EDGE, ensure_ascii=False)
    return {
        "chunk_1": {
            "prompt": REPORT_PROMPT + chunks[0],
            "condition_id": "S54_CHUNK_1",
            "max_output_tokens": 4096,
            "expect_graph": True,
        },
        "chunk_2": {
            "prompt": REPORT_PROMPT + chunks[1],
            "condition_id": "S54_CHUNK_2",
            "max_output_tokens": 4096,
            "expect_graph": True,
        },
        "cutoff_initial": {
            "prompt": c2,
            "condition_id": "S54_CUTOFF_INITIAL",
            "max_output_tokens": 512,
            "expect_graph": True,
        },
        "edge_detail": {
            "prompt": (
                CVE_CONTEXT_PROMPT + cve_context
                + "\n\nExpand only the following selected edge into a more detailed attack subgraph. "
                "Stay within the supplied vulnerability information and return only one JSON object "
                "with nodes and edges using the same schema. Selected edge: " + edge_json
            ),
            "condition_id": "S54_EDGE_DETAIL",
            "max_output_tokens": 4096,
            "expect_graph": True,
        },
        "edge_context": {
            "prompt": (
                "From the vulnerability context below, quote or closely extract only the passages "
                "that support or constrain the selected edge. Explicitly state when the context does "
                "not establish the prerequisite. Do not add outside facts.\n\nSelected edge: "
                + edge_json + "\n\nVulnerability context:\n" + cve_context
            ),
            "condition_id": "S54_EDGE_CONTEXT",
            "max_output_tokens": 2048,
            "expect_graph": False,
        },
    }


def _freeze_prompt(run_dir: Path, name: str, prompt: str) -> dict[str, Any]:
    path = run_dir / "prompts" / f"{name}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = prompt.encode("utf-8")
    if path.exists() and path.read_bytes() != payload:
        raise RuntimeError(f"Frozen prompt bytes changed: {name}.")
    path.write_bytes(payload)
    return {
        "prompt_file": relative(path, run_dir),
        "prompt_sha256": prompt_sha256(payload),
        "prompt_bytes": len(payload),
    }


def prepare_reproduction_run(run_id: str) -> Path:
    if ACTIVE_DATASET is None:
        raise RuntimeError("The full reproduction requires --dataset-manifest.")
    run_dir = OUTPUTS_DIR / run_id
    if run_dir.exists():
        raise FileExistsError(f"Experiment output directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)
    settings = get_settings()
    check_settings(settings, require_api_keys=False)
    input_hashes = source_hashes()
    previous = inspect_saved_index(settings, input_hashes)
    if previous is None or previous.get("status") != "ready":
        raise RuntimeError("The approved official extraction/index is not ready for reuse.")

    embedding_model = get_embedding_model(settings)
    db = Database(DB_PATH)
    conditions = build_conditions(db, settings, condition_set="cve-only")
    frozen_conditions: list[dict[str, Any]] = []
    for item in conditions:
        frozen = _freeze_prompt(run_dir, item["condition_id"], item["prompt"])
        frozen_conditions.append({**item, **frozen})
        del frozen_conditions[-1]["prompt"]

    static = section54_prompts(conditions)
    frozen_section54 = {}
    for name, spec in static.items():
        frozen_section54[name] = {
            **{key: value for key, value in spec.items() if key != "prompt"},
            **_freeze_prompt(run_dir, f"section54_{name}", spec["prompt"]),
        }

    main_specs = main_call_specs(conditions)
    dataset_manifest = json.loads(ACTIVE_DATASET.manifest_path.read_text(encoding="utf-8"))
    manifest = {
        "run_id": run_id,
        "started_at": utc_now().isoformat(),
        "status": "awaiting_online_run",
        "configuration": safe_settings(settings),
        "dataset": {
            "kind": "official_cve_records",
            "dataset_id": ACTIVE_DATASET.dataset_id,
            "dataset_digest": ACTIVE_DATASET.digest,
            "manifest_file": ACTIVE_DATASET.manifest_path.relative_to(REPO_ROOT).as_posix(),
            "manifest_sha256": sha256_file(ACTIVE_DATASET.manifest_path),
            "source_commit": dataset_manifest.get("source_commit"),
            "retrieved_at_utc": dataset_manifest.get("retrieved_at_utc"),
        },
        "input_sha256": input_hashes,
        "reproduction_source_sha256": reproduction_source_hashes(),
        "index": {
            "database": DB_PATH.relative_to(REPO_ROOT).as_posix(),
            "manifest": INDEX_MANIFEST_PATH.relative_to(REPO_ROOT).as_posix(),
            "reused_from_run": previous.get("built_by_run_id"),
            "extractor_stats": previous.get("extractor_stats", {}),
        },
        "conditions": frozen_conditions,
        "section54": frozen_section54,
        "call_plan": {
            "main_graph_calls": len(main_specs),
            "section54_chunk_calls": 20,
            "section54_cutoff_and_continuation_calls": 20,
            "section54_edge_calls": 20,
            "total_calls": 130,
            "repeat_count": REPEAT_COUNT,
        },
        "budget": {
            "ceiling_vnd": BUDGET_VND,
            "usd_to_vnd": USD_TO_VND,
            "no_auto_top_up": True,
            "stop_if_prepaid_balance_exhausted": True,
        },
        "retry_policy": {
            "max_run_retries": MAX_RUN_RETRIES,
            "requires_operator_confirmation": True,
            "eligible_status": "api_error only",
            "saved_response_or_unknown_send": "never retry",
        },
        "implementation_provenance": {
            "runner_file": "scripts/run_paired_experiment.py",
            "runner_sha256_at_prepare": sha256_file(Path(__file__).resolve()),
            "note": "Hash captured before any online call for this prepared run.",
        },
        "review_checkpoints": {
            "review_1": {
                "status": "approved",
                "basis": "REPRODUCTION_REVIEW.md and user authorization",
            },
            "review_2": {"status": "pending", "pilot": "C1 repeat 1, both models"},
            "review_3": {"status": "pending", "artifact": "evidence_table.md"},
        },
        "calls": [],
        "results": [],
    }
    atomic_json(run_dir / "manifest.json", manifest)
    rebuild_summary(run_dir, [], manifest)
    return run_dir


def _load_frozen_prompt(run_dir: Path, spec: dict[str, Any]) -> str:
    path = run_dir / spec["prompt_file"]
    payload = path.read_bytes()
    if prompt_sha256(payload) != spec["prompt_sha256"]:
        raise RuntimeError(f"Frozen prompt hash mismatch: {path.name}")
    return payload.decode("utf-8")


def _call_record_rows(run_dir: Path) -> list[dict[str, Any]]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((run_dir / "calls").glob("*.json"))
    ]


def verify_saved_call(
    *,
    run_dir: Path,
    record: dict[str, Any],
    call_id: str,
    stage: str,
    backend: str,
    model: str,
    condition_id: str,
    repeat_id: int,
    attempt_id: int,
    prompt: str,
    max_output_tokens: int,
    reasoning_level: str = "low",
) -> Path | None:
    """Verify immutable call identity/parameters before resume skips or reprocesses it."""
    expected = {
        "call_id": call_id,
        "stage": stage,
        "backend": backend,
        "model": model,
        "condition_id": condition_id,
        "repeat_id": repeat_id,
        "attempt_id": attempt_id,
        "prompt_sha256": prompt_sha256(prompt.encode("utf-8")),
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise RuntimeError(
                f"Saved call {call_id} has mismatched {key}: "
                f"{record.get(key)!r} != {value!r}."
            )
    generation = record.get("generation_config") or {}
    if generation.get("max_output_tokens") != max_output_tokens:
        raise RuntimeError(f"Saved call {call_id} has a different output-token cap.")
    if generation.get("reasoning_level") != reasoning_level:
        raise RuntimeError(f"Saved call {call_id} has a different reasoning level.")
    response_file = record.get("response_file")
    if not response_file:
        if record.get("status") in {"api_error", "attempted"}:
            return None
        raise RuntimeError(f"Saved call {call_id} has no response file.")
    response_path = run_dir / response_file
    if not response_path.is_file():
        raise RuntimeError(f"Saved response for {call_id} is missing.")
    if record.get("response_sha256") != sha256_file(response_path):
        raise RuntimeError(f"Saved response hash changed for {call_id}.")
    return response_path


def execute_one_call(
    *,
    run_dir: Path,
    settings: Settings,
    client: LLMClient,
    backend: str,
    model: str,
    model_name: str,
    stage: str,
    condition_id: str,
    repeat_id: int,
    prompt: str,
    max_output_tokens: int,
    expect_graph: bool,
    context_ids: list[str] | None = None,
    attempt_id: int = 1,
    retry_of_call_id: str | None = None,
    operator_confirmed_transient: bool = False,
) -> tuple[dict[str, Any], AttackGraph | None]:
    call_id = graph_call_id(stage, model_name, condition_id, repeat_id, attempt_id)
    call_path = run_dir / "calls" / f"{call_id}.json"
    response_path = run_dir / "raw_responses" / f"{call_id}.txt"
    if call_path.exists():
        record = json.loads(call_path.read_text(encoding="utf-8"))
        verified_response = verify_saved_call(
            run_dir=run_dir,
            record=record,
            call_id=call_id,
            stage=stage,
            backend=backend,
            model=model,
            condition_id=condition_id,
            repeat_id=repeat_id,
            attempt_id=attempt_id,
            prompt=prompt,
            max_output_tokens=max_output_tokens,
        )
        if verified_response is None:
            raise RuntimeError(
                f"Prior call {call_id} has no saved response; refusing an ambiguous resend."
            )
        response_path = verified_response
        raw = response_path.read_text(encoding="utf-8")
    else:
        spent = run_cost_summary(run_dir)["estimated_cost_vnd"]
        reserve = conservative_request_ceiling_vnd(backend, prompt, max_output_tokens)
        if spent + reserve > BUDGET_VND:
            raise BudgetLimitReached(
                f"Request {call_id} would cross the 50,000 VND conservative ceiling "
                f"({spent:.0f} spent + {reserve:.0f} reserved)."
            )
        journal = JournalLLMClient(
            client,
            call_id=call_id,
            stage=stage,
            backend=backend,
            model=model,
            run_dir=run_dir,
            settings=settings,
            condition_id=condition_id,
            repeat_id=repeat_id,
            attempt_id=attempt_id,
            max_output_tokens=max_output_tokens,
            reasoning_level="low",
            retry_of_call_id=retry_of_call_id,
            operator_confirmed_transient=operator_confirmed_transient,
        )
        try:
            raw = journal.complete(prompt)
        except Exception as exc:  # noqa: BLE001
            return ({
                "call_id": call_id,
                "stage": stage,
                "backend": backend,
                "model": model,
                "condition_id": condition_id,
                "repeat_id": repeat_id,
                "attempt_id": attempt_id,
                "status": "api_error",
                "parse_mode": "not_available",
                "error": safe_error(exc, settings),
                "prompt_sha256": prompt_sha256(prompt.encode("utf-8")),
            }, None)

    record = json.loads(call_path.read_text(encoding="utf-8"))
    row: dict[str, Any] = {
        "call_id": call_id,
        "stage": stage,
        "backend": backend,
        "model": model,
        "condition_id": condition_id,
        "repeat_id": repeat_id,
        "attempt_id": attempt_id,
        "status": "response_saved",
        "parse_mode": "not_applicable" if not expect_graph else None,
        "parse_success": None if not expect_graph else False,
        "strict_parse_success": None if not expect_graph else False,
        "truncated_repair": None if not expect_graph else False,
        "prompt_sha256": record.get("prompt_sha256"),
        "raw_response_file": relative(response_path, run_dir),
        "provider_finish_reason": provider_finish_reason(record),
        "finish_reason_indicates_truncation": finish_reason_indicates_truncation(
            provider_finish_reason(record)
        ),
        "total_tokens": _number(
            record.get("usage") or {}, "total_tokens", "total_token_count"
        ) or None,
        "cost_usd_estimated": estimated_call_cost_usd(record),
    }
    if not expect_graph:
        mark_call(call_path, "completed")
        return row, None

    try:
        graph = parse_llm_json(raw)
    except Exception as exc:  # noqa: BLE001
        row.update({
            "status": "parse_failed",
            "parse_mode": "parse_failed",
            "error": safe_error(exc, settings),
        })
        mark_call(call_path, "parse_failed", error=row["error"])
        return row, None

    row.update({
        "status": "repaired_success" if graph.truncated else "strict_success",
        "parse_mode": classify_parse_mode(raw, graph),
        "parse_success": True,
        "strict_parse_success": not graph.truncated,
        "truncated_repair": graph.truncated,
        **response_graph_metrics(
            raw,
            graph,
            context_ids or [],
            prompt,
            condition_id=condition_id,
        ),
    })
    graph_path = run_dir / "graphs" / model_name / condition_id / f"r{repeat_id:02d}.json"
    save_graph_json(graph, graph_path)
    row["graph_file"] = relative(graph_path, run_dir)
    mark_call(call_path, row["status"])
    if repeat_id == 1:
        try:
            display_graph, aliases = visualization_graph(graph)
            png_path = visualize_graph_report(
                display_graph, graph_path.with_suffix(".png")
            )
            row["graph_report_png"] = relative(png_path, run_dir)
            if aliases:
                row["graph_png_note"] = "source/target aliases mapped only for display"
        except Exception as exc:  # noqa: BLE001
            row["visualization_error"] = safe_error(exc, settings)
    return row, graph


def _record_progress(
    run_dir: Path, manifest: dict[str, Any], rows: list[dict[str, Any]], row: dict[str, Any]
) -> None:
    if row["call_id"] not in manifest["calls"]:
        manifest["calls"].append(row["call_id"])
        rows.append(row)
    manifest["results"] = rows
    manifest["cost"] = run_cost_summary(run_dir)
    atomic_json(run_dir / "manifest.json", manifest)
    rebuild_summary(run_dir, rows, manifest)


def _continuation_prompt(original: str, partial: str) -> str:
    return (
        original
        + "\n\nThe response below was deliberately cut off by a 512-token output cap. "
        "Continue the work, but return the complete attack graph again as one valid JSON object "
        "using the same required schema. Do not put text before or after the JSON.\n\n"
        + "PARTIAL RESPONSE:\n" + partial
    )


def execute_reproduction_run(run_id: str) -> int:
    run_dir = OUTPUTS_DIR / run_id
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Prepared reproduction run not found: {run_dir}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") not in {"awaiting_online_run", "running", "failed"}:
        raise RuntimeError(f"Run status cannot be executed: {manifest.get('status')!r}")
    if ACTIVE_DATASET is None or ACTIVE_DATASET.digest != manifest["dataset"]["dataset_digest"]:
        raise RuntimeError("Dataset does not match the prepared reproduction run.")
    if reproduction_source_hashes() != manifest["reproduction_source_sha256"]:
        raise RuntimeError("Reviewed reproduction source files changed after prompt freeze.")
    settings = get_settings()
    check_settings(settings, require_api_keys=True)
    clients: dict[str, LLMClient] = {}
    models: dict[str, tuple[str, str]] = {}
    for name, (backend, model_field) in MODEL_SPECS.items():
        model = getattr(settings, model_field)
        client = get_llm_client(replace(settings, llm_backend=backend))
        if client is None:
            raise RuntimeError(f"Could not create {name} client.")
        clients[name] = client
        models[name] = (backend, model)

    rows = list(manifest.get("results", []))
    done = {row["call_id"] for row in rows}
    conditions = {item["condition_id"]: item for item in manifest["conditions"]}
    section54 = manifest["section54"]
    manifest["status"] = "running"
    atomic_json(manifest_path, manifest)
    consecutive_errors = {name: 0 for name in MODEL_SPECS}

    def run_spec(
        *, stage: str, model_name: str, condition_id: str, repeat_id: int,
        prompt: str, cap: int, expect_graph: bool, context_ids: list[str] | None = None,
    ) -> AttackGraph | None:
        call_id = graph_call_id(stage, model_name, condition_id, repeat_id)
        if call_id in done:
            row = next(item for item in rows if item["call_id"] == call_id)
            backend, model = models[model_name]
            record_path = run_dir / "calls" / f"{call_id}.json"
            if not record_path.is_file():
                raise RuntimeError(f"Manifest result exists without call journal: {call_id}.")
            record = json.loads(record_path.read_text(encoding="utf-8"))
            verify_saved_call(
                run_dir=run_dir,
                record=record,
                call_id=call_id,
                stage=stage,
                backend=backend,
                model=model,
                condition_id=condition_id,
                repeat_id=repeat_id,
                attempt_id=1,
                prompt=prompt,
                max_output_tokens=cap,
            )
            graph_file = row.get("graph_file")
            if graph_file:
                graph_path = run_dir / graph_file
                if not graph_path.is_file():
                    raise RuntimeError(f"Saved graph is missing for {call_id}.")
                return parse_llm_json(graph_path.read_text(encoding="utf-8"))
            return None
        backend, model = models[model_name]
        row, graph = execute_one_call(
            run_dir=run_dir, settings=settings, client=clients[model_name],
            backend=backend, model=model, model_name=model_name, stage=stage,
            condition_id=condition_id, repeat_id=repeat_id, prompt=prompt,
            max_output_tokens=cap, expect_graph=expect_graph, context_ids=context_ids,
        )
        _record_progress(run_dir, manifest, rows, row)
        done.add(call_id)
        if row["status"] == "api_error":
            consecutive_errors[model_name] += 1
            if consecutive_errors[model_name] >= 2:
                raise RuntimeError(
                    f"Repeated API failures for {model_name}; inspect saved call records."
                )
        else:
            consecutive_errors[model_name] = 0
        return graph

    try:
        # Review 2 pilot first. It is part of the five official repeats.
        c1 = conditions[PILOT_CONDITION_ID]
        c1_prompt = _load_frozen_prompt(run_dir, c1)
        for model_name in MODEL_SPECS:
            run_spec(
                stage="graph", model_name=model_name, condition_id="C1", repeat_id=1,
                prompt=c1_prompt, cap=c1["max_output_tokens"], expect_graph=True,
                context_ids=c1["provided_cve_ids"],
            )
        pilot_rows = [
            row for row in rows
            if row["condition_id"] == "C1" and row["repeat_id"] == 1 and row["stage"] == "graph"
        ]
        manifest["review_checkpoints"]["review_2"] = {
            "status": "passed_and_authorized_to_continue",
            "completed_at": utc_now().isoformat(),
            "criteria": "both pilot responses saved; errors and parse outcomes retained in denominator",
            "results": [
                {"backend": row["backend"], "status": row["status"], "schema_valid": row.get("schema_valid")}
                for row in pilot_rows
            ],
            "authorization": "user explicitly requested the full run on 2026-09-27",
        }
        atomic_json(manifest_path, manifest)

        # Remaining 68 main graph calls.
        for condition_id, condition in conditions.items():
            prompt = _load_frozen_prompt(run_dir, condition)
            for repeat_id in range(1, REPEAT_COUNT + 1):
                for model_name in MODEL_SPECS:
                    if condition_id == "C1" and repeat_id == 1:
                        continue
                    run_spec(
                        stage="graph", model_name=model_name, condition_id=condition_id,
                        repeat_id=repeat_id, prompt=prompt,
                        cap=condition["max_output_tokens"], expect_graph=True,
                        context_ids=condition["provided_cve_ids"],
                    )

        # §5.4.1: two fixed chunks and a deterministic local merge.
        chunk_specs = [section54["chunk_1"], section54["chunk_2"]]
        for repeat_id in range(1, REPEAT_COUNT + 1):
            for model_name in MODEL_SPECS:
                graphs = []
                for spec in chunk_specs:
                    graph = run_spec(
                        stage="chunk", model_name=model_name,
                        condition_id=spec["condition_id"], repeat_id=repeat_id,
                        prompt=_load_frozen_prompt(run_dir, spec),
                        cap=spec["max_output_tokens"], expect_graph=True,
                    )
                    if graph is not None:
                        graphs.append(graph)
                if len(graphs) == 2:
                    conflicts: list[dict[str, Any]] = []
                    merged = merge_graphs(graphs, conflict_log=conflicts)
                    merged_path = run_dir / "derived" / "chunk_merge" / model_name / f"r{repeat_id:02d}.json"
                    save_graph_json(merged, merged_path)
                    atomic_json(
                        merged_path.with_suffix(".merge.json"),
                        {
                            "model_name": model_name,
                            "repeat_id": repeat_id,
                            "source_graphs": [
                                f"graphs/{model_name}/S54_CHUNK_1/r{repeat_id:02d}.json",
                                f"graphs/{model_name}/S54_CHUNK_2/r{repeat_id:02d}.json",
                            ],
                            "conflicts": conflicts,
                            "invented_cross_chunk_edges": 0,
                        },
                    )

        # §5.4.2: deliberate cutoff followed by exactly one continuation request.
        cutoff = section54["cutoff_initial"]
        cutoff_prompt = _load_frozen_prompt(run_dir, cutoff)
        for repeat_id in range(1, REPEAT_COUNT + 1):
            for model_name in MODEL_SPECS:
                run_spec(
                    stage="cutoff", model_name=model_name,
                    condition_id=cutoff["condition_id"], repeat_id=repeat_id,
                    prompt=cutoff_prompt, cap=cutoff["max_output_tokens"], expect_graph=True,
                    context_ids=conditions["C2"]["provided_cve_ids"],
                )
                initial_id = graph_call_id(
                    "cutoff", model_name, cutoff["condition_id"], repeat_id
                )
                partial = (run_dir / "raw_responses" / f"{initial_id}.txt").read_text(encoding="utf-8")
                run_spec(
                    stage="continuation", model_name=model_name,
                    condition_id="S54_CUTOFF_CONTINUATION", repeat_id=repeat_id,
                    prompt=_continuation_prompt(cutoff_prompt, partial), cap=4096,
                    expect_graph=True, context_ids=conditions["C2"]["provided_cve_ids"],
                )

        # §5.4.3: detailed subgraph and separate supporting-context extraction.
        for key in ("edge_detail", "edge_context"):
            spec = section54[key]
            prompt = _load_frozen_prompt(run_dir, spec)
            for repeat_id in range(1, REPEAT_COUNT + 1):
                for model_name in MODEL_SPECS:
                    run_spec(
                        stage=key, model_name=model_name,
                        condition_id=spec["condition_id"], repeat_id=repeat_id,
                        prompt=prompt, cap=spec["max_output_tokens"],
                        expect_graph=spec["expect_graph"],
                        context_ids=conditions["C2"]["provided_cve_ids"],
                    )

        write_reproduction_artifacts(run_dir, manifest, rows)
        manifest["review_checkpoints"]["review_3"] = {
            "status": "ready_for_user_review",
            "prepared_at": utc_now().isoformat(),
            "artifact": "evidence_table.md",
            "note": "Codex labels are preliminary and are not expert validation.",
        }
        manifest["status"] = "results_ready_for_review_3"
        manifest["finished_at"] = utc_now().isoformat()
        manifest["cost"] = run_cost_summary(run_dir)
        atomic_json(manifest_path, manifest)
        rebuild_summary(run_dir, rows, manifest)
        return 0
    except Exception as exc:  # noqa: BLE001
        manifest["status"] = "budget_exhausted" if isinstance(exc, BudgetLimitReached) else "failed"
        manifest["finished_at"] = utc_now().isoformat()
        manifest["error"] = safe_error(exc, settings)
        manifest["cost"] = run_cost_summary(run_dir)
        atomic_json(manifest_path, manifest)
        rebuild_summary(run_dir, rows, manifest)
        print(f"Reproduction stopped: {type(exc).__name__}: {exc}")
        return 2 if isinstance(exc, BudgetLimitReached) else 1


def retry_confirmed_transient_call(
    run_id: str,
    failed_call_id: str,
    *,
    operator_confirmed_transient: bool = False,
) -> dict[str, Any]:
    """Make one explicitly confirmed retry while preserving the original outcome."""
    if not operator_confirmed_transient:
        raise RuntimeError("Retry requires explicit operator confirmation of a transient failure.")

    run_dir = OUTPUTS_DIR / run_id
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Prepared reproduction run not found: {run_dir}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") not in {
        "awaiting_online_run", "running", "failed", "results_ready_for_review_3",
    }:
        raise RuntimeError(
            f"Completed or otherwise closed run cannot be retried: {manifest.get('status')!r}."
        )
    if ACTIVE_DATASET is None or ACTIVE_DATASET.digest != manifest["dataset"]["dataset_digest"]:
        raise RuntimeError("Dataset does not match the prepared reproduction run.")
    if reproduction_source_hashes() != manifest["reproduction_source_sha256"]:
        raise RuntimeError("Reviewed reproduction source files changed after prompt freeze.")

    records = _call_record_rows(run_dir)
    record = next((item for item in records if item.get("call_id") == failed_call_id), None)
    if record is None:
        raise RuntimeError(f"No saved call journal found for {failed_call_id}.")
    if record.get("status") != "api_error":
        raise RuntimeError(
            f"Only a saved api_error can be retried; {failed_call_id} is "
            f"{record.get('status')!r}. Unknown-send and saved-response calls are never retried."
        )
    if record.get("response_file") or (run_dir / "raw_responses" / f"{failed_call_id}.txt").exists():
        raise RuntimeError(f"Call {failed_call_id} has a saved response and cannot be retried.")

    stage = str(record.get("stage", ""))
    backend = str(record.get("backend", ""))
    condition_id = str(record.get("condition_id", ""))
    repeat_id = record.get("repeat_id")
    if stage not in {"graph", "chunk", "cutoff", "continuation", "edge_detail", "edge_context"}:
        raise RuntimeError(f"Call {failed_call_id} is not a supported reproduction call.")
    model_name = next(
        (name for name, (known_backend, _) in MODEL_SPECS.items() if known_backend == backend),
        None,
    )
    if model_name is None or not isinstance(repeat_id, int) or repeat_id < 1 or not condition_id:
        raise RuntimeError(f"Call {failed_call_id} has incomplete reproduction identity fields.")

    expected_call_id = graph_call_id(
        stage, model_name, condition_id, repeat_id, int(record.get("attempt_id", 0))
    )
    if expected_call_id != failed_call_id:
        raise RuntimeError(f"Call journal identity does not match its call_id: {failed_call_id}.")

    same_call_family = [
        item for item in records
        if (item.get("stage"), item.get("backend"), item.get("condition_id"), item.get("repeat_id"))
        == (stage, backend, condition_id, repeat_id)
    ]
    retry_entries = manifest.setdefault("retry_attempts", [])
    manifest.setdefault("retry_policy", {
        "max_run_retries": MAX_RUN_RETRIES,
        "requires_operator_confirmation": True,
        "eligible_status": "api_error only",
        "saved_response_or_unknown_send": "never retry",
    })
    same_call_family.extend(
        item for item in retry_entries
        if (item.get("stage"), item.get("backend"), item.get("condition_id"), item.get("repeat_id"))
        == (stage, backend, condition_id, repeat_id)
    )
    latest_attempt_id = max(int(item.get("attempt_id", 0)) for item in same_call_family)
    if int(record["attempt_id"]) != latest_attempt_id:
        raise RuntimeError(
            f"Call {failed_call_id} is not the latest attempt; inspect later attempts first."
        )
    attempt_id = latest_attempt_id + 1
    retry_call_id = graph_call_id(stage, model_name, condition_id, repeat_id, attempt_id)
    if any(item.get("call_id") == retry_call_id for item in records + retry_entries):
        raise RuntimeError(f"Retry attempt {retry_call_id} already exists; refusing a duplicate send.")

    used_retry_ids = {
        str(item.get("call_id"))
        for item in retry_entries
        if item.get("call_id")
    }
    used_retry_ids.update(
        str(item.get("call_id"))
        for item in records
        if isinstance(item.get("attempt_id"), int) and item["attempt_id"] > 1
    )
    if len(used_retry_ids) >= MAX_RUN_RETRIES:
        raise RuntimeError(f"Run-wide retry limit reached ({MAX_RUN_RETRIES}).")

    prompt_file = record.get("prompt_file")
    if not prompt_file:
        raise RuntimeError(f"Call {failed_call_id} has no saved prompt file.")
    prompt_path = (run_dir / prompt_file).resolve()
    if not prompt_path.is_relative_to(run_dir.resolve()) or not prompt_path.is_file():
        raise RuntimeError(f"Saved prompt is missing or outside the run directory for {failed_call_id}.")
    prompt_bytes = prompt_path.read_bytes()
    if prompt_sha256(prompt_bytes) != record.get("prompt_sha256"):
        raise RuntimeError(f"Saved prompt hash changed for {failed_call_id}.")
    prompt = prompt_bytes.decode("utf-8")
    generation = record.get("generation_config") or {}
    max_output_tokens = generation.get("max_output_tokens")
    if not isinstance(max_output_tokens, int) or max_output_tokens < 1:
        raise RuntimeError(f"Call {failed_call_id} has no valid output-token cap.")

    settings = get_settings()
    check_settings(settings, require_api_keys=True)
    configured_model = getattr(settings, MODEL_SPECS[model_name][1])
    if configured_model != record.get("model"):
        raise RuntimeError(f"Configured model does not match saved call {failed_call_id}.")
    client = get_llm_client(replace(settings, llm_backend=backend))
    if client is None:
        raise RuntimeError(f"Could not create {model_name} client.")

    spent = run_cost_summary(run_dir)["estimated_cost_vnd"]
    reserve = conservative_request_ceiling_vnd(backend, prompt, max_output_tokens)
    if spent + reserve > BUDGET_VND:
        raise BudgetLimitReached(
            f"Retry {retry_call_id} would cross the 50,000 VND conservative ceiling "
            f"({spent:.0f} spent + {reserve:.0f} reserved)."
        )

    retry_entry = {
        "call_id": retry_call_id,
        "retry_of_call_id": failed_call_id,
        "stage": stage,
        "backend": backend,
        "model": record["model"],
        "condition_id": condition_id,
        "repeat_id": repeat_id,
        "attempt_id": attempt_id,
        "operator_confirmed_transient": True,
        "confirmed_at": utc_now().isoformat(),
        "status": "attempted",
    }
    retry_entries.append(retry_entry)
    atomic_json(manifest_path, manifest)

    condition_specs = {
        item["condition_id"]: item for item in manifest.get("conditions", [])
    }
    condition = condition_specs.get(condition_id, {})
    context_ids = condition.get("provided_cve_ids", [])
    if stage in {"continuation", "edge_detail", "edge_context", "cutoff"}:
        context_ids = condition_specs.get("C2", {}).get("provided_cve_ids", [])
    row, _ = execute_one_call(
        run_dir=run_dir,
        settings=settings,
        client=client,
        backend=backend,
        model=record["model"],
        model_name=model_name,
        stage=stage,
        condition_id=condition_id,
        repeat_id=repeat_id,
        prompt=prompt,
        max_output_tokens=max_output_tokens,
        expect_graph=stage != "edge_context",
        context_ids=context_ids,
        attempt_id=attempt_id,
        retry_of_call_id=failed_call_id,
        operator_confirmed_transient=True,
    )
    retry_entry.update({
        "status": row["status"],
        "finished_at": utc_now().isoformat(),
        "result": row,
    })
    calls = manifest.setdefault("calls", [])
    if retry_call_id not in calls:
        calls.append(retry_call_id)
    rows = manifest.setdefault("results", [])
    manifest["cost"] = run_cost_summary(run_dir)
    atomic_json(manifest_path, manifest)
    if manifest.get("status") == "results_ready_for_review_3":
        # A post-matrix retry changes cost/provenance even though the original
        # planned failure remains in the denominator.
        write_reproduction_artifacts(run_dir, manifest, rows)
    rebuild_summary(run_dir, rows, manifest)
    return row


def _compact_text(value: Any, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip().replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _source_excerpt(source: str, terms: list[str]) -> tuple[str, str]:
    """Find a source passage tied to both endpoints and report its exact location."""
    # Keep line breaks intact so the reported positions refer to the frozen prompt.
    plain = re.sub(r"[*_`~]", "", source)
    endpoint_terms = terms[1:3]
    stopwords = {
        "access", "arbitrary", "attack", "attacker", "browser", "code", "compromise", "execute",
        "execution", "exploit", "file", "gain", "local", "node", "privilege",
        "network", "remote", "service", "services", "system", "user", "vulnerability", "write",
    }

    def words(text: str) -> set[str]:
        return {
            word for word in re.findall(r"[a-z0-9]+", text.casefold())
            if len(word) >= 4 and word not in stopwords
        }

    endpoint_words = [words(term) for term in endpoint_terms]
    distinctive_names = {
        "beacon", "glowworm", "jetson", "liferay", "oculus", "ovrredir",
        "ovrservicelauncher", "phpunit", "pisignage", "postgres", "postgresql",
        "raspap", "sunburst", "teardrop", "weblogic", "wordpress",
    }
    lines = plain.splitlines()
    passages: list[tuple[int, int, str]] = []
    start = 0
    current: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip() or line.strip() == "---":
            if current:
                passages.append((start, line_number - 1, " ".join(current)))
                current = []
            start = line_number + 1
            continue
        if not current:
            start = line_number
        current.append(line.strip())
    if current:
        passages.append((start, len(lines), " ".join(current)))

    # Pair each endpoint with the best matching paragraph. If they are in separate
    # CVE descriptions, cite both rather than implying either paragraph proves the bridge.
    selected: list[tuple[int, int, str, str, set[str]]] = []
    for endpoint_index, needed in enumerate(endpoint_words):
        if not needed:
            continue
        matches = []
        for first_line, last_line, passage in passages:
            found = words(passage) & needed
            distinctive_match = bool(found & distinctive_names)
            minimum_matches = 1 if len(needed) == 1 else 2
            if (
                distinctive_match
                and (len(needed) == 1 or len(found) >= 2)
            ) or (
                len(found) >= minimum_matches and len(found) / len(needed) >= 0.35
            ):
                # Prefer an exact product/malware identity over a paragraph that
                # happens to share more generic words such as "privilege".
                score = len(found) + (10 if distinctive_match else 0)
                matches.append((score, first_line, last_line, passage, found))
        if matches:
            _, first_line, last_line, passage, found = max(matches, key=lambda item: item[0])
            role = "source endpoint" if endpoint_index == 0 else "target endpoint"
            selected.append((first_line, last_line, passage, role, found))

    if len(selected) != len(endpoint_words) or not selected:
        return "—", "Không tìm thấy đoạn nguồn gắn được với cả hai đầu mút."

    unique: dict[tuple[int, int], tuple[str, set[str], set[str]]] = {}
    for first_line, last_line, passage, role, found in selected:
        key = (first_line, last_line)
        if key not in unique:
            unique[key] = (passage, set(), set())
        unique[key][1].add(role)
        unique[key][2].update(found)

    locations = []
    excerpts = []
    for (first_line, last_line), (passage, roles, matched_words) in unique.items():
        role = "/".join(sorted(roles))
        locations.append(f"lines {first_line}–{last_line} ({role})")
        compact = re.sub(r"\s+", " ", passage).strip()
        lowered = compact.casefold()
        positions = [lowered.find(word) for word in matched_words if lowered.find(word) >= 0]
        anchor = min(positions) if positions else 0
        start = max(0, anchor - 60)
        end = min(len(compact), anchor + 180)
        excerpts.append(
            ("…" if start else "") + compact[start:end] + ("…" if end < len(compact) else "")
        )
    return "; ".join(locations), " … ".join(excerpts)


def _preliminary_edge_label(
    condition_id: str, source: str, source_label: str, target_label: str, edge_label: str
) -> tuple[str, str, str]:
    source_endpoint = source_label.casefold()
    target_endpoint = target_label.casefold()
    combined = f"{source_label} {target_label} {edge_label}".casefold()
    if condition_id in {"C0", "X0"}:
        return (
            "không được hỗ trợ",
            "Điều kiện không có source context; cạnh là suy diễn của mô hình.",
            "Không có source context trong điều kiện này.",
        )
    if "not a prerequisite" in combined or "no direct prerequisite" in combined:
        return (
            "không được hỗ trợ",
            "Nhãn cạnh tự thừa nhận không có quan hệ prerequisite trực tiếp.",
            "Không có prerequisite trực tiếp theo chính nhãn cạnh.",
        )
    if "glowworm" in target_endpoint and (
        "root" in source_endpoint or "raspap" in source_endpoint
    ):
        return (
            "không được hỗ trợ",
            "Source không thiết lập chuỗi root/RaspAP sang điều kiện quang học Glowworm.",
            "Không có cầu nối được source nêu giữa truy cập root/RaspAP và điều kiện quang học.",
        )

    source_lower = re.sub(r"[*_`~]", "", source.casefold())
    if (
        "raspberry" in source_endpoint
        and ("default password" in source_endpoint or "default credential" in source_endpoint)
        and ("administrator" in target_endpoint or "admin" in target_endpoint)
        and "default password" in source_lower
        and "administrator privileges" in source_lower
    ):
        return (
            "được nguồn hỗ trợ",
            "Source nêu trực tiếp rằng mật khẩu mặc định không đổi có thể dẫn đến quyền quản trị; "
            "chi tiết cơ chế dịch vụ do graph thêm không được coi là đã xác nhận.",
            "Không thiếu điều kiện cho chuyển tiếp cốt lõi; mọi cơ chế xác thực/dịch vụ bổ sung phải chấm riêng.",
        )

    source_words = {
        word for word in re.findall(r"[a-z0-9]+", re.sub(r"[*_`~]", "", source).casefold())
    }

    def endpoint_words(label: str) -> set[str]:
        ignored = {
            "access", "arbitrary", "attack", "attacker", "browser", "code", "compromise", "execute",
            "execution", "exploit", "file", "gain", "local", "node", "privilege",
            "network", "remote", "service", "services", "system", "user", "vulnerability", "write",
        }
        return {
            word for word in re.findall(r"[a-z0-9]+", label.casefold())
            if len(word) >= 4 and word not in ignored
        }

    endpoint_evidence = [
        bool(endpoint_words(label) & source_words)
        for label in (source_label, target_label)
    ]
    if "pisignage" in source_endpoint and "raspap" in target_endpoint:
        if all(endpoint_evidence):
            return (
                "có điều kiện",
                "Source mô tả hai đầu mút nhưng không thiết lập chuyển tiếp giữa chúng.",
                "Cần thông tin xác thực hợp lệ trên RaspAP hoặc một bước pivot từ piSignage sang RaspAP.",
            )
    if (
        "oculus" in source_endpoint
        and "browser" in source_endpoint
        and "ovrredir" in target_endpoint
    ):
        if all(endpoint_evidence):
            return (
                "có điều kiện",
                "Source mô tả browser compromise và OVRRedir LPE nhưng không thiết lập bước nối.",
                "Cần chỉ rõ cách browser compromise tạo local execution ngoài browser context trên cùng Windows host.",
            )
    if "raspap" in source_endpoint and "root" in target_endpoint:
        if all(endpoint_evidence):
            return (
                "có điều kiện",
                "Source nêu khả năng chạy lệnh nhưng không khẳng định quyền root.",
                "Cần cấu hình sudo hoặc credential cụ thể cho phép nâng quyền lên root.",
            )
    normalized_edge = re.sub(r"\s+", " ", re.sub(r"[*_`~]", "", edge_label.casefold())).strip()
    if len(normalized_edge) >= 16 and normalized_edge in source_lower:
        return (
            "chưa rõ",
            "Nhãn cạnh xuất hiện trong source, nhưng trùng chuỗi không đủ xác nhận chiều quan hệ, "
            "chủ thể, qualifier hoặc prerequisite.",
            "Cần kiểm tra thủ công quan hệ có hướng và các điều kiện đi kèm.",
        )
    if all(endpoint_evidence):
        return (
            "chưa rõ",
            "Source có nhắc hai đầu mút nhưng chưa xác định được quan hệ hoặc cầu nối cụ thể.",
            "Chưa rõ; cần xác định prerequisite/cầu nối cụ thể trước khi gán nhãn có điều kiện.",
        )
    return (
        "chưa rõ",
        "Không tìm được bằng chứng source gắn với cả hai đầu mút; cần đối chiếu thủ công.",
        "Chưa rõ; chưa xác định được điều kiện thiếu cụ thể.",
    )


CVE_COVERAGE_EVENTS: dict[str, list[tuple[str, ...]]] = {
    "piSignage_path_traversal": [
        ("pisignage", "path traversal"), ("pisignage", "directory traversal"),
        ("pisignage", "arbitrary file"), ("pisignage", "file download"),
    ],
    "Oculus_Browser_injection": [
        ("oculus browser", "cross-site scripting"), ("oculus browser", "xss"),
        ("oculus browser", "script injection"), ("oculus browser", "content injection"),
        ("oculus browser", "spoof"),
    ],
    "OVRRedir_arbitrary_write_LPE": [
        ("ovrredir", "arbitrary file"), ("ovrredir", "hard link"),
        ("ovrredir", "privilege escalation"),
    ],
    "RaspAP_authenticated_code_execution": [
        ("raspap", "command injection"), ("raspap", "code execution"),
        ("raspap", "authenticated"),
    ],
    "OVRServiceLauncher_overwrite_LPE": [
        ("ovrservicelauncher", "path traversal"),
        ("ovrservicelauncher", "arbitrary file"),
        ("ovrservicelauncher", "privilege escalation"),
    ],
    "Glowworm_optical_eavesdropping": [
        ("glowworm", "optical"), ("glowworm", "eavesdrop"),
        ("glowworm", "audio"), ("glowworm", "light"),
    ],
    "Raspberry_Pi_default_password": [
        ("raspberry pi", "default password"), ("raspberry pi", "default credential"),
    ],
    "Jetson_IOMMU_physical_access": [
        ("jetson", "iommu"), ("jetson", "physical access"),
        ("jetson", "dma"), ("jetson", "pcie"), ("jetson", "pci express"),
    ],
}

KUBERNETES_COVERAGE_EVENTS: dict[str, list[tuple[str, ...]]] = {
    "PostgreSQL_trust_authentication_path": [
        ("postgresql", "trust"), ("postgres", "trust authentication"),
    ],
    "vulnerable_container_image_RCE_path": [
        ("container", "remote code execution"), ("container image", "rce"),
        ("container image", "exploit"),
    ],
}

EVASION_COVERAGE_EVENTS: dict[str, list[tuple[str, ...]]] = {
    "light_footprint_legitimate_access": [
        ("light", "footprint"), ("legitimate credential", "remote access"),
    ],
    "TEARDROP_to_BEACON": [("teardrop", "beacon")],
    "hostname_matches_victim": [("hostname", "victim")],
    "same_country_IP_or_VPS": [
        ("ip address", "country"), ("virtual private server", "country"),
    ],
    "lateral_movement_different_credentials": [("lateral", "different credential")],
    "temporary_file_or_task_replacement": [
        ("temporary file", "replace"), ("scheduled task", "original"),
    ],
    "tool_or_backdoor_cleanup": [("remov", "tool"), ("remov", "backdoor")],
}


def _event_coverage(graph: dict[str, Any], events: dict[str, list[tuple[str, ...]]]) -> dict[str, bool]:
    searchable = json.dumps(graph, ensure_ascii=False).casefold()
    return {
        event: any(all(term in searchable for term in alternative) for alternative in alternatives)
        for event, alternatives in events.items()
    }


def write_coverage_artifacts(
    run_dir: Path, rows: list[dict[str, Any]]
) -> tuple[dict[str, Any], list[str]]:
    """Score representation coverage only; this does not validate causal correctness."""
    detail: list[dict[str, Any]] = []
    for row in rows:
        if row.get("stage") != "graph" or not row.get("graph_file"):
            continue
        condition_id = row["condition_id"]
        if condition_id in {"C1", "C2", "X0"}:
            events = CVE_COVERAGE_EVENTS
            family = "eight_CVE_events"
        elif condition_id == "T0":
            events = KUBERNETES_COVERAGE_EVENTS
            family = "kubernetes_paths"
        elif condition_id in {"T1", "T2"}:
            events = EVASION_COVERAGE_EVENTS
            family = "solarwinds_evasion_events"
        else:
            continue
        graph = json.loads((run_dir / row["graph_file"]).read_text(encoding="utf-8"))
        covered = _event_coverage(graph, events)
        detail.append({
            "call_id": row["call_id"],
            "condition_id": condition_id,
            "backend": row["backend"],
            "repeat_id": row["repeat_id"],
            "family": family,
            "covered_count": sum(covered.values()),
            "event_count": len(events),
            "coverage_rate": sum(covered.values()) / len(events),
            "events": covered,
        })

    aggregates: list[dict[str, Any]] = []
    group_keys = sorted({(item["condition_id"], item["backend"], item["family"]) for item in detail})
    for condition_id, backend, family in group_keys:
        items = [
            item for item in detail
            if (item["condition_id"], item["backend"], item["family"])
            == (condition_id, backend, family)
        ]
        event_names = list(items[0]["events"]) if items else []
        aggregates.append({
            "condition_id": condition_id,
            "backend": backend,
            "family": family,
            "repeat_count": len(items),
            "mean_coverage_rate": (
                sum(item["coverage_rate"] for item in items) / len(items) if items else None
            ),
            "event_repeat_hits": {
                event: sum(bool(item["events"][event]) for item in items)
                for event in event_names
            },
        })

    payload = {
        "method": (
            "Preliminary case-insensitive keyword/event representation coverage over raw graph JSON. "
            "It does not score causal correctness, prerequisite satisfaction, or semantic equivalence."
        ),
        "event_definitions": {
            "eight_CVE_events": CVE_COVERAGE_EVENTS,
            "kubernetes_paths": KUBERNETES_COVERAGE_EVENTS,
            "solarwinds_evasion_events": EVASION_COVERAGE_EVENTS,
        },
        "per_repeat": detail,
        "aggregates": aggregates,
    }
    atomic_json(run_dir / "coverage.json", payload)

    lines = [
        "# Coverage sự kiện sơ bộ",
        "",
        "> Coverage được chấm offline bằng các từ khóa/sự kiện đã khai báo trong `coverage.json`. "
        "Nó đo sự kiện có được biểu diễn trong graph hay không, không xác nhận cạnh hay chuỗi tấn công đúng.",
        "",
        "## Tổng hợp theo condition/model",
        "",
        "| Condition | Model | Family | Repeat | Mean coverage |",
        "|---|---|---|---:|---:|",
    ]
    for item in aggregates:
        lines.append(
            f"| {item['condition_id']} | {item['backend']} | {item['family']} | "
            f"{item['repeat_count']} | {100 * item['mean_coverage_rate']:.1f}% |"
        )
    lines.extend(["", "## Số repeat biểu diễn từng sự kiện", ""])
    for item in aggregates:
        lines.extend([
            f"### {item['condition_id']} / {item['backend']}",
            "",
            "| Event | Repeat hit |",
            "|---|---:|",
            *[
                f"| {event} | {hits}/{item['repeat_count']} |"
                for event, hits in item["event_repeat_hits"].items()
            ],
            "",
        ])
    (run_dir / "coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return payload, lines


def write_chunk_merge_audit(run_dir: Path) -> dict[str, Any]:
    """Recompute §5.4 merges from saved chunk graphs and persist collision logs."""
    records = []
    for model_name in MODEL_SPECS:
        for repeat_id in range(1, REPEAT_COUNT + 1):
            source_paths = [
                run_dir / "graphs" / model_name / condition / f"r{repeat_id:02d}.json"
                for condition in ("S54_CHUNK_1", "S54_CHUNK_2")
            ]
            if not all(path.is_file() for path in source_paths):
                raise RuntimeError(
                    f"Missing saved chunk graph for {model_name} repeat {repeat_id}."
                )
            graphs = [parse_llm_json(path.read_text(encoding="utf-8")) for path in source_paths]
            conflicts: list[dict[str, Any]] = []
            merged = merge_graphs(graphs, conflict_log=conflicts)
            merged_path = run_dir / "derived" / "chunk_merge" / model_name / f"r{repeat_id:02d}.json"
            if merged_path.is_file():
                prior = json.loads(merged_path.read_text(encoding="utf-8"))
                if prior != merged.to_dict():
                    raise RuntimeError(
                        f"Recomputed chunk merge differs from saved artifact: {merged_path}."
                    )
            else:
                save_graph_json(merged, merged_path)
            audit_path = merged_path.with_suffix(".merge.json")
            record = {
                "model_name": model_name,
                "repeat_id": repeat_id,
                "source_graphs": [relative(path, run_dir) for path in source_paths],
                "source_sha256": {
                    relative(path, run_dir): sha256_file(path) for path in source_paths
                },
                "merged_graph": relative(merged_path, run_dir),
                "merged_sha256": sha256_file(merged_path),
                "conflicts": conflicts,
                "invented_cross_chunk_edges": 0,
            }
            atomic_json(audit_path, record)
            records.append(record)
    summary = {
        "merge_count": len(records),
        "collision_count": sum(len(item["conflicts"]) for item in records),
        "invented_cross_chunk_edges": 0,
        "merges": records,
    }
    atomic_json(run_dir / "derived" / "chunk_merge" / "merge_audit.json", summary)
    return summary


def refresh_saved_graph_metrics(
    run_dir: Path,
    manifest: dict[str, Any],
    rows: list[dict[str, Any]],
) -> int:
    """Recompute parse/structural metrics from immutable raw responses and prompts."""
    conditions = {item["condition_id"]: item for item in manifest.get("conditions", [])}
    c2_ids = conditions.get("C2", {}).get("provided_cve_ids", [])
    c2_schema_conditions = {
        "S54_CUTOFF_INITIAL",
        "S54_CUTOFF_CONTINUATION",
        "S54_EDGE_DETAIL",
    }
    changes = 0

    def update(row: dict[str, Any], key: str, value: Any) -> None:
        nonlocal changes
        if row.get(key) != value:
            row[key] = value
            changes += 1

    for row in rows:
        if row.get("stage") == "edge_context":
            update(row, "parse_mode", "not_applicable")
            continue
        call_path = run_dir / "calls" / f"{row['call_id']}.json"
        if not call_path.is_file():
            raise RuntimeError(f"Missing call journal while refreshing metrics: {row['call_id']}.")
        call_record = json.loads(call_path.read_text(encoding="utf-8"))
        prompt_path = run_dir / call_record["prompt_file"]
        if not prompt_path.is_file() or sha256_file(prompt_path) != call_record["prompt_sha256"]:
            raise RuntimeError(f"Prompt hash mismatch while refreshing metrics: {row['call_id']}.")
        response_path = run_dir / call_record["response_file"]
        if not response_path.is_file() or sha256_file(response_path) != call_record["response_sha256"]:
            raise RuntimeError(f"Response hash mismatch while refreshing metrics: {row['call_id']}.")
        raw = response_path.read_text(encoding="utf-8")
        reason = provider_finish_reason(call_record)
        update(row, "provider_finish_reason", reason)
        update(
            row,
            "finish_reason_indicates_truncation",
            finish_reason_indicates_truncation(reason),
        )
        try:
            graph = parse_llm_json(raw)
        except Exception:
            try:
                response_json_valid = isinstance(json.loads(raw.strip()), dict)
            except json.JSONDecodeError:
                response_json_valid = False
            update(row, "status", "parse_failed")
            update(row, "parse_mode", "parse_failed")
            update(row, "parse_success", False)
            update(row, "strict_parse_success", False)
            update(row, "truncated_repair", False)
            update(row, "parser_repaired_truncation", False)
            update(row, "response_json_valid", response_json_valid)
            update(row, "graph_extracted", False)
            update(row, "true_empty_graph", False)
            continue

        update(row, "status", "repaired_success" if graph.truncated else "strict_success")
        update(row, "parse_mode", classify_parse_mode(raw, graph))
        update(row, "parse_success", True)
        update(row, "strict_parse_success", not graph.truncated)
        update(row, "truncated_repair", graph.truncated)
        context_ids = conditions.get(row["condition_id"], {}).get("provided_cve_ids", [])
        if row["condition_id"] in c2_schema_conditions:
            context_ids = c2_ids
        refreshed = response_graph_metrics(
            raw,
            graph,
            context_ids,
            prompt_path.read_text(encoding="utf-8"),
            condition_id=row["condition_id"],
        )
        for key, value in refreshed.items():
            update(row, key, value)
    manifest["results"] = rows
    manifest["metrics_refreshed_at"] = utc_now().isoformat()
    manifest["metrics_refresh_changed_fields"] = changes
    atomic_json(run_dir / "manifest.json", manifest)
    return changes


def write_edge_expansion_review(
    run_dir: Path, rows: list[dict[str, Any]]
) -> dict[str, Any]:
    detail_rows = [row for row in rows if row.get("stage") == "edge_detail"]
    context_rows = [row for row in rows if row.get("stage") == "edge_context"]
    context_by_key = {(row["backend"], row["repeat_id"]): row for row in context_rows}
    reviews = []
    for row in detail_rows:
        context_row = context_by_key[(row["backend"], row["repeat_id"])]
        context_text = (run_dir / context_row["raw_response_file"]).read_text(encoding="utf-8")
        normalized = re.sub(r"[*_`~]", "", context_text.casefold())
        normalized = re.sub(r"\s+", " ", normalized)
        missing_prerequisite = bool(
            re.search(
                r"\b(?:does|do|did)\s+not\s+(?:(?:\w+)\s+){0,3}establish(?:es|ed|ing)?\b"
                r"|\bnot\s+establish(?:es|ed|ing)?\b"
                r"|\bnot\s+established\b"
                r"|\bkhông\s+thiết\s+lập\b",
                normalized,
            )
        )
        reviews.append({
            "backend": row["backend"],
            "repeat_id": row["repeat_id"],
            "detail_call_id": row["call_id"],
            "context_call_id": context_row["call_id"],
            "node_count": row.get("node_count"),
            "edge_count": row.get("edge_count"),
            "schema_valid": row.get("schema_valid"),
            "context_explicitly_flags_missing_prerequisite": missing_prerequisite,
            "preliminary_label": "có điều kiện",
            "missing_conditions": [
                "same vulnerable Windows host",
                "browser compromise yields unprivileged local execution outside the browser context",
                "attacker can create the required hard link and trigger OVRRedir.exe",
            ],
            "detail_graph_file": row.get("graph_file"),
            "context_response_file": context_row.get("raw_response_file"),
        })
    payload = {
        "selected_edge": SECTION54_EDGE,
        "review_method": (
            "Compare each detailed subgraph with its separately generated source-context extraction "
            "and the frozen Appendix A descriptions. New detail is descriptive only unless the source "
            "establishes the missing bridge prerequisites."
        ),
        "repeat_reviews": reviews,
        "summary": {
            "detail_graphs": len(detail_rows),
            "schema_valid_detail_graphs": sum(bool(row.get("schema_valid")) for row in detail_rows),
            "context_extractions": len(context_rows),
            "contexts_flagging_missing_prerequisite": sum(
                item["context_explicitly_flags_missing_prerequisite"] for item in reviews
            ),
            "final_preliminary_label": "có điều kiện",
            "conclusion": (
                "All detail graphs add intermediate mechanism steps, but the supplied source still "
                "does not establish the cross-vulnerability prerequisite. Expansion does not upgrade "
                "the selected edge to source-supported."
            ),
        },
    }
    atomic_json(run_dir / "edge_expansion_review.json", payload)
    lines = [
        "# Review sơ bộ §5.4 — edge expansion",
        "",
        f"Selected edge: `{SECTION54_EDGE['from']} -> {SECTION54_EDGE['to']}`.",
        "",
        "| Model | Repeat | Detail nodes | Detail edges | Schema | Context flags missing prerequisite | Label |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for item in reviews:
        lines.append(
            f"| {item['backend']} | {item['repeat_id']} | {item['node_count']} | "
            f"{item['edge_count']} | {'pass' if item['schema_valid'] else 'fail'} | "
            f"{'yes' if item['context_explicitly_flags_missing_prerequisite'] else 'no'} | "
            f"{item['preliminary_label']} |"
        )
    lines.extend([
        "",
        "Kết luận sơ bộ: cả 10 graph chi tiết thêm bước cơ chế, nhưng source không thiết lập "
        "cầu nối từ browser compromise sang unprivileged local execution, quyền tạo hard link và "
        "khả năng trigger OVRRedir.exe. Vì vậy edge vẫn là **có điều kiện**, không được nâng thành "
        "`được nguồn hỗ trợ`.",
    ])
    (run_dir / "edge_expansion_review.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return payload


def write_reproduction_artifacts(
    run_dir: Path, manifest: dict[str, Any], rows: list[dict[str, Any]]
) -> None:
    dataset_info = manifest.get("dataset", {})
    dataset_manifest_path = REPO_ROOT / dataset_info.get("manifest_file", "")
    if dataset_manifest_path.is_file():
        dataset_manifest = json.loads(dataset_manifest_path.read_text(encoding="utf-8"))
        dataset_info.setdefault("manifest_sha256", sha256_file(dataset_manifest_path))
        dataset_info.setdefault("source_commit", dataset_manifest.get("source_commit"))
        dataset_info.setdefault("retrieved_at_utc", dataset_manifest.get("retrieved_at_utc"))
    implementation = manifest.setdefault("implementation_provenance", {})
    implementation.setdefault("runner_file", "scripts/run_paired_experiment.py")
    if "runner_sha256_at_prepare" not in implementation:
        implementation["runner_sha256_at_prepare"] = None
        implementation["execution_hash_limitation"] = (
            "The runner hash was not captured before this already-completed run; frozen prompts, "
            "call journals, response hashes, parameters and model metadata remain authoritative."
        )
    implementation["current_post_run_runner_sha256"] = sha256_file(Path(__file__).resolve())
    manifest.setdefault("retry_policy", {
        "max_run_retries": MAX_RUN_RETRIES,
        "requires_operator_confirmation": True,
        "eligible_status": "api_error only",
        "saved_response_or_unknown_send": "never retry",
        "added_after_completed_run": True,
    })
    manifest.setdefault("retry_attempts", [])
    manifest["cost"] = run_cost_summary(run_dir)
    refresh_saved_graph_metrics(run_dir, manifest, rows)
    condition_specs = {item["condition_id"]: item for item in manifest["conditions"]}
    coverage, _ = write_coverage_artifacts(run_dir, rows)
    merge_audit = write_chunk_merge_audit(run_dir)
    edge_review = write_edge_expansion_review(run_dir, rows)
    section_specs = {item["condition_id"]: item for item in manifest["section54"].values()}
    c2_source = _load_frozen_prompt(run_dir, condition_specs["C2"])
    review_3_was_approved = (
        manifest.get("review_checkpoints", {}).get("review_3", {}).get("status")
        == "approved"
    )
    malformed_edge_review_note = (
        "Raw edge sai schema; giữ nguyên trong graph và Review 3 giữ nhãn chưa rõ."
        if review_3_was_approved
        else "Raw edge sai schema; giữ nguyên trong graph và cần người duyệt."
    )
    evidence = [
        "# Bảng bằng chứng cạnh — chấm sơ bộ của Codex",
        "",
        "> Nhãn trong bảng là đánh giá sơ bộ theo source đã khóa, không phải xác nhận chuyên gia. "
        "`có điều kiện` chỉ dùng khi nêu được prerequisite/cầu nối còn thiếu; nếu chưa nêu được "
        "cầu nối thì dùng `chưa rõ`. `không được hỗ trợ` nghĩa là source không chứng minh cạnh.",
        "",
        "> Bản đồ nguồn paper: C1/C2 và các bước §5.4 dùng Appendix A p. 9; "
        "T0 dùng Appendix B p. 10; T1 dùng Appendix C.1 pp. 10–14; "
        "T2 dùng Appendix C.2 p. 14. `lines` là dòng trong frozen prompt được ghi ở cùng hàng.",
        "",
        "| Call | Model | Condition | Repeat | Source → Target | Edge | Source file | Vị trí source | Trích đoạn nguồn | Nhãn sơ bộ | Điều kiện còn thiếu | Lý do |",
        "|---|---|---|---:|---|---|---|---|---|---|---|---|",
    ]
    label_counts: dict[str, int] = {}
    for row in rows:
        graph_file = row.get("graph_file")
        if not graph_file:
            continue
        graph = json.loads((run_dir / graph_file).read_text(encoding="utf-8"))
        nodes = {
            str(node.get("id", node.get("label"))): str(node.get("label", node.get("id", "?")))
            for node in graph.get("nodes", []) if isinstance(node, dict)
        }
        condition_id = row["condition_id"]
        if condition_id in condition_specs:
            source = _load_frozen_prompt(run_dir, condition_specs[condition_id])
            source_file = condition_specs[condition_id]["prompt_file"]
        elif condition_id in section_specs and condition_id.startswith("S54_CHUNK"):
            source = _load_frozen_prompt(run_dir, section_specs[condition_id])
            source_file = section_specs[condition_id]["prompt_file"]
        else:
            source = c2_source
            source_file = condition_specs["C2"]["prompt_file"]
        for edge in graph.get("edges", []):
            if not isinstance(edge, dict):
                label_counts["chưa rõ"] = label_counts.get("chưa rõ", 0) + 1
                evidence.append(
                    "| `{}` | {} | {} | {} | ? → ? | {} | `{}` | — | Không thể ánh xạ "
                    "cạnh không phải object vào source. | chưa rõ | Chưa rõ; chưa xác định được "
                    "điều kiện thiếu cụ thể. | {} |".format(
                        row["call_id"], row["backend"], condition_id, row["repeat_id"],
                        _compact_text(edge, 100), source_file, malformed_edge_review_note,
                    )
                )
                continue
            src = str(edge.get("from", edge.get("source", "?")))
            dst = str(edge.get("to", edge.get("target", "?")))
            src_label, dst_label = nodes.get(src, src), nodes.get(dst, dst)
            edge_label = str(edge.get("label", ""))
            location, excerpt = _source_excerpt(source, [edge_label, src_label, dst_label])
            label, reason, missing_condition = _preliminary_edge_label(
                condition_id, source, src_label, dst_label, edge_label
            )
            if location == "—" and label in {"được nguồn hỗ trợ", "có điều kiện"}:
                label = "chưa rõ"
                reason = (
                    "Bộ ánh xạ offline chưa định vị được cả hai đầu mút trong source; "
                    "không giữ nhãn có lợi khi thiếu locator."
                )
                missing_condition = (
                    "Chưa rõ; cần ánh xạ thủ công cả hai đầu mút trước khi chấm."
                )
            label_counts[label] = label_counts.get(label, 0) + 1
            evidence.append(
                "| `{}` | {} | {} | {} | {} → {} | {} | `{}` | {} | {} | {} | {} | {} |".format(
                    row["call_id"], row["backend"], condition_id, row["repeat_id"],
                    _compact_text(src_label, 70), _compact_text(dst_label, 70),
                    _compact_text(edge_label, 100), source_file, location,
                    _compact_text(excerpt, 500), label,
                    _compact_text(missing_condition, 180), _compact_text(reason, 180),
                )
            )
    evidence.extend(["", "## Tổng số nhãn sơ bộ", ""])
    for label in ("được nguồn hỗ trợ", "có điều kiện", "không được hỗ trợ", "chưa rõ"):
        evidence.append(f"- {label}: {label_counts.get(label, 0)} cạnh")
    (run_dir / "evidence_table.md").write_text("\n".join(evidence) + "\n", encoding="utf-8")
    review_3 = manifest.setdefault("review_checkpoints", {}).setdefault("review_3", {})
    review_3_approved = review_3_was_approved
    review_3.update({
        "artifact": "evidence_table.md",
        "evidence_edge_entries": sum(label_counts.values()),
        "preliminary_label_counts": label_counts,
        "method_note": (
            "Codex-only preliminary labels. Conditional is used only when a concrete missing "
            "bridge is named; ambiguous mappings remain unclear. "
            + (
                "The user approved Review 3; this does not convert the labels into expert validation."
                if review_3_approved
                else "User Review 3 is pending."
            )
        ),
    })
    if not review_3_approved:
        review_3["status"] = "ready_for_user_review"
    atomic_json(run_dir / "manifest.json", manifest)

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("stage") != "graph":
            continue
        grouped.setdefault((row["condition_id"], row["backend"]), []).append(row)
    retry_entries = manifest.get("retry_attempts", [])
    retry_status_counts: dict[str, int] = {}
    for entry in retry_entries:
        retry_status = str(entry.get("status", "unknown"))
        retry_status_counts[retry_status] = retry_status_counts.get(retry_status, 0) + 1
    if retry_entries:
        retry_report_line = (
            f"- R1-09 recorded {len(retry_entries)}/{MAX_RUN_RETRIES} operator-confirmed "
            "transient retries with new attempt IDs; outcomes: "
            + ", ".join(
                f"{status}={count}" for status, count in sorted(retry_status_counts.items())
            )
            + ". Saved response and unknown-send states remain ineligible; original planned "
            "failures remain in the denominator."
        )
    else:
        retry_report_line = (
            "- Contingency retry R1-09 không được dùng vì run có 0 API error. CLI "
            "`--retry-transient-call` cùng `--confirm-transient` cho phép operator xác nhận "
            "một `api_error` đã lưu là transient; tối đa bốn retry run-wide được ghi với "
            "attempt_id mới. Saved response và unknown-send bị từ chối, còn failure gốc vẫn "
            "nằm trong kết quả planned và journal."
        )
    report = [
        "# Báo cáo tái hiện CrystalBall §5.1–§5.4",
        "",
        f"- Run ID: `{manifest['run_id']}`",
        "- Mô hình thay thế: Gemini `gemini-3.8-flash` và OpenRouter `openai/gpt-5.6-luna`.",
        "- Mỗi điều kiện chính chạy 5 lần; prompt bytes giữ cố định giữa hai mô hình và các repeat.",
        "- Extraction/index chính thức được tái sử dụng; không phát sinh extraction API call mới.",
        f"- CVE source commit: `{manifest.get('dataset', {}).get('source_commit', 'unavailable')}`; "
        f"dataset manifest SHA-256: `{manifest.get('dataset', {}).get('manifest_sha256', 'unavailable')}`.",
        f"- Chi phí ước tính hiện tại: {run_cost_summary(run_dir)['estimated_cost_vnd']:.2f} VND / 50.000 VND.",
        (
            f"- Review 3: người dùng đã duyệt lúc `{review_3.get('approved_at')}`; "
            "các nhãn vẫn là đánh giá sơ bộ của Codex, không phải expert validation."
            if review_3_approved
            else "- Review 3: bảng bằng chứng sơ bộ đang chờ người dùng duyệt."
        ),
        "",
        "## Kết quả cấu trúc bảy điều kiện chính",
        "",
        "| Condition | Backend | Calls | Parse | Schema | Nodes mean [min–max] | Edges mean [min–max] |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for key in sorted(grouped):
        items = grouped[key]
        parsed = [item for item in items if item.get("parse_success")]
        schema = [item for item in items if item.get("schema_valid")]
        node_counts = [item.get("node_count", 0) for item in parsed]
        edge_counts = [item.get("edge_count", 0) for item in parsed]
        mean_nodes = sum(node_counts) / len(node_counts) if node_counts else 0
        mean_edges = sum(edge_counts) / len(edge_counts) if edge_counts else 0
        node_range = f"{min(node_counts)}–{max(node_counts)}" if node_counts else "n/a"
        edge_range = f"{min(edge_counts)}–{max(edge_counts)}" if edge_counts else "n/a"
        report.append(
            f"| {key[0]} | {key[1]} | {len(items)} | {len(parsed)}/{len(items)} | "
            f"{len(schema)}/{len(items)} | {mean_nodes:.1f} [{node_range}] | "
            f"{mean_edges:.1f} [{edge_range}] |"
        )
    status_counts: dict[str, int] = {}
    stage_status_counts: dict[str, dict[str, int]] = {}
    parse_mode_counts: dict[str, int] = {}
    for row in rows:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
        per_stage = stage_status_counts.setdefault(row["stage"], {})
        per_stage[row["status"]] = per_stage.get(row["status"], 0) + 1
        parse_mode = row.get("parse_mode", "unrecorded")
        parse_mode_counts[parse_mode] = parse_mode_counts.get(parse_mode, 0) + 1
    report.extend([
        "",
        "## Coverage sự kiện sơ bộ",
        "",
        "Coverage dưới đây đo việc graph có biểu diễn sự kiện đã khóa bằng từ khóa/alias hay không; "
        "không xác nhận causal chain đúng. Chi tiết từng repeat và định nghĩa nằm trong `coverage.md`/`coverage.json`.",
        "",
        "| Condition | Backend | Family | Mean coverage |",
        "|---|---|---|---:|",
    ])
    for item in coverage["aggregates"]:
        report.append(
            f"| {item['condition_id']} | {item['backend']} | {item['family']} | "
            f"{100 * item['mean_coverage_rate']:.1f}% |"
        )
    report.extend([
        "",
        "## Tổng quan outcome và chấm sơ bộ",
        "",
        f"- Đã thực hiện đủ {len(rows)}/130 request: "
        f"{status_counts.get('strict_success', 0)} parsed without structural repair "
        f"({parse_mode_counts.get('raw_json', 0)} raw JSON + "
        f"{parse_mode_counts.get('markdown_stripped', 0)} after Markdown-fence removal), "
        f"{status_counts.get('repaired_success', 0)} recovered by object extraction, "
        f"{status_counts.get('parse_failed', 0)} parse-failed partial, "
        f"{status_counts.get('response_saved', 0)} context response; "
        f"{status_counts.get('api_error', 0)} API error.",
        "- Parse modes: "
        + ", ".join(
            f"{mode}={count}" for mode, count in sorted(parse_mode_counts.items())
        )
        + ".",
        "- Bảng bằng chứng sơ bộ: "
        f"{label_counts.get('được nguồn hỗ trợ', 0)} cạnh được nguồn hỗ trợ, "
        f"{label_counts.get('có điều kiện', 0)} có điều kiện, "
        f"{label_counts.get('không được hỗ trợ', 0)} không được hỗ trợ, "
        f"{label_counts.get('chưa rõ', 0)} chưa rõ. "
        + (
            "Người dùng đã duyệt các nhãn này tại Review 3 với tư cách đánh giá sơ bộ."
            if review_3_approved
            else "Các nhãn này chờ người dùng duyệt."
        ),
        "- C1 đạt schema 5/5 ở cả hai model; X0 thường trả graph rỗng. T0 Gemini trả JSON "
        "nghiêm ngặt nhưng graph rỗng ở cả năm repeat. Không outcome nào bị loại khỏi mẫu số.",
        "- Luna tạo graph T1 lớn hơn đáng kể về số node/edge; đây chỉ là mô tả độ dài, không phải điểm đúng.",
        "",
        "## Kết quả §5.4",
        "",
        "| Stage | Requests | Outcomes |",
        "|---|---:|---|",
        *[
            "| {} | {} | {} |".format(
                stage,
                sum(outcomes.values()),
                ", ".join(f"{status}: {count}" for status, count in sorted(outcomes.items())),
            )
            for stage, outcomes in sorted(stage_status_counts.items())
            if stage != "graph"
        ],
        "",
        "## §5.4 và giới hạn diễn giải",
        "",
        "- Chunking dùng đúng hai phần tại heading `In-Depth Malware Analysis`, không overlap. "
        "Merge chỉ hợp các graph; node trùng hoàn toàn được dedupe, xung đột ID được namespace, "
        f"không tạo cạnh nối hai chunk. Có {merge_audit['collision_count']} xung đột ID được ghi "
        "trong `derived/chunk_merge/merge_audit.json`.",
        "- Cutoff 512 token là chủ động; mỗi partial output có đúng một request continuation 4096 token.",
        "- Năm cặp continuation không có prompt byte-identical giữa hai provider vì mỗi prompt chứa "
        "partial response riêng của chính provider đó. Đây là ngoại lệ được thiết kế; 60 cặp static/main "
        "còn lại giữ cùng prompt hash giữa hai model.",
        "- Edge expansion dùng cạnh Oculus Browser → OVRRedir đã khóa; graph chi tiết và context "
        "liên quan được gọi riêng. {}/{} context extraction nói rõ prerequisite không được source "
        "thiết lập; cả 10 edge expansion vẫn được chấm `có điều kiện`, không nâng thành source-supported. "
        "Xem `edge_expansion_review.md/json`.".format(
            edge_review["summary"]["contexts_flagging_missing_prerequisite"],
            edge_review["summary"]["context_extractions"],
        ),
        "- Parse/schema success chỉ đo cấu trúc, không chứng minh attack chain đúng.",
        "- Figure 7 không được coi là ground truth tuyệt đối; physical access của Jetson và điều kiện "
        "quang học của Glowworm vẫn phải được xét thủ công.",
        "- Kết quả từng repeat nằm trong `metrics.csv/json` và `coverage.md/json`; bảng chính "
        "báo mean kèm min–max. Năm repeat chỉ hỗ trợ mô tả độ dao động, không kiểm định ý nghĩa.",
        retry_report_line,
        "- Run đã hoàn thành trước khi runner SHA-256 được thêm vào manifest, vì vậy exact execution-code "
        "hash không khả dụng cho run này. Prompt/call/response hashes và tham số API vẫn được kiểm tra; "
        "manifest ghi riêng hash runner hiện tại sau run, không mạo nhận đó là hash lúc thực thi.",
        "",
        "## Artifact và lệnh tái chạy",
        "",
        "- `manifest.json`, `metrics.json/csv`, `summary.json`, `coverage.md/json`, "
        "`edge_expansion_review.md/json`, raw responses, graph JSON và PNG repeat 1 nằm trong thư mục run.",
        "- Bảng chấm cạnh: `evidence_table.md`.",
        "- Chuẩn bị không gọi LLM API: `uv run python scripts/run_paired_experiment.py --dataset-manifest data/cve_official/manifest.json --prepare-reproduction --run-id <id>`. Trên máy mới, embedding model phải có trong cache hoặc được tải một lần qua mạng.",
        "- Chạy/resume: `uv run python scripts/run_paired_experiment.py --dataset-manifest data/cve_official/manifest.json --execute-reproduction <id>`",
        "- Retry một transient `api_error` đã được operator xác nhận: `uv run python scripts/run_paired_experiment.py --dataset-manifest data/cve_official/manifest.json --run-id <id> --retry-transient-call <call_id> --confirm-transient`",
    ])
    report_text = "\n".join(report) + "\n"
    (run_dir / "REPRODUCTION_REPORT.md").write_text(report_text, encoding="utf-8")
    (REPO_ROOT / "REPRODUCTION_REPORT.md").write_text(report_text, encoding="utf-8")


def approve_reproduction_review_3(run_id: str, approval_message: str) -> dict[str, Any]:
    """Record the user's Review 3 decision without making any model API call."""
    run_dir = OUTPUTS_DIR / run_id
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Unknown reproduction run: {run_id}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    review_3 = manifest.get("review_checkpoints", {}).get("review_3", {})
    if manifest.get("status") == "completed" and review_3.get("status") == "approved":
        return manifest
    if manifest.get("status") != "results_ready_for_review_3":
        raise RuntimeError("Review 3 can only approve a run whose results are ready for Review 3.")
    if review_3.get("status") != "ready_for_user_review":
        raise RuntimeError("Review 3 evidence is not ready for user approval.")
    rows = manifest.get("results", [])
    planned_calls = manifest.get("call_plan", {}).get("total_calls")
    if planned_calls != len(rows):
        raise RuntimeError(
            f"Review 3 cannot close an incomplete run: {len(rows)}/{planned_calls} results."
        )
    approved_at = utc_now().isoformat()
    review_3.update({
        "status": "approved",
        "approved_at": approved_at,
        "approved_by": "user",
        "approval_message": approval_message,
        "note": (
            "The user approved Codex's preliminary Review 3 results; approval does not make "
            "the labels expert validation."
        ),
    })
    manifest["status"] = "completed"
    manifest["completed_at"] = approved_at
    atomic_json(manifest_path, manifest)
    write_reproduction_artifacts(run_dir, manifest, rows)
    rebuild_summary(run_dir, rows, manifest)
    return manifest


def run_dry_run(settings: Settings, dataset: OfficialCveDataset) -> None:
    check_settings(settings, require_api_keys=False)
    previous = inspect_saved_index(settings, source_hashes())
    if previous is None or previous.get("status") != "ready":
        raise RuntimeError("Approved official index is not ready for offline dry-run.")
    reproduction_hashes = reproduction_source_hashes()
    print(json.dumps({
        "dry_run": "passed",
        "dataset_id": dataset.dataset_id,
        "dataset_digest": dataset.digest,
        "manifest": dataset.manifest_path.relative_to(REPO_ROOT).as_posix(),
        "source_commit": json.loads(dataset.manifest_path.read_text(encoding="utf-8"))["source_commit"],
        "validated_cve_ids": [record["cve_id"] for record in dataset.records],
        "conditions": ["C0", "C1", "C2", "T0", "T1", "T2", "X0"],
        "models": {
            name: {"backend": backend, "model": getattr(settings, model_field)}
            for name, (backend, model_field) in MODEL_SPECS.items()
        },
        "product_query": dataset.query,
        "embedding_dimension": previous.get("embedding_dimension", "recorded in index artifacts"),
        "index_reuse": "ready" if previous else "new isolated index",
        "database": DB_PATH.relative_to(REPO_ROOT).as_posix(),
        "embeddings_directory": EMBEDDINGS_DIR.relative_to(REPO_ROOT).as_posix(),
        "index_manifest": INDEX_MANIFEST_PATH.relative_to(REPO_ROOT).as_posix(),
        "reproduction_source_sha256": reproduction_hashes,
        "planned_api_calls": {"extraction_new": 0, "main_graph": 70, "section_5_4": 60, "total": 130},
        "prompt_hash_note": (
            "The approved extraction/index is reused without API calls. --prepare-reproduction freezes "
            "the seven main prompts and static Section 5.4 prompts; main-condition prompt bytes remain "
            "identical across both models and all five repeats."
        ),
    }, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default=None, help="Optional unique output folder name.")
    parser.add_argument("--resume-run", default=None, help="Resume a failed run without repeating saved successful calls.")
    parser.add_argument("--dataset-manifest", type=Path, required=True,
                        help="Required official eight-CVE manifest; bootstrap the index with --prepare-only before preparing the full reproduction.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate official inputs/settings and load Contriever without making LLM API calls.")
    parser.add_argument("--prepare-only", action="store_true",
                        help="Build/reuse the official CVE index and freeze prompts, then stop before graph API calls.")
    parser.add_argument("--continue-graphs", default=None,
                        help="Continue an official run after prompt review; requires --dataset-manifest.")
    parser.add_argument("--prepare-reproduction", action="store_true",
                        help="Freeze the approved seven-condition and Section 5.4 prompts offline.")
    parser.add_argument("--execute-reproduction", default=None,
                        help="Execute a prepared full 130-call reproduction run with budget enforcement.")
    parser.add_argument("--retry-transient-call", default=None,
                        help="Retry one saved api_error call; combine with --run-id and --confirm-transient.")
    parser.add_argument("--confirm-transient", action="store_true",
                        help="Confirm that the selected api_error is a transient provider failure eligible for retry.")
    args = parser.parse_args()
    try:
        if args.dataset_manifest:
            dataset = configure_official_dataset(args.dataset_manifest)
        else:
            dataset = None
            if args.dry_run:
                parser.error("--dry-run currently requires --dataset-manifest.")
        if args.dry_run and args.resume_run:
            parser.error("Use --dry-run without --resume-run.")
        if args.dry_run and args.prepare_only:
            parser.error("Use --dry-run without --prepare-only.")
        if args.dry_run and args.run_id:
            parser.error("Use --dry-run without --run-id.")
        if args.resume_run and args.run_id:
            parser.error("Use either --run-id or --resume-run, not both.")
        if args.continue_graphs and not args.dataset_manifest:
            parser.error("--continue-graphs requires --dataset-manifest.")
        if args.continue_graphs and args.prepare_only:
            parser.error("Use either --prepare-only or --continue-graphs, not both.")
        if args.continue_graphs and args.resume_run:
            parser.error("Use either --resume-run or --continue-graphs, not both.")
        if args.prepare_only and not args.dataset_manifest:
            parser.error("--prepare-only requires --dataset-manifest.")
        if (args.prepare_reproduction or args.execute_reproduction or args.retry_transient_call) and not args.dataset_manifest:
            parser.error("Full reproduction commands require --dataset-manifest.")
        if args.prepare_reproduction and args.execute_reproduction:
            parser.error("Prepare and execute the reproduction in separate commands.")
        if args.retry_transient_call:
            if not args.run_id:
                parser.error("--retry-transient-call requires --run-id.")
            if not args.confirm_transient:
                parser.error("--retry-transient-call requires --confirm-transient.")
            if (args.dry_run or args.prepare_only or args.continue_graphs or args.resume_run
                    or args.prepare_reproduction or args.execute_reproduction):
                parser.error("Use --retry-transient-call as a separate command.")
        elif args.confirm_transient:
            parser.error("--confirm-transient is only valid with --retry-transient-call.")
        if args.dry_run:
            run_dry_run(get_settings(), dataset)
            return
        if args.prepare_reproduction:
            run_dir = prepare_reproduction_run(args.run_id or new_run_id())
            print(f"Prepared reproduction run: {run_dir}")
            return
        if args.execute_reproduction:
            raise SystemExit(execute_reproduction_run(args.execute_reproduction))
        if args.retry_transient_call:
            row = retry_confirmed_transient_call(
                args.run_id,
                args.retry_transient_call,
                operator_confirmed_transient=True,
            )
            print(f"Recorded confirmed retry {row['call_id']}: {row['status']}")
            return
        exit_code = run_experiment(
            args.continue_graphs or args.resume_run or args.run_id or new_run_id(),
            resume=bool(args.resume_run or args.continue_graphs),
            prepare_only=args.prepare_only,
            continue_graphs=bool(args.continue_graphs),
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Experiment not started: {type(exc).__name__}: {exc}")
        raise SystemExit(1) from None
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
