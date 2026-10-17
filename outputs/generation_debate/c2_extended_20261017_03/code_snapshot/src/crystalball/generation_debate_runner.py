"""Prepare offline, then explicitly execute a frozen C2 generation pilot."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from .config import PROJECT_ROOT, Settings
from .generation_debate import (DebateConfig, STRATEGIES, create_draft, draft_prompt,
                                packed, run_strategy)
from .llm.base import to_metadata_value
from .llm.factory import get_llm_client
from .validation.config import ValidatorConfig
from .validation.evidence import EvidenceStore
from .validation.metrics import token_usage
from .validation.pipeline import write_artifacts

BACKENDS = ("gemini", "openrouter", "openrouter_v2", "openai")
ROLES = ("generator", "defender", "skeptic", "judge")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def save(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
                         encoding="utf-8", newline="\n")
    temporary.replace(path)


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def identity(settings: Settings, backend: str) -> dict:
    model = getattr(settings, {"gemini": "gemini_model", "openai": "openai_model",
                              "openrouter": "openrouter_model", "openrouter_v2": "openrouter_model_v2"}[backend])
    if not model.strip():
        raise ValueError(f"Empty model for {backend}")
    result = {"backend": backend, "model": model}
    if backend == "openrouter_v2":
        provider = json.loads(settings.openrouter_provider_config_v2)
        if not isinstance(provider, dict):
            raise ValueError("V2 provider config must be a JSON object")
        result["provider_config"] = provider
    return result


def code_hashes() -> dict:
    paths = [PROJECT_ROOT / "src/crystalball" / name for name in (
        "generation_debate.py", "generation_debate_runner.py", "experiment.py", "postprocess.py",
        "cve_mapping.py",
        "llm/base.py", "llm/factory.py", "llm/gemini_client.py", "llm/openrouter_client.py", "llm/openai_client.py")]
    paths += list((PROJECT_ROOT / "src/crystalball/validation").glob("*.py"))
    return {str(path.relative_to(PROJECT_ROOT)): sha(path.read_bytes()) for path in sorted(paths)}


def prepare(out: Path, settings: Settings, *, repeats: int, config: DebateConfig,
            backends: dict[str, str], strategies: tuple[str, ...] = STRATEGIES) -> dict:
    if type(repeats) is not int or not 1 <= repeats <= 100:
        raise ValueError("Repeats must be between 1 and 100")
    if (not strategies or len(set(strategies)) != len(strategies)
            or not set(strategies) <= set(STRATEGIES)):
        raise ValueError("Choose unique strategies: grounded, self_refine, debate")
    roles = {role: identity(settings, backends[role]) for role in ROLES}
    store = EvidenceStore.load(PROJECT_ROOT / "data/cve_official/manifest.json")
    sources = {cve: row["description"] for cve, row in sorted(store.records.items())}
    prompt = draft_prompt(sources)
    extra = 2 * config.rounds + 1
    calls = 1 + extra * sum(strategy != "grounded" for strategy in strategies)
    manifest = {"version": 1, "scope": "C2_source_grounded_generation_pilot",
                "created_at": datetime.now(timezone.utc).isoformat(), "repeats": repeats,
                "strategies": list(strategies), "roles": roles, "config": asdict(config),
                "sources_sha256": sha(packed(sources).encode()), "dataset_digest": store.dataset_digest,
                "draft_prompt_sha256": sha(prompt.encode()),
                "snapshot_sha256": sha(packed(store.records).encode()), "code_sha256": code_hashes(),
                "environment": "absent", "automatic_retries": False, "shared_draft": True,
                "max_api_calls_per_repeat": calls, "max_api_calls_total": repeats * calls,
                "max_sum_output_token_caps": repeats * calls * config.max_output_tokens,
                "same_model_for_all_roles": len({packed(value) for value in roles.values()}) == 1,
                "accuracy": None,
                "limitations": ["Caps do not bound input-token charges or monetary cost.",
                    "Matched call counts/output caps do not equal matched actual tokens or input lengths.",
                    "Debate uses independent role prompts; agents need not be different models.",
                    "This is a graph-generation adaptation, not a replication of Khan et al.'s reading task.",
                    "Verified quotations authenticate text; causal entailment needs independent assessment.",
                    "New prompt, exact CVE IDs and granularity differ from the historical paper baseline."]}
    out.mkdir(parents=True, exist_ok=False)
    save(out / "sources.json", sources)
    (out / "draft_prompt.txt").write_bytes(prompt.encode("utf-8"))
    (out / "PROTOCOL.md").write_bytes((PROJECT_ROOT / "docs/GENERATION_DEBATE.md").read_bytes())
    save(out / "evidence_snapshot.json", {"dataset_digest": store.dataset_digest, "records": store.records})
    save(out / "manifest.json", manifest)
    (out / "manifest.sha256").write_text(sha(packed(manifest).encode()), encoding="ascii")
    # This covers omitted edges too; leave labels blank and never fill them with AI votes.
    save(out / "pair_annotation_blind.json", {"independent": True, "label_source": "human",
        "provenance": "", "sources_sha256": manifest["sources_sha256"],
        "question": "Does the source effect plausibly enable the target prerequisite, subject to stated conditions?",
        "environment_exploitability": "not_assessed", "sources": sources,
        "pairs": [{"from": source, "to": target, "plausible_bridge": None,
                   "source_quote": "", "target_quote": "", "conditions": [], "reason": ""}
                  for source in sources for target in sources if source != target]})
    return manifest


def verify(out: Path, settings: Settings) -> tuple[dict, dict, EvidenceStore]:
    manifest = read(out / "manifest.json")
    if sha(packed(manifest).encode()) != (out / "manifest.sha256").read_text(encoding="ascii"):
        raise ValueError("Frozen manifest changed; use a new run")
    if manifest["code_sha256"] != code_hashes():
        raise ValueError("Generation/validation code changed since prepare; use a new run")
    sources, snapshot = read(out / "sources.json"), read(out / "evidence_snapshot.json")
    if (sha(packed(sources).encode()) != manifest["sources_sha256"]
            or sha((out / "draft_prompt.txt").read_bytes()) != manifest["draft_prompt_sha256"]
            or sha(draft_prompt(sources).encode()) != manifest["draft_prompt_sha256"]
            or sha(packed(snapshot["records"]).encode()) != manifest["snapshot_sha256"]
            or snapshot["dataset_digest"] != manifest["dataset_digest"]):
        raise ValueError("Frozen source/evidence snapshot changed")
    for role, value in manifest["roles"].items():
        if identity(settings, value["backend"]) != value:
            raise ValueError(f"Model/provider changed for {role}; use a new run")
    return manifest, sources, EvidenceStore(snapshot["records"], snapshot["dataset_digest"])


class Journal:
    def __init__(self, folder: Path, settings: Settings, manifest: dict):
        self.folder, self.settings, self.manifest = folder, settings, manifest
        self.config = DebateConfig(**manifest["config"])
        self.clients = {}

    def complete(self, stage: str, role: str, prompt: str) -> str:
        path = self.folder / "calls" / f"{stage}.json"
        prompt_hash = sha(prompt.encode())
        identity_now = self.manifest["roles"][role]
        raw_path = path.with_suffix(".response.txt")
        if path.exists():
            record = read(path)
            if record["prompt_sha256"] != prompt_hash or record["identity"] != identity_now:
                raise ValueError("Saved stage has different prompt/model/provider")
            if record["status"] != "received":
                raise RuntimeError(f"Stage {stage} failed or has an uncertain request; automatic retry disabled")
            raw = raw_path.read_bytes()
            if sha(raw) != record["response_sha256"]:
                raise ValueError("Saved raw response changed")
            if record.get("output_truncated"):
                raise RuntimeError(f"Stage {stage} reached its output limit; no repair or retry")
            return raw.decode("utf-8")
        if len(list((self.folder / "calls").glob("*.json"))) >= self.manifest["max_api_calls_per_repeat"]:
            raise RuntimeError("Frozen request budget exhausted")
        if role not in self.clients:
            self.clients[role] = get_llm_client(replace(self.settings, llm_backend=identity_now["backend"]))
        client = self.clients[role]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.with_suffix(".prompt.txt").write_bytes(prompt.encode("utf-8"))
        record = {"stage": stage, "role": role, "identity": identity_now,
                  "prompt_sha256": prompt_hash, "status": "started",
                  "max_output_tokens": self.config.max_output_tokens,
                  "reasoning_level": self.config.reasoning_level, "api_calls": 1}
        save(path, record)  # Intent is durable before sending a potentially billable request.
        started = time.perf_counter()
        try:
            raw = client.complete(prompt, max_output_tokens=self.config.max_output_tokens,
                                  reasoning_level=self.config.reasoning_level)
            raw_path.write_bytes(raw.encode("utf-8"))  # Raw is durable before any parsing.
        except Exception as exc:
            record.update(status="error", error_type=type(exc).__name__,
                          usage=to_metadata_value(client.last_usage),
                          metadata=to_metadata_value(client.last_response_metadata),
                          seconds=time.perf_counter() - started)
            save(path, record)
            raise RuntimeError(f"Request failed at {stage}: {type(exc).__name__}; stopped without retry") from None
        metadata = to_metadata_value(client.last_response_metadata)
        finish = str((metadata or {}).get("finish_reason", "")).lower()
        truncated = finish in {"length", "max_tokens", "max_output_tokens"} or finish.endswith(".max_tokens")
        record.update(status="received", response_sha256=sha(raw.encode()), output_truncated=truncated,
                      usage=to_metadata_value(client.last_usage),
                      metadata=metadata,
                      seconds=time.perf_counter() - started)
        save(path, record)
        if truncated:
            raise RuntimeError(f"Stage {stage} reached its output limit; no repair or retry")
        return raw


def _artifact(folder: Path, result: dict, store: EvidenceStore, *, render: bool) -> None:
    save(folder / "candidate.json", result["candidate"])
    save(folder / "generation_audit.json", {k: v for k, v in result.items() if k != "candidate"})
    # Preserve even a failed candidate, but do not silently promote it to a deliverable graph.
    if result["status"] == "ready_for_independent_validation":
        save(folder / "graph.json", result["candidate"]["graph"])
        write_artifacts(folder / "graph.json", folder / "validation", store,
                        ValidatorConfig(mode="offline", llm_enabled=False), render=render)


def execute(out: Path, settings: Settings, *, repeat_ids: list[int] | None = None,
            render: bool = False) -> dict:
    manifest, sources, store = verify(out, settings)
    ids = repeat_ids if repeat_ids is not None else list(range(1, manifest["repeats"] + 1))
    if not ids or len(set(ids)) != len(ids) or any(i < 1 or i > manifest["repeats"] for i in ids):
        raise ValueError("Invalid repeat IDs")
    lock = out / ".execute.lock"
    with lock.open("x", encoding="utf-8") as handle:
        handle.write("Execution owns this run. A stale lock requires checking journal states before removal.\n")
    try:
        for repeat in ids:
            folder = out / "runs" / f"r{repeat:02d}"
            journal = Journal(folder, settings, manifest)
            stage = "draft"
            try:
                save(folder / "generation_status.json", {"status": "running"})
                initial = create_draft(sources, journal.complete)
                save(folder / "draft.json", initial)
                for strategy in manifest["strategies"]:
                    stage = strategy
                    result = run_strategy(initial, strategy, sources, journal.complete,
                                          DebateConfig(**manifest["config"]), defender_first=repeat % 2 == 1)
                    _artifact(folder / strategy, result, store, render=render)
                save(folder / "generation_status.json", {"status": "completed"})
            except Exception as exc:
                save(folder / "generation_status.json", {"status": "failed", "stage": stage,
                     "error_type": type(exc).__name__})
                if stage != "draft":
                    save(folder / stage / "generation_audit.json",
                         {"status": "failed", "error_type": type(exc).__name__, "accuracy": None})
                raise
    finally:
        lock.unlink()
        report(out)  # Includes failed/partial runs too, without another API call.
    return report(out)


def report(out: Path) -> dict:
    manifest = read(out / "manifest.json")
    rows = []
    for repeat in range(1, manifest["repeats"] + 1):
        base = out / "runs" / f"r{repeat:02d}"
        for strategy in manifest["strategies"]:
            folder = base / strategy
            path = folder / "generation_audit.json"
            state = read(path) if path.exists() else {"status": "not_run"}
            repeat_state = read(base / "generation_status.json") if (base / "generation_status.json").exists() else {}
            if repeat_state.get("status") == "failed" and repeat_state.get("stage") == "draft":
                state = {"status": "draft_failed"}
            validation_path = folder / "validation/validation_results.json"
            counts = (dict(Counter(row["final"]["status"] for row in read(validation_path)["edges"]))
                      if validation_path.exists() else None)
            calls = [read(path) for path in sorted((base / "calls").glob("*.json"))
                     if path.stem == "draft" or path.stem.startswith(strategy + ".")]
            rows.append({"repeat": repeat, "strategy": strategy, "status": state["status"],
                         "edge_count": state.get("audit", {}).get("edge_count"),
                         "offline_tags": counts, "api_calls_including_shared_draft": len(calls),
                         "request_states": dict(Counter(call["status"] for call in calls)),
                         "request_seconds": sum(call.get("seconds", 0) for call in calls),
                         "usage": token_usage(calls), "accuracy": None})
    summary = {"manifest": manifest, "runs": rows,
               "note": "Offline tags, mechanical pass rates and fewer edges do not measure accuracy. "
                       "The common draft is charged to each condition when comparing, but billed once."}
    save(out / "comparison.json", summary)
    lines = ["# C2: grounded / self-refine / debate", "",
             "Cùng graph nháp; validation offline không gọi LLM. Chưa có gold độc lập: accuracy = N/A.", "",
             "| Round | Cách sinh | Trạng thái | Cạnh | Nhãn offline | Calls (gồm draft chung) |",
             "|---|---|---|---:|---|---:|"]
    for row in rows:
        lines.append(f"| {row['repeat']} | {row['strategy']} | {row['status']} | "
                     f"{row['edge_count'] if row['edge_count'] is not None else 'N/A'} | "
                     f"{row['offline_tags']} | {row['api_calls_including_shared_draft']} |")
    (out / "COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "execute", "report"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--backend", choices=BACKENDS, default="gemini")
    for role in ROLES[1:]:
        parser.add_argument(f"--{role}-backend", choices=BACKENDS)
    parser.add_argument("--strategies", nargs="+", choices=STRATEGIES, default=list(STRATEGIES))
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--max-output-tokens", type=int, default=16384)
    parser.add_argument("--reasoning", choices=("low", "medium", "high"), default="medium")
    parser.add_argument("--repeat-ids", nargs="+", type=int)
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args(argv)
    settings = Settings()
    if args.command == "prepare":
        backends = {role: (getattr(args, f"{role}_backend", None) or args.backend) for role in ROLES}
        value = prepare(args.out, settings, repeats=args.repeats,
                        config=DebateConfig(args.rounds, args.max_output_tokens, args.reasoning),
                        backends=backends, strategies=tuple(args.strategies))
        print(f"Prepared only; no API calls. Maximum requests: {value['max_api_calls_total']}.")
    elif args.command == "execute":
        execute(args.out, settings, repeat_ids=args.repeat_ids, render=args.render)
        print(f"Saved {args.out / 'COMPARISON.md'}")
    else:
        report(args.out)
        print(f"Saved {args.out / 'COMPARISON.md'}")
    return 0
