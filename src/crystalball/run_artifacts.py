"""Naming and metadata helpers for reproducible experiment runs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .config import Settings


def new_run_id(*directories: Path, now: datetime | None = None) -> str:
    """Return a UTC timestamp id that does not overwrite known run artifacts."""
    now = now or datetime.now(timezone.utc)
    base = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    index = 0
    while True:
        run_id = base if index == 0 else f"{base}_{index:02d}"
        names = (
            f"prompt_{run_id}.txt",
            f"prompt_{run_id}.meta.json",
            f"response_{run_id}.txt",
            f"graph_{run_id}.json",
            f"graph_{run_id}.png",
            f"metadata_{run_id}.json",
        )
        if not any((directory / name).exists() for directory in directories for name in names):
            return run_id
        index += 1


def experiment_metadata(
    settings: Settings,
    *,
    run_id: str,
    timestamp: str,
    input_mode: str,
    context_mode: str,
    retrieved_cve_ids: list[str] | None = None,
    model: str | None = None,
    parse_status: str = "pending",
) -> dict:
    backend = settings.llm_backend.lower()
    configured_models = {
        "openai": settings.openai_model,
        "openrouter": settings.openrouter_model.strip() or None,
        "gemini": settings.gemini_model,
    }
    return {
        "run_id": run_id,
        "timestamp": timestamp,
        "backend": backend,
        "model": model if model is not None else configured_models.get(backend),
        "input_mode": input_mode,
        "context_mode": context_mode,
        "extractor_backend": settings.extractor_backend,
        "embedding_backend": settings.embedding_backend,
        "embedding_model": settings.embedding_model,
        "min_similarity": settings.min_similarity,
        "context_tokens_per_query": settings.context_tokens_per_query,
        "retrieved_cve_ids": retrieved_cve_ids or [],
        "parse_status": parse_status,
    }
