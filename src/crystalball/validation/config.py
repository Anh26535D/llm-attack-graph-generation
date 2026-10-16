"""Validator controls are independent of generation settings and credentials."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

STATUSES = ("supported", "conditional", "unsupported", "contradicted", "unknown")


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name, str(default)).strip().lower()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError(f"{name} must be true or false")
    return value in {"true", "1"}


@dataclass(frozen=True)
class ValidatorConfig:
    mode: str = "hybrid"
    llm_enabled: bool = False
    llm_backend: str = "gemini"
    review_statuses: tuple[str, ...] = ("conditional", "unknown")
    max_llm_calls: int = 20
    max_output_tokens: int = 1024
    reasoning_level: str = "low"
    cache_enabled: bool = True
    cache_dir: Path = Path("outputs/validator_cache")
    allow_control_review: bool = False

    def __post_init__(self) -> None:
        if self.mode not in {"offline", "hybrid"}:
            raise ValueError("VALIDATOR_MODE must be offline or hybrid")
        if self.llm_backend not in {"gemini", "openai", "openrouter", "openrouter_v2"}:
            raise ValueError("Unsupported VALIDATOR_LLM_BACKEND")
        if not set(self.review_statuses) <= set(STATUSES):
            raise ValueError("Invalid VALIDATOR_REVIEW_STATUSES")
        if not self.allow_control_review and not set(self.review_statuses) <= {"conditional", "unknown"}:
            raise ValueError("Reviewing decided edges requires explicit allow_control_review")
        for value, minimum in ((self.max_llm_calls, 0), (self.max_output_tokens, 1)):
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise ValueError("Invalid validator call/token limit")
        if self.reasoning_level not in {"low", "medium", "high"}:
            raise ValueError("Invalid VALIDATOR_REASONING_LEVEL")

    @property
    def review_enabled(self) -> bool:
        return self.mode == "hybrid" and self.llm_enabled

    @classmethod
    def from_env(cls, *, allow_control_review: bool = False) -> ValidatorConfig:
        # Importing config loads .env using the same mechanism as generation.
        from .. import config as _config  # noqa: F401

        return cls(
            mode=os.getenv("VALIDATOR_MODE", "hybrid").strip().lower(),
            llm_enabled=_bool("VALIDATOR_LLM_ENABLED", False),
            llm_backend=os.getenv("VALIDATOR_LLM_BACKEND", "gemini").strip().lower(),
            review_statuses=tuple(s.strip() for s in os.getenv(
                "VALIDATOR_REVIEW_STATUSES", "conditional,unknown").split(",") if s.strip()),
            max_llm_calls=int(os.getenv("VALIDATOR_MAX_LLM_CALLS", "20")),
            max_output_tokens=int(os.getenv("VALIDATOR_MAX_OUTPUT_TOKENS", "1024")),
            reasoning_level=os.getenv("VALIDATOR_REASONING_LEVEL", "low").strip().lower(),
            cache_enabled=_bool("VALIDATOR_CACHE_ENABLED", True),
            cache_dir=Path(os.getenv("VALIDATOR_CACHE_DIR", "outputs/validator_cache")),
            allow_control_review=allow_control_review,
        )

    def public_dict(self) -> dict:
        return {**asdict(self), "cache_dir": str(self.cache_dir)}
