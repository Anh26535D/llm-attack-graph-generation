"""LLM is used as a black box in the system (Section 3, "LLM" component)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any


def to_metadata_value(value: Any) -> Any:
    """Copy SDK response values into JSON-serializable primitives."""
    if isinstance(value, Enum):
        return value.name
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): to_metadata_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_metadata_value(item) for item in value]

    for method_name in ("model_dump", "to_json_dict"):
        method = getattr(value, method_name, None)
        if callable(method):
            try:
                dumped = method(exclude_none=True) if method_name == "model_dump" else method()
            except TypeError:
                dumped = method()
            return to_metadata_value(dumped)

    attributes = getattr(value, "__dict__", None)
    if isinstance(attributes, dict):
        return {
            str(key): to_metadata_value(item)
            for key, item in attributes.items()
            if not str(key).startswith("_") and item is not None
        }
    return str(value)


def validate_generation_options(max_output_tokens: int, reasoning_level: str) -> None:
    if (
        isinstance(max_output_tokens, bool)
        or not isinstance(max_output_tokens, int)
        or max_output_tokens <= 0
    ):
        raise ValueError("max_output_tokens must be a positive integer.")
    if reasoning_level not in {"low", "medium", "high"}:
        raise ValueError("reasoning_level must be one of: low, medium, high.")


class LLMClient(ABC):
    """Anything that can turn a prompt string into a text completion."""

    name: str = "base"
    last_usage: dict[str, Any] | None = None
    last_response_metadata: dict[str, Any] | None = None

    @abstractmethod
    def complete(
        self,
        prompt: str,
        *,
        max_output_tokens: int | None = None,
        reasoning_level: str | None = None,
    ) -> str:
        """Generate text; existing callers can keep passing just prompt."""
        ...
