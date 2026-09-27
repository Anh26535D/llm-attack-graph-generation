"""OpenRouter Chat Completions via its OpenAI-compatible API."""

from __future__ import annotations

from typing import Any

from ..config import get_settings
from .base import LLMClient, to_metadata_value, validate_generation_options


class OpenRouterLLMClient(LLMClient):
    name = "openrouter"

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        max_output_tokens: int | None = None,
        reasoning_level: str | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("OPENROUTER_MODEL must be an exact, non-empty model slug.")
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                'The openai package is required. Run `pip install -e ".[openrouter]"`.'
            ) from exc
        # Each runner-level call is one request; avoid SDK retries silently
        # exceeding the experiment's explicit API-call budget.
        self._client = OpenAI(api_key=api_key, base_url="https://openrouter.ai/api/v1", max_retries=0)
        self.model = model.strip()
        settings = get_settings()
        self.max_output_tokens = (
            settings.llm_max_output_tokens if max_output_tokens is None else max_output_tokens
        )
        self.reasoning_level = (
            settings.llm_reasoning_level if reasoning_level is None else reasoning_level
        )
        self.last_usage: dict[str, Any] | None = None
        self.last_response_metadata: dict[str, Any] | None = None

    def complete(
        self,
        prompt: str,
        *,
        max_output_tokens: int | None = None,
        reasoning_level: str | None = None,
    ) -> str:
        output_limit = self.max_output_tokens if max_output_tokens is None else max_output_tokens
        effort = self.reasoning_level if reasoning_level is None else reasoning_level
        validate_generation_options(output_limit, effort)
        self.last_usage = None
        self.last_response_metadata = {
            "requested_model": self.model,
            "actual_model": None,
            "finish_reason": None,
            "usage": None,
            "generation_config": {
                "max_output_tokens": output_limit,
                "reasoning_effort": effort,
            },
        }
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=output_limit,
            reasoning_effort=effort,
        )
        usage = getattr(response, "usage", None)
        if usage is not None:
            serialized_usage = to_metadata_value(usage)
            self.last_usage = serialized_usage if isinstance(serialized_usage, dict) else None

        choices = getattr(response, "choices", None) or []
        finish_reasons = [
            to_metadata_value(getattr(choice, "finish_reason", None))
            for choice in choices
        ]
        actual_model = (
            getattr(response, "model", None)
            or getattr(response, "model_id", None)
            or getattr(response, "actual_model", None)
        )
        self.last_response_metadata = {
            **self.last_response_metadata,
            "actual_model": to_metadata_value(actual_model),
            "finish_reason": finish_reasons[0] if finish_reasons else None,
            "finish_reasons": finish_reasons,
            "usage": self.last_usage,
        }
        return response.choices[0].message.content or ""
