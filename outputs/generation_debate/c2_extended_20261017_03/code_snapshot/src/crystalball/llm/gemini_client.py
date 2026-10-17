"""Google Gemini backend through the current ``google-genai`` SDK."""

from __future__ import annotations

from typing import Any

from ..config import get_settings
from .base import LLMClient, to_metadata_value, validate_generation_options


class GeminiLLMClient(LLMClient):
    name = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-3.8-flash",
        *,
        max_output_tokens: int | None = None,
        reasoning_level: str | None = None,
    ) -> None:
        try:
            from google import genai
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                'The google-genai package is required. Run `pip install -e ".[gemini]"`.'
            ) from exc
        self._genai = genai
        self._client = genai.Client(
            api_key=api_key,
            http_options=genai.types.HttpOptions(
                retry_options=genai.types.HttpRetryOptions(attempts=1)
            ),
        )
        self.model = model
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
        thinking_level = self.reasoning_level if reasoning_level is None else reasoning_level
        validate_generation_options(output_limit, thinking_level)
        self.last_usage = None
        self.last_response_metadata = {
            "requested_model": self.model,
            "actual_model": None,
            "finish_reason": None,
            "usage": None,
            "generation_config": {
                "max_output_tokens": output_limit,
                "thinking_level": thinking_level,
            },
        }

        response = self._client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=self._genai.types.GenerateContentConfig(
                max_output_tokens=output_limit,
                thinking_config=self._genai.types.ThinkingConfig(thinking_level=thinking_level),
            ),
        )
        usage = getattr(response, "usage_metadata", None)
        if usage is not None:
            serialized_usage = to_metadata_value(usage)
            self.last_usage = serialized_usage if isinstance(serialized_usage, dict) else None

        candidates = getattr(response, "candidates", None) or []
        finish_reasons = [
            to_metadata_value(getattr(candidate, "finish_reason", None))
            for candidate in candidates
        ]
        actual_model = (
            getattr(response, "model_version", None)
            or getattr(response, "model", None)
            or getattr(response, "actual_model", None)
        )
        self.last_response_metadata = {
            **self.last_response_metadata,
            "actual_model": to_metadata_value(actual_model),
            "finish_reason": finish_reasons[0] if finish_reasons else None,
            "finish_reasons": finish_reasons,
            "usage": self.last_usage,
        }
        return response.text or ""
