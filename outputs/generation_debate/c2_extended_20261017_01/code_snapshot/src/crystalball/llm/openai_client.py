"""ChatGPT/GPT-4 backend (paper Section 4: "openai package is used for
automatic communication with ChatGPT models")."""

from __future__ import annotations

from .base import LLMClient, to_metadata_value, validate_generation_options


class OpenAILLMClient(LLMClient):
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                'The openai package is required. Run `pip install -e ".[openai]"`.'
            ) from exc
        self._client = OpenAI(api_key=api_key, max_retries=0)
        self.model = model
        self.last_usage = None
        self.last_response_metadata = None

    def complete(self, prompt: str, *, max_output_tokens: int | None = None,
                 reasoning_level: str | None = None) -> str:
        request = {"model": self.model, "messages": [{"role": "user", "content": prompt}]}
        if max_output_tokens is not None or reasoning_level is not None:
            from ..config import get_settings
            settings = get_settings()
            limit = settings.llm_max_output_tokens if max_output_tokens is None else max_output_tokens
            effort = settings.llm_reasoning_level if reasoning_level is None else reasoning_level
            validate_generation_options(limit, effort)
            request["max_completion_tokens"] = limit
            # The default GPT-4o family does not support a reasoning_effort field.
            if self.model.startswith(("o1", "o3", "o4", "gpt-5", "gpt-6")):
                request["reasoning_effort"] = effort
        self.last_usage = None
        self.last_response_metadata = None
        response = self._client.chat.completions.create(
            **request,
        )
        self.last_usage = to_metadata_value(getattr(response, "usage", None))
        self.last_response_metadata = {
            "requested_model": self.model, "actual_model": getattr(response, "model", None),
            "usage": self.last_usage,
            "finish_reason": to_metadata_value(getattr(response.choices[0], "finish_reason", None)),
            "generation_config": {k: v for k, v in request.items() if k not in {"model", "messages"}},
        }
        return response.choices[0].message.content or ""
