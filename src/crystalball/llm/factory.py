"""Picks an LLMClient based on Settings.llm_backend, or None for "manual"
(i.e. the user copy/pastes prompts and responses by hand)."""

from __future__ import annotations

import json

from ..config import OPENROUTER_V2_REASONING_LEVEL, Settings, get_settings
from .base import LLMClient


def get_llm_client(settings: Settings | None = None) -> LLMClient | None:
    settings = settings or get_settings()
    backend = settings.llm_backend.lower()

    if backend == "manual":
        return None

    if backend == "openai":
        if not settings.openai_api_key:
            raise RuntimeError(
                "LLM_BACKEND=openai but OPENAI_API_KEY is not set. "
                "Copy .env.example to .env and fill it in, or use LLM_BACKEND=manual."
            )
        from .openai_client import OpenAILLMClient

        return OpenAILLMClient(settings.openai_api_key, settings.openai_model)

    if backend in {"openrouter", "openrouter_v2"}:
        is_v2 = backend == "openrouter_v2"
        suffix = "_V2" if is_v2 else ""
        api_key = settings.openrouter_api_key_v2 if is_v2 else settings.openrouter_api_key
        model = settings.openrouter_model_v2 if is_v2 else settings.openrouter_model
        if not api_key:
            raise RuntimeError(
                f"LLM_BACKEND={backend} but OPENROUTER_API_KEY{suffix} is not set. "
                "Copy .env.example to .env and fill it in, or use LLM_BACKEND=manual."
            )
        if not model.strip():
            raise RuntimeError(
                f"LLM_BACKEND={backend} but OPENROUTER_MODEL{suffix} is empty. "
                "Set it to an exact OpenRouter model slug from https://openrouter.ai/models."
            )
        options = {}
        if is_v2:
            try:
                provider_config = json.loads(settings.openrouter_provider_config_v2)
            except json.JSONDecodeError:
                raise ValueError("OPENROUTER_PROVIDER_CONFIG_V2 must be a valid JSON object.") from None
            if not isinstance(provider_config, dict):
                raise ValueError("OPENROUTER_PROVIDER_CONFIG_V2 must be a JSON object.")
            options = {
                "provider_config": provider_config,
                "reasoning_level": OPENROUTER_V2_REASONING_LEVEL,
                "max_output_tokens": settings.llm_max_output_tokens,
            }
        from .openrouter_client import OpenRouterLLMClient

        client = OpenRouterLLMClient(api_key, model, **options)
        if is_v2:
            client.name = "openrouter_v2"
        return client

    if backend == "gemini":
        if not settings.gemini_api_key:
            raise RuntimeError(
                "LLM_BACKEND=gemini but GEMINI_API_KEY is not set. "
                "Copy .env.example to .env and fill it in, or use LLM_BACKEND=manual."
            )
        from .gemini_client import GeminiLLMClient

        return GeminiLLMClient(settings.gemini_api_key, settings.gemini_model)

    raise ValueError(f"Unknown LLM_BACKEND: {settings.llm_backend!r}")
