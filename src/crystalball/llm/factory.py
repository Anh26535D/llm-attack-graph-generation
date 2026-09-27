"""Picks an LLMClient based on Settings.llm_backend, or None for "manual"
(i.e. the user copy/pastes prompts and responses by hand)."""

from __future__ import annotations

from ..config import Settings, get_settings
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

    if backend == "openrouter":
        if not settings.openrouter_api_key:
            raise RuntimeError(
                "LLM_BACKEND=openrouter but OPENROUTER_API_KEY is not set. "
                "Copy .env.example to .env and fill it in, or use LLM_BACKEND=manual."
            )
        if not settings.openrouter_model.strip():
            raise RuntimeError(
                "LLM_BACKEND=openrouter but OPENROUTER_MODEL is empty. "
                "Set it to an exact OpenRouter model slug from https://openrouter.ai/models."
            )
        from .openrouter_client import OpenRouterLLMClient

        return OpenRouterLLMClient(settings.openrouter_api_key, settings.openrouter_model)

    if backend == "gemini":
        if not settings.gemini_api_key:
            raise RuntimeError(
                "LLM_BACKEND=gemini but GEMINI_API_KEY is not set. "
                "Copy .env.example to .env and fill it in, or use LLM_BACKEND=manual."
            )
        from .gemini_client import GeminiLLMClient

        return GeminiLLMClient(settings.gemini_api_key, settings.gemini_model)

    raise ValueError(f"Unknown LLM_BACKEND: {settings.llm_backend!r}")
