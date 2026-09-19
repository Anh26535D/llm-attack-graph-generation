"""Gemini backend.

The paper notes: "Gemini does not expose any API endpoint. As a result, we
have to provide the prompt to Gemini manually." That is still the
recommended default workflow here (see scripts/build_prompt.py +
scripts/ingest_response.py). This client is provided for convenience now
that Gemini does have a public API, for anyone who wants full automation.
"""

from __future__ import annotations

from .base import LLMClient


class GeminiLLMClient(LLMClient):
    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-1.5-pro") -> None:
        try:
            import google.generativeai as genai
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                'The google-generativeai package is required. Run `pip install -e ".[gemini]"`.'
            ) from exc
        genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel(model)

    def complete(self, prompt: str) -> str:
        response = self._model.generate_content(prompt)
        return response.text or ""
