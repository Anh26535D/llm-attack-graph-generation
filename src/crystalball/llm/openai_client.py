"""ChatGPT/GPT-4 backend (paper Section 4: "openai package is used for
automatic communication with ChatGPT models")."""

from __future__ import annotations

from .base import LLMClient


class OpenAILLMClient(LLMClient):
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                'The openai package is required. Run `pip install -e ".[openai]"`.'
            ) from exc
        self._client = OpenAI(api_key=api_key)
        self.model = model

    def complete(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""
