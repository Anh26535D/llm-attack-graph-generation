"""LLM is used as a black box in the system (Section 3, "LLM" component)."""

from __future__ import annotations

from abc import ABC, abstractmethod


class LLMClient(ABC):
    """Anything that can turn a prompt string into a text completion."""

    name: str = "base"

    @abstractmethod
    def complete(self, prompt: str) -> str: ...
