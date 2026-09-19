"""Token counting used by the Retriever to respect `context_tokens_per_query`
(Algorithm 2, lines 5 and 35-40 of the paper).

Uses `tiktoken` when available for an accurate count; otherwise falls back to
a simple whitespace-based estimate (~1.3 tokens per word), which is enough to
keep prompts within typical context windows for this reproduction.
"""

from __future__ import annotations

try:
    import tiktoken

    _ENC = tiktoken.get_encoding("cl100k_base")
except ImportError:
    _ENC = None


def count_tokens(text: str) -> int:
    if _ENC is not None:
        return len(_ENC.encode(text))
    if not text:
        return 0
    return int(len(text.split()) * 1.3)
