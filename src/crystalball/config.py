"""Central configuration, all overridable via environment variables / .env.

Defaults reproduce the values reported in the paper (Algorithm 2):
MIN_SIMILARITY = 0.68, CONTEXT_TOKENS_PER_QUERY = 3750.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("CRYSTALBALL_DATA_DIR", PROJECT_ROOT / "data"))
EMBEDDINGS_DIR = Path(os.getenv("CRYSTALBALL_EMBEDDINGS_DIR", DATA_DIR / "embeddings"))
DB_PATH = Path(os.getenv("CRYSTALBALL_DB_PATH", DATA_DIR / "db" / "crystalball.sqlite3"))
OUTPUTS_DIR = Path(os.getenv("CRYSTALBALL_OUTPUTS_DIR", PROJECT_ROOT / "outputs"))
PROMPTS_DIR = OUTPUTS_DIR / "prompts"
GRAPHS_DIR = OUTPUTS_DIR / "graphs"


@dataclass
class Settings:
    # --- Retriever (Algorithm 2) ---
    min_similarity: float = field(
        default_factory=lambda: float(os.getenv("MIN_SIMILARITY", "0.68"))
    )
    context_tokens_per_query: int = field(
        default_factory=lambda: int(os.getenv("CONTEXT_TOKENS_PER_QUERY", "3750"))
    )

    # --- Embeddings ---
    # "hashing"            -> zero-dependency deterministic bag-of-words embedding
    #                          (works offline, good enough to exercise the pipeline/tests)
    # "sentence-transformers" -> paper-accurate facebook/contriever-msmarco embeddings
    embedding_backend: str = field(
        default_factory=lambda: os.getenv("EMBEDDING_BACKEND", "hashing")
    )
    embedding_model: str = field(
        default_factory=lambda: os.getenv("EMBEDDING_MODEL", "facebook/contriever-msmarco")
    )

    # --- Property extraction (Algorithm 1, prompt on line 13) ---
    # "heuristic" -> regex/structured-field based, no API key needed
    # "llm"       -> uses the configured LLM_BACKEND to run the paper's extraction prompt
    extractor_backend: str = field(
        default_factory=lambda: os.getenv("EXTRACTOR_BACKEND", "heuristic")
    )

    # --- LLM backend used for both extraction (if extractor_backend == "llm") and
    # attack-graph generation when the user wants a fully automated call instead of
    # copy/pasting into a chat UI. ---
    # "manual" -> no API call is made; scripts write a prompt file for the user to
    #             paste into ChatGPT/Gemini/etc, and read the pasted answer back in.
    # "openai" -> calls the OpenAI Chat Completions API (needs OPENAI_API_KEY)
    # "gemini" -> calls the Google Gemini API (needs GEMINI_API_KEY)
    llm_backend: str = field(default_factory=lambda: os.getenv("LLM_BACKEND", "manual"))
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    openai_api_key: str | None = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    gemini_model: str = field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-1.5-pro"))
    gemini_api_key: str | None = field(default_factory=lambda: os.getenv("GEMINI_API_KEY"))


def get_settings() -> Settings:
    return Settings()


def ensure_dirs() -> None:
    for d in (DATA_DIR, EMBEDDINGS_DIR, DB_PATH.parent, PROMPTS_DIR, GRAPHS_DIR):
        d.mkdir(parents=True, exist_ok=True)
