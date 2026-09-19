"""Embedding backends for the Retriever (Section 3.2 / Section 4 "Retriever").

The paper uses the pretrained `facebook/contriever-msmarco` model from
Hugging Face via sentence-transformers. That is available here as the
"sentence-transformers" backend (install the `embeddings` extra).

A dependency-free "hashing" backend is provided as the default so the whole
pipeline (ingestion, retrieval, prompt building) can be exercised offline
without downloading a ~1GB model. Swap `EMBEDDING_BACKEND=sentence-transformers`
in `.env` to reproduce the paper's actual retriever quality.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path

import numpy as np

from .config import Settings, get_settings

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class EmbeddingModel(ABC):
    """Common interface: text -> fixed-size float32 vector."""

    dim: int

    @abstractmethod
    def encode(self, text: str) -> np.ndarray: ...


class HashingEmbedding(EmbeddingModel):
    """Deterministic bag-of-words hashing vector (no downloads, no training).

    Good enough to demonstrate the retriever's control flow (cosine
    similarity thresholding, token-budgeted context building) without any
    external dependency. Not a substitute for a real semantic embedding.
    """

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim

    def encode(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        tokens = _TOKEN_RE.findall(text.lower())
        if not tokens:
            return vec
        for tok in tokens:
            h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
            vec[h % self.dim] += 1.0
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec


class SentenceTransformerEmbedding(EmbeddingModel):
    """Paper-accurate backend using `facebook/contriever-msmarco` (or any
    other sentence-transformers-compatible model)."""

    def __init__(self, model_name: str) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "sentence-transformers is not installed. Run "
                '`pip install -e ".[embeddings]"` or set EMBEDDING_BACKEND=hashing.'
            ) from exc
        self._model = SentenceTransformer(model_name)
        self.dim = self._model.get_sentence_embedding_dimension()

    def encode(self, text: str) -> np.ndarray:
        return np.asarray(self._model.encode(text, normalize_embeddings=True), dtype=np.float32)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 or b.size == 0:
        return 0.0
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)


def save_embedding(vec: np.ndarray, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    np.save(path, vec)


def load_embedding(path: Path) -> np.ndarray:
    return np.load(path if str(path).endswith(".npy") else str(path) + ".npy")


def embedding_path(embeddings_dir: Path, cve_id: str, kind: str) -> Path:
    """`kind` is one of "product", "platform", "problem_type" (mirrors the
    *_vector_file naming in Algorithm 1)."""
    return embeddings_dir / f"{cve_id}_{kind}.npy"


@lru_cache(maxsize=1)
def _cached_model(backend: str, model_name: str) -> EmbeddingModel:
    if backend == "sentence-transformers":
        try:
            return SentenceTransformerEmbedding(model_name)
        except ImportError:
            print(
                "[crystalball] sentence-transformers unavailable, "
                "falling back to the hashing embedding backend."
            )
            return HashingEmbedding()
    return HashingEmbedding()


def get_embedding_model(settings: Settings | None = None) -> EmbeddingModel:
    settings = settings or get_settings()
    return _cached_model(settings.embedding_backend, settings.embedding_model)
