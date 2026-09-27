import sys

import pytest

from crystalball.config import Settings
from crystalball.embeddings import _cached_model, get_embedding_model


def test_sentence_transformer_backend_fails_clearly_when_dependency_is_missing(monkeypatch):
    _cached_model.cache_clear()
    monkeypatch.setitem(sys.modules, "sentence_transformers", None)

    with pytest.raises(ImportError, match="sentence-transformers is not installed"):
        get_embedding_model(Settings(embedding_backend="sentence-transformers"))


def test_unknown_embedding_backend_fails_fast():
    _cached_model.cache_clear()

    with pytest.raises(ValueError, match="Unknown EMBEDDING_BACKEND: 'typo'"):
        get_embedding_model(Settings(embedding_backend="typo"))
