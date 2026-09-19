from crystalball.config import Settings
from crystalball.db import Database
from crystalball.embeddings import HashingEmbedding, save_embedding
from crystalball.retriever import get_context


def _make_db_with_cve(tmp_path, embedding_model, cve_id, description, product_name, platform=None):
    db = Database(tmp_path / "test.sqlite3")
    db.store_cve(cve_id, description, "PUBLISHED")

    product_vec = embedding_model.encode(product_name)
    product_vec_path = tmp_path / f"{cve_id}_product.npy"
    save_embedding(product_vec, product_vec_path)
    db.store_product(cve_id, product_name, str(product_vec_path))

    if platform:
        platform_vec = embedding_model.encode(platform)
        platform_vec_path = tmp_path / f"{cve_id}_platform.npy"
        save_embedding(platform_vec, platform_vec_path)
        db.store_platform(cve_id, platform, str(platform_vec_path))

    return db


def test_get_context_matches_relevant_product(tmp_path):
    embedding_model = HashingEmbedding(dim=256)
    db = _make_db_with_cve(
        tmp_path,
        embedding_model,
        "CVE-2020-1885",
        "OVRRedir.exe privilege escalation in Oculus Desktop",
        "Oculus Desktop",
        platform="Windows",
    )

    settings = Settings(min_similarity=0.3, context_tokens_per_query=1000)
    result = get_context(["Oculus Desktop"], db, embedding_model=embedding_model, settings=settings)

    assert "CVE-2020-1885" in result.relevant_cve_ids
    assert "OVRRedir" in result.context


def test_get_context_excludes_unrelated_product(tmp_path):
    embedding_model = HashingEmbedding(dim=256)
    db = _make_db_with_cve(
        tmp_path,
        embedding_model,
        "CVE-2020-1885",
        "OVRRedir.exe privilege escalation in Oculus Desktop",
        "Oculus Desktop",
    )

    settings = Settings(min_similarity=0.99, context_tokens_per_query=1000)
    result = get_context(["Completely Unrelated Widget"], db, embedding_model=embedding_model, settings=settings)

    assert result.relevant_cve_ids == []
    assert result.context == ""


def test_get_context_respects_token_budget(tmp_path):
    embedding_model = HashingEmbedding(dim=256)
    db = Database(tmp_path / "test.sqlite3")
    for i in range(3):
        cve_id = f"CVE-2020-{i}"
        db.store_cve(cve_id, "word " * 2000, "PUBLISHED")
        vec = embedding_model.encode("Oculus Desktop")
        vec_path = tmp_path / f"{cve_id}_product.npy"
        save_embedding(vec, vec_path)
        db.store_product(cve_id, "Oculus Desktop", str(vec_path))

    settings = Settings(min_similarity=0.3, context_tokens_per_query=500)
    result = get_context(["Oculus Desktop"], db, embedding_model=embedding_model, settings=settings)

    # Token budget should stop us from including all 3 large descriptions.
    assert len(result.relevant_cve_ids) < 3
