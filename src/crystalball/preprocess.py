"""Algorithm 1: Preprocess CVE(P).

Reads a CVE JSON record (CVE Record Format v5, as published at
https://github.com/CVEProject/cvelistV5), extracts product/platform/version/
problem-type properties, embeds them, and stores everything in the
database + embedding files that the Retriever (Algorithm 2) later reads.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .config import EMBEDDINGS_DIR, Settings, get_settings
from .db import Database
from .embeddings import EmbeddingModel, embedding_path, get_embedding_model, save_embedding
from .extractors import Extractor, get_extractor
from .llm.factory import get_llm_client


@dataclass
class PreprocessResult:
    cve_id: str
    skipped: bool
    reason: str | None = None


def _get_description(cve_json: dict) -> str:
    descriptions = cve_json.get("containers", {}).get("cna", {}).get("descriptions", [])
    for d in descriptions:
        if d.get("lang", "en").startswith("en"):
            return d.get("value", "")
    return descriptions[0]["value"] if descriptions else ""


def preprocess_cve(
    path: Path,
    db: Database,
    embedding_model: EmbeddingModel | None = None,
    extractor: Extractor | None = None,
    embeddings_dir: Path | None = None,
    settings: Settings | None = None,
) -> PreprocessResult:
    settings = settings or get_settings()
    embedding_model = embedding_model or get_embedding_model(settings)
    embeddings_dir = embeddings_dir or EMBEDDINGS_DIR
    if extractor is None:
        llm_client = get_llm_client(settings) if settings.extractor_backend == "llm" else None
        extractor = get_extractor(settings.extractor_backend, llm_client)

    cve_json = json.loads(Path(path).read_text(encoding="utf-8"))

    state = cve_json.get("cveMetadata", {}).get("state", "").upper()
    cve_id = cve_json.get("cveMetadata", {}).get("cveId", Path(path).stem)

    if state == "REJECTED":
        return PreprocessResult(cve_id=cve_id, skipped=True, reason="rejected")

    description = _get_description(cve_json)
    if not description:
        return PreprocessResult(cve_id=cve_id, skipped=True, reason="no description")

    db.store_cve(cve_id, description, state)

    props = extractor.extract(description, cve_json)

    if props.product_name:
        product_vec = embedding_model.encode(props.product_name)
        product_vec_path = embedding_path(embeddings_dir, cve_id, "product")
        save_embedding(product_vec, product_vec_path)
        product_id = db.store_product(cve_id, props.product_name, str(product_vec_path))
        if props.version.version_number or props.version.qualifier:
            db.store_version(product_id, props.version.version_number, props.version.qualifier)

    if props.problem_type:
        problem_vec = embedding_model.encode(props.problem_type)
        problem_vec_path = embedding_path(embeddings_dir, cve_id, "problem_type")
        save_embedding(problem_vec, problem_vec_path)
        db.store_problem_type(cve_id, props.problem_type, str(problem_vec_path))

    if props.platform:
        platform_vec = embedding_model.encode(props.platform)
        platform_vec_path = embedding_path(embeddings_dir, cve_id, "platform")
        save_embedding(platform_vec, platform_vec_path)
        db.store_platform(cve_id, props.platform, str(platform_vec_path))

    return PreprocessResult(cve_id=cve_id, skipped=False)


def preprocess_directory(
    directory: Path,
    db: Database,
    settings: Settings | None = None,
) -> list[PreprocessResult]:
    settings = settings or get_settings()
    embedding_model = get_embedding_model(settings)
    llm_client = get_llm_client(settings) if settings.extractor_backend == "llm" else None
    extractor = get_extractor(settings.extractor_backend, llm_client)

    results = []
    for path in sorted(Path(directory).glob("*.json")):
        results.append(
            preprocess_cve(path, db, embedding_model=embedding_model, extractor=extractor, settings=settings)
        )
    return results
