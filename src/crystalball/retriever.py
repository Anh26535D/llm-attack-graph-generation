"""Algorithm 2: Get Context(Q).

Given a user query (a list of product/package names describing the target
system), find CVEs whose product-name or platform embedding is close enough
(cosine similarity > min_similarity) to any query term, then concatenate
their descriptions into a context string bounded by context_tokens_per_query.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Settings, get_settings
from .db import Database
from .embeddings import EmbeddingModel, cosine_similarity, get_embedding_model, load_embedding
from .tokens import count_tokens


@dataclass
class RetrievalResult:
    context: str
    relevant_cve_ids: list[str]
    matches: list[tuple[str, str, float]]  # (cve_id, matched_on, score)


def get_context(
    query_terms: list[str],
    db: Database,
    embedding_model: EmbeddingModel | None = None,
    settings: Settings | None = None,
) -> RetrievalResult:
    settings = settings or get_settings()
    embedding_model = embedding_model or get_embedding_model(settings)

    min_similarity = settings.min_similarity
    max_tokens = settings.context_tokens_per_query

    relevant_cves: set[str] = set()
    matches: list[tuple[str, str, float]] = []

    query_vectors = [(term, embedding_model.encode(term)) for term in query_terms]

    for product in db.all_products():
        try:
            product_vec = load_embedding(product.product_embedding_file)
        except FileNotFoundError:
            continue
        best = max(
            (cosine_similarity(qvec, product_vec) for _, qvec in query_vectors),
            default=0.0,
        )
        if best > min_similarity:
            relevant_cves.add(product.cve_id)
            matches.append((product.cve_id, f"product:{product.product_name}", best))

    for platform in db.all_platforms():
        try:
            platform_vec = load_embedding(platform.platform_embedding_file)
        except FileNotFoundError:
            continue
        best = max(
            (cosine_similarity(qvec, platform_vec) for _, qvec in query_vectors),
            default=0.0,
        )
        if best > min_similarity:
            relevant_cves.add(platform.cve_id)
            matches.append((platform.cve_id, f"platform:{platform.platform}", best))

    descriptions = db.get_cve_descriptions(relevant_cves)

    context = ""
    included: list[str] = []
    for cve_id, description in descriptions.items():
        candidate = f"{context}\n---\n{description}" if context else description
        if count_tokens(candidate) < max_tokens:
            context = candidate
            included.append(cve_id)
        else:
            break

    return RetrievalResult(context=context, relevant_cve_ids=included, matches=matches)
