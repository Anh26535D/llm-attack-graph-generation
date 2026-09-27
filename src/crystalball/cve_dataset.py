"""Validation helpers for the official eight-CVE case-study dataset."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

OFFICIAL_CVE_IDS = frozenset({
    "CVE-2020-1885",
    "CVE-2019-20354",
    "CVE-2019-3562",
    "CVE-2020-24572",
    "CVE-2021-24038",
    "CVE-2021-38545",
    "CVE-2021-38759",
    "CVE-2022-21819",
})
CVELIST_V5_COMMIT = "73ca210d8ac127ab434175fe2a8a050d3c8844d0"
PLACEHOLDER_CVE_RE = re.compile(r"CVE-2024-9000[1-6]$", re.IGNORECASE)


@dataclass(frozen=True)
class OfficialCveDataset:
    manifest_path: Path
    dataset_id: str
    query: list[str]
    records: list[dict[str, Any]]
    files: list[Path]
    digest: str


def official_record_url(cve_id: str, commit: str = CVELIST_V5_COMMIT) -> str:
    year, number = cve_id.removeprefix("CVE-").split("-", 1)
    prefix = number[:-3] + "xxx"
    return (
        f"https://raw.githubusercontent.com/CVEProject/cvelistV5/{commit}/"
        f"cves/{year}/{prefix}/{cve_id}.json"
    )


def _english_description(record: dict[str, Any]) -> str | None:
    descriptions = record.get("containers", {}).get("cna", {}).get("descriptions", [])
    for item in descriptions:
        if str(item.get("lang", "")).lower() in {"en", "en-us", "en-gb"}:
            value = item.get("value")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def load_official_cve_dataset(
    manifest_path: Path,
    *,
    required_ids: set[str] | frozenset[str] | None = None,
    expected_count: int = 8,
) -> OfficialCveDataset:
    """Load and strictly validate a flat set of official CVE Record Format v5 JSONs.

    Manifest record entries have ``cve_id``, ``path``, ``source_url`` and ``sha256``.
    Relative paths must be flat filenames beside the manifest, avoiding accidental
    traversal or a silent scan of an entire cvelistV5 checkout.
    """
    manifest_path = manifest_path.resolve()
    raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if raw_manifest.get("source_commit") != CVELIST_V5_COMMIT:
        raise ValueError(f"Manifest must pin CVEProject/cvelistV5 commit {CVELIST_V5_COMMIT}.")
    if not isinstance(raw_manifest.get("retrieved_at_utc"), str):
        raise ValueError("Manifest must record retrieved_at_utc.")
    entries = raw_manifest.get("records")
    if not isinstance(entries, list) or len(entries) != expected_count:
        raise ValueError(f"Manifest must contain exactly {expected_count} records.")

    ids: list[str] = []
    seen_paths: set[str] = set()
    files: list[Path] = []
    validated: list[dict[str, Any]] = []
    digest_rows = []
    for entry in entries:
        cve_id = entry.get("cve_id")
        filename = entry.get("path")
        if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            raise ValueError("Each manifest record needs a valid CVE ID.")
        if PLACEHOLDER_CVE_RE.fullmatch(cve_id):
            raise ValueError(f"Placeholder CVE ID is not allowed: {cve_id}.")
        if not isinstance(filename, str) or Path(filename).name != filename or filename != f"{cve_id}.json":
            raise ValueError(f"Record filename must be the flat filename {cve_id}.json.")
        if filename in seen_paths:
            raise ValueError(f"Duplicate record path: {filename}.")
        seen_paths.add(filename)
        path = manifest_path.parent / filename
        if not path.is_file():
            raise FileNotFoundError(f"Missing official CVE record: {path}.")
        expected_url = official_record_url(cve_id, CVELIST_V5_COMMIT)
        source_url = entry.get("source_url")
        parsed_url = urlparse(source_url) if isinstance(source_url, str) else None
        if source_url != expected_url or parsed_url is None or parsed_url.hostname != "raw.githubusercontent.com":
            raise ValueError(f"Unexpected official source URL for {cve_id}.")
        expected_sha = entry.get("sha256")
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise ValueError(f"Missing SHA-256 for {cve_id}.")
        actual_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            raise ValueError(f"SHA-256 mismatch for {cve_id}.")

        record = json.loads(path.read_text(encoding="utf-8"))
        metadata = record.get("cveMetadata", {})
        if record.get("dataType") != "CVE_RECORD":
            raise ValueError(f"{filename} is not a CVE_RECORD JSON document.")
        if not str(record.get("dataVersion", "")).startswith("5."):
            raise ValueError(f"{filename} is not CVE Record Format v5.")
        if metadata.get("cveId") != cve_id:
            raise ValueError(f"Manifest ID, filename and cveMetadata.cveId differ for {filename}.")
        if metadata.get("state") != "PUBLISHED":
            raise ValueError(f"{cve_id} is not in PUBLISHED state.")
        if not _english_description(record):
            raise ValueError(f"{cve_id} has no non-empty English description.")
        ids.append(cve_id)
        files.append(path)
        clean_entry = {
            "cve_id": cve_id,
            "path": filename,
            "source_url": source_url,
            "sha256": actual_sha,
        }
        validated.append(clean_entry)
        digest_rows.append(clean_entry)

    if len(set(ids)) != expected_count:
        raise ValueError("Manifest CVE IDs must be unique.")
    if required_ids is not None and set(ids) != set(required_ids):
        missing = sorted(set(required_ids) - set(ids))
        extra = sorted(set(ids) - set(required_ids))
        raise ValueError(f"Official CVE set mismatch; missing={missing}, extra={extra}.")

    query = raw_manifest.get("product_query")
    if not isinstance(query, list) or not query or any(not isinstance(item, str) or not item.strip() for item in query):
        raise ValueError("Manifest product_query must be a non-empty list of strings.")
    digest_payload = {
        "dataset_id": raw_manifest.get("dataset_id"),
        "product_query": query,
        "records": sorted(digest_rows, key=lambda row: row["cve_id"]),
    }
    digest = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return OfficialCveDataset(
        manifest_path=manifest_path,
        dataset_id=str(raw_manifest.get("dataset_id", "official-cve-set")),
        query=query,
        records=validated,
        files=files,
        digest=digest,
    )
