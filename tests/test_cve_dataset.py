import hashlib
import json

import pytest

from crystalball.cve_dataset import (
    CVELIST_V5_COMMIT,
    load_official_cve_dataset,
    official_record_url,
)


def write_fixture(tmp_path, *, cve_id="CVE-2030-12345", state="PUBLISHED", body=None):
    record = body or {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "state": state},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Test vulnerability."}]}},
    }
    record_path = tmp_path / f"{cve_id}.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    manifest = {
        "dataset_id": "fixture",
        "source_commit": CVELIST_V5_COMMIT,
        "retrieved_at_utc": "2026-09-24T00:00:00+00:00",
        "product_query": ["Test product"],
        "records": [{
            "cve_id": cve_id,
            "path": record_path.name,
            "source_url": official_record_url(cve_id),
            "sha256": hashlib.sha256(record_path.read_bytes()).hexdigest(),
        }],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, record_path, manifest


def test_load_official_dataset_checks_pin_hash_schema_and_metadata(tmp_path):
    manifest_path, record_path, manifest = write_fixture(tmp_path)

    dataset = load_official_cve_dataset(
        manifest_path, required_ids={"CVE-2030-12345"}, expected_count=1
    )

    assert dataset.files == [record_path.resolve()]
    assert dataset.records[0]["sha256"] == manifest["records"][0]["sha256"]
    assert dataset.query == ["Test product"]
    assert len(dataset.digest) == 64


def test_load_official_dataset_rejects_changed_record_hash(tmp_path):
    manifest_path, record_path, _ = write_fixture(tmp_path)
    record_path.write_text(record_path.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_official_cve_dataset(
            manifest_path, required_ids={"CVE-2030-12345"}, expected_count=1
        )


def test_load_official_dataset_rejects_unpublished_record(tmp_path):
    manifest_path, _, _ = write_fixture(tmp_path, state="REJECTED")

    with pytest.raises(ValueError, match="PUBLISHED"):
        load_official_cve_dataset(
            manifest_path, required_ids={"CVE-2030-12345"}, expected_count=1
        )


def test_load_official_dataset_rejects_id_mismatch(tmp_path):
    body = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": "CVE-2030-54321", "state": "PUBLISHED"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Test."}]}},
    }
    manifest_path, _, _ = write_fixture(tmp_path, body=body)

    with pytest.raises(ValueError, match="filename"):
        load_official_cve_dataset(
            manifest_path, required_ids={"CVE-2030-12345"}, expected_count=1
        )


def test_load_official_dataset_rejects_placeholder_ids(tmp_path):
    manifest_path, _, _ = write_fixture(tmp_path, cve_id="CVE-2024-90001")

    with pytest.raises(ValueError, match="Placeholder"):
        load_official_cve_dataset(
            manifest_path, required_ids={"CVE-2024-90001"}, expected_count=1
        )
