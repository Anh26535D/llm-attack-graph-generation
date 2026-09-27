import json
import sqlite3

from crystalball.config import Settings
from crystalball.db import Database
from crystalball.extractors import LLMExtractor
from crystalball.llm.base import LLMClient
from crystalball.preprocess import preprocess_cve


def test_reingesting_cve_replaces_its_derived_rows(tmp_path):
    cve_path = tmp_path / "CVE-2025-1234.json"
    cve_path.write_text(
        json.dumps(
            {
                "cveMetadata": {"cveId": "CVE-2025-1234", "state": "PUBLISHED"},
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "A flaw in Widget before 2.0."}],
                        "affected": [
                            {
                                "vendor": "Acme",
                                "product": "Widget",
                                "platforms": ["Linux"],
                                "versions": [{"version": "2.0", "lessThan": "2.0"}],
                            }
                        ],
                        "problemTypes": [
                            {"descriptions": [{"lang": "en", "description": "Path Traversal"}]}
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    db = Database(tmp_path / "cves.sqlite3")
    settings = Settings(embedding_backend="hashing", extractor_backend="heuristic")
    kwargs = {
        "db": db,
        "settings": settings,
        "embeddings_dir": tmp_path / "embeddings",
    }

    preprocess_cve(cve_path, **kwargs)
    preprocess_cve(cve_path, **kwargs)

    with sqlite3.connect(db.db_path) as conn:
        counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("cve_info", "product_info", "version_info", "problem_type", "platform")
        }

    assert counts == {
        "cve_info": 1,
        "product_info": 1,
        "version_info": 1,
        "problem_type": 1,
        "platform": 1,
    }


def test_preprocess_persists_every_version_range_entry(tmp_path):
    cve_path = tmp_path / "CVE-2025-5678.json"
    cve_path.write_text(
        json.dumps(
            {
                "cveMetadata": {"cveId": "CVE-2025-5678", "state": "PUBLISHED"},
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "Affected Widget range."}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    class FakeLLMClient(LLMClient):
        name = "fake"

        def complete(self, prompt):
            return json.dumps(
                {
                    "ProductInfo": {
                        "ProductName": "Widget",
                        "Version": [
                            {"VersionNumber": "5.2.7", "Qualifier": ">="},
                            {"VersionNumber": "5.7.11", "Qualifier": "<="},
                        ],
                    }
                }
            )

    db = Database(tmp_path / "range.sqlite3")
    preprocess_cve(
        cve_path,
        db,
        extractor=LLMExtractor(FakeLLMClient()),
        embeddings_dir=tmp_path / "range-embeddings",
        settings=Settings(embedding_backend="hashing"),
    )

    with sqlite3.connect(db.db_path) as conn:
        versions = conn.execute(
            "SELECT version_number, qualifier FROM version_info ORDER BY id"
        ).fetchall()

    assert versions == [("5.2.7", ">="), ("5.7.11", "<=")]
