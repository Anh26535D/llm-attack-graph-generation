"""SQLite-backed "semantic search capable structured database" (Section 3,
"Database" component). Table names mirror the ones referenced in Algorithm 1
and Algorithm 2: CVE_INFO, PRODUCT_INFO, VERSION_INFO, PROBLEM_TYPE, PLATFORM.

An additional GRAPHS table stores generated attack graphs (Post-Processor,
Section 3.4).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_info (
    cve_id      TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    state       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS product_info (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                  TEXT NOT NULL REFERENCES cve_info(cve_id),
    product_name            TEXT NOT NULL,
    product_embedding_file  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS version_info (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id      INTEGER NOT NULL REFERENCES product_info(id),
    version_number  TEXT,
    qualifier       TEXT
);

CREATE TABLE IF NOT EXISTS problem_type (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                 TEXT NOT NULL REFERENCES cve_info(cve_id),
    problem_type           TEXT,
    problem_embedding_file TEXT
);

CREATE TABLE IF NOT EXISTS platform (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                  TEXT NOT NULL REFERENCES cve_info(cve_id),
    platform                TEXT,
    platform_embedding_file TEXT
);

CREATE TABLE IF NOT EXISTS graphs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    query        TEXT NOT NULL,
    prompt       TEXT NOT NULL,
    raw_response TEXT,
    graph_json   TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


@contextmanager
def connect(db_path: Path | None = None) -> Iterator[sqlite3.Connection]:
    db_path = db_path or DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Path | None = None) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


@dataclass
class ProductRow:
    id: int
    cve_id: str
    product_name: str
    product_embedding_file: str


@dataclass
class PlatformRow:
    id: int
    cve_id: str
    platform: str
    platform_embedding_file: str


class Database:
    """Thin CRUD wrapper used by preprocess.py and retriever.py."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or DB_PATH
        init_db(self.db_path)

    def store_cve(self, cve_id: str, description: str, state: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_info (cve_id, description, state) "
                "VALUES (?, ?, ?)",
                (cve_id, description, state),
            )

    def store_product(self, cve_id: str, product_name: str, embedding_file: str) -> int:
        with connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO product_info (cve_id, product_name, product_embedding_file) "
                "VALUES (?, ?, ?)",
                (cve_id, product_name, embedding_file),
            )
            return cur.lastrowid

    def store_version(self, product_id: int, version_number: str | None, qualifier: str | None) -> None:
        with connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO version_info (product_id, version_number, qualifier) VALUES (?, ?, ?)",
                (product_id, version_number, qualifier),
            )

    def store_problem_type(self, cve_id: str, problem_type: str | None, embedding_file: str | None) -> None:
        with connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO problem_type (cve_id, problem_type, problem_embedding_file) VALUES (?, ?, ?)",
                (cve_id, problem_type, embedding_file),
            )

    def store_platform(self, cve_id: str, platform: str | None, embedding_file: str | None) -> None:
        with connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO platform (cve_id, platform, platform_embedding_file) VALUES (?, ?, ?)",
                (cve_id, platform, embedding_file),
            )

    def cve_exists(self, cve_id: str) -> bool:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT 1 FROM cve_info WHERE cve_id = ?", (cve_id,)).fetchone()
            return row is not None

    def delete_cve(self, cve_id: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute("DELETE FROM product_info WHERE cve_id = ?", (cve_id,))
            conn.execute("DELETE FROM problem_type WHERE cve_id = ?", (cve_id,))
            conn.execute("DELETE FROM platform WHERE cve_id = ?", (cve_id,))
            conn.execute("DELETE FROM cve_info WHERE cve_id = ?", (cve_id,))

    def all_products(self) -> list[ProductRow]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, cve_id, product_name, product_embedding_file FROM product_info"
            ).fetchall()
            return [ProductRow(**dict(r)) for r in rows]

    def all_platforms(self) -> list[PlatformRow]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, cve_id, platform, platform_embedding_file FROM platform "
                "WHERE platform IS NOT NULL AND platform_embedding_file IS NOT NULL"
            ).fetchall()
            return [PlatformRow(**dict(r)) for r in rows]

    def get_cve_descriptions(self, cve_ids: set[str]) -> dict[str, str]:
        if not cve_ids:
            return {}
        with connect(self.db_path) as conn:
            placeholders = ",".join("?" for _ in cve_ids)
            rows = conn.execute(
                f"SELECT cve_id, description FROM cve_info WHERE cve_id IN ({placeholders})",
                tuple(cve_ids),
            ).fetchall()
            return {r["cve_id"]: r["description"] for r in rows}

    def count_cves(self) -> int:
        with connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM cve_info").fetchone()[0]

    def save_graph(self, query: str, prompt: str, raw_response: str | None, graph: dict | None) -> int:
        with connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO graphs (query, prompt, raw_response, graph_json) VALUES (?, ?, ?, ?)",
                (query, prompt, raw_response, json.dumps(graph) if graph is not None else None),
            )
            return cur.lastrowid
