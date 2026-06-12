"""SQLite storage layer for normalized URLhaus indicators."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS indicators (
    id TEXT PRIMARY KEY,
    dateadded TEXT,
    dateadded_utc TEXT,
    url TEXT NOT NULL,
    scheme TEXT,
    host TEXT,
    host_type TEXT,
    registered_domain TEXT,
    tld TEXT,
    ip_address TEXT,
    port INTEGER,
    path TEXT,
    path_depth INTEGER,
    url_length INTEGER,
    url_status TEXT,
    last_online TEXT,
    threat TEXT,
    tags TEXT,
    tag_count INTEGER,
    has_query INTEGER,
    host_length INTEGER,
    host_digit_ratio REAL,
    host_entropy REAL,
    path_length INTEGER,
    path_digit_ratio REAL,
    file_extension TEXT,
    has_executable_extension INTEGER,
    has_suspicious_path_keyword INTEGER,
    is_ip_host INTEGER,
    is_default_port INTEGER,
    is_non_standard_port INTEGER,
    urlhaus_link TEXT,
    reporter TEXT
);

CREATE INDEX IF NOT EXISTS idx_indicators_host ON indicators(host);
CREATE INDEX IF NOT EXISTS idx_indicators_status ON indicators(url_status);
CREATE INDEX IF NOT EXISTS idx_indicators_threat ON indicators(threat);
CREATE INDEX IF NOT EXISTS idx_indicators_date ON indicators(dateadded_utc);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA foreign_keys=ON;")
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_SQL)
    connection.commit()


def upsert_indicators(frame: pd.DataFrame, db_path: str | Path) -> int:
    """Upsert normalized indicators into SQLite."""

    columns = [
        "id",
        "dateadded",
        "dateadded_utc",
        "url",
        "scheme",
        "host",
        "host_type",
        "registered_domain",
        "tld",
        "ip_address",
        "port",
        "path",
        "path_depth",
        "url_length",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "tag_count",
        "has_query",
        "host_length",
        "host_digit_ratio",
        "host_entropy",
        "path_length",
        "path_digit_ratio",
        "file_extension",
        "has_executable_extension",
        "has_suspicious_path_keyword",
        "is_ip_host",
        "is_default_port",
        "is_non_standard_port",
        "urlhaus_link",
        "reporter",
    ]
    frame_to_store = frame[columns].copy()
    frame_to_store["dateadded_utc"] = frame_to_store["dateadded_utc"].astype(str)
    integer_columns = [
        "has_query",
        "host_length",
        "path_length",
        "has_executable_extension",
        "has_suspicious_path_keyword",
        "is_ip_host",
        "is_default_port",
        "is_non_standard_port",
    ]
    for column in integer_columns:
        frame_to_store[column] = frame_to_store[column].fillna(0).astype(int)

    with connect(db_path) as connection:
        initialize_database(connection)
        placeholders = ", ".join(["?"] * len(columns))
        update_clause = ", ".join(
            [f"{column}=excluded.{column}" for column in columns if column != "id"]
        )
        sql = f"""
            INSERT INTO indicators ({", ".join(columns)})
            VALUES ({placeholders})
            ON CONFLICT(id) DO UPDATE SET {update_clause};
        """
        records = (
            frame_to_store.astype(object)
            .where(pd.notna(frame_to_store), None)
            .values.tolist()
        )
        connection.executemany(sql, records)
        connection.commit()

    return len(frame_to_store)
