"""SQLite persistence layer (stdlib sqlite3, one shared connection guarded by a lock)."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    source TEXT NOT NULL,              -- builtin | imported
    file_path TEXT,
    sha256 TEXT,
    case_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    dataset_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    log_type TEXT NOT NULL,
    label TEXT NOT NULL,
    severity TEXT NOT NULL,
    scenario TEXT NOT NULL,
    attack_type TEXT,
    injection_field TEXT,
    data TEXT NOT NULL,                -- full JSON record
    PRIMARY KEY (dataset_id, case_id)
);

CREATE TABLE IF NOT EXISTS benchmarks (
    id TEXT PRIMARY KEY,
    version TEXT,
    description TEXT,
    template_count INTEGER NOT NULL,
    data TEXT NOT NULL,
    imported_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,              -- pending | running | paused | interrupted | completed | failed
    is_mock INTEGER NOT NULL,
    config TEXT NOT NULL,
    total_runs INTEGER NOT NULL,
    completed_runs INTEGER NOT NULL DEFAULT 0,
    failed_runs INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id TEXT,                -- NULL for playground analyses
    dataset_id TEXT,
    case_id TEXT,
    variant TEXT,                      -- clean | modified | adhoc
    model TEXT NOT NULL,
    provider TEXT NOT NULL,
    defense TEXT NOT NULL,
    is_mock INTEGER NOT NULL,
    label TEXT,
    attack_type TEXT,
    log_type TEXT,
    verdict_raw TEXT,
    verdict_final TEXT,
    severity_final TEXT,
    correct INTEGER,
    attack_success_raw INTEGER,
    attack_success_final INTEGER,
    indicator_recall REAL,
    tripwire_fired INTEGER NOT NULL DEFAULT 0,
    tool_violation_attempted INTEGER NOT NULL DEFAULT 0,
    injection_flagged INTEGER NOT NULL DEFAULT 0,
    parse_ok INTEGER NOT NULL DEFAULT 1,
    latency_ms REAL,
    error TEXT,
    detail TEXT,                       -- JSON: prompt, raw response, parsed output, tool decisions, tripwire
    created_at TEXT NOT NULL,
    UNIQUE (experiment_id, case_id, variant, model, defense)
);
CREATE INDEX IF NOT EXISTS idx_results_exp ON results(experiment_id);

CREATE TABLE IF NOT EXISTS tripwire_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER,
    experiment_id TEXT,
    case_id TEXT,
    variant TEXT,
    model TEXT,
    defense TEXT,
    is_mock INTEGER NOT NULL,
    reasons TEXT NOT NULL,             -- JSON list
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER,
    experiment_id TEXT,
    case_id TEXT,
    variant TEXT,
    model TEXT,
    defense TEXT,
    is_mock INTEGER NOT NULL,
    tool TEXT NOT NULL,
    arguments TEXT,
    decision TEXT NOT NULL,            -- allowed_simulated | denied
    reason TEXT,
    executed_externally INTEGER NOT NULL DEFAULT 0,  -- always 0: nothing is ever executed
    created_at TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self._conn.executemany(sql, [tuple(r) for r in rows])
            self._conn.commit()

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return [dict(r) for r in cur.fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)
