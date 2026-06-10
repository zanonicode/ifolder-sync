"""Sync baseline persisted in SQLite, plus a small key/value meta table.

For each relative path we store the signature (kind, size, mtime) of how the file
looked at the last successful sync, separately per side. That is what lets us tell
"created" from "deleted" and detect conflicts (both sides changed since baseline).
The meta table holds status fields (last sync, last error) for the `status` command.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class BaselineEntry:
    relpath: str
    kind: str  # "file" | "dir"
    local_size: int
    local_mtime: float
    remote_size: int
    remote_mtime: float


class StateStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS baseline (
                relpath      TEXT PRIMARY KEY,
                kind         TEXT NOT NULL,
                local_size   INTEGER NOT NULL DEFAULT 0,
                local_mtime  REAL    NOT NULL DEFAULT 0,
                remote_size  INTEGER NOT NULL DEFAULT 0,
                remote_mtime REAL    NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        self.conn.commit()

    def all(self) -> dict[str, BaselineEntry]:
        rows = self.conn.execute("SELECT * FROM baseline").fetchall()
        return {r["relpath"]: self._row(r) for r in rows}

    @staticmethod
    def _row(r: sqlite3.Row) -> BaselineEntry:
        return BaselineEntry(
            relpath=r["relpath"],
            kind=r["kind"],
            local_size=r["local_size"],
            local_mtime=r["local_mtime"],
            remote_size=r["remote_size"],
            remote_mtime=r["remote_mtime"],
        )

    def upsert(self, entry: BaselineEntry) -> None:
        self.conn.execute(
            """
            INSERT INTO baseline (relpath, kind, local_size, local_mtime, remote_size, remote_mtime)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(relpath) DO UPDATE SET
                kind=excluded.kind,
                local_size=excluded.local_size,
                local_mtime=excluded.local_mtime,
                remote_size=excluded.remote_size,
                remote_mtime=excluded.remote_mtime
            """,
            (
                entry.relpath,
                entry.kind,
                entry.local_size,
                entry.local_mtime,
                entry.remote_size,
                entry.remote_mtime,
            ),
        )

    def delete(self, relpath: str) -> None:
        self.conn.execute("DELETE FROM baseline WHERE relpath = ?", (relpath,))

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        r = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return r["value"] if r else None

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
