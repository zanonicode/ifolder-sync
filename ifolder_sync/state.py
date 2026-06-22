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
    # iCloud entity tag of the remote file at last sync: a content fingerprint that
    # catches a same-size/same-mtime remote edit (which size+mtime alone would miss).
    # "" when unknown (dirs, or just-uploaded files whose new etag we did not fetch).
    remote_etag: str = ""


class CorruptBaselineError(RuntimeError):
    """The baseline SQLite file is unreadable or fails an integrity check. It is never
    silently re-created (an empty baseline reads as mass create/delete next pass);
    recovery is an explicit `ifolder-sync rebaseline` (backup + fresh additive pass)."""


_CORRUPT_HINT = "run `ifolder-sync rebaseline` to back it up and start a fresh baseline"


class StateStore:
    def __init__(self, db_path: Path, *, read_only: bool = False):
        self.db_path = Path(db_path)
        self.read_only = read_only
        if read_only:
            # A mode=ro URI connection: SQLite itself rejects every write ("attempt to write
            # a readonly database"), so a read-only observer (the dashboard, feature 04) is
            # guaranteed not to mutate the daemon's baseline by the CONNECTION, not by
            # reviewer discipline. No journal_mode=WAL pragma (it is a write) and no
            # schema init/migrate/commit — the observer reads meta only. The file must exist
            # (the daemon created it); callers check baseline_path().exists() first.
            self.conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA busy_timeout=5000")  # wait out a checkpoint, never write
            return
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        try:
            self._configure()
            self._init_schema()
        except sqlite3.DatabaseError as exc:
            self.conn.close()
            raise CorruptBaselineError(
                f"baseline at {self.db_path} is unreadable ({exc}); {_CORRUPT_HINT}"
            ) from exc

    def _configure(self) -> None:
        # WAL: a reader (`status`) never blocks the daemon's writer and vice-versa.
        # busy_timeout: a brief lock during a checkpoint waits instead of raising the
        # raw "database is locked" that used to crash `status`.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        # synchronous=NORMAL: under WAL each per-op commit (one per applied action, for
        # SIGKILL-mid-pass crash-safety) becomes a WAL append instead of a full fsync — ~2-3x
        # cheaper. Still durable against an application OR OS crash; only a sudden power loss can
        # drop the last committed txn, which is not the threat the per-op commits guard against.
        self.conn.execute("PRAGMA synchronous=NORMAL")

    def quick_check(self) -> None:
        """Raise CorruptBaselineError if the database fails SQLite's integrity check.
        Run at daemon start so a silently-corrupted baseline stops the daemon (with a
        rebaseline hint) instead of being read as empty (which would mass create/delete)."""
        try:
            rows = self.conn.execute("PRAGMA quick_check").fetchall()
        except sqlite3.DatabaseError as exc:
            raise CorruptBaselineError(
                f"baseline at {self.db_path} failed its integrity check ({exc}); {_CORRUPT_HINT}"
            ) from exc
        if not (len(rows) == 1 and rows[0][0] == "ok"):
            detail = "; ".join(str(r[0]) for r in rows[:3])
            raise CorruptBaselineError(
                f"baseline at {self.db_path} failed its integrity check ({detail}); {_CORRUPT_HINT}"
            )

    def backup_to(self, dest: Path) -> None:
        """Write a consistent copy of the baseline to `dest` (SQLite online-backup API,
        WAL-safe even while the daemon writes). Used for the rotated recovery snapshots."""
        self.conn.commit()
        dst = sqlite3.connect(str(dest))
        try:
            with dst:
                self.conn.backup(dst)
        finally:
            dst.close()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS baseline (
                relpath      TEXT PRIMARY KEY,
                kind         TEXT NOT NULL,
                local_size   INTEGER NOT NULL DEFAULT 0,
                local_mtime  REAL    NOT NULL DEFAULT 0,
                remote_size  INTEGER NOT NULL DEFAULT 0,
                remote_mtime REAL    NOT NULL DEFAULT 0,
                remote_etag  TEXT    NOT NULL DEFAULT ''
            )
            """
        )
        self.conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Additive column migrations for baselines created by older versions. Safe and
        idempotent: ADD COLUMN with a default never rewrites existing rows."""
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(baseline)")}
        if "remote_etag" not in cols:
            self.conn.execute(
                "ALTER TABLE baseline ADD COLUMN remote_etag TEXT NOT NULL DEFAULT ''"
            )

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
            remote_etag=r["remote_etag"],
        )

    def upsert(self, entry: BaselineEntry) -> None:
        self.conn.execute(
            """
            INSERT INTO baseline
                (relpath, kind, local_size, local_mtime, remote_size, remote_mtime, remote_etag)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(relpath) DO UPDATE SET
                kind=excluded.kind,
                local_size=excluded.local_size,
                local_mtime=excluded.local_mtime,
                remote_size=excluded.remote_size,
                remote_mtime=excluded.remote_mtime,
                remote_etag=excluded.remote_etag
            """,
            (
                entry.relpath,
                entry.kind,
                entry.local_size,
                entry.local_mtime,
                entry.remote_size,
                entry.remote_mtime,
                entry.remote_etag,
            ),
        )

    def delete(self, relpath: str) -> None:
        self.conn.execute("DELETE FROM baseline WHERE relpath = ?", (relpath,))

    def drop_rows(self, relpaths: list[str]) -> int:
        """Delete a batch of baseline rows in one transaction (the `doctor --fix-orphans`
        remediation). Returns the number requested. The caller MUST take a backup first (the
        recovery net for a wrong drop) and ensure no daemon is writing concurrently — this
        mutates the baseline the same way a sync pass does."""
        self.conn.executemany("DELETE FROM baseline WHERE relpath = ?", [(r,) for r in relpaths])
        self.conn.commit()
        return len(relpaths)

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
