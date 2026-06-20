"""The daemon-owned live status surface (feature 04 Phase 2).

An in-memory `dict[relpath -> SyncRow]` the engine feeds via per-path `SyncEvent`s, flushed
atomically to `status.json` for the `status --watch` observer to poll. Decoupled from the
SQLite baseline (a separate file -> zero lock/WAL contention); a torn write lands as a
`.part` and is engine-hard-ignored (invariant 8). Entirely best-effort: a flush failure is
swallowed, because an observer must never affect a sync pass.

Access is single-threaded: the daemon drives it only inside `_run_sync` (under its sync
lock) — `pass_started`/`pass_finished` at the boundaries and `record` via the engine's
`on_event` callback during the pass — so no locking is needed.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from .syncstate import SyncEvent, SyncRow, make_envelope

log = logging.getLogger("ifolder-sync.inflight")


class InflightSurface:
    def __init__(self, path: Path, *, min_write_interval_ms: int = 200) -> None:
        self.path = Path(path)
        self._rows: dict[str, SyncRow] = {}
        self._min_interval = max(0.0, min_write_interval_ms / 1000.0)
        self._last_flush = 0.0
        self._header: dict[str, Any] = {}

    def pass_started(self, **header: Any) -> None:
        """A new pass begins: clear the transient in-flight rows (the prior pass rebuilt them
        to its stuck set at the end) and refresh the header. Forces a flush so the observer
        sees the pass start promptly."""
        self._rows = {}
        self._header = dict(header)
        self._flush(force=True)

    def record(self, event: SyncEvent) -> None:
        """Engine callback (wired as `Syncer.on_event`). A 'done' event removes the path — it
        finished, so it disappears from the live list; any other state upserts it. The flush
        is throttled so a burst of small transfers does not rewrite status.json hundreds of
        times a second."""
        if event.state == "done":
            self._rows.pop(event.relpath, None)
        else:
            self._rows[event.relpath] = SyncRow(
                relpath=event.relpath,
                state=event.state,
                op=event.op,
                kind=event.kind,
                bytes=event.bytes,
                passes_stuck=event.passes_stuck,
                reason=event.reason,
                last_seen_pass=event.pass_id,
            )
        self._flush()

    def pass_finished(self, stuck: list[SyncRow], **header: Any) -> None:
        """A pass ended: replace the transient in-flight rows with the engine's authoritative
        stuck set (the settle/unreadable registries) so anything that completed disappears and
        only genuinely-stuck paths persist. Forces a flush."""
        self._rows = {r.relpath: r for r in stuck}
        self._header = dict(header)
        self._flush(force=True)

    def _flush(self, *, force: bool = False) -> None:
        now = time.time()
        if not force and (now - self._last_flush) < self._min_interval:
            return
        self._last_flush = now
        env = make_envelope(list(self._rows.values()), generated_at=now, **self._header)
        try:
            tmp = self.path.with_name(self.path.name + ".part")  # config.py:80 atomic idiom
            tmp.write_text(json.dumps(env))
            os.replace(tmp, self.path)  # atomic: a reader sees whole-old-or-whole-new
        except OSError as exc:
            log.debug("status.json flush skipped (non-fatal): %s", exc)
