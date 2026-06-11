"""Local filesystem watcher (FSEvents on macOS via watchdog).

Real-time change detection is only possible on the LOCAL side. Each event schedules a
debounced wake: after N quiet seconds it triggers a sync, so a large file copy does
not run one sync per file.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger("ifolder-sync.watcher")


class _DebouncedHandler(FileSystemEventHandler):
    def __init__(
        self,
        on_trigger: Callable[[], None],
        debounce: float,
        root: Path,
        is_ignored: Optional[Callable[[str], bool]] = None,
    ):
        self.on_trigger = on_trigger
        self.debounce = debounce
        self.root = root
        self.is_ignored = is_ignored
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    def on_any_event(self, event):
        if event.is_directory and event.event_type == "modified":
            return  # common noise; real changes come via create/delete/move
        if self._all_ignored(event):
            # Every path this event touches is engine-ignored (volatile config like
            # workspace.json, *.part download tempfiles, the vault marker), so it cannot
            # be a real sync change — skip the wake. Obsidian rewrites workspace.json
            # constantly and each download writes a .part; without this filter every one
            # pins the active poll window and spends an API round-trip on a no-op. The
            # interval poll still backstops anything misjudged.
            return
        self._schedule()

    def _all_ignored(self, event) -> bool:
        if self.is_ignored is None:
            return False
        # A move carries both a source and a destination; suppress only when BOTH are
        # ignored (a file moved into a watched area must still wake a pass).
        rels = []
        for attr in ("src_path", "dest_path"):
            raw = getattr(event, attr, "")
            if not raw:
                continue
            try:
                rels.append(Path(os.fsdecode(raw)).relative_to(self.root).as_posix())
            except ValueError:
                return False  # a path outside the root we cannot classify -> do not suppress
        return bool(rels) and all(self.is_ignored(r) for r in rels)

    def _schedule(self):
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self.debounce, self.on_trigger)
            self._timer.daemon = True
            self._timer.start()


class LocalWatcher:
    def __init__(
        self,
        path: Path,
        on_trigger: Callable[[], None],
        debounce: float,
        is_ignored: Optional[Callable[[str], bool]] = None,
    ):
        self.path = path
        self.handler = _DebouncedHandler(on_trigger, debounce, path, is_ignored)
        self.observer = Observer()

    def start(self):
        self.path.mkdir(parents=True, exist_ok=True)
        self.observer.schedule(self.handler, str(self.path), recursive=True)
        self.observer.start()
        log.info("local watcher active on %s", self.path)

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=5)
