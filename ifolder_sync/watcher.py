"""Local filesystem watcher (FSEvents on macOS via watchdog).

Real-time change detection is only possible on the LOCAL side. Each event schedules a
debounced wake: after N quiet seconds it triggers a sync, so a large file copy does
not run one sync per file.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger("ifolder-sync.watcher")


class _DebouncedHandler(FileSystemEventHandler):
    def __init__(self, on_trigger: Callable[[], None], debounce: float):
        self.on_trigger = on_trigger
        self.debounce = debounce
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    def on_any_event(self, event):
        if event.is_directory and event.event_type == "modified":
            return  # common noise; real changes come via create/delete/move
        self._schedule()

    def _schedule(self):
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self.debounce, self.on_trigger)
            self._timer.daemon = True
            self._timer.start()


class LocalWatcher:
    def __init__(self, path: Path, on_trigger: Callable[[], None], debounce: float):
        self.path = path
        self.handler = _DebouncedHandler(on_trigger, debounce)
        self.observer = Observer()

    def start(self):
        self.path.mkdir(parents=True, exist_ok=True)
        self.observer.schedule(self.handler, str(self.path), recursive=True)
        self.observer.start()
        log.info("local watcher active on %s", self.path)

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=5)
