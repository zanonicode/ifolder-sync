"""Single-instance lock backed by a PID file, with stale-lock reclaim.

Prevents two daemons from racing the same SQLite baseline. A lock left by a crashed
process (its PID no longer alive) is reclaimed automatically, so launchd KeepAlive can
restart the daemon without manual cleanup.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


class AlreadyRunning(RuntimeError):
    """Raised when another live instance already holds the lock."""


def holder_pid(path: Path) -> Optional[int]:
    """PID of the live process holding the lock, or None (absent/stale lock)."""
    try:
        pid = int(path.read_text().strip() or "0")
    except (OSError, ValueError):
        return None
    return pid if pid and _alive(pid) else None


class SingleInstanceLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._held = False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL makes creation atomic: two simultaneous starts cannot both win.
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                pid = holder_pid(self.path)
                if pid:
                    raise AlreadyRunning(f"ifolder-sync already running (pid {pid})") from None
                try:
                    self.path.unlink()  # stale lock: owner is dead
                except FileNotFoundError:
                    pass
                continue
            with os.fdopen(fd, "w") as fh:
                fh.write(str(os.getpid()))
            self._held = True
            return
        raise AlreadyRunning("could not acquire the lock (contention)")

    def release(self) -> None:
        if not self._held:
            return
        try:
            if self.path.exists() and self._read_pid() == os.getpid():
                self.path.unlink()
        except FileNotFoundError:
            pass
        self._held = False

    def _read_pid(self) -> int:
        try:
            return int(self.path.read_text().strip() or "0")
        except (OSError, ValueError):
            return 0


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
