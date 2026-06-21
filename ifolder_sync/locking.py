"""Single-instance lock backed by a PID file, with stale-lock reclaim.

Prevents two daemons from racing the same SQLite baseline. A lock left by a crashed
process (its PID no longer alive) is reclaimed automatically, so launchd KeepAlive can
restart the daemon without manual cleanup.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Optional


class AlreadyRunning(RuntimeError):
    """Raised when another live instance already holds the lock."""


_boot_time_cache: Optional[int] = None

# kern.boottime "sec" = wall_clock - uptime, so NTP discipline of the wall clock makes the
# reported value drift across a boot session (seconds, ~1s per day of uptime); a real reboot
# shifts it by at least the prior uptime + downtime (tens of seconds to hours). Tolerate the
# drift so a live lock is not misread as stale: the band sits above realistic multi-day drift
# yet well below the reboot floor. Widening is the safe direction — the dangerous error is a
# live lock seen as stale (a second daemon on one baseline); a previous boot stays far outside.
_BOOT_TOL = 30  # seconds


def _boot_time() -> Optional[int]:
    """macOS boot wall-clock time (epoch seconds), memoized. The lock file lives in the
    home dir, so it survives a reboot; after a reboot its PID may have been recycled by an
    unrelated process, which os.kill(pid, 0) cannot tell from a live daemon. Stamping the
    boot time lets a lock from a previous boot be recognized as stale. Returns None if it
    cannot be read (then only the liveness check is used — the prior behavior)."""
    global _boot_time_cache
    if _boot_time_cache is None:
        try:
            out = subprocess.run(
                ["sysctl", "-n", "kern.boottime"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            m = re.search(r"sec\s*=\s*(\d+)", out)  # "{ sec = 1718000000, usec = 0 } ..."
            _boot_time_cache = int(m.group(1)) if m else 0
        except (OSError, subprocess.SubprocessError, ValueError):
            _boot_time_cache = 0
    return _boot_time_cache or None


def _read_lock(path: Path) -> tuple[int, Optional[int]]:
    """(pid, boot_time) from the lock file. boot_time is None for a pre-P2-7 single-line
    lock or when it was unavailable at write time."""
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return 0, None
    try:
        pid = int(lines[0].strip() or "0") if lines else 0
    except ValueError:
        pid = 0
    boot: Optional[int] = None
    if len(lines) > 1 and lines[1].strip():
        try:
            boot = int(lines[1].strip())
        except ValueError:
            boot = None
    return pid, boot


def holder_pid(path: Path) -> Optional[int]:
    """PID of the live process holding the lock, or None (absent/stale lock)."""
    pid, boot = _read_lock(path)
    if not pid:
        return None
    cur = _boot_time()
    if boot is not None and cur is not None and abs(boot - cur) > _BOOT_TOL:
        return None  # lock from a previous boot: its PID may have been recycled -> stale
    return pid if _alive(pid) else None


class SingleInstanceLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._held = False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL makes creation atomic: two simultaneous starts cannot both win. 0600 keeps
        # the pidfile owner-only (invariant 7's posture for state files); umask only clears
        # bits, so the mode is an exact ceiling on a freshly O_EXCL-created file.
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
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
                fh.write(f"{os.getpid()}\n{_boot_time() or ''}")
            self._held = True
            return
        raise AlreadyRunning("could not acquire the lock (contention)")

    def release(self) -> None:
        if not self._held:
            return
        try:
            if self.path.exists() and _read_lock(self.path)[0] == os.getpid():
                self.path.unlink()
        except FileNotFoundError:
            pass
        self._held = False


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
