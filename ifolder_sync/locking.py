"""Single-instance lock backed by a kernel advisory lock (fcntl.flock).

Prevents two daemons from racing the same SQLite baseline. The lock is held on a file
descriptor kept open for the whole process lifetime; the kernel drops it on ANY process
exit (clean, SIGKILL, or crash), so a dead holder's lock is freed instantly with no
liveness heuristic and no stale-reclaim. The pid written into the file body is a
human-readable label only -- never a liveness decision (flock acquirability is the authority).

Assumes the lock file lives on a LOCAL filesystem (here: APFS under $HOME). flock semantics
are unreliable over network filesystems (NFS, some SMB); this lock is not valid there. The
lock is ADVISORY: it only excludes other processes that also flock the same path, which is
exactly the single-instance contract (nothing else touches the file).
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from typing import Optional


class AlreadyRunning(RuntimeError):
    """Raised when another live instance already holds the lock."""


def _read_pid_label(path: Path) -> Optional[int]:
    """First line of the lock file parsed as an int, for human messages only. None if the
    label is absent, torn, or unparseable -- the caller already knows a live holder exists."""
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return None
    if not lines:
        return None
    try:
        return int(lines[0].strip())
    except ValueError:
        return None


def holder_pid(path: Path) -> Optional[int]:
    """PID label of the live process holding the lock, or None when the lock is free.

    Liveness is decided by the kernel: a non-blocking flock probe on a throwaway fd. A
    successful probe means nobody holds the lock (release it, return None); a refused probe
    means a live holder exists (return its pid label). The pid is never a liveness input -- a
    crashed holder's lock is already gone, so the probe is never blocked by a dead process
    (this retires the kern.boottime/_BOOT_TOL stale-reclaim heuristic)."""
    try:
        fd = os.open(path, os.O_RDONLY)  # LOCK_EX needs no write access; only acquire() writes
    except FileNotFoundError:
        return None  # no lock file -> free
    except OSError:
        # can't probe (fd exhaustion / EIO) -> assume held, the safe side
        return _read_pid_label(path)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return _read_pid_label(path)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    finally:
        os.close(fd)


class SingleInstanceLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        if self._fd is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_RDWR (not O_WRONLY): holder_pid() reads the pid label back through an fd on the same
        # path; the file is the flock target, not a write-once pidfile. 0o600 keeps the lock
        # owner-only (invariant 7's posture); O_CREAT does not re-apply the mode to a pre-existing
        # file, so fchmod enforces 0600 even on a lock file left by an older build.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        os.set_inheritable(fd, False)  # a forked/exec'd child must not inherit and pin the lock
        while True:
            try:
                # LOCK_NB: a live holder is rejected at once, never a hang. flock raises
                # BlockingIOError (an OSError subclass) on contention; treat any flock error as a
                # refusal -- for a data-safety mutex, refuse to start rather than risk two writers.
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except InterruptedError:
                # Defense-in-depth: CPython already retries EINTR internally (PEP 475) and a
                # non-blocking flock barely has an EINTR window, but retry by hand so a signal
                # at startup can never surface here as a false AlreadyRunning (a refused start).
                continue
            except OSError:
                os.close(fd)
                raise AlreadyRunning(
                    f"ifolder-sync already running (pid {_read_pid_label(self.path)})"
                ) from None
        # The lock is ours. Rewrite the body to our pid as a human-readable label only; a stale
        # label from a crashed prior holder is meaningless (the kernel already freed its lock).
        try:
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
        except OSError:
            pass  # the label is cosmetic; a write failure must not drop a lock we already hold
        # Keep the fd open for the whole process lifetime: flock is tied to the open file
        # description, so closing it would release the lock.
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
