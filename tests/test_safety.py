"""Resilience and security guards: walk guard (AT-04), delete threshold (AT-05),
path-traversal (AT-07), single-instance lock (AT-12), soft-delete (AT-06), dry-run,
and no post-upload stat (AT-09).
"""

from __future__ import annotations

import os

import pytest

from ifolder_sync.locking import AlreadyRunning, SingleInstanceLock
from ifolder_sync.trash import trash_count

from .helpers import write_file


def test_walk_guard_aborts_without_deletions(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "keep.md", b"x", mtime=1000)
    syncer.sync_once()

    fake.fail_walk = True
    with pytest.raises(RuntimeError):
        syncer.sync_once()

    assert (local_dir / "keep.md").exists()
    assert "keep.md" in fake.files
    store.close()


def test_delete_threshold_skips_mass_delete(make_syncer, fake, local_dir):
    syncer, store = make_syncer(delete_threshold_pct=50, delete_threshold_count=5)
    for i in range(10):
        write_file(local_dir, f"n{i}.md", b"x", mtime=1000)
    syncer.sync_once()

    for i in range(8):
        fake.delete(f"n{i}.md")
    s = syncer.sync_once()
    assert s.skipped_deletes == 8, s.summary()
    assert s.deleted_local == 0
    assert all((local_dir / f"n{i}.md").exists() for i in range(8))

    s = syncer.sync_once(force_delete=True)
    assert s.deleted_local == 8, s.summary()
    store.close()


def test_path_traversal_blocked(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    fake.put("../evil.txt", b"pwn", mtime=2000)
    fake.put("safe.txt", b"ok", mtime=2000)

    syncer.sync_once()

    assert (local_dir / "safe.txt").exists()
    assert not (local_dir.parent / "evil.txt").exists()
    store.close()


def test_soft_delete_moves_to_trash(make_syncer, fake, local_dir, tmp_path):
    syncer, store = make_syncer()
    write_file(local_dir, "doomed.md", b"bye", mtime=1000)
    syncer.sync_once()

    fake.delete("doomed.md")
    s = syncer.sync_once()
    assert s.deleted_local == 1
    assert not (local_dir / "doomed.md").exists()
    assert trash_count(tmp_path / "trash") == 1
    store.close()


def test_dry_run_writes_nothing(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "x.md", b"data", mtime=1000)
    s = syncer.sync_once(dry_run=True)
    assert s.uploaded == 1
    assert fake.files == {}
    assert store.all() == {}
    store.close()


def test_no_post_upload_stat(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "x.md", b"data", mtime=1000)
    syncer.sync_once()
    assert fake.calls["stat"] == 0
    store.close()


def test_single_instance_lock(tmp_path):
    lock_path = tmp_path / "daemon.lock"
    a = SingleInstanceLock(lock_path)
    a.acquire()
    b = SingleInstanceLock(lock_path)
    with pytest.raises(AlreadyRunning):
        b.acquire()
    a.release()
    b.acquire()
    b.release()


def test_stale_lock_reclaimed(tmp_path):
    lock_path = tmp_path / "daemon.lock"
    lock_path.write_text("2147483647")  # almost certainly not a live PID (legacy 1-line lock)
    lock = SingleInstanceLock(lock_path)
    lock.acquire()
    # P2-7: the lock now stores "pid\nboot_time"; the first line is the owning pid.
    assert lock_path.read_text().splitlines()[0].strip() == str(os.getpid())
    lock.release()


def test_lock_from_previous_boot_is_stale(tmp_path):
    """P2-7: a lock whose recorded boot time differs from this boot is treated as stale
    even if its PID is alive — after a reboot the PID may have been recycled."""
    from ifolder_sync.locking import _boot_time, holder_pid

    if _boot_time() is None:
        pytest.skip("boot time unavailable (non-macOS); falls back to the liveness check")
    lock_path = tmp_path / "daemon.lock"
    other_boot = (_boot_time() or 0) - 100000  # a different (earlier) boot
    lock_path.write_text(f"{os.getpid()}\n{other_boot}")  # OUR live pid, but a prior boot
    assert holder_pid(lock_path) is None  # stale despite being alive
    # a current-boot lock with our live pid IS held
    lock_path.write_text(f"{os.getpid()}\n{_boot_time() or ''}")
    assert holder_pid(lock_path) == os.getpid()


def test_same_boot_jitter_is_not_stale(tmp_path, monkeypatch):
    """A same-boot kern.boottime jitter (NTP disciplines the wall clock) must NOT flip a live
    lock to stale; tolerated two-sided since the wall clock can step in either direction."""
    from ifolder_sync.locking import _BOOT_TOL, holder_pid

    assert _BOOT_TOL >= 1
    stamped = 1780079296
    lock_path = tmp_path / "daemon.lock"
    lock_path.write_text(f"{os.getpid()}\n{stamped}")
    monkeypatch.setattr("ifolder_sync.locking._boot_time", lambda: stamped + 1)
    assert holder_pid(lock_path) == os.getpid()  # forward 1s jitter (the live bug)
    monkeypatch.setattr("ifolder_sync.locking._boot_time", lambda: stamped - 1)
    assert holder_pid(lock_path) == os.getpid()  # backward jitter too (two-sided)


def test_boot_skew_tolerance_boundary(tmp_path, monkeypatch):
    """Boundary: delta within _BOOT_TOL is held, delta beyond it is stale (pins the band so a
    future widening cannot silently erode the previous-boot guard)."""
    from ifolder_sync.locking import _BOOT_TOL, holder_pid

    base = 1780079296
    lock_path = tmp_path / "daemon.lock"
    lock_path.write_text(f"{os.getpid()}\n{base}")
    for delta, held in ((0, True), (_BOOT_TOL, True), (_BOOT_TOL + 1, False)):
        monkeypatch.setattr("ifolder_sync.locking._boot_time", lambda d=delta: base + d)
        got = holder_pid(lock_path)
        assert (got == os.getpid()) is held


def test_previous_boot_lock_still_stale_with_tolerance(tmp_path, monkeypatch):
    """P2-7 survives the tolerance: a genuine previous-boot lock (delta >> band) is still stale,
    deterministic on any platform (no real sysctl, no macOS-only skip)."""
    from ifolder_sync.locking import holder_pid

    stamped = 1780079296
    lock_path = tmp_path / "daemon.lock"
    lock_path.write_text(f"{os.getpid()}\n{stamped}")
    monkeypatch.setattr("ifolder_sync.locking._boot_time", lambda: stamped + 100000)
    assert holder_pid(lock_path) is None


def test_multiday_boottime_drift_is_not_stale(tmp_path, monkeypatch):
    """Regression: kern.boottime drift grows with uptime (~1s/day) and reached 3s after ~3.4 days,
    exceeding the original _BOOT_TOL=2 and false-staling a live daemon (status lied "stopped"). The
    band must cover realistic multi-day drift; this fails under any tolerance below 5s."""
    from ifolder_sync.locking import _BOOT_TOL, holder_pid

    assert _BOOT_TOL >= 5  # floor above the observed 3s drift, with margin
    stamped = 1780079296
    lock_path = tmp_path / "daemon.lock"
    lock_path.write_text(f"{os.getpid()}\n{stamped}")
    for drift in (5, -5):  # NTP can step either way
        monkeypatch.setattr("ifolder_sync.locking._boot_time", lambda d=drift: stamped + d)
        assert holder_pid(lock_path) == os.getpid()


def test_retry_recovers_from_transient():
    from pyicloud.exceptions import PyiCloudAPIResponseException

    from ifolder_sync.retry import with_retry

    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise PyiCloudAPIResponseException("busy", 503)
        return "ok"

    assert with_retry(flaky, attempts=3, base=0) == "ok"
    assert calls["n"] == 3


def test_retry_skips_logic_error():
    from pyicloud.exceptions import PyiCloudAPIResponseException

    from ifolder_sync.retry import with_retry

    calls = {"n": 0}

    def bad():
        calls["n"] += 1
        raise PyiCloudAPIResponseException("bad request", 400)

    with pytest.raises(PyiCloudAPIResponseException):
        with_retry(bad, attempts=3, base=0)
    assert calls["n"] == 1  # 400 is a logic error -> not retried
