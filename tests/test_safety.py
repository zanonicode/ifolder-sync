"""Resilience and security guards: walk guard (AT-04), delete threshold (AT-05),
path-traversal (AT-07), single-instance lock (AT-12), soft-delete (AT-06), dry-run,
and no post-upload stat (AT-09).
"""

from __future__ import annotations

import fcntl
import os
import signal

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


def test_lock_file_is_owner_only_0600(tmp_path):
    """Invariant 7 posture: the pidfile is born 0600 (owner-only) at create time, like the
    session/cookie credential files — no world-readable window and no dependence on umask."""
    lock_path = tmp_path / "daemon.lock"
    lock = SingleInstanceLock(lock_path)
    lock.acquire()
    try:
        assert oct(lock_path.stat().st_mode & 0o777) == "0o600"
    finally:
        lock.release()


def test_single_instance_lock_reacquire_after_release(tmp_path):
    """A released lock is immediately reacquirable -- the kernel frees the flock on release,
    leaving the (now-unlocked) lock file on disk for the next acquirer to reopen and re-flock."""
    lock_path = tmp_path / "daemon.lock"
    a = SingleInstanceLock(lock_path)
    a.acquire()
    a.release()
    b = SingleInstanceLock(lock_path)
    b.acquire()
    assert lock_path.read_text().splitlines()[0].strip() == str(os.getpid())
    b.release()


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


# ---------------------------------------------------------------- flock lock ---
# The single-instance lock is a kernel advisory lock (fcntl.flock) held on an fd kept
# open for the process lifetime; the kernel frees it on ANY exit. The pid in the file
# body is a human label only -- flock acquirability, not the pid, decides liveness.


def test_two_instances_in_process_contend(tmp_path):
    """Mutual exclusion via the kernel: two SingleInstanceLock objects on one path hold
    DISTINCT fds (distinct open file descriptions), so the second flock genuinely conflicts --
    even in one process. Subsumes the deleted kern.boottime/_BOOT_TOL false-stale tests: flock
    never reads the boot clock, so the multi-day-drift false-stale class is structurally gone."""
    lock_path = tmp_path / "daemon.lock"
    a = SingleInstanceLock(lock_path)
    a.acquire()
    b = SingleInstanceLock(lock_path)
    with pytest.raises(AlreadyRunning) as exc:
        b.acquire()
    assert str(os.getpid()) in str(exc.value)  # pid written + read back as a human label
    a.release()
    b.acquire()  # freed -> now acquirable
    b.release()


def test_write_label_does_not_drop_lock(tmp_path):
    """acquire() writes the pid label by reusing the held fd (ftruncate+write), never re-opening
    or O_TRUNC-creating the file, so the advisory lock is not momentarily dropped by the write."""
    lock_path = tmp_path / "daemon.lock"
    a = SingleInstanceLock(lock_path)
    a.acquire()
    try:
        assert lock_path.read_text().splitlines()[0].strip() == str(os.getpid())
        with pytest.raises(AlreadyRunning):
            SingleInstanceLock(lock_path).acquire()  # still held after the label write
    finally:
        a.release()


def test_holder_pid_none_when_unheld_pidfile(tmp_path):
    """flock acquirability -- not the pid in the body -- decides liveness. A lock file naming a
    LIVE pid but held by NO flock is free (holder_pid -> None); only a real flock holder yields a
    pid. Guards the _observe_daemon foreground fallback against a phantom holder."""
    from ifolder_sync.locking import holder_pid

    lock_path = tmp_path / "daemon.lock"
    lock_path.write_text(f"{os.getpid()}\n")  # our live pid, but nothing holds the flock
    assert holder_pid(lock_path) is None
    held = SingleInstanceLock(lock_path)
    held.acquire()
    try:
        assert holder_pid(lock_path) == os.getpid()
    finally:
        held.release()
    assert holder_pid(lock_path) is None  # released -> free again


def test_migration_crossover_legacy_pidfile_is_acquirable(tmp_path):
    """Upgrade crossover: a legacy O_EXCL pidfile (a bare pid[/boot] body) carries NO kernel
    flock, so new-code acquire() takes the lock cleanly and rewrites the body to its own pid.
    This is why the upgrade requires a daemon restart (an old-code holder is invisible to the new
    flock probe); the test pins that a leftover file never wedges a fresh start."""
    lock_path = tmp_path / "daemon.lock"
    lock_path.write_text(f"{os.getpid()}\n1780079296")  # legacy two-line body, no flock held
    lock = SingleInstanceLock(lock_path)
    lock.acquire()  # not blocked by a merely-written legacy pidfile
    try:
        assert lock_path.read_text().splitlines()[0].strip() == str(os.getpid())
    finally:
        lock.release()


@pytest.mark.skipif(not hasattr(fcntl, "flock"), reason="flock unavailable on this platform")
def test_killed_child_auto_releases_lock(tmp_path):
    """The kernel drops the flock on ANY process exit, including SIGKILL -- no liveness probe and
    no stale-reclaim. A child holds the lock; the parent is refused; after SIGKILL the parent
    acquires with no cleanup. Replaces the deleted os.kill/kern.boottime stale-reclaim tests."""
    lock_path = tmp_path / "daemon.lock"
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        os.close(r)
        try:
            SingleInstanceLock(lock_path).acquire()
            os.write(w, b"1")  # signal: lock held
            os.close(w)
            signal.pause()  # wait to be killed
        finally:
            os._exit(0)
    os.close(w)
    parent = SingleInstanceLock(lock_path)
    try:
        assert os.read(r, 1) == b"1"  # block until the child holds the lock (no sleep)
        with pytest.raises(AlreadyRunning):
            parent.acquire()  # child holds it
    finally:
        os.close(r)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # child already exited
        os.waitpid(pid, 0)  # always reap (no zombie), even if an assertion above failed
    parent.acquire()  # kernel auto-released the dead child's flock
    parent.release()


def test_lock_file_0600_even_if_preexisting_wider(tmp_path):
    """A lock file left wider than 0600 by an earlier build is narrowed to 0600 on acquire:
    O_CREAT does not re-apply the mode to an existing file, so acquire() fchmods it back."""
    lock_path = tmp_path / "daemon.lock"
    lock_path.write_text("999999\n")
    os.chmod(lock_path, 0o644)
    lock = SingleInstanceLock(lock_path)
    lock.acquire()
    try:
        assert oct(lock_path.stat().st_mode & 0o777) == "0o600"
    finally:
        lock.release()
