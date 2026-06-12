"""End-to-end engine tests (the AT-11 regression anchor) against the in-memory fake.

Covers the bidirectional matrix: create/edit/delete on each side, idempotence (no
ping-pong), and conflict resolution.
"""

from __future__ import annotations

from ifolder_sync.syncer import MTIME_TOL, MTIME_TOL_LOCAL, Syncer

from .helpers import FAR, write_file


def test_crud_matrix(make_syncer, fake, local_dir):
    syncer, store = make_syncer()

    # 1) new local file -> uploads
    write_file(local_dir, "a.txt", b"hello-a", mtime=1000)
    s = syncer.sync_once()
    assert fake.files["a.txt"]["content"] == b"hello-a"
    assert s.uploaded == 1, s.summary()

    # idempotence: a second pass with no change is a no-op (no ping-pong)
    s = syncer.sync_once()
    assert s.uploaded == 0 and s.downloaded == 0, s.summary()

    # 2) new remote file -> downloads
    fake.put("b.txt", b"hello-b", mtime=2000)
    s = syncer.sync_once()
    assert (local_dir / "b.txt").read_bytes() == b"hello-b"
    assert s.downloaded == 1, s.summary()

    # 3) local edit -> uploads
    write_file(local_dir, "a.txt", b"hello-a-v2", mtime=1000 + FAR)
    s = syncer.sync_once()
    assert fake.files["a.txt"]["content"] == b"hello-a-v2"
    assert s.uploaded == 1, s.summary()

    # 4) remote edit -> downloads
    fake.put("b.txt", b"hello-b-v2", mtime=2000 + FAR)
    s = syncer.sync_once()
    assert (local_dir / "b.txt").read_bytes() == b"hello-b-v2"
    assert s.downloaded == 1, s.summary()

    # 5) local delete -> removes remote
    (local_dir / "a.txt").unlink()
    s = syncer.sync_once()
    assert "a.txt" not in fake.files
    assert s.deleted_remote == 1, s.summary()

    # 6) remote delete -> removes local
    fake.delete("b.txt")
    s = syncer.sync_once()
    assert not (local_dir / "b.txt").exists()
    assert s.deleted_local == 1, s.summary()

    store.close()


def test_conflict_newer_keeps_local_with_backup(make_syncer, fake, local_dir):
    syncer, store = make_syncer(policy="newer")

    write_file(local_dir, "c.txt", b"base", mtime=5000)
    syncer.sync_once()  # establish baseline on both sides

    # edit both sides; local mtime higher -> local wins, remote loser becomes a backup
    write_file(local_dir, "c.txt", b"local-wins", mtime=5000 + 2 * FAR)
    fake.put("c.txt", b"remote-loses", mtime=5000 + FAR)
    s = syncer.sync_once()

    assert fake.files["c.txt"]["content"] == b"local-wins"
    assert s.conflicts == 1, s.summary()
    backups = list(local_dir.glob("c.conflict-*.txt"))
    assert backups, "the losing remote version should become a local backup"
    assert backups[0].read_bytes() == b"remote-loses"
    store.close()


# ----------------------------------------------- P5-1 conflict policy matrix ---
def _force_conflict(syncer, fake, local_dir, lbytes, lmt, rbytes, rmt):
    """Sync a shared file (baseline), then change BOTH sides so the next pass conflicts."""
    write_file(local_dir, "c.txt", b"baseline", mtime=5000)
    syncer.sync_once()
    write_file(local_dir, "c.txt", lbytes, mtime=lmt)
    fake.put("c.txt", rbytes, mtime=rmt)
    return syncer.sync_once()


def test_conflict_policy_local_keeps_local(make_syncer, fake, local_dir):
    syncer, store = make_syncer(policy="local")
    # remote mtime is newer, but policy=local ignores mtime: local wins, no backup made.
    s = _force_conflict(syncer, fake, local_dir, b"LOCAL", 5000 + FAR, b"remote", 5000 + 2 * FAR)
    assert s.conflicts == 1, s.summary()
    assert fake.files["c.txt"]["content"] == b"LOCAL"
    assert (local_dir / "c.txt").read_bytes() == b"LOCAL"
    assert not list(local_dir.glob("c.conflict-*")), "local policy keeps no backup"
    store.close()


def test_conflict_policy_remote_keeps_remote(make_syncer, fake, local_dir):
    syncer, store = make_syncer(policy="remote")
    s = _force_conflict(syncer, fake, local_dir, b"local", 5000 + 2 * FAR, b"REMOTE", 5000 + FAR)
    assert s.conflicts == 1, s.summary()
    assert (local_dir / "c.txt").read_bytes() == b"REMOTE"
    assert fake.files["c.txt"]["content"] == b"REMOTE"
    assert not list(local_dir.glob("c.conflict-*")), "remote policy keeps no backup"
    store.close()


def test_conflict_newer_remote_wins_backs_up_local(make_syncer, fake, local_dir):
    # The previously-uncovered `newer` branch: remote is newer, so it wins AND the losing
    # LOCAL copy is preserved as a .conflict backup (_backup_local_then).
    syncer, store = make_syncer(policy="newer")
    s = _force_conflict(
        syncer, fake, local_dir, b"local-old", 5000 + FAR, b"remote-new", 5000 + 2 * FAR
    )
    assert s.conflicts == 1, s.summary()
    assert (local_dir / "c.txt").read_bytes() == b"remote-new"
    backups = list(local_dir.glob("c.conflict-*.txt"))
    assert backups and backups[0].read_bytes() == b"local-old"
    store.close()


def test_conflict_policy_both_preserves_both(make_syncer, fake, local_dir):
    syncer, store = make_syncer(policy="both")
    s = _force_conflict(syncer, fake, local_dir, b"LOCAL", 5000 + 2 * FAR, b"REMOTE", 5000 + FAR)
    assert s.conflicts == 1, s.summary()
    assert fake.files["c.txt"]["content"] == b"LOCAL"  # local takes the live name
    assert (local_dir / "c.txt").read_bytes() == b"LOCAL"
    backups = list(local_dir.glob("c.conflict-*.txt"))
    assert backups and backups[0].read_bytes() == b"REMOTE"  # remote kept as a backup
    store.close()


def test_conflict_empty_remote_never_overwrites_local(make_syncer, fake, local_dir):
    # The 0-byte guard overrides policy: an empty remote never wins, even under policy=remote
    # (a publish-before-content husk must not clobber a real note).
    syncer, store = make_syncer(policy="remote")
    _force_conflict(syncer, fake, local_dir, b"real content", 5000 + FAR, b"", 5000 + 2 * FAR)
    assert (local_dir / "c.txt").read_bytes() == b"real content"
    assert fake.files["c.txt"]["content"] == b"real content"  # local healed the remote
    store.close()


# ------------------------------------------------ P5-4 MTIME_TOL boundary ---
def test_mtime_tol_remote_boundary_is_inclusive():
    # MTIME_TOL absorbs sub-second clock skew between APFS and iCloud; the boundary (== tol)
    # is NOT a change (`> tol`), one tick past it IS.
    assert MTIME_TOL == 2.0
    assert Syncer._changed(10, 100.0, 10, 100.0 + 1.9, MTIME_TOL) is False
    assert Syncer._changed(10, 100.0, 10, 100.0 + 2.0, MTIME_TOL) is False
    assert Syncer._changed(10, 100.0, 10, 100.0 + 2.1, MTIME_TOL) is True


def test_mtime_tol_local_is_exact():
    # The local side uses a 0 tolerance (same clock): any mtime move is a change, so a
    # same-size edit right after a pass is not silently missed.
    assert MTIME_TOL_LOCAL == 0.0
    assert Syncer._changed(10, 100.0, 10, 100.0, MTIME_TOL_LOCAL) is False
    assert Syncer._changed(10, 100.0, 10, 100.5, MTIME_TOL_LOCAL) is True


def test_changed_is_true_on_size_difference_regardless_of_mtime():
    # A size change is always a change, even with identical mtime (within any tolerance).
    assert Syncer._changed(11, 100.0, 10, 100.0, MTIME_TOL) is True
