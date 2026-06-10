"""End-to-end engine tests (the AT-11 regression anchor) against the in-memory fake.

Covers the bidirectional matrix: create/edit/delete on each side, idempotence (no
ping-pong), and conflict resolution.
"""

from __future__ import annotations

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
