"""Phase D regression anchors (refactor + perf, no behavior change).

Batch D2: download mtime restore (P2-6), the _is_safe_rel fast path (P2-3), and the
SyncClient Protocol conformance (P3-6).
"""

from __future__ import annotations

import pytest

from ifolder_sync.icloud_client import ICloudClient
from ifolder_sync.syncer import SyncClient


# --------------------------------------------------------------- P2-6 mtime ---
def test_download_restores_remote_mtime(make_syncer, fake, local_dir):
    """A downloaded file carries the REMOTE mtime, not the download instant — so
    Obsidian recent-files and Dataview `file.mtime` show the real edit time vault-wide,
    and the baseline records that value so the next pass is a no-op (no phantom change)."""
    syncer, store = make_syncer()
    fake.put("note.md", b"# hello", mtime=1_234_567.0)

    s = syncer.sync_once()
    p = local_dir / "note.md"
    assert s.downloaded == 1, s.summary()
    assert p.read_bytes() == b"# hello"
    assert p.stat().st_mtime == pytest.approx(1_234_567.0, abs=1e-4)

    s2 = syncer.sync_once()
    assert s2.uploaded == 0 and s2.downloaded == 0, s2.summary()
    store.close()


def test_download_zero_remote_mtime_is_not_stamped_to_epoch(make_syncer, fake, local_dir):
    """A 0/unknown remote mtime is left as the download time, never stamped to the
    1970 epoch (which would read as an ancient file across the vault)."""
    syncer, store = make_syncer()
    fake.put("z.md", b"x", mtime=0.0)

    syncer.sync_once()
    assert (local_dir / "z.md").stat().st_mtime > 1_000_000_000  # not 1970
    store.close()


# ------------------------------------------------- P2-3 cached-root realpath ---
def test_is_safe_rel_semantics_unchanged(make_syncer):
    """Caching the resolved root must not weaken invariant 5: contained paths stay safe,
    traversal and absolute paths stay unsafe, and a '..' that cancels back inside still
    resolves to contained."""
    syncer, store = make_syncer()
    assert syncer._is_safe_rel("Obsidian/note.md")
    assert syncer._is_safe_rel("a/../b.md")  # '..' cancels -> resolves inside
    assert not syncer._is_safe_rel("../outside.md")
    assert not syncer._is_safe_rel("/abs/outside.md")
    store.close()


def test_unsafe_remote_path_is_excluded_from_scan(make_syncer, fake):
    """End to end: an escaping remote relpath is dropped from the remote snapshot rather
    than written outside the vault."""
    syncer, store = make_syncer()
    fake.put("safe.md", b"ok", mtime=1000.0)
    fake.put("../escape.md", b"evil", mtime=1000.0)
    remote = syncer._scan_remote()
    assert "safe.md" in remote
    assert "../escape.md" not in remote
    store.close()


def test_remote_path_through_symlinked_subdir_is_excluded(make_syncer, fake, local_dir, tmp_path):
    """invariant 5, the case a purely-lexical check would miss: a remote relpath whose
    parent is a symlinked vault subdir pointing OUTSIDE the vault must be rejected by
    _scan_remote (resolve() follows the symlink and sees it escape), so a download can
    never write remote-controlled bytes outside local_root."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (local_dir / "link").symlink_to(outside, target_is_directory=True)

    syncer, store = make_syncer()
    fake.put("link/escape.md", b"PWNED", mtime=1000.0)
    fake.put("kept.md", b"ok", mtime=1000.0)
    remote = syncer._scan_remote()

    assert "kept.md" in remote
    assert "link/escape.md" not in remote
    syncer.sync_once()
    assert not (outside / "escape.md").exists(), "must never write through the symlink"
    store.close()


# ----------------------------------------------------- P3-6 SyncClient proto ---
def test_syncclient_protocol_conformance(fake):
    """The runtime-checkable Protocol is the contract both the real client and the test
    fake honor; a partial stub does not."""
    assert isinstance(fake, SyncClient)
    assert isinstance(ICloudClient("x@y.com"), SyncClient)

    class Partial:
        def refresh(self) -> None: ...

    assert not isinstance(Partial(), SyncClient)
