"""Sync-drift hardening guards: local walk guard, vault identity marker, bootstrap
additive pass, .part hard-ignore, daemon preflight, and the rebaseline command.

The destructive scenarios assert the invariant that matters: an unreliable local
snapshot must abort the pass with ZERO deletions on either side.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import unicodedata
from pathlib import Path

import pytest

import ifolder_sync.cli as cli
from ifolder_sync.cli import main
from ifolder_sync.config import (
    VAULT_MARKER_NAME,
    Config,
    baseline_path,
    config_path,
    lock_path,
    read_vault_marker,
    write_vault_marker,
)
from ifolder_sync.state import StateStore
from ifolder_sync.syncer import LocalScanError, VaultIdentityError

from .helpers import FAR, sandbox_home, write_file

needs_chmod = pytest.mark.skipif(os.geteuid() == 0, reason="chmod-based denial does not block root")


# --------------------------------------------------------- G1: local walk guard ---
@needs_chmod
def test_local_scan_permission_error_aborts(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "sub/keep.md", b"x", mtime=1000)
    syncer.sync_once()
    assert "sub/keep.md" in fake.files

    sub = local_dir / "sub"
    os.chmod(sub, 0)
    try:
        with pytest.raises(LocalScanError):
            syncer.sync_once()
    finally:
        os.chmod(sub, 0o755)

    assert "sub/keep.md" in fake.files  # zero remote deletions
    assert "sub/keep.md" in store.all()  # baseline untouched
    store.close()


def test_missing_root_with_baseline_aborts(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "keep.md", b"x", mtime=1000)
    syncer.sync_once()

    shutil.rmtree(local_dir)
    with pytest.raises(LocalScanError):
        syncer.sync_once()

    assert "keep.md" in fake.files
    assert not local_dir.exists()  # the engine must not fabricate an empty root
    store.close()


# ------------------------------------------------- G3: vault identity marker ---
def test_marker_adopted_and_never_synced(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "a.md", b"x", mtime=1000)
    syncer.sync_once()

    marker = local_dir / VAULT_MARKER_NAME
    assert marker.exists()
    assert store.get_meta("vault_uuid") == read_vault_marker(local_dir)
    assert VAULT_MARKER_NAME not in fake.files
    assert VAULT_MARKER_NAME not in store.all()
    store.close()


def test_marker_mismatch_aborts(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "a.md", b"x", mtime=1000)
    syncer.sync_once()

    write_vault_marker(local_dir)  # new uuid = a different vault took this path
    with pytest.raises(VaultIdentityError):
        syncer.sync_once()
    assert "a.md" in fake.files

    (local_dir / VAULT_MARKER_NAME).unlink()  # missing marker is equally suspect
    with pytest.raises(VaultIdentityError):
        syncer.sync_once()
    assert "a.md" in fake.files
    store.close()


def test_existing_marker_adopted_not_overwritten(make_syncer, fake, local_dir):
    prior = write_vault_marker(local_dir)  # e.g. written by another profile
    syncer, store = make_syncer()
    write_file(local_dir, "a.md", b"x", mtime=1000)
    syncer.sync_once()
    assert store.get_meta("vault_uuid") == prior
    assert read_vault_marker(local_dir) == prior
    store.close()


def test_dry_run_writes_no_marker(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "a.md", b"x", mtime=1000)
    syncer.sync_once(dry_run=True)
    assert not (local_dir / VAULT_MARKER_NAME).exists()
    store.close()


# ------------------------------------------------------- G7: bootstrap pass ---
def test_bootstrap_defers_deletes_then_applies(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "a.md", b"x", mtime=1000)
    write_file(local_dir, "b.md", b"y", mtime=1000)
    syncer.sync_once()

    (local_dir / "a.md").unlink()
    s = syncer.sync_once(defer_deletes=True)
    assert s.deferred_deletes == 1, s.summary()
    assert s.deleted_remote == 0
    assert "a.md" in fake.files  # nothing destroyed on the bootstrap pass

    s = syncer.sync_once()  # next pass re-derives and applies normally
    assert s.deleted_remote == 1, s.summary()
    assert "a.md" not in fake.files
    store.close()


def test_bootstrap_still_transfers_content(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    write_file(local_dir, "up.md", b"local", mtime=1000)
    fake.put("down.md", b"remote", mtime=2000)
    s = syncer.sync_once(defer_deletes=True)
    assert s.uploaded == 1 and s.downloaded == 1, s.summary()
    assert (local_dir / "down.md").exists()
    store.close()


# --------------------------------------------------- public-ready hardening ---
def test_failed_trash_keeps_baseline_row(make_syncer, fake, local_dir, monkeypatch):
    """If the soft-delete move fails, the baseline row must survive: dropping it would
    make the still-present file look new and resurrect it remotely next pass."""
    import ifolder_sync.syncer as syncer_mod

    syncer, store = make_syncer()
    write_file(local_dir, "doomed.md", b"x", mtime=1000)
    syncer.sync_once()
    fake.delete("doomed.md")

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(syncer_mod, "trash_local", boom)
    s = syncer.sync_once()
    assert s.errors == 1, s.summary()
    assert "doomed.md" in store.all()  # row kept -> the delete retries next pass
    assert (local_dir / "doomed.md").exists()
    store.close()


def test_secure_session_files_sets_0600(tmp_path, monkeypatch):
    from ifolder_sync.config import session_paths, sessions_dir
    from ifolder_sync.icloud_client import ICloudClient

    _sandbox(tmp_path, monkeypatch)
    session_file, cookie_file = session_paths("x@y.com")
    session_file.write_text("{}")
    cookie_file.write_text("#LWP-Cookies-2.0\n")

    ICloudClient("x@y.com")._secure_session_files()

    assert oct(sessions_dir().stat().st_mode & 0o777) == "0o700"
    assert oct(session_file.stat().st_mode & 0o777) == "0o600"
    assert oct(cookie_file.stat().st_mode & 0o777) == "0o600"


def test_manual_sync_blocked_while_daemon_runs(tmp_path, monkeypatch, capsys):
    from ifolder_sync.locking import SingleInstanceLock

    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    held = SingleInstanceLock(lock_path("work"))
    held.acquire()  # a live daemon holds the kernel lock
    try:
        with pytest.raises(SystemExit):
            main(["sync", "--profile", "work"])
        assert "daemon is running" in capsys.readouterr().err
    finally:
        held.release()


def test_invalid_profile_name_rejected(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    with pytest.raises(SystemExit):  # argparse rejects traversal-shaped names
        main(["status", "--profile", "../evil"])


# ---------------------------------------- settle guard (simultaneous create) ---
def test_simultaneous_create_with_remote_husk_waits(make_syncer, fake, local_dir):
    """iCloud publishes a new file's record before its content finishes uploading.
    A both-sides-create conflict against that husk must wait, not judge."""
    syncer, store = make_syncer()
    write_file(local_dir, "fire.md", b"PC", mtime=2000 + FAR)
    fake.put("fire.md", b"", mtime=2000)  # husk: record exists, 0 bytes

    s = syncer.sync_once()
    assert s.conflicts == 0 and s.uploaded == 0 and s.downloaded == 0, s.summary()
    assert fake.files["fire.md"]["content"] == b""  # in-flight remote untouched
    assert (local_dir / "fire.md").read_bytes() == b"PC"

    fake.put("fire.md", b"Celular", mtime=2000)  # content materialized
    s = syncer.sync_once()
    assert s.conflicts == 1, s.summary()  # judged with real data now
    assert fake.files["fire.md"]["content"] == b"PC"  # newer local wins
    backups = list(local_dir.glob("fire.conflict-*.md"))
    assert backups and backups[0].read_bytes() == b"Celular"  # loser kept, NOT empty
    store.close()


# ----------------------------------------------------- parallel walk + adaptive ---
class _FakeNode:
    def __init__(self, name, type_, children=None, size=0, etag=None):
        self.name = name
        self.type = type_
        self.size = size
        self.date_modified = None
        self.data = {"etag": etag}
        self.calls = 0
        self._children = children or []

    def get_children(self):
        self.calls += 1
        return self._children


def monkeypatch_navigate(client, node):
    """Make client.download resolve relpath to `node` (bypass the real Drive tree)."""

    class _Parent:
        def __getitem__(self, name):
            return node

    client._navigate = lambda relpath, create_dirs=False: (_Parent(), "x")


def test_parallel_walk_lists_tree_and_prunes(monkeypatch):
    from ifolder_sync.icloud_client import ICloudClient

    root = _FakeNode(
        "root",
        "folder",
        [
            _FakeNode("a", "folder", [_FakeNode("f1.md", "file", size=3)]),
            _FakeNode("f0.md", "file", size=1),
            _FakeNode(".trash", "folder", [_FakeNode("junk.md", "file", size=9)]),
        ],
    )
    c = ICloudClient("x@y.com", walk_workers=4)
    monkeypatch.setattr(c, "_root_node", lambda: root)

    res = c.walk(lambda rel: rel.split("/")[-1] == ".trash")

    assert set(res) == {"a", "a/f1.md", "f0.md"}  # .trash pruned, tree complete
    assert res["a"].kind == "dir" and res["a/f1.md"].size == 3


def test_parallel_walk_propagates_listing_errors(monkeypatch):
    from ifolder_sync.icloud_client import ICloudClient

    class _Boom(_FakeNode):
        def get_children(self):
            raise RuntimeError("listing failed")

    root = _FakeNode("root", "folder", [_Boom("bad", "folder")])
    c = ICloudClient("x@y.com", walk_workers=4, max_retries=1)
    monkeypatch.setattr(c, "_root_node", lambda: root)

    with pytest.raises(RuntimeError):
        c.walk(None)  # the walk guard must see the failure, never a partial tree


def _etag_tree():
    a = _FakeNode("a", "folder", [_FakeNode("f1.md", "file", size=3)], etag="ea1")
    b = _FakeNode("b", "folder", [_FakeNode("f2.md", "file", size=2)], etag="eb1")
    root = _FakeNode("root", "folder", [a, b, _FakeNode("f0.md", "file", size=1)], etag="er1")
    return root, a, b


def test_etag_cache_skips_unchanged_subtrees(monkeypatch):
    from ifolder_sync.icloud_client import ICloudClient

    root, a, b = _etag_tree()
    c = ICloudClient("x@y.com", walk_workers=4, full_walk_interval=3600)
    monkeypatch.setattr(c, "_root_node", lambda: root)

    r1 = c.walk(None)  # cold cache: every folder listed once
    assert (root.calls, a.calls, b.calls) == (1, 1, 1)

    r2 = c.walk(None)  # warm + nothing changed: ZERO listings
    assert (root.calls, a.calls, b.calls) == (1, 1, 1)
    assert r2 == r1

    # A child of `a` changes; etags bump along the path (verified propagation).
    a._children = [_FakeNode("f1.md", "file", size=99)]
    a.data["etag"] = "ea2"
    root.data["etag"] = "er2"
    r3 = c.walk(None)
    assert (root.calls, a.calls) == (2, 2)  # only the changed path re-listed
    assert b.calls == 1  # untouched branch served from cache
    assert r3["a/f1.md"].size == 99
    assert "b/f2.md" in r3  # cached branch fully present

    # `b` deleted remotely: root re-listed, b's cached subtree must not leak back.
    root._children = [a, _FakeNode("f0.md", "file", size=1)]
    root.data["etag"] = "er3"
    r4 = c.walk(None)
    assert "b" not in r4 and "b/f2.md" not in r4


def test_etag_cache_disabled_always_walks_fully(monkeypatch):
    from ifolder_sync.icloud_client import ICloudClient

    root, a, b = _etag_tree()
    c = ICloudClient("x@y.com", full_walk_interval=0)  # caching off
    monkeypatch.setattr(c, "_root_node", lambda: root)
    c.walk(None)
    c.walk(None)
    assert (root.calls, a.calls, b.calls) == (2, 2, 2)


def test_etag_cache_emit_respects_changed_ignore(monkeypatch):
    """A subtree cached while NOT ignored must be pruned on a later cache HIT once the
    ignore set excludes it. The cache key is the iCloud folder etag (a REMOTE fingerprint,
    blind to the local ignore set): a newly-ignored, etag-stable subtree would otherwise be
    replayed from cache forever, never pruned by a fresh listing."""
    from ifolder_sync.icloud_client import ICloudClient

    root, a, b = _etag_tree()
    c = ICloudClient("x@y.com", walk_workers=4, full_walk_interval=3600)
    monkeypatch.setattr(c, "_root_node", lambda: root)

    r1 = c.walk(None)  # cold: `b` listed and cached with a stable etag
    assert "b/f2.md" in r1

    # `b` becomes ignored. Etags are unchanged (only the LOCAL ignore moved), so `b` is a
    # cache HIT served via _emit_cached. The emit path must reapply the predicate.
    r2 = c.walk(lambda rel: rel.split("/")[0] == "b")
    assert "b" not in r2 and "b/f2.md" not in r2
    assert "a/f1.md" in r2  # the un-ignored branch is still served from cache


def test_invalidate_walk_cache_forces_fresh_listing(monkeypatch):
    """invalidate_walk_cache() drops the etag cache so the next walk lists every folder
    fresh — the only way a newly-UN-ignored path (absent from the cached children list,
    its parent etag unchanged) can reappear."""
    from ifolder_sync.icloud_client import ICloudClient

    root, a, b = _etag_tree()
    c = ICloudClient("x@y.com", walk_workers=4, full_walk_interval=3600)
    monkeypatch.setattr(c, "_root_node", lambda: root)

    c.walk(None)
    assert (root.calls, a.calls, b.calls) == (1, 1, 1)
    c.walk(None)
    assert (root.calls, a.calls, b.calls) == (1, 1, 1)  # warm: served from cache

    c.invalidate_walk_cache()
    c.walk(None)
    assert (root.calls, a.calls, b.calls) == (2, 2, 2)  # cache dropped: all re-listed


def test_syncer_invalidates_walk_cache_when_ignore_changes(make_syncer, fake, local_dir, tmp_path):
    """When the effective ignore set changes between passes, the engine drops the remote
    walk cache (and its persisted copy) so the next walk re-lists with the new filters — the
    etag cache cannot otherwise reflect a local ignore change."""
    from ifolder_sync.config import Config
    from ifolder_sync.syncer import Syncer

    syncer1, store = make_syncer(ignore=[".DS_Store"])
    syncer1.sync_once()
    assert fake.calls["invalidate_walk_cache"] == 0  # first pass: hash recorded, no change yet

    cfg2 = Config(
        apple_id="x@y.com",
        remote_folder="",
        local_folder=str(local_dir),
        ignore=[".DS_Store", "secret/"],
    )
    Syncer(cfg2, fake, store, trash_dir=tmp_path / "trash").sync_once()
    assert fake.calls["invalidate_walk_cache"] == 1  # ignore changed -> walk cache dropped
    assert store.get_meta("walk_cache") == ""  # persisted blob cleared so a restart can't re-import


def test_poll_timeout_adaptive(tmp_path, monkeypatch):
    import time

    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")
    d._interval = 60
    assert d._poll_timeout() == 60  # idle -> base interval
    d._last_activity = time.time()
    assert d._poll_timeout() == d.cfg.interval_active_seconds  # active -> fast cadence
    d._backoff = 600
    assert d._poll_timeout() == 600  # drift backoff wins over everything
    d.store.close()


# --------------------------------------------- hot-file upload (autosave race) ---
def test_hot_file_upload_does_not_conflict(make_syncer, fake, local_dir):
    """An editor autosave landing mid-upload must not turn into a conflict loop.

    The engine uploads a frozen snapshot and records ITS signature, so the next pass
    sees the autosave as a plain local edit (upload), never as a both-sides change.
    """
    syncer, store = make_syncer()
    write_file(local_dir, "hot.md", b"v1", mtime=1000)

    orig_upload = fake.upload

    def racy_upload(relpath, src, mtime):
        write_file(local_dir, "hot.md", b"v2-longer-content", mtime=1000 + FAR)
        orig_upload(relpath, src, mtime)

    fake.upload = racy_upload
    syncer.sync_once()
    fake.upload = orig_upload
    assert fake.files["hot.md"]["content"] == b"v1"  # the frozen snapshot was sent

    s = syncer.sync_once()  # the autosave is a plain local edit, not a conflict
    assert s.conflicts == 0, s.summary()
    assert s.uploaded == 1, s.summary()
    assert fake.files["hot.md"]["content"] == b"v2-longer-content"

    s = syncer.sync_once()  # converged: nothing left to do
    assert s.uploaded == 0 and s.conflicts == 0, s.summary()
    assert not list(local_dir.glob("hot.conflict-*")), "no conflict backups expected"
    store.close()


# ---------------------------------------------- subtree deletion (one call) ---
def test_remote_subtree_deleted_in_one_call_and_not_resurrected(make_syncer, fake, local_dir):
    syncer, store = make_syncer()
    for i in range(4):
        write_file(local_dir, f"proj/sub{i // 2}/f{i}.md", b"x", mtime=1000)
    syncer.sync_once()
    assert sum(1 for k in fake.files if k.startswith("proj")) >= 4
    calls_before = fake.calls["delete"]

    shutil.rmtree(local_dir / "proj")
    s = syncer.sync_once()

    assert fake.calls["delete"] - calls_before == 1  # ONE call for the whole tree
    assert not [k for k in fake.files if k.startswith("proj")]
    assert not [k for k in store.all() if k.startswith("proj")]
    assert s.deleted_remote >= 4, s.summary()
    assert not (local_dir / "proj").exists()  # dirs are not resurrected locally

    s = syncer.sync_once()  # converged
    assert s.uploaded == 0 and s.downloaded == 0 and s.deleted_remote == 0, s.summary()
    store.close()


def test_subtree_with_remote_edit_blocks_tree_delete(make_syncer, fake, local_dir):
    """A remotely-edited file under a deleted dir must survive (rescue), so the dir
    cannot be tree-deleted nor rmdir'd out from under it."""
    syncer, store = make_syncer()
    for name in ("keep.md", "a.md", "b.md"):
        write_file(local_dir, f"proj/{name}", b"x", mtime=1000)
    syncer.sync_once()

    shutil.rmtree(local_dir / "proj")
    fake.put("proj/keep.md", b"edited-on-phone", mtime=1000 + FAR)
    s = syncer.sync_once()

    assert (local_dir / "proj/keep.md").read_bytes() == b"edited-on-phone"  # rescued
    assert "proj/keep.md" in fake.files  # still remote: the dir was NOT tree-deleted
    assert "proj/a.md" not in fake.files and "proj/b.md" not in fake.files
    assert s.conflicts == 1, s.summary()  # the rescue is flagged
    store.close()


# ------------------------------------------------------------ .part hard-ignore ---
def test_part_files_never_uploaded_even_with_legacy_ignore(make_syncer, fake, local_dir):
    # Legacy config: ignore list saved before *.part entered DEFAULT_IGNORE.
    syncer, store = make_syncer(ignore=[".DS_Store"])
    write_file(local_dir, "note.md", b"x", mtime=1000)
    write_file(local_dir, "note.md.part", b"partial", mtime=1000)
    syncer.sync_once()
    assert "note.md" in fake.files
    assert "note.md.part" not in fake.files
    store.close()


# ----------------------------------------------------------- G2: daemon preflight ---
def _daemon(tmp_path, monkeypatch, local_folder):
    from ifolder_sync.daemon import Daemon

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    cfg = Config(apple_id="x@y.com", local_folder=str(local_folder))
    return Daemon(cfg, "preflight-test")


def test_preflight_fails_on_missing_root_with_baseline(tmp_path, monkeypatch):
    d = _daemon(tmp_path, monkeypatch, tmp_path / "gone")
    from ifolder_sync.state import BaselineEntry

    d.store.upsert(BaselineEntry("a.md", "file", 1, 1, 1, 1))
    d.store.commit()
    assert d._preflight() is False
    assert "preflight" in (d.store.get_meta("last_error") or "")
    d.store.close()


@needs_chmod
def test_preflight_fails_on_unwritable_root(tmp_path, monkeypatch):
    root = tmp_path / "vault"
    root.mkdir()
    os.chmod(root, 0o555)
    d = _daemon(tmp_path, monkeypatch, root)
    try:
        assert d._preflight() is False
    finally:
        os.chmod(root, 0o755)
    d.store.close()


def test_preflight_creates_fresh_root(tmp_path, monkeypatch):
    root = tmp_path / "newvault"
    d = _daemon(tmp_path, monkeypatch, root)
    assert d._preflight() is True
    assert root.is_dir()
    d.store.close()


# ------------------------------------------------------------- G5: rebaseline ---
_sandbox = sandbox_home


def test_rebaseline_backs_up_and_resets(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "orphan.md.part").write_text("junk")
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    store = StateStore(baseline_path("work"))
    store.set_meta("vault_uuid", "stale")
    store.close()

    main(["rebaseline", "--profile", "work"])

    assert not baseline_path("work").exists()
    backups = list(baseline_path("work").parent.glob("baseline.sqlite3.bak-*"))
    assert len(backups) == 1
    assert not (vault / "orphan.md.part").exists()
    assert read_vault_marker(vault) is not None
    assert "Next steps" in capsys.readouterr().out


def test_rebaseline_keeps_existing_marker(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    prior = write_vault_marker(vault)
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))

    main(["rebaseline", "--profile", "work"])
    assert read_vault_marker(vault) == prior


def test_rebaseline_refuses_running_daemon(tmp_path, monkeypatch):
    from ifolder_sync.locking import SingleInstanceLock

    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    held = SingleInstanceLock(lock_path("work"))
    held.acquire()  # a live daemon holds the kernel lock
    try:
        with pytest.raises(SystemExit):
            main(["rebaseline", "--profile", "work"])
        assert baseline_path("work").parent.exists()
    finally:
        held.release()


def test_rebaseline_refuses_when_lock_held(tmp_path, monkeypatch, capsys):
    """TOCTOU: even if holder_pid reads None (the boot-jitter window), the real
    SingleInstanceLock is held, so rebaseline refuses instead of deleting the baseline out
    from under a daemon that started right after the snapshot. Mirrors the --fix-orphans fix."""
    from ifolder_sync.locking import SingleInstanceLock

    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    store = StateStore(baseline_path("work"))
    store.set_meta("vault_uuid", "keep-me")  # a non-empty baseline that must survive
    store.close()

    held = SingleInstanceLock(lock_path("work"))
    held.acquire()
    monkeypatch.setattr("ifolder_sync.cli.holder_pid", lambda _p: None)  # stale-pid window
    try:
        with pytest.raises(SystemExit):
            main(["rebaseline", "--profile", "work"])
        assert "race the baseline" in capsys.readouterr().err
        assert baseline_path("work").exists()  # never deleted
    finally:
        held.release()


# --------------------------------------------------- plist: no-crash-loop keys ---
def test_plist_has_no_crash_loop_keys(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    body = cli._write_agent_plist("work").read_text()
    assert "<key>SuccessfulExit</key>" in body
    assert "<key>ThrottleInterval</key>" in body


# --- Phase C Batch 1: independent engine/daemon/client safety guards -----------


def test_conflict_aborts_when_remote_backup_download_fails(make_syncer, fake, local_dir):
    """P1-4: if the remote loser cannot be backed up, conflict resolution must abort so
    a transient error never hard-deletes the only copy of the losing version."""
    syncer, store = make_syncer(policy="newer")
    write_file(local_dir, "c.md", b"base", mtime=5000)
    syncer.sync_once()

    write_file(local_dir, "c.md", b"local-wins", mtime=5000 + 2 * FAR)
    fake.put("c.md", b"remote-loses", mtime=5000 + FAR)

    orig_download = fake.download

    def boom_download(relpath, dest):
        raise RuntimeError("transient backup download failure")

    fake.download = boom_download
    s = syncer.sync_once()
    fake.download = orig_download

    assert fake.files["c.md"]["content"] == b"remote-loses", s.summary()
    assert not list(local_dir.glob("c.conflict-*.md"))

    s2 = syncer.sync_once()
    assert fake.files["c.md"]["content"] == b"local-wins", s2.summary()
    backups = list(local_dir.glob("c.conflict-*.md"))
    assert backups and backups[0].read_bytes() == b"remote-loses"
    store.close()


def test_symlinked_file_skipped_not_synced(make_syncer, fake, local_dir):
    """P1-12: a symlinked file is never uploaded and the link is left intact."""
    syncer, store = make_syncer()
    write_file(local_dir, "real.md", b"real-content", mtime=1000)
    os.symlink(local_dir / "real.md", local_dir / "link.md")
    syncer.sync_once()
    assert "real.md" in fake.files
    assert "link.md" not in fake.files
    assert "link.md" not in store.all()
    assert (local_dir / "link.md").is_symlink()
    store.close()


def test_symlinked_dir_skipped_and_not_descended(make_syncer, fake, local_dir):
    """P1-12: a symlinked directory is neither recorded nor descended."""
    syncer, store = make_syncer()
    write_file(local_dir, "target/inside.md", b"x", mtime=1000)
    os.symlink(local_dir / "target", local_dir / "alias")
    syncer.sync_once()
    assert "target" in store.all() and "target/inside.md" in fake.files
    assert "alias" not in store.all()
    assert "alias" not in fake.files
    assert "alias/inside.md" not in fake.files
    assert (local_dir / "alias").is_symlink()
    store.close()


def test_request_timeout_installed_and_applied():
    """P1-5: connect() wraps session.request so calls with no explicit timeout get the
    configured (connect,read) tuple; an explicit timeout is left untouched; idempotent."""
    from ifolder_sync.icloud_client import ICloudClient

    captured = []

    class _FakeSession:
        def request(self, method, url, **kwargs):
            captured.append(kwargs.get("timeout"))
            return "ok"

    class _FakeApi:
        def __init__(self):
            self.session = _FakeSession()

    c = ICloudClient("x@y.com", request_timeout=42)
    c.api = _FakeApi()
    c._install_request_timeout()

    assert c.api.session.request("GET", "https://example") == "ok"
    assert captured[-1] == (42.0, 42.0)
    c.api.session.request("GET", "https://example", timeout=5)
    assert captured[-1] == 5
    c._install_request_timeout()
    c.api.session.request("GET", "https://example")
    assert captured[-1] == (42.0, 42.0)


def test_request_timeout_zero_disables():
    """P1-5: request_timeout <= 0 disables wrapping (timeout stays None)."""
    from ifolder_sync.icloud_client import ICloudClient

    captured = []

    class _FakeSession:
        def request(self, method, url, **kwargs):
            captured.append(kwargs.get("timeout"))
            return "ok"

    class _FakeApi:
        session = _FakeSession()

    c = ICloudClient("x@y.com", request_timeout=0)
    c.api = _FakeApi()
    c._install_request_timeout()
    c.api.session.request("GET", "https://example")
    assert captured[-1] is None


def test_timeout_error_is_retried_then_raised():
    """P1-5: a requests Timeout is transient: retried up to attempts then propagated so
    the walk guard aborts the pass (zero deletions)."""
    import requests

    from ifolder_sync.retry import with_retry

    calls = {"n": 0}

    def hangs():
        calls["n"] += 1
        raise requests.exceptions.ReadTimeout("read timed out")

    with pytest.raises(requests.exceptions.RequestException):
        with_retry(hangs, attempts=3, base=0)
    assert calls["n"] == 3


def test_run_sync_stops_clean_on_auth_failure(tmp_path, monkeypatch):
    """P1-13: a mid-run pyicloud login failure stops the daemon cleanly (sets _stop so
    run() exits 0 and launchd does not restart), not the generic retry path."""
    from pyicloud.exceptions import PyiCloudFailedLoginException

    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")

    def boom(*_a, **_k):
        raise PyiCloudFailedLoginException("trust token expired")

    monkeypatch.setattr(d.syncer, "sync_once", boom)
    d._run_sync("poll")

    assert d._stop.is_set()
    assert d._wake.is_set()
    assert "auth" in (d.store.get_meta("last_error") or "")
    d.store.close()


def test_run_sync_stops_clean_on_runtime_auth_error(tmp_path, monkeypatch):
    """P1-13: a RuntimeError from the connect/2FA helpers mid-run also clean-stops."""
    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")

    def boom(*_a, **_k):
        raise RuntimeError("iCloud requires 2FA verification")

    monkeypatch.setattr(d.syncer, "sync_once", boom)
    d._run_sync("poll")

    assert d._stop.is_set()
    assert "auth" in (d.store.get_meta("last_error") or "")
    d.store.close()


def test_run_sync_local_scan_error_keeps_retrying(tmp_path, monkeypatch):
    """P1-13: a transient LocalScanError must NOT stop the daemon (retry next poll)."""
    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")

    def boom(*_a, **_k):
        raise LocalScanError("local scan failed: transient")

    monkeypatch.setattr(d.syncer, "sync_once", boom)
    d._run_sync("poll")

    assert not d._stop.is_set()
    assert "local scan failed" in (d.store.get_meta("last_error") or "")
    d.store.close()


def test_engine_ignore_merged_for_legacy_config_missing_conflict_pattern(
    make_syncer, fake, local_dir
):
    """P1-18: a legacy config whose `ignore` predates *.conflict-* still excludes
    conflict backups (merged from ENGINE_IGNORE at load time)."""
    syncer, store = make_syncer(ignore=[".DS_Store"])
    write_file(local_dir, "note.md", b"x", mtime=1000)
    write_file(local_dir, "note.conflict-20260101-000000.md", b"backup", mtime=1000)
    syncer.sync_once()
    assert "note.md" in fake.files
    assert "note.conflict-20260101-000000.md" not in fake.files
    assert "note.conflict-20260101-000000.md" not in store.all()
    store.close()


def test_effective_ignore_merges_engine_set_without_duplicates():
    """P1-18: ENGINE_IGNORE is merged into effective_ignore, deduplicated."""
    from ifolder_sync.config import ENGINE_IGNORE, Config

    cfg = Config(apple_id="x@y.com", local_folder="/tmp/x", ignore=[".DS_Store"])
    eff = cfg.effective_ignore
    for pat in ENGINE_IGNORE:
        assert pat in eff
    cfg2 = Config(apple_id="x@y.com", local_folder="/tmp/x", ignore=list(ENGINE_IGNORE))
    assert cfg2.effective_ignore.count(ENGINE_IGNORE[0]) == 1


def test_run_sync_stops_clean_on_reauth_required(tmp_path, monkeypatch):
    """P1-13 (adversarial follow-up): a mid-run PyiCloudAuthRequiredException (HTTP 450
    FIND_MY_REAUTH_REQUIRED) must also clean-stop — it does not subclass RuntimeError and
    would otherwise be retried every poll (lockout risk)."""
    from unittest.mock import MagicMock

    from pyicloud.exceptions import PyiCloudAuthRequiredException

    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")

    def boom(*_a, **_k):
        raise PyiCloudAuthRequiredException("x@y.com", MagicMock())

    monkeypatch.setattr(d.syncer, "sync_once", boom)
    d._run_sync("poll")

    assert d._stop.is_set()
    assert "auth" in (d.store.get_meta("last_error") or "")
    d.store.close()


def test_run_sync_stops_clean_on_service_not_activated(tmp_path, monkeypatch):
    """P1-13 (adversarial follow-up): PyiCloudServiceNotActivatedException (auth-failed)
    subclasses PyiCloudAPIResponseException and is classed non-transient; it must
    clean-stop, not retry."""
    from pyicloud.exceptions import PyiCloudServiceNotActivatedException

    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")

    def boom(*_a, **_k):
        raise PyiCloudServiceNotActivatedException("authentication failed", "ERROR")

    monkeypatch.setattr(d.syncer, "sync_once", boom)
    d._run_sync("poll")

    assert d._stop.is_set()
    assert "auth" in (d.store.get_meta("last_error") or "")
    d.store.close()


def test_is_session_relapse_classifier_distinguishes_recoverable_from_terminal():
    """The classifier must say YES to the recoverable 421 LOGIN_TOKEN_EXPIRED (and its
    code=None 'Missing X-APPLE-WEBAUTH-TOKEN cookie' variant) but NO to a transient 503 and
    to 409/450/500 (which share the rewritten 'Authentication required for Account.' reason
    yet genuinely need 2FA, so must keep clean-stopping — not reconnect)."""
    from pyicloud.const import AppleAuthError
    from pyicloud.exceptions import PyiCloudAPIResponseException

    from ifolder_sync.icloud_client import is_session_relapse

    # observed live failure (mid-session drive call): 421, generic API exception
    assert is_session_relapse(
        PyiCloudAPIResponseException(
            "Authentication required for Account.", AppleAuthError.LOGIN_TOKEN_EXPIRED
        )
    )
    # re-validation variant: code=None, reason carries the webauth-cookie string
    assert is_session_relapse(
        PyiCloudAPIResponseException("Missing X-APPLE-WEBAUTH-TOKEN cookie", None)
    )
    # genuine transient: must NOT trigger a reconnect-storm
    assert not is_session_relapse(PyiCloudAPIResponseException("Service Unavailable", 503))
    # 2FA-required (409) shares the rewritten reason but is NOT reconnectable
    assert not is_session_relapse(
        PyiCloudAPIResponseException(
            "Authentication required for Account.", AppleAuthError.TWO_FACTOR_REQUIRED
        )
    )
    assert not is_session_relapse(RuntimeError("boom"))


def _relapse_boom(*_a, **_k):
    from pyicloud.const import AppleAuthError
    from pyicloud.exceptions import PyiCloudAPIResponseException

    raise PyiCloudAPIResponseException(
        "Authentication required for Account.", AppleAuthError.LOGIN_TOKEN_EXPIRED
    )


def test_run_sync_reconnects_on_session_relapse(tmp_path, monkeypatch):
    """A lapsed login token (421) must self-heal: the daemon reconnects in place and keeps
    running, instead of looping forever in the broad exception handler."""
    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")
    reconnects = []
    monkeypatch.setattr(d.client, "connect", lambda *a, **k: reconnects.append(1))
    monkeypatch.setattr(d.syncer, "sync_once", _relapse_boom)

    d._run_sync("poll")

    assert not d._stop.is_set()
    assert len(reconnects) == 1  # reconnected once
    assert d._relapse_count == 1
    d.store.close()


def test_run_sync_stops_when_reconnect_needs_reauth(tmp_path, monkeypatch):
    """If the in-place reconnect itself needs interactive 2FA, the daemon clean-stops with a
    'run auth' hint rather than spinning (the trust token is gone, not just the web cookie)."""
    from pyicloud.exceptions import PyiCloudFailedLoginException

    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")
    monkeypatch.setattr(d.syncer, "sync_once", _relapse_boom)

    def reconnect_fails(*_a, **_k):
        raise PyiCloudFailedLoginException("trust token expired")

    monkeypatch.setattr(d.client, "connect", reconnect_fails)

    d._run_sync("poll")

    assert d._stop.is_set()
    assert "auth" in (d.store.get_meta("last_error") or "")
    d.store.close()


def test_run_sync_throttles_reconnect_storm(tmp_path, monkeypatch):
    """A tight relapse storm must NOT replay SRP every poll (Apple lockout): inside
    min_reconnect_interval the daemon retries WITHOUT reconnecting."""
    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")
    d._min_reconnect_interval = 9999
    reconnects = []
    monkeypatch.setattr(d.client, "connect", lambda *a, **k: reconnects.append(1))
    monkeypatch.setattr(d.syncer, "sync_once", _relapse_boom)

    d._run_sync("poll")  # first relapse -> reconnect
    d._run_sync("poll")  # immediate second -> throttled, no SRP replay

    assert len(reconnects) == 1
    assert d._relapse_count == 1
    assert not d._stop.is_set()
    d.store.close()


def test_run_sync_stops_after_max_session_reconnects(tmp_path, monkeypatch):
    """If the session keeps lapsing with no clean pass between, the bounded budget must
    clean-stop instead of reconnecting forever."""
    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")
    d._max_session_reconnects = 2
    d._min_reconnect_interval = 0  # don't throttle so each relapse reconnects
    monkeypatch.setattr(d.client, "connect", lambda *a, **k: None)  # reconnect "succeeds"
    monkeypatch.setattr(d.syncer, "sync_once", _relapse_boom)

    d._run_sync("poll")  # count=1, reconnect
    d._run_sync("poll")  # count=2, reconnect
    assert not d._stop.is_set()
    d._run_sync("poll")  # count=3 > 2 -> stop
    assert d._stop.is_set()
    assert "auth" in (d.store.get_meta("last_error") or "")
    d.store.close()


def test_completed_pass_resets_relapse_count_and_clears_last_error(tmp_path, monkeypatch):
    """A pass that completes proves the session is healthy: it must zero the reconnect budget
    and clear a stale last_error so `status` reflects the recovery (P4-3 / status truthful)."""
    from ifolder_sync.syncer import SyncStats

    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")
    d._relapse_count = 3
    d._set_last_error("auth: session expired earlier")
    monkeypatch.setattr(d.syncer, "sync_once", lambda *a, **k: SyncStats())

    d._run_sync("poll")

    assert d._relapse_count == 0
    assert (d.store.get_meta("last_error") or "") == ""
    d.store.close()


def test_session_relapse_classifier_ignores_cookie_string_in_server_body():
    """Hardening (adversarial review): the WEBAUTH branch anchors on exc.reason, not str(exc),
    so a terminal 409 whose raw response body merely CONTAINS the cookie string is NOT mistaken
    for a recoverable relapse (which would trigger a wrong reconnect)."""
    from types import SimpleNamespace

    from pyicloud.const import AppleAuthError
    from pyicloud.exceptions import PyiCloudAPIResponseException

    from ifolder_sync.icloud_client import is_session_relapse

    resp = SimpleNamespace(text="server said: ...Missing X-APPLE-WEBAUTH-TOKEN cookie...")
    exc = PyiCloudAPIResponseException(
        "Authentication required for Account.", AppleAuthError.TWO_FACTOR_REQUIRED, resp
    )
    assert "Missing X-APPLE-WEBAUTH-TOKEN cookie" in str(exc)  # the trap the str() check fell into
    assert not is_session_relapse(exc)  # reason-anchored -> correctly terminal, no reconnect


def test_run_sync_retries_on_transient_during_reconnect(tmp_path, monkeypatch):
    """Hardening (adversarial review): a transient API error (e.g. 503) raised DURING the
    reconnect login must not crash or clean-stop the daemon — it retries next poll within the
    bounded budget, rather than escaping _run_sync and crashing the process."""
    from pyicloud.exceptions import PyiCloudAPIResponseException

    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")

    def reconnect_blips(*_a, **_k):
        raise PyiCloudAPIResponseException("Service Unavailable", 503)

    monkeypatch.setattr(d.client, "connect", reconnect_blips)
    monkeypatch.setattr(d.syncer, "sync_once", _relapse_boom)

    d._run_sync("poll")

    assert not d._stop.is_set()
    assert "reconnect transient" in (d.store.get_meta("last_error") or "")
    d.store.close()


def test_unhandled_op_is_loud_not_silent(make_syncer):
    """P3-1: an unknown op must be a loud error, not a silent drop (file) nor a baseline
    fall-through (dir/cleanup). Guards the exhaustive `else: raise` dispatch."""
    from ifolder_sync.syncer import Op, SyncStats

    syncer, store = make_syncer()
    # dir + cleanup dispatchers raise directly (no internal try/except)
    with pytest.raises(ValueError):
        syncer._apply_dir("d", "bogus_op", SyncStats(), dry_run=False)
    with pytest.raises(ValueError):
        syncer._apply_cleanup("d", "bogus_op", SyncStats(), dry_run=False)
    # the file dispatcher wraps reconcile errors -> counts an error, records nothing
    stats = SyncStats()
    syncer._apply_file("f", "bogus_op", {}, {}, stats, dry_run=False)
    assert stats.errors == 1
    assert store.all() == {}  # the bogus dir op did NOT fall through to a baseline upsert
    # Op renders as its wire value (not "Op.UPLOAD") on every supported Python, so a future
    # %s/f-string interpolation of an op cannot silently diverge from the string form.
    assert str(Op.UPLOAD) == "upload" and f"{Op.DELETE_REMOTE}" == "delete_remote"
    store.close()


def test_dangling_and_circular_symlinks_do_not_abort_the_pass(make_syncer, fake, local_dir):
    """P1-12 (adversarial follow-up): a broken/circular symlink must be skipped, never
    reaching p.stat() in a way that raises LocalScanError (invariant 2 false-positive).
    os.path.islink is True for both, so the guard skips them before stat."""
    write_file(local_dir, "real.md", b"x", mtime=1000)
    os.symlink(local_dir / "nonexistent-target", local_dir / "dead.md")  # dangling
    os.symlink(local_dir / "loopb", local_dir / "loopa")  # circular pair
    os.symlink(local_dir / "loopa", local_dir / "loopb")

    syncer, store = make_syncer()
    s = syncer.sync_once()  # must NOT raise LocalScanError

    assert "real.md" in fake.files
    for link in ("dead.md", "loopa", "loopb"):
        assert link not in fake.files
        assert link not in store.all()
    assert s.errors == 0, s.summary()
    store.close()


# --- Phase C Batch 2: baseline durability ---------------------------------------


def test_wal_and_busy_timeout_enabled(tmp_path):
    """P1-7a: the baseline opens in WAL with a busy_timeout so `status` reads never
    block (or crash on `database is locked`) while the daemon writes."""
    with StateStore(tmp_path / "b.sqlite3") as s:
        assert s.conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert s.conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_corrupt_baseline_raises_on_open(tmp_path):
    """P1-7d: an unreadable baseline file surfaces as CorruptBaselineError (a clear,
    rebaseline-pointing error), never a silent empty DB."""
    from ifolder_sync.state import CorruptBaselineError

    bad = tmp_path / "bad.sqlite3"
    bad.write_bytes(b"this is definitely not a sqlite database " * 20)
    with pytest.raises(CorruptBaselineError):
        StateStore(bad)


def test_quick_check_ok_on_fresh_db(tmp_path):
    """P1-7e: a fresh/valid baseline passes its integrity check (no false positive)."""
    with StateStore(tmp_path / "fresh.sqlite3") as s:
        s.quick_check()  # must not raise


def test_per_action_commit_during_pass(make_syncer, fake, local_dir):
    """P1-7b: the apply loop commits after each action, not once at pass end."""
    syncer, store = make_syncer()
    for i in range(3):
        write_file(local_dir, f"n{i}.md", b"x", mtime=1000)
    commits = {"n": 0}
    real = store.commit

    def counted():
        commits["n"] += 1
        real()

    store.commit = counted
    syncer.sync_once()
    assert commits["n"] >= 3  # at least one commit per uploaded file
    store.close()


def test_committed_rows_survive_midpass_crash(make_syncer, fake, local_dir):
    """P1-7b: a hard abort mid-pass leaves the already-applied file's baseline row
    durable (no rollback -> no spurious conflict next pass)."""
    syncer, store = make_syncer()
    write_file(local_dir, "a.md", b"x", mtime=1000)
    write_file(local_dir, "b.md", b"y", mtime=1000)
    db_path = store.db_path
    calls = {"n": 0}
    real = syncer._apply_file

    def flaky(relpath, op, *a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt  # escapes the per-file try/except, aborts the pass
        return real(relpath, op, *a, **k)

    syncer._apply_file = flaky
    with pytest.raises(KeyboardInterrupt):
        syncer.sync_once()
    store.close()

    with StateStore(db_path) as reopened:
        rows = reopened.all()
    assert len(rows) == 1  # exactly the first file, committed before the abort
    assert "a.md" in rows or "b.md" in rows


def test_stop_check_halts_apply_loop(make_syncer, fake, local_dir):
    """P1-7c: a stop signal between actions breaks the apply loop promptly; what was
    applied before the stop stays committed (durable, not rolled back)."""
    syncer, store = make_syncer()
    for i in range(3):
        write_file(local_dir, f"n{i}.md", b"x", mtime=1000)
    flags = {"n": 0}

    def stop():
        flags["n"] += 1
        return flags["n"] > 1  # allow the first file, then stop

    syncer._stop_check = stop
    syncer.sync_once()
    assert len(fake.files) == 1  # only one file uploaded before the stop
    store.close()


def test_mkdir_local_failure_is_caught(make_syncer, local_dir):
    """P1-7c: a failed local mkdir (a file occupies the path) is caught, counted, and
    leaves no baseline row for a directory that was not created."""
    from ifolder_sync.syncer import SyncStats

    syncer, store = make_syncer()
    (local_dir / "d").write_bytes(b"x")  # a regular file occupies the dir path
    stats = SyncStats()
    syncer._apply_dir("d", "mkdir_local", stats, dry_run=False)
    assert stats.errors == 1
    assert "d" not in store.all()
    store.close()


def test_backup_to_creates_valid_copy(tmp_path):
    """P1-7e: backup_to writes a consistent, integrity-clean copy of the baseline."""
    from ifolder_sync.state import BaselineEntry

    src = StateStore(tmp_path / "src.sqlite3")
    src.upsert(BaselineEntry("x.md", "file", 5, 1.0, 5, 1.0))
    src.commit()
    dest = tmp_path / "copy.sqlite3"
    src.backup_to(dest)
    src.close()
    with StateStore(dest) as copy:
        assert "x.md" in copy.all()
        copy.quick_check()


def test_daemon_rotate_backup_keeps_n(tmp_path, monkeypatch):
    """P1-7e: rotated baseline backups are ring-buffered to baseline_backups copies, and
    the newest is a valid restorable baseline."""
    from ifolder_sync.config import baseline_path
    from ifolder_sync.state import BaselineEntry

    d = _daemon(tmp_path, monkeypatch, tmp_path / "vault")
    d.cfg.baseline_backups = 3
    d.store.upsert(BaselineEntry("a.md", "file", 1, 1, 1, 1))
    d.store.commit()
    for _ in range(5):
        d._rotate_backup()

    bdir = baseline_path("preflight-test").parent / "baseline-backups"
    backups = list(bdir.glob("autobak-*.sqlite3"))
    assert len(backups) == 3
    newest = max(backups, key=d._backup_index)
    with StateStore(newest) as restored:
        assert "a.md" in restored.all()
    d.store.close()


def test_daemon_construction_raises_on_corrupt_baseline(tmp_path, monkeypatch):
    """P1-7d: a corrupt baseline is detected when the daemon opens its store (so it never
    proceeds against a silently-empty DB)."""
    from ifolder_sync.config import baseline_path
    from ifolder_sync.daemon import Daemon
    from ifolder_sync.state import CorruptBaselineError

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    bp = baseline_path("corrupt-test")
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_bytes(b"not a database " * 50)
    cfg = Config(apple_id="x@y.com", local_folder=str(tmp_path / "v"))
    with pytest.raises(CorruptBaselineError):
        Daemon(cfg, "corrupt-test")


def test_cmd_start_clean_exits_on_corrupt_baseline(tmp_path, monkeypatch, capsys):
    """P1-7d: `start` on a corrupt baseline exits cleanly (no SystemExit, exit 0) with a
    rebaseline hint -> launchd KeepAlive=SuccessfulExit:false does not crash-loop."""
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("corrupt"))
    bp = baseline_path("corrupt")
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_bytes(b"garbage" * 50)

    main(["start", "--profile", "corrupt"])  # must NOT raise SystemExit (clean exit 0)
    assert "rebaseline" in capsys.readouterr().err


def test_rebaseline_backup_survives_uncheckpointed_wal(tmp_path, monkeypatch):
    """P1-7a/HIGH-1: under WAL, rebaseline must take a consistent copy (committed rows
    can live only in -wal until a checkpoint). A raw file copy of the main DB would lose
    them; the backup must preserve every committed row, and no -wal/-shm may be orphaned."""
    from ifolder_sync.state import BaselineEntry, StateStore

    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    db = baseline_path("work")

    # Simulate a daemon SIGKILLed without a clean close: rows are committed but stay in
    # the WAL (50 rows is far below the auto-checkpoint threshold) and the conn is left
    # open, so nothing flushes them into the main file.
    live = StateStore(db)
    for i in range(50):
        live.upsert(BaselineEntry(f"n{i}.md", "file", i, float(i), i, float(i)))
    live.commit()

    main(["rebaseline", "--profile", "work"])
    live.close()

    backups = list(db.parent.glob("baseline.sqlite3.bak-*"))
    assert len(backups) == 1
    with StateStore(backups[0]) as restored:
        assert len(restored.all()) == 50  # rows preserved, not lost to the WAL
    assert not db.exists()
    assert not db.with_name(db.name + "-wal").exists()  # siblings not orphaned


# --- Phase C Batch 3: client resilience -----------------------------------------


def test_baseline_remote_etag_column_migration(tmp_path):
    """P1-15: a baseline created without the remote_etag column gains it (additive
    ALTER TABLE) and round-trips the etag."""
    import sqlite3

    from ifolder_sync.state import BaselineEntry, StateStore

    db = tmp_path / "old.sqlite3"
    legacy = sqlite3.connect(str(db))
    legacy.execute(
        "CREATE TABLE baseline (relpath TEXT PRIMARY KEY, kind TEXT NOT NULL, "
        "local_size INTEGER, local_mtime REAL, remote_size INTEGER, remote_mtime REAL)"
    )
    legacy.execute("INSERT INTO baseline VALUES ('old.md','file',1,1.0,1,1.0)")
    legacy.commit()
    legacy.close()

    with StateStore(db) as store:  # opens -> migrates
        assert store.all()["old.md"].remote_etag == ""  # legacy row defaults to ""
        store.upsert(BaselineEntry("new.md", "file", 2, 2.0, 2, 2.0, "etag-xyz"))
        store.commit()
        assert store.all()["new.md"].remote_etag == "etag-xyz"


def test_etag_divergence_triggers_download(make_syncer, fake, local_dir):
    """P1-15: a remote file with the SAME size+mtime as the baseline but a DIFFERENT
    iCloud etag is treated as a remote change and downloaded (catches same-size edits)."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer()
    write_file(local_dir, "n.md", b"AAA", mtime=1000)
    fake.put("n.md", b"AAA", mtime=1000, etag="e1")
    # Seed a clean baseline directly (the both-sides-create adopt-identical case is P1-1,
    # Batch 4; here we isolate the etag-divergence behavior).
    store.upsert(BaselineEntry("n.md", "file", 3, 1000.0, 3, 1000.0, "e1"))
    store.commit()

    # Remote content changes but size+mtime are identical; only the etag moves.
    fake.put("n.md", b"BBB", mtime=1000, etag="e2")
    s = syncer.sync_once()
    assert s.downloaded == 1, s.summary()
    assert (local_dir / "n.md").read_bytes() == b"BBB"  # diverged content rescued
    assert store.all()["n.md"].remote_etag == "e2"

    s = syncer.sync_once()  # etags now match -> no repeat download (no loop)
    assert s.downloaded == 0, s.summary()
    store.close()


def test_etag_divergence_disabled(make_syncer, fake, local_dir):
    """P1-15: with verify_remote_etag off, an etag-only change is NOT acted on."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer(verify_remote_etag=False)
    write_file(local_dir, "n.md", b"AAA", mtime=1000)
    fake.put("n.md", b"AAA", mtime=1000, etag="e1")
    store.upsert(BaselineEntry("n.md", "file", 3, 1000.0, 3, 1000.0, "e1"))
    store.commit()

    fake.put("n.md", b"BBB", mtime=1000, etag="e2")
    s = syncer.sync_once()
    assert s.downloaded == 0, s.summary()
    store.close()


def test_download_size_mismatch_aborts_and_keeps_old_file(tmp_path):
    """P1-15: a truncated download (bytes != listing size) raises and removes the .part
    so no half-file is installed; the old local file is untouched."""
    from ifolder_sync.icloud_client import ICloudClient

    class _Resp:
        def __init__(self, data):
            self.raw = io.BytesIO(data)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Node:
        def __init__(self, data, claimed_size):
            self._data = data
            self.size = claimed_size

        def open(self, stream=True):
            return _Resp(self._data)

    c = ICloudClient("x@y.com", max_retries=1)
    node = _Node(b"AB", claimed_size=99)  # only 2 bytes arrive, listing claims 99
    monkeypatch_navigate(c, node)

    dest = tmp_path / "f.md"
    dest.write_bytes(b"OLD")
    with pytest.raises(OSError):
        c.download("f.md", dest)
    assert dest.read_bytes() == b"OLD"  # old file untouched
    assert not (tmp_path / "f.md.part").exists()  # truncated .part removed


def test_download_size_match_installs(tmp_path):
    """P1-15: a complete download (bytes == listing size) installs normally."""
    from ifolder_sync.icloud_client import ICloudClient

    class _Resp:
        def __init__(self, data):
            self.raw = io.BytesIO(data)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Node:
        def __init__(self, data):
            self._data = data
            self.size = len(data)

        def open(self, stream=True):
            return _Resp(self._data)

    c = ICloudClient("x@y.com", max_retries=1)
    monkeypatch_navigate(c, _Node(b"HELLO"))
    dest = tmp_path / "f.md"
    c.download("f.md", dest)
    assert dest.read_bytes() == b"HELLO"


def test_strict_child_count_aborts_on_truncated_listing(monkeypatch):
    """P1-17: with strict_child_count, a listing shorter than directChildrenCount raises
    (walk guard -> zero deletions); off (default) it only warns."""
    from ifolder_sync.icloud_client import ICloudClient

    kids = [_FakeNode("a.md", "file", size=1), _FakeNode("b.md", "file", size=1)]
    root = _FakeNode("root", "folder", kids)
    root.data["directChildrenCount"] = 5  # claims 5, only 2 returned -> truncated

    c = ICloudClient("x@y.com", strict_child_count=True)
    monkeypatch.setattr(c, "_root_node", lambda: root)
    with pytest.raises(RuntimeError):
        c.walk(None)

    c2 = ICloudClient("x@y.com", strict_child_count=False)
    monkeypatch.setattr(c2, "_root_node", lambda: root)
    res = c2.walk(None)  # default: warns, returns what it has (no abort)
    assert set(res) == {"a.md", "b.md"}


def test_atomic_session_save_writes_valid_files(tmp_path):
    """P1-6: the installed atomic save writes the session JSON (minus non-persisted
    keys) and the cookiejar via tmp + os.replace, at 0600, and is idempotent."""
    import stat as stat_mod

    from ifolder_sync.icloud_client import ICloudClient

    sdir = tmp_path / "sessions"
    sdir.mkdir()
    spath = sdir / "acct.session"
    cpath = sdir / "acct.cookiejar"

    saved = {"n": 0}
    seen_modes = []

    class _Cookies:
        filename = str(cpath)

        def save(self, filename=None, **kw):
            # write at the prevailing umask, then record the resulting mode: the atomic
            # writer must have tightened the umask so even this tmp is born 0600 (no
            # world-readable credential window — invariant 7).
            Path(filename).write_text("#LWP-Cookies-2.0\nDUMMY\n")
            seen_modes.append(stat_mod.S_IMODE(os.stat(filename).st_mode))

    class _Session:
        def __init__(self):
            self.data = {"session_token": "tok", "trust_token": "trust", "salt": "DROP"}
            self.session_path = str(spath)
            self.cookiejar_path = str(cpath)
            self.cookies = _Cookies()

        def _save_session_data(self):
            saved["n"] += 1

    class _Api:
        def __init__(self):
            self.session = _Session()

    c = ICloudClient("x@y.com")
    c.api = _Api()
    c._install_atomic_session_save()
    c._install_atomic_session_save()  # idempotent: must not double-wrap

    c.api.session._save_session_data()  # trigger an atomic write
    data = json.loads(spath.read_text())
    assert data["trust_token"] == "trust"
    assert "salt" not in data  # NON_PERSISTED_SESSION_KEYS filtered out
    assert cpath.exists()
    assert stat_mod.S_IMODE(spath.stat().st_mode) == 0o600  # invariant 7 preserved
    assert stat_mod.S_IMODE(cpath.stat().st_mode) == 0o600  # cookiejar also 0600
    assert seen_modes and all(m == 0o600 for m in seen_modes)  # tmp born 0600, no leak window
    assert not list(sdir.glob("*.tmp"))  # tmps replaced/cleaned, none orphaned
    assert saved["n"] == 0  # the original save was replaced, not also called


# --- Phase C Batch 4: decide/apply value logic ----------------------------------


def test_local_mtime_is_exact_remote_tolerant(make_syncer, fake, local_dir):
    """P1-11: a same-size local edit within 2s of the baseline IS detected (local
    tolerance is exact); a remote mtime within 2s is NOT a change (remote keeps 2s)."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer()
    write_file(local_dir, "n.md", b"AAA", mtime=1000.0)
    fake.put("n.md", b"AAA", mtime=1000.0)
    # Baseline: local mtime 1000, remote mtime 1000.
    store.upsert(BaselineEntry("n.md", "file", 3, 1000.0, 3, 1000.0, ""))
    store.commit()

    # Local edited 1.0s later, same size (a checkbox toggle right after a pass).
    write_file(local_dir, "n.md", b"BBB", mtime=1001.0)
    s = syncer.sync_once()
    assert s.uploaded == 1, s.summary()  # exact local tolerance caught the sub-2s edit
    assert fake.files["n.md"]["content"] == b"BBB"

    # A remote mtime 1.5s off baseline with same size+content is NOT a change.
    syncer2, store2 = make_syncer()
    write_file(local_dir, "m.md", b"CCC", mtime=2000.0)
    fake.put("m.md", b"CCC", mtime=2000.0)
    store2.upsert(BaselineEntry("m.md", "file", 3, 2000.0, 3, 2000.0, ""))
    store2.commit()
    fake.put("m.md", b"CCC", mtime=2001.5)  # remote mtime jitter within 2s
    s2 = syncer2.sync_once()
    assert s2.downloaded == 0 and s2.conflicts == 0, s2.summary()
    store.close()
    store2.close()


def test_adopt_identical_kills_rebaseline_conflict_storm(make_syncer, fake, local_dir):
    """P1-1: sync -> rebaseline (empty baseline) -> sync must be 0 conflicts, 0 uploads
    (both sides already agree, so the baseline is adopted, not re-fought)."""
    syncer, store = make_syncer()
    write_file(local_dir, "a.md", b"hello", mtime=1000.0)
    write_file(local_dir, "sub/b.md", b"world", mtime=1000.0)
    syncer.sync_once()  # uploads both, records baseline
    assert set(fake.files) >= {"a.md", "sub/b.md"}

    # Simulate rebaseline: wipe the baseline, keep local + remote as-is.
    for rel in list(store.all()):
        store.delete(rel)
    store.commit()

    s = syncer.sync_once()
    assert s.conflicts == 0, s.summary()
    assert s.uploaded == 0 and s.downloaded == 0, s.summary()
    assert "a.md" in store.all() and "sub/b.md" in store.all()  # baseline re-adopted
    store.close()


def test_settle_wait_escalates_to_conflict(make_syncer, fake, local_dir):
    """P1-10: a genuinely-empty remote husk that never gains content escalates from
    settle_wait to a conflict after settle_max_passes (no permanent livelock)."""
    syncer, store = make_syncer("local", settle_max_passes=3)
    write_file(local_dir, "fire.md", b"CONTENT", mtime=2000.0 + FAR)
    fake.put("fire.md", b"", mtime=2000.0)  # husk: 0-byte record, never fills

    for i in range(2):
        s = syncer.sync_once()
        assert s.conflicts == 0 and s.uploaded == 0, f"pass {i}: {s.summary()}"
        assert fake.files["fire.md"]["content"] == b""  # still deferred

    s = syncer.sync_once()  # 3rd pass -> escalate
    assert s.conflicts == 1, s.summary()
    assert fake.files["fire.md"]["content"] == b"CONTENT"  # policy=local resolved it
    store.close()


def test_empty_remote_never_overwrites_local_under_newer(make_syncer, fake, local_dir):
    """F1: under policy=newer with a husk whose mtime is NEWER than the local file (so
    'newer' would otherwise pick the empty side), the escalated conflict must NOT empty
    the local note — an empty side never wins a conflict."""
    syncer, store = make_syncer("newer", settle_max_passes=2)
    write_file(local_dir, "n.md", b"REALCONTENT", mtime=1000.0)
    fake.put("n.md", b"", mtime=5000.0)  # husk mtime far newer than local

    syncer.sync_once()  # settle_wait (count 1)
    s = syncer.sync_once()  # count 2 -> escalate -> conflict -> empty-side-never-wins
    assert s.conflicts == 1, s.summary()
    assert (local_dir / "n.md").read_bytes() == b"REALCONTENT"  # NOT emptied
    assert fake.files["n.md"]["content"] == b"REALCONTENT"  # local content kept on remote
    store.close()


def test_empty_local_never_overwrites_remote_under_newer(make_syncer, fake, local_dir):
    """F1 (mirror): an empty LOCAL file never wins against non-empty remote content."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer("newer")
    write_file(local_dir, "n.md", b"", mtime=5000.0)  # local emptied, newer mtime
    fake.put("n.md", b"REMOTECONTENT", mtime=1000.0)
    # Baseline so both sides read as changed (a genuine conflict, not a fresh create).
    store.upsert(BaselineEntry("n.md", "file", 7, 100.0, 7, 100.0, ""))
    store.commit()

    s = syncer.sync_once()
    assert s.conflicts == 1, s.summary()
    assert (local_dir / "n.md").read_bytes() == b"REMOTECONTENT"  # remote content kept
    store.close()


def test_adopt_with_different_content_conflicts_not_records(make_syncer, fake, local_dir):
    """F2: equal-size but DIFFERENT content on both sides (base None) must NOT be silently
    recorded as identical — verify_adopt downloads, sees the bytes differ, and conflicts,
    preserving both sides (policy=both)."""
    syncer, store = make_syncer("both")
    write_file(local_dir, "n.md", b"AAAA", mtime=1000.0)
    fake.put("n.md", b"BBBB", mtime=1000.5)  # same size (4), mtime within 2s, different bytes

    s = syncer.sync_once()
    assert s.conflicts == 1, s.summary()  # a real conflict, not a silent adopt
    backups = list(local_dir.glob("n.conflict-*.md"))
    assert backups, "the remote content must be preserved, not frozen away"
    assert {(local_dir / "n.md").read_bytes(), backups[0].read_bytes()} == {b"AAAA", b"BBBB"}
    store.close()


def test_settle_escalation_count_survives_failed_escalation(make_syncer, fake, local_dir):
    """F5: a transiently-failed escalation must re-escalate next pass (the count is kept),
    not restart the countdown."""
    syncer, store = make_syncer("newer", settle_max_passes=2)
    write_file(local_dir, "n.md", b"CONTENT", mtime=1000.0)
    fake.put("n.md", b"", mtime=2000.0)
    syncer.sync_once()  # count 1
    syncer.sync_once()  # count 2 -> escalate; the count must remain >= 2 in meta
    counts = json.loads(store.get_meta("settle_counts") or "{}")
    assert counts.get("n.md", 0) >= 2  # not dropped on escalation
    store.close()


# --- Phase C Batch 5: rmdir_local correctness -----------------------------------


def test_rmdir_local_ignored_residue_no_resurrection(make_syncer, fake, local_dir):
    """P1-3: a locally-surviving dir kept alive only by ignored residue (.DS_Store) after
    its remote was deleted is trashed (dir actually gone -> baseline row dropped), so it
    is NOT resurrected remotely next pass."""
    syncer, store = make_syncer()
    write_file(local_dir, "repo/note.md", b"x", mtime=1000.0)
    syncer.sync_once()  # baseline + remote get repo/, repo/note.md
    assert "repo" in store.all() and "repo/note.md" in fake.files

    fake.delete("repo")  # remote deletes the whole folder
    (local_dir / "repo" / "note.md").unlink()  # local file gone too (drop_baseline)
    (local_dir / "repo" / ".DS_Store").write_bytes(b"junk")  # ignored residue lingers

    syncer.sync_once()
    assert "repo" not in store.all()  # baseline row dropped only because the dir is gone
    assert not (local_dir / "repo").exists()  # residue dir trashed, not left behind

    s = syncer.sync_once()  # the critical check: no resurrection
    assert "repo" not in fake.files, "a deleted folder must not resurrect remotely"
    assert s.uploaded == 0, s.summary()
    store.close()


def test_rmdir_local_defers_when_real_file_survives(make_syncer, fake, local_dir):
    """P1-3: if a non-ignored file still lives in the dir, rmdir_local must NOT drop the
    baseline row (which would resurrect the dir); it defers and keeps the dir."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer()
    write_file(local_dir, "d/keep.md", b"real", mtime=1000.0)
    # Baseline knows the dir but NOT keep.md (so keep.md is a fresh local file that must
    # survive), and the remote has neither -> the dir's cleanup is rmdir_local.
    store.upsert(BaselineEntry("d", "dir", 0, 0, 0, 0))
    store.commit()

    syncer.sync_once()
    assert "d" in store.all()  # row kept: a real file survives in the dir
    assert (local_dir / "d").exists()
    assert "d/keep.md" in fake.files  # the real file was uploaded, not lost
    store.close()


def test_rmdir_local_defers_on_ignored_subdir_with_real_data(make_syncer, fake, local_dir):
    """P1-3 (review F1): an engine-ignored SUBDIR (.Trash) can hide real untracked files,
    so rmdir_local must NOT sweep the dir into the soft-delete trash on a name match —
    a subdirectory is opaque, so defer instead."""
    syncer, store = make_syncer()
    write_file(local_dir, "repo/keep.md", b"x", mtime=1000.0)
    syncer.sync_once()

    fake.delete("repo")
    (local_dir / "repo" / "keep.md").unlink()
    (local_dir / "repo" / ".Trash").mkdir()  # ignored subdir...
    (local_dir / "repo" / ".Trash" / "real.md").write_bytes(b"precious")  # ...with real data

    syncer.sync_once()
    assert (local_dir / "repo" / ".Trash" / "real.md").read_bytes() == b"precious"  # NOT swept
    assert (local_dir / "repo").exists()  # deferred, not trashed
    store.close()


# --- Phase C Batch 6: filename identity (NFC/NFD, casefold) ----------------------


def test_nfd_local_nfc_remote_is_one_identity(make_syncer, fake, local_dir):
    """P1-2: a local file stored decomposed (NFD) and the same remote name composed (NFC)
    are ONE identity — no phantom create+delete, no deletion of the accented file."""
    name_nfc = unicodedata.normalize("NFC", "Anotações.md")
    name_nfd = unicodedata.normalize("NFD", "Anotações.md")
    assert name_nfc != name_nfd  # the bytes really differ

    syncer, store = make_syncer()
    write_file(local_dir, name_nfd, b"data", mtime=1000.0)  # local on disk: NFD
    fake.put(name_nfc, b"data", mtime=1000.0)  # remote: NFC, same bytes
    from ifolder_sync.state import BaselineEntry

    store.upsert(BaselineEntry(name_nfc, "file", 4, 1000.0, 4, 1000.0, ""))
    store.commit()

    s = syncer.sync_once()
    assert s.deleted_local == 0 and s.deleted_remote == 0, s.summary()  # no phantom delete
    assert s.uploaded == 0 and s.downloaded == 0, s.summary()  # recognized as identical
    assert list(fake.files) == [name_nfc]  # no NFD duplicate created remotely
    store.close()


def test_case_collision_is_skipped_not_clobbered(make_syncer, fake, local_dir):
    """P1-2: local `note.md` vs remote `Note.md` (differ only by case) is a collision the
    engine refuses to guess — skip both, warn, count; never clobber the local original."""
    syncer, store = make_syncer()
    write_file(local_dir, "note.md", b"local", mtime=1000.0)
    fake.put("Note.md", b"remote", mtime=2000.0)

    s = syncer.sync_once()
    assert s.errors >= 1, s.summary()  # collision surfaced
    assert (local_dir / "note.md").read_bytes() == b"local"  # local original untouched
    assert fake.files["Note.md"]["content"] == b"remote"  # remote untouched
    assert "note.md" not in store.all() and "Note.md" not in store.all()  # neither recorded
    store.close()


def test_case_rename_baseline_ghost_resolves_not_freezes(make_syncer, fake, local_dir):
    """P1-2 regression: after a case-only rename on case-insensitive APFS (`note.md`->`Note.md`),
    the OLD name survives only as a baseline ghost while local carries the NEW name. The collision
    guard must NOT freeze on a baseline-only ghost (which would stall the upload and leave the ghost
    forever, errors>0 every pass); only a collision between >=2 LIVE (local/remote) variants is
    unresolvable. The live `Note.md` uploads; the ghost `note.md` resolves as DROP_BASELINE."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer()
    write_file(local_dir, "Note.md", b"data", mtime=1000.0)  # live local, new case
    store.upsert(BaselineEntry("note.md", "file", 4, 1000.0, 4, 1000.0, ""))  # ghost, old case
    store.commit()

    s = syncer.sync_once()
    assert s.errors == 0, s.summary()  # not frozen as an eternal collision
    assert fake.files["Note.md"]["content"] == b"data"  # live variant uploaded
    rows = store.all()
    assert "Note.md" in rows and "note.md" not in rows  # ghost dropped, real recorded
    store.close()


def test_vault_marker_hard_ignore_is_case_insensitive(make_syncer, fake, local_dir):
    """P1-2: a remote `.IFOLDER-SYNC-VAULT` (any case) is hard-ignored, so it can never be
    downloaded and clobber the local `.ifolder-sync-vault` identity marker."""
    syncer, store = make_syncer()
    write_file(local_dir, "real.md", b"x", mtime=1000.0)
    fake.put(".IFOLDER-SYNC-VAULT", b'{"uuid":"evil"}', mtime=1000.0)

    syncer.sync_once()
    assert "real.md" in fake.files
    # On case-insensitive APFS the evil remote would clobber the real marker IF synced.
    # The hard-ignore must keep it out, so the local marker keeps its real UUID.
    assert read_vault_marker(local_dir) != "evil"
    assert ".IFOLDER-SYNC-VAULT" not in store.all()  # never recorded/synced
    store.close()


def test_baseline_nfc_migration_rekeys_legacy_rows(make_syncer, fake, local_dir):
    """P1-2: a legacy baseline row stored under an NFD key is re-keyed to NFC on the first
    pass (so it matches the NFC scan and does not read as delete + re-create)."""
    from ifolder_sync.state import BaselineEntry

    name_nfc = unicodedata.normalize("NFC", "Café.md")
    name_nfd = unicodedata.normalize("NFD", "Café.md")
    syncer, store = make_syncer()
    store.upsert(BaselineEntry(name_nfd, "file", 4, 1000.0, 4, 1000.0, ""))  # legacy NFD row
    store.commit()
    assert name_nfd in store.all()

    write_file(local_dir, name_nfd, b"data", mtime=1000.0)
    fake.put(name_nfc, b"data", mtime=1000.0)
    s = syncer.sync_once()

    rows = store.all()
    assert name_nfc in rows and name_nfd not in rows  # migrated to NFC
    assert s.deleted_local == 0 and s.deleted_remote == 0, s.summary()
    assert store.get_meta("nfc_migrated") == "1"
    store.close()


def test_ignore_change_defers_deletions_one_pass(make_syncer, fake, local_dir):
    """F-P1-14: when the effective ignore set changed since the last pass, deletions are
    deferred for one pass (so an ignore edit that coincides with apparent deletions can
    never propagate them blindly — the rclone-bisync 'filters changed' safeguard)."""
    syncer, store = make_syncer(ignore=[".DS_Store"])
    write_file(local_dir, "keep.md", b"x", mtime=1000.0)
    write_file(local_dir, "gone.md", b"y", mtime=1000.0)
    syncer.sync_once()  # records the ignore_hash; uploads both
    assert "gone.md" in fake.files
    assert syncer._ignore_changed(dry_run=True) is False  # stable -> no trip

    (local_dir / "gone.md").unlink()  # a real local deletion...
    syncer.ignore_patterns = [".DS_Store", "tmp-*"]  # ...coinciding with an ignore edit
    s = syncer.sync_once()
    assert s.deferred_deletes >= 1, s.summary()
    assert "gone.md" in fake.files  # deletion deferred this pass, not propagated
    store.close()


def test_client_child_resolves_nfd_remote_by_nfc_key():
    """Batch 6 H1: navigating by an NFC key resolves a remote node stored NFD (placed by
    Apple's native client), so a remote NFD file never reads as a phantom deletion or
    spawns a duplicate."""
    from ifolder_sync.icloud_client import ICloudClient

    nfd = unicodedata.normalize("NFD", "Café.md")
    nfc = unicodedata.normalize("NFC", "Café.md")
    assert nfd != nfc
    child = _FakeNode(nfd, "file", size=3)

    class _Parent:
        def __getitem__(self, name):
            if name == nfd:
                return child
            raise KeyError(name)  # exact NFC lookup misses the NFD node

        def get_children(self):
            return [child]

    assert ICloudClient._child(_Parent(), nfc) is child  # NFC-insensitive fallback


def test_normalize_unicode_opt_out_uses_raw_keys(make_syncer):
    """Batch 6 M1: the config opt-out (and a normalization-sensitive volume) fall back to
    raw identity keys — no NFC folding."""
    nfd = unicodedata.normalize("NFD", "Café.md")
    syncer_off, store_off = make_syncer(normalize_unicode=False)
    assert syncer_off._normalize_active() is False
    assert syncer_off._ident(nfd) == nfd  # unchanged
    store_off.close()

    syncer_on, store_on = make_syncer()  # default on; tmp_path is APFS (insensitive)
    assert syncer_on._normalize_active() is True
    assert syncer_on._ident(nfd) == unicodedata.normalize("NFC", nfd)
    store_on.close()


def test_part_exact_case_marker_case_insensitive(make_syncer):
    """Batch 6 L1: `*.part` hard-ignore stays exact-case (a real `gearbox.PART` syncs),
    while the vault marker is matched case-insensitively (anti-clobber)."""
    syncer, store = make_syncer()
    assert syncer._ignored("gearbox.PART") is False  # real user file, not the engine temp
    assert syncer._ignored("download.part") is True  # engine temp
    assert syncer._ignored(".IFOLDER-SYNC-VAULT") is True  # marker, any case
    assert syncer._ignored(".ifolder-sync-vault") is True
    store.close()


def test_migration_collision_drops_both(make_syncer):
    """Batch 6 M2: when a legacy NFD row and an NFC row both exist for one path, the
    migration drops BOTH and lets the next pass re-derive (verify_adopt) rather than keep
    a possibly-stale signature."""
    from ifolder_sync.state import BaselineEntry

    nfd = unicodedata.normalize("NFD", "Café.md")
    nfc = unicodedata.normalize("NFC", "Café.md")
    syncer, store = make_syncer()
    store.upsert(BaselineEntry(nfd, "file", 1, 1.0, 1, 1.0, "old"))
    store.upsert(BaselineEntry(nfc, "file", 2, 2.0, 2, 2.0, "new"))
    store.commit()

    migrated = syncer._migrate_baseline_nfc(store.all(), dry_run=False)
    assert nfd not in migrated and nfc not in migrated  # both dropped
    assert nfd not in store.all() and nfc not in store.all()
    store.close()


def test_persistent_partial_download_failure_backs_off(make_syncer, fake, local_dir):
    """A genuine PARTIAL read (0<got<N: a dropped stream, not publish-before-content lag)
    raises a plain transient OSError and must back off after DOWNLOAD_MAX_FAILS, not retry
    every pass forever (which hammers Apple + spams the log + churns a .part that re-triggers
    the watcher). This is the unchanged broken-blob class; got==0 is handled separately."""
    from ifolder_sync.state import BaselineEntry
    from ifolder_sync.syncer import DOWNLOAD_MAX_FAILS

    syncer, store = make_syncer()
    fake.put("broken.md", b"AAAA", mtime=2000.0)  # remote mtime != baseline -> decides download
    write_file(local_dir, "broken.md", b"AAAA", mtime=1000.0)
    store.upsert(BaselineEntry("broken.md", "file", 4, 1000.0, 4, 1000.0, ""))
    store.commit()

    attempts = {"n": 0}
    real_dl = fake.download

    def boom(relpath, dest):
        if relpath == "broken.md":
            attempts["n"] += 1
            raise OSError("download size mismatch: got 2 bytes, expected 4")  # partial read
        return real_dl(relpath, dest)

    fake.download = boom
    for _ in range(6):
        syncer.sync_once()

    # Attempts are bounded to DOWNLOAD_MAX_FAILS, not one per pass.
    assert attempts["n"] == DOWNLOAD_MAX_FAILS, attempts["n"]
    assert (local_dir / "broken.md").read_bytes() == b"AAAA"  # local untouched, no data loss
    store.close()


def test_unreadable_download_defers_not_backs_off(make_syncer, fake, local_dir):
    """The got==0 (publish-before-content) class is NOT a broken-blob backoff: it defers
    silently every pass (UnreadableRemoteError -> stats.pending), leaving the baseline and
    local file untouched, never reaching stats.errors. (The companion of the partial-read
    backoff test above; together they cover both halves of the old got!=expected branch.)"""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer()
    fake.put_unreadable("lag.md", size=4, mtime=2000.0)  # listed size 4, body 0 bytes
    write_file(local_dir, "lag.md", b"AAAA", mtime=1000.0)
    store.upsert(BaselineEntry("lag.md", "file", 4, 1000.0, 4, 1000.0, ""))
    store.commit()

    for _ in range(6):
        s = syncer.sync_once()
        assert s.errors == 0, s.summary()
        assert s.pending >= 1, s.summary()

    assert (local_dir / "lag.md").read_bytes() == b"AAAA"  # local untouched
    store.close()


def test_conflict_backup_failure_aborts_and_retries(make_syncer, fake, local_dir):
    """A conflict whose remote loser cannot be backed up for a NON-lag reason (a real,
    non-zero-byte download error) must abort-and-retry every pass — NEVER upload the good
    local copy over the unbacked-up remote loser (the removed resolve-without-backup clobber).
    The remote stays in place until the backup succeeds."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer("newer")
    write_file(local_dir, "n.md", b"GOOD-LOCAL", mtime=5000.0)
    fake.put("n.md", b"REMOTE-V", mtime=2000.0)
    store.upsert(BaselineEntry("n.md", "file", 3, 1.0, 3, 1.0, ""))  # both sides differ -> conflict
    store.commit()

    real_dl = fake.download

    def boom(relpath, dest):  # a genuine (non-lag) backup failure on every attempt
        if relpath == "n.md":
            raise OSError("transient backup read error")
        return real_dl(relpath, dest)

    fake.download = boom
    for _ in range(6):
        syncer.sync_once()

    # No clobber: the remote loser is never uploaded over without a saved backup.
    assert fake.files["n.md"]["content"] == b"REMOTE-V", "remote must not be clobbered"
    assert fake.calls["upload"] == 0, "local must not be uploaded over an unbacked-up remote"
    assert (local_dir / "n.md").read_bytes() == b"GOOD-LOCAL"  # local intact
    store.close()


def test_unreadable_remote_download_defers_silently(make_syncer, fake, local_dir, caplog):
    """Publish-before-content lag on a DOWNLOAD-only path (remote edited, local unchanged):
    several passes defer silently (errors=0, pending>=1, no 'error reconciling', baseline row
    unchanged, local untouched). Once the blob materializes it downloads, records both
    signatures, and the next pass is fully clean."""
    import logging

    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer()
    write_file(local_dir, "data.json", b"LOCAL", mtime=1000.0)  # local == baseline (unchanged)
    store.upsert(BaselineEntry("data.json", "file", 5, 1000.0, 5, 1000.0, "e0"))
    store.commit()
    # Remote rewritten (new size/mtime/etag) but the body has not materialized yet.
    fake.put_unreadable("data.json", size=7, mtime=2000.0, etag="e1")

    with caplog.at_level(logging.DEBUG, logger="ifolder-sync.syncer"):
        for _ in range(4):
            s = syncer.sync_once()
            assert s.errors == 0, s.summary()
            assert s.pending >= 1, s.summary()
            assert s.downloaded == 0, s.summary()
            base = store.all()["data.json"]
            assert (base.remote_size, base.remote_mtime) == (5, 1000.0)  # row UNCHANGED
            assert (local_dir / "data.json").read_bytes() == b"LOCAL"  # local untouched

    assert "error reconciling" not in caplog.text

    # Blob materializes with the real content.
    fake.put("data.json", b"NEWBODY", mtime=2000.0, etag="e1")
    s = syncer.sync_once()
    assert s.downloaded == 1 and s.errors == 0 and s.pending == 0, s.summary()
    assert (local_dir / "data.json").read_bytes() == b"NEWBODY"
    base = store.all()["data.json"]
    assert base.remote_size == 7 and base.remote_etag == "e1"

    s = syncer.sync_once()  # fully clean steady state
    from ifolder_sync.syncer import SyncStats

    assert s.summary() == SyncStats().summary(), s.summary()
    store.close()


def test_unreadable_remote_conflict_never_clobbers(make_syncer, fake, local_dir, caplog):
    """Both sides changed, local newer, policy=newer, remote unreadable (publish-before-
    content). Several passes: conflicts=0, errors=0, pending>=1, NO upload, remote NOT
    trashed, local intact. Then the remote materializes with DIFFERENT bytes -> a REAL
    conflict resolves WITH a backup (the iPhone content is preserved as a conflict copy)."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer("newer")
    write_file(local_dir, "n.md", b"LOCAL-NEW", mtime=5000.0)  # local newer
    store.upsert(BaselineEntry("n.md", "file", 3, 1.0, 3, 1.0, "e0"))  # both sides differ
    store.commit()
    fake.put_unreadable("n.md", size=8, mtime=2000.0, etag="e1")

    for _ in range(4):
        s = syncer.sync_once()
        assert s.conflicts == 0, s.summary()
        assert s.errors == 0, s.summary()
        assert s.pending >= 1, s.summary()
        assert fake.calls["upload"] == 0, "no upload while remote unreadable"
        assert "n.md" in fake.files, "remote must not be trashed"
        assert (local_dir / "n.md").read_bytes() == b"LOCAL-NEW"  # local intact
        assert not list(local_dir.glob("n.conflict-*.md")), "no premature backup"

    # The iPhone's edit finally materializes with DIFFERENT bytes -> a genuine conflict.
    fake.put("n.md", b"IPHONE-X", mtime=2000.0, etag="e1")
    s = syncer.sync_once()
    assert s.conflicts == 1, s.summary()
    backups = list(local_dir.glob("n.conflict-*.md"))
    assert backups, "the remote loser must be preserved as a backup, never silently dropped"
    assert backups[0].read_bytes() == b"IPHONE-X"  # iPhone content preserved
    assert fake.files["n.md"]["content"] == b"LOCAL-NEW"  # newer (local) won
    store.close()


def test_partial_download_still_transient():
    """A genuine partial read (0<got<N) stays a plain transient OSError — NOT reclassified
    as UnreadableRemoteError — so real truncation keeps its retry + .part-discard semantics."""
    from unittest.mock import patch

    from ifolder_sync.errors import UnreadableRemoteError
    from ifolder_sync.icloud_client import ICloudClient

    client = ICloudClient("x@y.com", max_retries=1)

    class _Resp:
        def __init__(self, data):
            self.raw = io.BytesIO(data)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Node:
        size = 4
        name = "f"

        def open(self, stream=True):
            return _Resp(b"AB")  # got=2 of expected 4 -> partial

    with (
        patch.object(client, "_navigate", return_value=(_Node(), "f")),
        patch.object(client, "_child", return_value=_Node()),
    ):
        dest = Path(os.environ.get("TMPDIR", "/tmp")) / "ifolder-partial-probe"
        try:
            with pytest.raises(OSError) as ei:
                client.download("f", dest)
        finally:
            for p in (dest, Path(str(dest) + ".part")):
                try:
                    p.unlink()
                except OSError:
                    pass
    assert not isinstance(ei.value, UnreadableRemoteError), "partial read must stay plain OSError"


def test_unreadable_got_zero_raises_typed():
    """A got==0 body (the empirically-confirmed publish-before-content shape) raises the
    typed UnreadableRemoteError from the real download() path (proves the fake mirrors it)."""
    from unittest.mock import patch

    from ifolder_sync.errors import UnreadableRemoteError
    from ifolder_sync.icloud_client import ICloudClient

    client = ICloudClient("x@y.com", max_retries=1)

    class _Resp:
        def __init__(self, data):
            self.raw = io.BytesIO(data)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Node:
        size = 4
        name = "f"

        def open(self, stream=True):
            return _Resp(b"")  # got=0 of expected 4 -> publish-before-content

    with (
        patch.object(client, "_navigate", return_value=(_Node(), "f")),
        patch.object(client, "_child", return_value=_Node()),
    ):
        dest = Path(os.environ.get("TMPDIR", "/tmp")) / "ifolder-gotzero-probe"
        try:
            with pytest.raises(UnreadableRemoteError):
                client.download("f", dest)
        finally:
            for p in (dest, Path(str(dest) + ".part")):
                try:
                    p.unlink()
                except OSError:
                    pass


def test_unreadable_sustained_escalates_one_warning(make_syncer, fake, local_dir, caplog):
    """A permanently-unreadable remote (same signature every pass) defers silently until the
    sustained window elapses, then emits EXACTLY ONE 'likely genuine corruption' warning,
    with stats.errors==0 throughout."""
    import logging

    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer(unreadable_max_passes=3)
    write_file(local_dir, "x.json", b"LOCAL", mtime=1000.0)  # local unchanged -> DOWNLOAD
    store.upsert(BaselineEntry("x.json", "file", 5, 1000.0, 5, 1000.0, "e0"))
    store.commit()
    fake.put_unreadable("x.json", size=9, mtime=2000.0, etag="e1")  # fixed signature

    with caplog.at_level(logging.WARNING, logger="ifolder-sync.syncer"):
        for _ in range(8):  # well past the 3-pass window
            s = syncer.sync_once()
            assert s.errors == 0, s.summary()

    corruption_warnings = [r for r in caplog.records if "likely genuine corruption" in r.message]
    assert len(corruption_warnings) == 1, [r.message for r in corruption_warnings]
    store.close()


def test_unreadable_fast_churn_no_false_corruption(make_syncer, fake, local_dir, caplog):
    """The real scenario: an actively-edited remote (signature changes EVERY pass) that keeps
    hitting a fresh 0-byte window must NOT false-escalate to 'corruption' — the per-signature
    timer resets on each change, so the sustained-corruption warning never fires."""
    import logging

    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer(unreadable_max_passes=3)
    write_file(local_dir, "churn.json", b"LOCAL", mtime=1000.0)  # local unchanged -> DOWNLOAD
    store.upsert(BaselineEntry("churn.json", "file", 5, 1000.0, 5, 1000.0, "e0"))
    store.commit()

    with caplog.at_level(logging.WARNING, logger="ifolder-sync.syncer"):
        for i in range(8):  # each pass a fresh edit (new mtime+etag), still 0-byte body
            fake.put_unreadable("churn.json", size=9, mtime=2000.0 + i, etag=f"e{i}")
            s = syncer.sync_once()
            assert s.errors == 0 and s.pending >= 1, s.summary()

    assert not any("likely genuine corruption" in r.message for r in caplog.records), caplog.text
    store.close()


def test_normalization_downgrade_defers_deletes_persistently(
    make_syncer, fake, local_dir, monkeypatch
):
    """Batch 6 W1: a baseline NFC-migrated on an insensitive volume, then run on a volume
    that reports raw names, defers deletions on EVERY pass (not one-shot) so accented
    files are never phantom-deleted while the state is inconsistent."""
    syncer, store = make_syncer()
    write_file(local_dir, "keep.md", b"x", mtime=1000.0)
    syncer.sync_once()  # normalize active; sets nfc_migrated
    assert store.get_meta("nfc_migrated") == "1"

    # The vault volume now reports as normalization-sensitive.
    monkeypatch.setattr(syncer, "_probe_nfc_insensitive", lambda: False)
    syncer._nfc_active = None  # force a re-probe
    assert syncer._normalization_downgraded() is True

    (local_dir / "keep.md").unlink()  # a real deletion
    s1 = syncer.sync_once()
    assert s1.deferred_deletes >= 1 and "keep.md" in fake.files  # deferred, not applied
    s2 = syncer.sync_once()
    assert s2.deferred_deletes >= 1 and "keep.md" in fake.files  # STILL deferred (persistent)
    store.close()


def test_remote_edit_husk_does_not_truncate_local(make_syncer, fake, local_dir):
    """P1-10: when a baseline-known remote file briefly drops to 0 bytes (an edit
    publishing its record before content), the local file is NOT truncated."""
    from ifolder_sync.state import BaselineEntry

    syncer, store = make_syncer()
    write_file(local_dir, "n.md", b"LOCALDATA", mtime=1000.0)
    fake.put("n.md", b"REMOTEDATA", mtime=1000.0)
    store.upsert(BaselineEntry("n.md", "file", 9, 1000.0, 10, 1000.0, ""))
    store.commit()

    # Remote edit publishes a 0-byte husk (content still uploading from device B).
    fake.put("n.md", b"", mtime=1001.0)
    s = syncer.sync_once()
    assert s.downloaded == 0, s.summary()  # husk not downloaded
    assert (local_dir / "n.md").read_bytes() == b"LOCALDATA"  # local intact
    store.close()


def test_kind_conflict_file_vs_dir_is_skipped(make_syncer, fake, local_dir):
    """P1-9: a path that is a file locally but a directory remotely (or vice versa) is
    warned + counted + skipped (with its subtree), never silently mis-synced or deleted."""
    syncer, store = make_syncer()
    write_file(local_dir, "x", b"i am a file", mtime=1000.0)  # local: file 'x'
    fake.mkdir("x")  # remote: dir 'x'
    fake.put("x/inside.md", b"child", mtime=1000.0)

    s = syncer.sync_once()
    assert s.errors >= 1, s.summary()  # kind conflict surfaced
    assert (local_dir / "x").read_bytes() == b"i am a file"  # local file untouched
    assert "x" in fake.files and fake.files["x"]["kind"] == "dir"  # remote dir untouched
    assert "x" not in store.all()  # nothing recorded for the conflicted path
    store.close()


# ============================================ P5-2 threshold-pct + drift escalation ===
def test_delete_threshold_pct_branch_suppresses(make_syncer, fake, local_dir):
    """The PCT branch (distinct from the count branch): a deletion count BELOW the count
    threshold but ABOVE the fraction-of-tracked threshold suppresses all deletes."""
    syncer, store = make_syncer(delete_threshold_pct=10, delete_threshold_count=1000)
    for name in ("a.txt", "b.txt", "c.txt", "d.txt"):
        write_file(local_dir, name, b"x", mtime=1000)
    syncer.sync_once()  # baseline: 4 files on both sides

    (local_dir / "a.txt").unlink()
    (local_dir / "b.txt").unlink()  # delete 2/4 = 50% > 10% pct, but 2 < 1000 count
    s = syncer.sync_once()

    assert s.skipped_deletes == 2, s.summary()
    assert s.deleted_remote == 0, s.summary()
    assert "a.txt" in fake.files and "b.txt" in fake.files  # remote intact
    store.close()


def _make_daemon(tmp_path, monkeypatch):
    from ifolder_sync.daemon import Daemon

    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    return Daemon(Config.load(config_path("work")), "work")


def test_track_drift_escalates_after_three_trips(tmp_path, monkeypatch):
    from ifolder_sync.syncer import SyncStats

    d = _make_daemon(tmp_path, monkeypatch)
    d._apply_passes = 5  # past startup, so no DRIFT-SUSPECTED special-casing
    assert d._backoff is None
    for _ in range(2):
        d._track_drift(SyncStats(skipped_deletes=1))
        assert d._backoff is None  # not yet escalated
    d._track_drift(SyncStats(skipped_deletes=1))  # 3rd consecutive trip
    assert d._trips == 3
    assert d._backoff is not None and d._backoff > 0
    d.store.close()


def test_track_drift_resets_on_clean_pass(tmp_path, monkeypatch):
    from ifolder_sync.syncer import SyncStats

    d = _make_daemon(tmp_path, monkeypatch)
    d._apply_passes = 5
    for _ in range(3):
        d._track_drift(SyncStats(skipped_deletes=1))
    assert d._backoff is not None
    d._track_drift(SyncStats())  # a clean pass restores the normal interval
    assert d._trips == 0
    assert d._backoff is None
    d.store.close()


def test_track_drift_flags_drift_suspected_at_startup(tmp_path, monkeypatch):
    from ifolder_sync.syncer import SyncStats

    d = _make_daemon(tmp_path, monkeypatch)
    d._apply_passes = 1  # the first applying pass: a suppression here is a startup red flag
    d._track_drift(SyncStats(skipped_deletes=2))
    assert "DRIFT SUSPECTED" in (d.store.get_meta("last_error") or "")
    d.store.close()
