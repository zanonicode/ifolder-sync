"""Sync-drift hardening guards: local walk guard, vault identity marker, bootstrap
additive pass, .part hard-ignore, daemon preflight, and the rebaseline command.

The destructive scenarios assert the invariant that matters: an unreliable local
snapshot must abort the pass with ZERO deletions on either side.
"""

from __future__ import annotations

import os
import shutil

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
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    lock_path("work").write_text(str(os.getpid()))  # a live daemon holds the lock

    with pytest.raises(SystemExit):
        main(["sync", "--profile", "work"])
    assert "daemon is running" in capsys.readouterr().err


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
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    lock_path("work").write_text(str(os.getpid()))  # a live pid holds the lock

    with pytest.raises(SystemExit):
        main(["rebaseline", "--profile", "work"])
    assert baseline_path("work").parent.exists()


# --------------------------------------------------- plist: no-crash-loop keys ---
def test_plist_has_no_crash_loop_keys(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    body = cli._write_agent_plist("work").read_text()
    assert "<key>SuccessfulExit</key>" in body
    assert "<key>ThrottleInterval</key>" in body
