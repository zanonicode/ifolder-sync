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
