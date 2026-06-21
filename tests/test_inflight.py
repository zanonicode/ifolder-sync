"""Live in-flight surface (feature 04 Phase 2): the engine emits, the atomic status.json
flush, and the observer's stale-snapshot gating.

The load-bearing safety property — with on_event=None the engine is OUTCOME-identical (no
observable side effect, no extra IO) — is pinned directly here (test_no_observer_is_inert)
and backstopped by the whole existing suite passing. A throwing observer is proven unable to
break or distort a pass. Emit-on-error and emit-on-pending-unreadable are driven through real
failing/unreadable transfers, not hand-built rows.
"""

from __future__ import annotations

import json
import shutil

from ifolder_sync.cli import _dashboard_view, _read_status_snapshot, cmd_sync
from ifolder_sync.config import Config, baseline_path, config_path, status_path
from ifolder_sync.inflight import InflightSurface
from ifolder_sync.state import StateStore
from ifolder_sync.syncer import Op, Syncer
from ifolder_sync.syncstate import SyncEvent, SyncRow

from .helpers import FAR, PERMISSIVE_THRESHOLDS, FakeICloud, sandbox_home, write_file


def _syncer_with_observer(tmp_path, fake, local_dir, events):
    cfg = Config(apple_id="x@y.com", local_folder=str(local_dir), **PERMISSIVE_THRESHOLDS)
    store = StateStore(tmp_path / "s.sqlite3")
    syncer = Syncer(cfg, fake, store, trash_dir=tmp_path / "trash", on_event=events.append)
    return syncer, store


def test_engine_emits_uploading_then_done(tmp_path, fake, local_dir):
    events: list = []
    syncer, store = _syncer_with_observer(tmp_path, fake, local_dir, events)
    write_file(local_dir, "a.txt", b"hi", mtime=1000)

    syncer.sync_once()

    seq = [(e.relpath, e.state) for e in events if e.relpath == "a.txt"]
    assert ("a.txt", "uploading") in seq
    assert ("a.txt", "done") in seq
    assert seq.index(("a.txt", "uploading")) < seq.index(("a.txt", "done"))
    store.close()


def test_engine_emits_downloading_then_done(tmp_path, fake, local_dir):
    events: list = []
    syncer, store = _syncer_with_observer(tmp_path, fake, local_dir, events)
    fake.put("b.txt", b"remote-body", mtime=2000)

    syncer.sync_once()

    seq = [(e.relpath, e.state) for e in events if e.relpath == "b.txt"]
    assert ("b.txt", "downloading") in seq and ("b.txt", "done") in seq
    store.close()


def test_engine_emits_carry_pass_id_and_op(tmp_path, fake, local_dir):
    events: list = []
    syncer, store = _syncer_with_observer(tmp_path, fake, local_dir, events)
    write_file(local_dir, "a.txt", b"hi", mtime=1000)
    syncer.sync_once()  # pass 1
    write_file(local_dir, "a.txt", b"hi-v2", mtime=20000)
    syncer.sync_once()  # pass 2

    up = [e for e in events if e.state == "uploading"]
    assert up[0].pass_id == 1 and up[-1].pass_id == 2
    assert all(e.op == Op.UPLOAD for e in up)
    store.close()


def test_engine_emits_queue_for_all_pending_transfers(tmp_path, fake, local_dir):
    """The whole pending file queue is announced up front (queued), before the serial engine
    starts the first transfer — so the dashboard shows what's coming, not just the current file."""
    events: list = []
    syncer, store = _syncer_with_observer(tmp_path, fake, local_dir, events)
    for name in ("a.md", "b.md", "c.md"):
        write_file(local_dir, name, name.encode(), mtime=1000)

    syncer.sync_once()

    queued = [e.relpath for e in events if e.state == "queued"]
    assert set(queued) == {"a.md", "b.md", "c.md"}  # the full queue
    first_queued = next(i for i, e in enumerate(events) if e.state == "queued")
    first_upload = next(i for i, e in enumerate(events) if e.state == "uploading")
    assert first_queued < first_upload  # queue announced before the first transfer starts
    store.close()


def test_surface_queued_is_throttled_active_forces(tmp_path):
    """'queued' coalesces (so enqueuing hundreds is a few writes); the first ACTIVE announce
    force-flushes and reveals the accumulated queue + the in-flight row."""
    surf = InflightSurface(tmp_path / "status.json", min_write_interval_ms=10_000)
    surf.pass_started()

    surf.record(SyncEvent(1.0, 1, "a.md", Op.UPLOAD, "queued", "file"))  # throttled
    surf.record(SyncEvent(1.0, 1, "b.md", Op.UPLOAD, "queued", "file"))  # throttled
    assert json.loads((tmp_path / "status.json").read_text())["rows"] == []  # coalesced

    surf.record(SyncEvent(2.0, 1, "a.md", Op.UPLOAD, "uploading", "file"))  # active -> force
    rows = json.loads((tmp_path / "status.json").read_text())["rows"]
    assert {r["relpath"] for r in rows} == {"a.md", "b.md"}  # whole queue revealed


def test_surface_record_upsert_and_done_removes(tmp_path):
    surf = InflightSurface(tmp_path / "status.json", min_write_interval_ms=0)
    surf.pass_started(pid=123, last_sync=None, last_stats=None, last_error=None)

    surf.record(SyncEvent(1.0, 1, "a.txt", Op.UPLOAD, "uploading", "file", bytes=10))
    data = json.loads((tmp_path / "status.json").read_text())
    assert data["schema"] == 1 and data["pid"] == 123
    assert [r["relpath"] for r in data["rows"]] == ["a.txt"]
    assert data["rows"][0]["state"] == "uploading" and data["rows"][0]["op"] == "upload"

    surf.record(SyncEvent(2.0, 1, "a.txt", Op.UPLOAD, "done", "file"))
    data = json.loads((tmp_path / "status.json").read_text())
    assert data["rows"] == []  # 'done' makes it vanish from the live list


def test_surface_pass_finished_rebuilds_to_stuck_set(tmp_path):
    surf = InflightSurface(tmp_path / "status.json", min_write_interval_ms=0)
    surf.pass_started()
    surf.record(SyncEvent(1.0, 1, "a.txt", Op.UPLOAD, "uploading", "file"))  # transient

    surf.pass_finished([SyncRow("h.md", "pending-unreadable", passes_stuck=5)], pid=1)

    data = json.loads((tmp_path / "status.json").read_text())
    assert [r["relpath"] for r in data["rows"]] == ["h.md"]  # transient cleared, stuck kept
    assert data["rows"][0]["state"] == "pending-unreadable"


def test_surface_announce_flushes_immediately_done_is_throttled(tmp_path):
    """An in-flight ANNOUNCE must reach status.json immediately even within the throttle window
    (the engine blocks on the IO right after, so a throttled announce would be invisible while
    the transfer runs). A 'done' removal stays throttled (coalesced)."""
    surf = InflightSurface(tmp_path / "status.json", min_write_interval_ms=10_000)
    surf.pass_started()  # forced flush writes the empty frame

    surf.record(SyncEvent(1.0, 1, "a.txt", Op.UPLOAD, "uploading", "file"))  # within the window
    data = json.loads((tmp_path / "status.json").read_text())
    assert [r["relpath"] for r in data["rows"]] == ["a.txt"]  # shown immediately, not coalesced

    surf.record(SyncEvent(2.0, 1, "a.txt", Op.UPLOAD, "done", "file"))  # throttled removal
    data = json.loads((tmp_path / "status.json").read_text())
    assert [r["relpath"] for r in data["rows"]] == ["a.txt"]  # lingers (done flush coalesced)


def test_read_status_snapshot_validates(tmp_path, monkeypatch):
    from .helpers import sandbox_home

    sandbox_home(tmp_path, monkeypatch)
    assert _read_status_snapshot("default") is None  # missing
    status_path("default").write_text(json.dumps({"schema": 1, "rows": [], "pid": 9}))
    assert _read_status_snapshot("default")["pid"] == 9
    status_path("default").write_text("{not json")
    assert _read_status_snapshot("default") is None  # corrupt
    status_path("default").write_text(json.dumps({"schema": 999, "rows": []}))
    assert _read_status_snapshot("default") is None  # wrong schema version


def test_dashboard_view_uses_snapshot_only_when_running(tmp_path, monkeypatch):
    from .helpers import sandbox_home

    sandbox_home(tmp_path, monkeypatch)
    with StateStore(baseline_path("default")) as s:
        s.set_meta("last_sync", "1.0")
    status_path("default").write_text(
        json.dumps(
            {
                "schema": 1,
                "pid": 7,
                "last_sync": 2.0,
                "rows": [{"relpath": "x.md", "state": "uploading", "op": "upload"}],
            }
        )
    )

    # daemon NOT running -> the stale snapshot's in-flight row must be ignored
    view = _dashboard_view("default")
    assert view["attention"] == []

    # daemon running -> the live in-flight row is shown
    monkeypatch.setattr("ifolder_sync.cli.holder_pid", lambda _p: 7)
    view = _dashboard_view("default")
    assert [r.relpath for r in view["attention"]] == ["x.md"]
    assert view["attention"][0].state == "uploading"


def test_daemon_inflight_helpers_write_status(tmp_path, monkeypatch, fake):
    from .helpers import sandbox_home

    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "ifolder_sync.icloud_client.ICloudClient.from_config",
        classmethod(lambda cls, c: fake),
    )
    from ifolder_sync.daemon import Daemon

    cfg = Config(apple_id="x@y.com", local_folder=str(tmp_path / "v"))
    d = Daemon(cfg, "default")
    d.store.set_meta("last_sync", "5.0")
    d.store.set_meta("settle_counts", json.dumps({"a.md": 4}))

    d._inflight_pass_started()
    d._inflight_pass_finished()

    data = json.loads(status_path("default").read_text())
    assert data["pid"] and data["last_sync"] == "5.0"
    assert [r["relpath"] for r in data["rows"]] == ["a.md"]  # stuck set rebuilt at pass end
    d.store.close()


def test_disabled_surface_writes_nothing(tmp_path, monkeypatch, fake):
    from .helpers import sandbox_home

    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "ifolder_sync.icloud_client.ICloudClient.from_config",
        classmethod(lambda cls, c: fake),
    )
    from ifolder_sync.daemon import Daemon

    cfg = Config(apple_id="x@y.com", local_folder=str(tmp_path / "v"), inflight_surface=False)
    d = Daemon(cfg, "default")
    assert d.inflight is None  # producer-side fully disabled
    d._inflight_pass_started()
    d._inflight_pass_finished()
    assert not status_path("default").exists()  # nothing written
    d.store.close()


def test_cmd_sync_feeds_inflight_surface(tmp_path, monkeypatch, fake):
    """A foreground `sync` (not just the daemon) emits live status.json rows stamped with its
    OWN pid, so `status --watch` shows a manual sync's progress instead of an empty/stale view."""
    import argparse
    import os

    from .helpers import sandbox_home, write_file

    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "v"
    vault.mkdir()
    write_file(vault, "a.txt", b"hi", mtime=1000)
    Config(apple_id="x@y.com", local_folder=str(vault), **PERMISSIVE_THRESHOLDS).save(
        config_path("default")
    )
    monkeypatch.setattr(
        "ifolder_sync.icloud_client.ICloudClient.from_config",
        classmethod(lambda cls, c: fake),
    )
    seen: list = []
    orig = InflightSurface.record

    def _spy(self, ev):
        seen.append((ev.relpath, ev.state))
        orig(self, ev)

    monkeypatch.setattr(InflightSurface, "record", _spy)

    args = argparse.Namespace(
        profile="default", dry_run=False, json=False, non_interactive=True, force_delete=False
    )
    cmd_sync(args)

    assert ("a.txt", "uploading") in seen  # live rows emitted mid-pass (the wiring works)
    data = json.loads(status_path("default").read_text())
    assert data["pid"] == os.getpid()  # stamped by THIS foreground sync, not a daemon
    assert data["rows"] == []  # cleared on finish (the upload completed)


def test_cmd_sync_dry_run_writes_no_status(tmp_path, monkeypatch, fake):
    """--dry-run takes no surface: it writes nothing and must not stamp a status.json."""
    import argparse

    from .helpers import sandbox_home, write_file

    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "v"
    vault.mkdir()
    write_file(vault, "a.txt", b"hi", mtime=1000)
    Config(apple_id="x@y.com", local_folder=str(vault), **PERMISSIVE_THRESHOLDS).save(
        config_path("default")
    )
    monkeypatch.setattr(
        "ifolder_sync.icloud_client.ICloudClient.from_config",
        classmethod(lambda cls, c: fake),
    )
    args = argparse.Namespace(
        profile="default", dry_run=True, json=False, non_interactive=True, force_delete=False
    )
    cmd_sync(args)
    assert not status_path("default").exists()


def test_dashboard_view_ignores_snapshot_from_other_pid(tmp_path, monkeypatch):
    """A status.json whose pid is NOT the live lock holder is stale (e.g. a dead daemon's file
    while a foreground sync now holds the lock) and must NOT render as live activity."""
    from .helpers import sandbox_home

    sandbox_home(tmp_path, monkeypatch)
    with StateStore(baseline_path("default")) as s:
        s.set_meta("last_sync", "1.0")
    status_path("default").write_text(
        json.dumps(
            {
                "schema": 1,
                "pid": 7,  # written by a now-dead daemon
                "rows": [{"relpath": "x.md", "state": "uploading", "op": "upload"}],
            }
        )
    )
    # a DIFFERENT live process holds the lock (e.g. a foreground sync) -> snapshot is stale
    monkeypatch.setattr("ifolder_sync.cli.holder_pid", lambda _p: 999)
    assert _dashboard_view("default")["attention"] == []
    # when the holder matches the snapshot's pid, the live row IS shown
    monkeypatch.setattr("ifolder_sync.cli.holder_pid", lambda _p: 7)
    assert [r.relpath for r in _dashboard_view("default")["attention"]] == ["x.md"]


# --------------------------------------------- the best-effort safety contract ---
def test_throwing_observer_does_not_break_pass(tmp_path, fake, local_dir):
    """The CORE guarantee: an observer that raises on every event can never abort or distort
    a sync pass — the upload still lands and errors stays 0."""

    def boom(_event):
        raise RuntimeError("viewer exploded")

    cfg = Config(apple_id="x@y.com", local_folder=str(local_dir), **PERMISSIVE_THRESHOLDS)
    store = StateStore(tmp_path / "s.sqlite3")
    syncer = Syncer(cfg, fake, store, trash_dir=tmp_path / "trash", on_event=boom)
    write_file(local_dir, "a.txt", b"hi", mtime=1000)

    stats = syncer.sync_once()

    assert stats.uploaded == 1 and stats.errors == 0
    assert fake.files["a.txt"]["content"] == b"hi"  # the upload actually landed
    store.close()


def test_no_observer_is_inert(tmp_path):
    """on_event=None ⇒ outcome-identical: a no-op observer must add ZERO network/stat calls
    and produce the same stats as no observer at all."""

    def run(on_event, tag):
        local = tmp_path / f"local-{tag}"
        local.mkdir()
        write_file(local, "a.md", b"x", mtime=1000)
        fk = FakeICloud()
        fk.put("b.md", b"y", mtime=2000)
        cfg = Config(apple_id="x@y.com", local_folder=str(local), **PERMISSIVE_THRESHOLDS)
        store = StateStore(tmp_path / f"{tag}.sqlite3")
        st = Syncer(cfg, fk, store, trash_dir=tmp_path / f"tr-{tag}", on_event=on_event).sync_once()
        store.close()
        return dict(fk.calls), st.summary()

    none_calls, none_stats = run(None, "none")
    noop_calls, noop_stats = run(lambda _e: None, "noop")
    assert none_calls == noop_calls
    assert none_stats == noop_stats


def test_engine_emits_error_on_failed_transfer(tmp_path, fake, local_dir, monkeypatch):
    """A transfer that raises emits 'error' (not 'done') — the dashboard never shows a failed
    upload as completed."""
    events: list = []
    syncer, store = _syncer_with_observer(tmp_path, fake, local_dir, events)
    write_file(local_dir, "boom.md", b"data", mtime=1000)
    monkeypatch.setattr(fake, "upload", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))

    stats = syncer.sync_once()

    states = [(e.relpath, e.state) for e in events if e.relpath == "boom.md"]
    assert ("boom.md", "uploading") in states
    assert ("boom.md", "error") in states
    assert ("boom.md", "done") not in states
    assert stats.errors == 1
    store.close()


def test_engine_emits_pending_unreadable_through_sync_once(tmp_path, fake, local_dir):
    """A publish-before-content lag (UnreadableRemoteError) emits 'pending-unreadable' (not
    'done'), ties to the defer-not-clobber invariant: pending counted, errors 0."""
    events: list = []
    syncer, store = _syncer_with_observer(tmp_path, fake, local_dir, events)
    fake.put_unreadable("lag.md", size=4, mtime=FAR)

    stats = syncer.sync_once()

    states = [(e.relpath, e.state) for e in events if e.relpath == "lag.md"]
    assert ("lag.md", "downloading") in states
    assert ("lag.md", "pending-unreadable") in states
    assert ("lag.md", "done") not in states
    assert stats.pending >= 1 and stats.errors == 0
    store.close()


def test_engine_emits_coalesced_tree_delete(tmp_path, fake, local_dir):
    """A coalesced remote subtree delete (the folder-move case) is visible as a single
    in-flight 'deleting-remote' row for the root, closed with 'done'."""
    events: list = []
    syncer, store = _syncer_with_observer(tmp_path, fake, local_dir, events)
    write_file(local_dir, "Folder/a.md", b"a", mtime=1000)
    write_file(local_dir, "Folder/b.md", b"b", mtime=1000)
    syncer.sync_once()  # upload the subtree + establish the baseline
    shutil.rmtree(local_dir / "Folder")  # delete the whole subtree locally
    events.clear()

    syncer.sync_once()  # coalesced remote tree delete

    states = [(e.relpath, e.state) for e in events]
    assert ("Folder", "deleting-remote") in states
    assert ("Folder", "done") in states
    store.close()


# ---------------------------------------------------- the atomic-flush edges ---
def test_flush_atomic_leaves_no_part(tmp_path):
    surf = InflightSurface(tmp_path / "status.json", min_write_interval_ms=0)
    surf.pass_started(pid=1)
    surf.record(SyncEvent(1.0, 1, "a.txt", Op.UPLOAD, "uploading", "file"))
    assert (tmp_path / "status.json").exists()
    assert not (tmp_path / "status.json.part").exists()  # os.replace consumed the temp


def test_flush_failure_is_swallowed(tmp_path, monkeypatch):
    """A flush that fails (disk full / read-only) must never raise into the engine."""
    surf = InflightSurface(tmp_path / "status.json", min_write_interval_ms=0)
    monkeypatch.setattr("os.replace", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    surf.record(SyncEvent(1.0, 1, "a.txt", Op.UPLOAD, "uploading", "file"))  # must not raise
    monkeypatch.undo()
    surf.record(SyncEvent(2.0, 1, "a.txt", Op.UPLOAD, "done", "file"))  # surface still usable
    assert (tmp_path / "status.json").exists()


# ----------------------------------------------- the daemon pass bracketing ---
def _make_daemon(tmp_path, monkeypatch, fake, **cfg_kw):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "ifolder_sync.icloud_client.ICloudClient.from_config",
        classmethod(lambda cls, c: fake),
    )
    from ifolder_sync.daemon import Daemon

    local = tmp_path / "vault"
    local.mkdir(exist_ok=True)
    cfg = Config(apple_id="x@y.com", local_folder=str(local), **{**PERMISSIVE_THRESHOLDS, **cfg_kw})
    return Daemon(cfg, "default"), local


def test_daemon_brackets_real_pass(tmp_path, monkeypatch, fake):
    """End-to-end through _run_sync: a transferred file is cleared from the live surface at
    pass end (pass_finished), proving the producer wiring, not just the helpers in isolation."""
    d, local = _make_daemon(tmp_path, monkeypatch, fake)
    write_file(local, "a.md", b"hi", mtime=1000)

    d._run_sync("test")

    data = json.loads(status_path("default").read_text())
    assert all(r["relpath"] != "a.md" for r in data["rows"])  # cleared by pass_finished
    assert fake.files["a.md"]["content"] == b"hi"  # the pass really transferred it
    d.store.close()


def test_pass_finished_runs_on_failure(tmp_path, monkeypatch, fake):
    """The finally fix: a pass that raises AFTER flushing an in-flight row must not strand it —
    the finally's pass_finished rebuilds the surface to the (empty) stuck set."""
    d, local = _make_daemon(tmp_path, monkeypatch, fake)

    def boom(**_k):
        d.inflight.record(SyncEvent(1.0, 1, "big.md", Op.UPLOAD, "uploading", "file"))
        raise RuntimeError("mid-apply boom")

    monkeypatch.setattr(d.syncer, "sync_once", boom)

    d._run_sync("test")  # RuntimeError is handled; finally must clean the surface

    data = json.loads(status_path("default").read_text())
    assert all(r["relpath"] != "big.md" for r in data["rows"])  # stale in-flight cleared
    d.store.close()
