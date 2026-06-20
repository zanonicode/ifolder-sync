"""Live in-flight surface (feature 04 Phase 2): the engine emits, the atomic status.json
flush, and the observer's stale-snapshot gating.

The load-bearing safety property — the engine is byte-for-byte unchanged when on_event is
None — is covered by the whole existing suite passing; here we exercise the producer with an
observer wired in, plus the surface and reader in isolation.
"""

from __future__ import annotations

import json

from ifolder_sync.cli import _dashboard_view, _read_status_snapshot
from ifolder_sync.config import Config, baseline_path, status_path
from ifolder_sync.inflight import InflightSurface
from ifolder_sync.state import StateStore
from ifolder_sync.syncer import Op, Syncer
from ifolder_sync.syncstate import SyncEvent, SyncRow

from .helpers import PERMISSIVE_THRESHOLDS, write_file


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


def test_surface_flush_is_throttled(tmp_path):
    surf = InflightSurface(tmp_path / "status.json", min_write_interval_ms=10_000)
    surf.pass_started()  # forced flush writes the (empty) frame
    before = (tmp_path / "status.json").read_text()
    surf.record(SyncEvent(1.0, 1, "a.txt", Op.UPLOAD, "uploading", "file"))  # within window
    assert (tmp_path / "status.json").read_text() == before  # coalesced, not rewritten


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
