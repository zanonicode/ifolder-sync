"""Live dashboard (`status --watch`, feature 04 Phase 1): the read-only observer.

Covers the mechanically read-only StateStore (a mode=ro connection that the database itself
refuses to write), the attention fold over the engine's persisted stuck registries
(settle_counts + unreadable_counts), and the pure frame renderer.
"""

from __future__ import annotations

import argparse
import json
import sqlite3

import pytest

from ifolder_sync.cli import (
    _attention_rows,
    _dashboard_banner,
    _dashboard_view,
    _fmt_age,
    _ordered_rows,
    _profile_status_data,
    _render_dashboard_frame,
    _render_multiprofile_frame,
    _render_rich,
    _watch_interval,
    _watch_route,
    _WatchState,
)
from ifolder_sync.config import Config, baseline_path, config_path
from ifolder_sync.state import BaselineEntry, StateStore
from ifolder_sync.syncstate import SyncRow

from .helpers import sandbox_home


def test_read_only_store_rejects_writes_but_reads(tmp_path):
    """The read-only guarantee is enforced by the CONNECTION (mode=ro), not by discipline:
    reads work, every write raises."""
    db = tmp_path / "baseline.sqlite3"
    with StateStore(db) as s:
        s.set_meta("k", "v")

    ro = StateStore(db, read_only=True)
    assert ro.read_only is True
    assert ro.get_meta("k") == "v"  # reads work
    with pytest.raises(sqlite3.OperationalError):
        ro.set_meta("k", "w")  # the connection rejects the write
    with pytest.raises(sqlite3.OperationalError):
        ro.upsert(BaselineEntry("x", "file", 0, 0.0, 0, 0.0))
    ro.close()


def test_attention_rows_folds_and_sorts_most_stuck_first(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    db = baseline_path("default")
    with StateStore(db) as s:
        s.set_meta("settle_counts", json.dumps({"a.md": 3, "b.md": 7}))
        s.set_meta("unreadable_counts", json.dumps({"c.md": [10, 1.0, "e", 20, True]}))

    rows = _attention_rows("default")

    assert [r.relpath for r in rows] == ["c.md", "b.md", "a.md"]  # 20 > 7 > 3
    assert rows[0].state == "pending-unreadable" and rows[0].passes_stuck == 20
    assert rows[2].state == "deferred-settle" and rows[2].passes_stuck == 3
    assert all(r.op is None for r in rows)  # registry rows have no decided Op


def test_attention_rows_missing_baseline_is_empty(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    assert _attention_rows("default") == []  # daemon never ran -> no baseline


def test_attention_rows_corrupt_meta_degrades_quietly(tmp_path, monkeypatch):
    """An observer must never crash the way a writer would: malformed meta -> empty list."""
    sandbox_home(tmp_path, monkeypatch)
    db = baseline_path("default")
    with StateStore(db) as s:
        s.set_meta("settle_counts", "{not valid json")
    assert _attention_rows("default") == []


def test_dashboard_view_shape(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    db = baseline_path("default")
    with StateStore(db) as s:
        s.set_meta("last_sync", "500.0")
        s.set_meta("last_stats", "up=3 down=1 errors=0")
        s.set_meta("settle_counts", json.dumps({"a.md": 2}))

    view = _dashboard_view("default")

    assert view["last_sync"] == 500.0
    assert view["last_stats"] == "up=3 down=1 errors=0"
    assert [r.relpath for r in view["attention"]] == ["a.md"]


def test_profile_status_json_includes_attention(tmp_path, monkeypatch):
    """`status --json` surfaces the same stuck registry (serialized rows) as the live view."""
    sandbox_home(tmp_path, monkeypatch)
    Config(apple_id="x@y.com", local_folder=str(tmp_path / "v")).save(config_path("default"))
    db = baseline_path("default")
    with StateStore(db) as s:
        s.set_meta("last_sync", "1.0")
        s.set_meta("unreadable_counts", json.dumps({"z.md": [1, 1.0, "e", 9, False]}))

    data = _profile_status_data("default")

    assert data["configured"] is True
    assert [r["relpath"] for r in data["attention"]] == ["z.md"]
    assert data["attention"][0]["state"] == "pending-unreadable"
    assert data["attention"][0]["op"] is None  # serialized None, not "None"


def test_render_frame_empty_then_populated():
    view = {
        "profile": "default",
        "daemon": {"running": True, "pid": 42},
        "baseline": "ok",
        "last_sync": 0.0,
        "last_stats": "up=1 down=0 errors=0",
        "last_error": None,
        "attention": [],
    }
    out = _render_dashboard_frame(view, 0.0)
    assert "ifolder-sync · default" in out
    assert "running (pid 42)" in out
    assert "all synced" in out

    view["attention"] = [SyncRow("notes/big.md", "deferred-settle", passes_stuck=3)]
    out = _render_dashboard_frame(view, 0.0)
    assert "Sync activity (1 active)" in out
    assert "notes/big.md" in out and "settling" in out


def test_render_frame_shows_stopped_and_error():
    view = {
        "profile": "p",
        "daemon": {"running": False, "pid": None},
        "baseline": "ok",
        "last_sync": None,
        "last_stats": None,
        "last_error": "boom",
        "attention": [],
    }
    out = _render_dashboard_frame(view, 100.0)
    assert "stopped" in out and "never" in out and "boom" in out


def test_fmt_age_units():
    assert _fmt_age(None, 100.0) == "never"
    assert _fmt_age(100.0, 100.0) == "0s ago"
    assert _fmt_age(100.0, 130.0) == "30s ago"
    assert _fmt_age(100.0, 100.0 + 120) == "2m ago"
    assert _fmt_age(100.0, 100.0 + 7200) == "2h ago"
    assert _fmt_age(100.0, 100.0 + 2 * 86400) == "2d ago"


def test_watch_interval_override_floor_and_config(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    assert _watch_interval("default", argparse.Namespace(interval=0.5)) == 0.5
    assert _watch_interval("default", argparse.Namespace(interval=0.01)) == 0.2  # floor
    assert _watch_interval("default", argparse.Namespace(interval=None)) == 1.0  # default 1s

    Config(
        apple_id="x@y.com",
        local_folder=str(tmp_path / "v"),
        dashboard_interval_seconds=5.0,
    ).save(config_path("default"))
    assert _watch_interval("default", argparse.Namespace(interval=None)) == 5.0


# ----------------------------------------------------------- Phase 3 polish ---
def _view(paths):
    return {"attention": [SyncRow(p, "uploading") for p in paths]}


def test_watchstate_surfaces_recently_synced_and_flapping():
    ws = _WatchState(recent_ttl=100, flap_threshold=2)
    ws.observe(_view(["a.md"]), 1.0)  # a.md in flight
    out = ws.observe(_view([]), 2.0)  # a.md completed (vanished)
    assert out["recently_synced"] == ["a.md"]
    assert out["flapping"] == []  # one completion is not flapping

    ws.observe(_view(["a.md"]), 3.0)
    out = ws.observe(_view([]), 4.0)  # a.md completed a second time
    assert "a.md" in out["flapping"]  # repeated completions == a re-sync loop


def test_watchstate_recent_rail_expires_after_ttl():
    ws = _WatchState(recent_ttl=5, flap_threshold=99)
    ws.observe(_view(["a.md"]), 0.0)
    assert ws.observe(_view([]), 1.0)["recently_synced"] == ["a.md"]  # just completed
    assert ws.observe(_view([]), 10.0)["recently_synced"] == []  # >5s later, expired


def test_watchstate_flapping_clears_after_quiet_window():
    """Flapping reflects CURRENT looping: once a path stops re-syncing for the window, it drops
    off the list and its per-path state is pruned (bounded memory on a long watch)."""
    ws = _WatchState(recent_ttl=1, flap_threshold=2, flap_window=10)
    for t in (0.0, 1.0, 2.0, 3.0):  # complete twice within the window -> flapping
        ws.observe(_view(["a.md"]), t)
        out = ws.observe(_view([]), t + 0.5)
    assert "a.md" in out["flapping"]

    out = ws.observe(_view([]), 100.0)  # long quiet -> outside the window
    assert out["flapping"] == []
    assert ws._completions == {}  # the per-path state was pruned, not leaked


def test_watchstate_concurrent_completions_have_stable_order():
    """Same-frame completions share a timestamp; the rail must order them deterministically
    (by path), not by set-hash."""
    ws = _WatchState(recent_ttl=100)
    ws.observe(_view(["c.md", "a.md", "b.md"]), 1.0)
    out = ws.observe(_view([]), 2.0)  # all three complete in one frame
    assert out["recently_synced"] == ["a.md", "b.md", "c.md"]


def test_dashboard_banner_for_suppressed_deletes():
    assert "suppressed" in _dashboard_banner("up=0 skipped_deletes=3 errors=0")
    assert _dashboard_banner("up=0 skipped_deletes=0 errors=0") is None
    assert _dashboard_banner(None) is None


def test_render_frame_shows_banner_flapping_and_recent():
    view = {
        "profile": "p",
        "daemon": {"running": True, "pid": 1},
        "baseline": "ok",
        "last_sync": 0.0,
        "last_stats": "skipped_deletes=2",
        "last_error": None,
        "attention": [],
        "flapping": ["x.md"],
        "recently_synced": ["y.md"],
    }
    out = _render_dashboard_frame(view, 0.0)
    assert "suppressed by the safety threshold" in out
    assert "flapping" in out and "x.md" in out
    assert "recently synced" in out and "y.md" in out


def test_render_multiprofile_frame(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    for prof in ("default", "work"):
        Config(apple_id="x@y.com", local_folder=str(tmp_path / prof)).save(config_path(prof))
        with StateStore(baseline_path(prof)) as s:
            s.set_meta("last_sync", "1.0")

    out = _render_multiprofile_frame(["default", "work"], 100.0)

    assert "all profiles" in out
    assert "default" in out and "work" in out
    assert "stopped" in out  # neither daemon is running


def test_render_multiprofile_frame_running_with_stuck(tmp_path, monkeypatch):
    """The operationally-important branch: a running daemon with a stuck count must surface in
    the multi-profile overview (not just the stopped/empty case)."""
    sandbox_home(tmp_path, monkeypatch)
    for prof in ("busy", "idle"):
        Config(apple_id="x@y.com", local_folder=str(tmp_path / prof)).save(config_path(prof))
        with StateStore(baseline_path(prof)) as s:
            s.set_meta("last_sync", "1.0")
    with StateStore(baseline_path("busy")) as s:
        s.set_meta("settle_counts", json.dumps({"a.md": 3, "b.md": 2}))  # 2 stuck
    monkeypatch.setattr("ifolder_sync.cli.holder_pid", lambda p: 99 if "busy" in str(p) else None)

    out = _render_multiprofile_frame(["busy", "idle"], 100.0)

    assert "running" in out and "2 stuck" in out  # busy profile
    assert "stopped" in out  # idle profile


def test_render_frame_without_phase3_keys_is_crash_free():
    """The one-shot (non-watch) path renders a `_dashboard_view` that has NO flapping/
    recently_synced keys — the frame must not crash and must show neither section."""
    view = {
        "profile": "p",
        "daemon": {"running": True, "pid": 1},
        "baseline": "ok",
        "last_sync": 0.0,
        "last_stats": "up=1 down=0 errors=0",
        "last_error": None,
        "attention": [],
    }
    out = _render_dashboard_frame(view, 0.0)
    assert "flapping" not in out and "recently synced" not in out


def test_watch_route_decision():
    assert _watch_route("work", ["default", "work"]) == ("single", "work")  # explicit -> single
    assert _watch_route(None, ["default"]) == ("single", "default")  # lone profile -> single
    assert _watch_route(None, ["a", "b"]) == ("multi", None)  # many -> multi overview
    assert _watch_route(None, []) == ("single", "default")  # none yet -> default fallback


def test_render_rich_reaches_parity_with_ansi():
    """The `[dashboard]` extra must never HIDE a signal the ANSI frame shows: the rich frame
    carries the error, the suppressed-deletes banner, flapping, and recently-synced too."""
    view = {
        "profile": "p",
        "daemon": {"running": True, "pid": 9},
        "last_sync": 0.0,
        "last_stats": "skipped_deletes=5",
        "last_error": "auth lapsed",
        "attention": [SyncRow("big.md", "uploading")],
        "flapping": ["loop.md"],
        "recently_synced": ["done.md"],
    }
    out = _render_rich(view, 0.0)
    assert out is not None  # rich is in [dev]
    for signal in ("big.md", "auth lapsed", "suppressed", "loop.md", "done.md"):
        assert signal in out, f"rich frame dropped {signal!r} — parity regression"


def test_ordered_rows_active_before_queue():
    rows = [
        SyncRow("q.md", "queued"),
        SyncRow("u.md", "uploading"),
        SyncRow("p.md", "pending-unreadable"),
    ]
    ordered = [r.relpath for r in _ordered_rows(rows)]
    assert ordered.index("u.md") < ordered.index("p.md") < ordered.index("q.md")


def test_render_rich_two_frames_show_queue():
    """The rich render is TWO frames (header panel + a separate files table) and the files
    table lists the full queue, not just the in-flight file."""
    view = {
        "profile": "default",
        "daemon": {"running": True, "pid": 1},
        "last_sync": 0.0,
        "last_stats": "up=1 down=0 errors=0",
        "last_error": None,
        "attention": [
            SyncRow("a.md", "uploading"),
            SyncRow("b.md", "queued"),
            SyncRow("c.md", "queued"),
        ],
    }
    out = _render_rich(view, 0.0)
    assert out is not None
    assert "ifolder-sync · default" in out  # header panel title
    assert "syncing" in out and "1 active, 2 queued" in out  # files-table title + queue count
    assert "a.md" in out and "b.md" in out and "c.md" in out  # the whole queue is listed


def test_render_ansi_frame_shows_queue_count():
    view = {
        "profile": "p",
        "daemon": {"running": True, "pid": 1},
        "baseline": "ok",
        "last_sync": 0.0,
        "last_stats": "up=1",
        "last_error": None,
        "attention": [SyncRow("a.md", "uploading"), SyncRow("b.md", "queued")],
    }
    out = _render_dashboard_frame(view, 0.0)
    assert "1 active, 1 queued" in out
    assert out.index("a.md") < out.index("b.md")  # active before queued
