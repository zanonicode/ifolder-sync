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
    _dashboard_view,
    _fmt_age,
    _profile_status_data,
    _render_dashboard_frame,
    _watch_interval,
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
    assert "Sync activity (1)" in out
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
    assert _watch_interval("default", argparse.Namespace(interval=None)) == 2.0  # no config

    Config(
        apple_id="x@y.com",
        local_folder=str(tmp_path / "v"),
        dashboard_interval_seconds=5.0,
    ).save(config_path("default"))
    assert _watch_interval("default", argparse.Namespace(interval=None)) == 5.0
