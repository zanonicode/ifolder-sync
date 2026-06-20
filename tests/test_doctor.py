"""`doctor` (feature 05): the read-only, decide-only consistency audit.

These assert the contract from DESIGN_05: orphan-baseline detection (the 2026-06-20 ghost
class), a mechanically read-only pass (no upload/download/delete/baseline write), abort-on-
scan-failure with NO false orphans, and the shared `SyncRow` envelope shape that `doctor
--json` and the dashboard both serialize.
"""

from __future__ import annotations

import pytest

from ifolder_sync.cli import _doctor_json, _print_doctor_report, _stats_has_trouble
from ifolder_sync.state import BaselineEntry
from ifolder_sync.syncer import Op
from ifolder_sync.syncstate import SCHEMA, Plan, SyncRow, make_envelope

from .helpers import write_file


def test_orphan_baseline_row_is_reported(make_syncer, fake):
    """AT-001: a path present in the baseline but absent from BOTH local and remote is the
    headline `orphan-baseline` class, reported with its reason — the incident's ghost."""
    syncer, store = make_syncer()
    store.upsert(BaselineEntry("Music/song.md", "file", 7, 1000.0, 7, 1000.0))
    store.commit()

    plan = syncer.plan()

    orphans = plan.orphans
    assert [r.relpath for r in orphans] == ["Music/song.md"]
    assert orphans[0].state == "orphan-baseline"
    assert orphans[0].reason == "in baseline, absent from local and remote"
    # read-only: the audit did NOT drop the row (that is what `--fix-orphans` would do).
    assert "Music/song.md" in store.all()
    store.close()


def test_dir_orphan_classified_via_cleanup(make_syncer, fake):
    """A baseline-only DIRECTORY row routes through the cleanup decision (DROP_BASELINE_DIR)
    and still lands as `orphan-baseline` with kind='dir' — no path double-counts."""
    syncer, store = make_syncer()
    store.upsert(BaselineEntry("olddir", "dir", 0, 0.0, 0, 0.0))
    store.commit()

    rows = syncer.plan().rows

    matches = [r for r in rows if r.relpath == "olddir"]
    assert len(matches) == 1
    assert matches[0].state == "orphan-baseline" and matches[0].kind == "dir"
    store.close()


def test_doctor_is_read_only(make_syncer, fake, local_dir):
    """AT-002: against an in-sync vault, `plan()` writes nothing — no upload/download/delete/
    mkdir, the baseline rows are byte-identical, and last_sync is not advanced."""
    syncer, store = make_syncer()
    write_file(local_dir, "a.txt", b"aaa", mtime=1000)
    fake.put("b.txt", b"bbb", mtime=2000)
    syncer.sync_once()  # establish the baseline on both sides

    before_rows = store.all()
    before_calls = dict(fake.calls)
    before_sync = store.get_meta("last_sync")

    plan = syncer.plan()

    assert plan.is_clean, [r.relpath for r in plan.rows]
    for io in ("upload", "download", "delete", "mkdir"):
        assert fake.calls[io] == before_calls[io], f"{io} happened during a read-only audit"
    assert store.all() == before_rows  # baseline untouched
    assert store.get_meta("last_sync") == before_sync  # the pass-end meta block never ran
    store.close()


def test_local_only_file_is_planned_upload_not_error(make_syncer, fake, local_dir):
    """AT-003: a new local file (not in baseline or remote) is drift (planned-upload), never
    an error, and the audit does not actually upload it."""
    syncer, store = make_syncer()
    write_file(local_dir, "new.md", b"new", mtime=3000)

    plan = syncer.plan()

    uploads = [r for r in plan.rows if r.state == "planned-upload"]
    assert [r.relpath for r in uploads] == ["new.md"]
    assert plan.errors == 0
    assert "new.md" not in fake.files  # nothing was written remotely
    store.close()


def test_clean_vault_reports_no_inconsistencies(make_syncer, fake, local_dir, capsys):
    """AT-004: when baseline, local, and remote agree, the plan is clean and the report
    says so."""
    syncer, store = make_syncer()
    write_file(local_dir, "a.txt", b"a", mtime=1000)
    fake.put("b.txt", b"b", mtime=2000)
    syncer.sync_once()

    plan = syncer.plan()
    assert plan.is_clean

    _print_doctor_report(plan, "default")
    assert "No inconsistencies found" in capsys.readouterr().out
    store.close()


def test_scan_failure_aborts_with_no_false_orphans(make_syncer, fake):
    """AT-005: a failed remote walk aborts the audit (walk guard). The baseline-only row is
    NOT surfaced as an orphan and is left untouched — a partial scan can never feed a
    remediation a false orphan list."""
    syncer, store = make_syncer()
    store.upsert(BaselineEntry("ghost.md", "file", 7, 1000.0, 7, 1000.0))
    store.commit()
    fake.fail_walk = True

    with pytest.raises(RuntimeError):
        syncer.plan()

    assert "ghost.md" in store.all()  # abort left it intact; nothing classified as orphan
    store.close()


def test_envelope_parity_and_row_roundtrip():
    """AT-006: a SyncRow round-trips through (de)serialization, its Op pins to the wire
    string, and `doctor --json` and a dashboard-style envelope share the schema+rows shape."""
    row = SyncRow(relpath="x.md", state="planned-upload", op=Op.UPLOAD, kind="file")

    d = row.to_dict()
    assert d["op"] == "upload"  # str-Enum pinned to its wire value
    assert SyncRow.from_dict(d) == row  # round-trip identity
    # a future producer's extra field must not crash an older reader
    assert SyncRow.from_dict({**d, "future_field": 1}) == row

    doctor_env = make_envelope([row], profile="default", suppressed_deletes=0)
    dashboard_env = make_envelope([row], profile="default", pid=123, last_sync=1.0)
    for env in (doctor_env, dashboard_env):
        assert env["schema"] == SCHEMA
        assert isinstance(env["rows"], list)
        assert env["rows"][0]["relpath"] == "x.md"


def test_doctor_json_envelope_from_plan(make_syncer, fake, local_dir):
    """`doctor --json` emits the versioned envelope with the inconsistency count."""
    syncer, store = make_syncer()
    store.upsert(BaselineEntry("Music/song.md", "file", 7, 1000.0, 7, 1000.0))
    store.commit()
    write_file(local_dir, "new.md", b"new", mtime=3000)

    j = _doctor_json(syncer.plan(), "default")

    assert j["schema"] == SCHEMA
    assert j["profile"] == "default"
    assert j["inconsistencies"] == len(j["rows"]) >= 2
    states = {r["state"] for r in j["rows"]}
    assert "orphan-baseline" in states and "planned-upload" in states
    store.close()


def test_report_banners_for_suppressed_and_unresolvable(capsys):
    """The text report surfaces the pass-level banners: suppressed-over-threshold deletions
    and unresolvable (collision/kind-conflict) paths."""
    plan = Plan(
        rows=[
            SyncRow(
                "d.md",
                "planned-delete",
                Op.DELETE_REMOTE,
                reason="suppressed (over delete threshold)",
            )
        ],
        suppressed_deletes=3,
        errors=2,
    )

    _print_doctor_report(plan, "default")
    out = capsys.readouterr().out

    assert "Planned deletions (1)" in out
    assert "3 deletion(s) would be withheld" in out
    assert "2 path(s) cannot be reconciled" in out


def test_status_trouble_hint_detection():
    """The `status` doctor-hint trigger: a cheap string scan of last_stats for non-zero
    errors/skipped_deletes (no network)."""
    assert _stats_has_trouble("up=0 down=0 errors=32 pending=0") is True
    assert _stats_has_trouble("up=1 down=0 skipped_deletes=5 errors=0") is True
    assert _stats_has_trouble("up=1 down=2 errors=0 skipped_deletes=0") is False
    assert _stats_has_trouble(None) is False
    assert _stats_has_trouble("") is False
