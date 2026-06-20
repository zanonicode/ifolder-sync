"""`doctor` (feature 05): the read-only, decide-only consistency audit.

These assert the contract from DESIGN_05: orphan-baseline detection (the 2026-06-20 ghost
class), a mechanically read-only pass (no upload/download/delete/baseline write), abort-on-
scan-failure with NO false orphans, and the shared `SyncRow` envelope shape that `doctor
--json` and the dashboard both serialize.
"""

from __future__ import annotations

import argparse
import json

import pytest

from ifolder_sync.cli import (
    _doctor_json,
    _fix_orphans,
    _print_doctor_report,
    _stats_has_trouble,
    cmd_doctor,
)
from ifolder_sync.config import Config, baseline_path, config_path, lock_path
from ifolder_sync.locking import SingleInstanceLock
from ifolder_sync.state import BaselineEntry, StateStore
from ifolder_sync.syncer import (
    _CLEANUP_PLAN_STATE,
    _DIR_PLAN_STATE,
    _FILE_DECISION_OPS,
    _FILE_PLAN_STATE,
    Op,
    RemoteScanError,
)
from ifolder_sync.syncstate import SCHEMA, Plan, SyncRow, make_envelope

from .helpers import sandbox_home, write_file


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
    mkdir, no remote-root mkdir, the baseline rows are byte-identical, and last_sync is not
    advanced. It still performs a real scan (refresh + walk increment)."""
    syncer, store = make_syncer()
    write_file(local_dir, "a.txt", b"aaa", mtime=1000)
    fake.put("b.txt", b"bbb", mtime=2000)
    syncer.sync_once()  # establish the baseline on both sides

    before_rows = store.all()
    before_calls = dict(fake.calls)
    before_sync = store.get_meta("last_sync")

    plan = syncer.plan()

    assert plan.is_clean, [r.relpath for r in plan.rows]
    for io in ("upload", "download", "delete", "mkdir", "ensure_remote_root"):
        assert fake.calls[io] == before_calls[io], f"{io} happened during a read-only audit"
    assert fake.calls["walk"] > before_calls["walk"]  # the audit actually scanned, not no-op'd
    assert fake.calls["refresh"] > before_calls["refresh"]
    assert store.all() == before_rows  # baseline untouched
    assert store.get_meta("last_sync") == before_sync  # the pass-end meta block never ran
    store.close()


def test_doctor_read_only_with_pending_actions(make_syncer, fake, local_dir):
    """AT-002 (strong): with REAL drift staged — a planned-upload plus a 0-byte remote husk
    that drives SETTLE_WAIT through `_escalate_settle` (whose settle_counts persistence is the
    classic dry_run-gated decide-write) — the audit STILL writes nothing: no IO, baseline and
    every side-effect meta key (last_sync, settle_counts, vault_uuid, ignore_hash) unchanged."""
    syncer, store = make_syncer()
    write_file(local_dir, "keep.md", b"keep", mtime=1000)
    syncer.sync_once()  # baseline keep.md

    write_file(local_dir, "new.md", b"new", mtime=3000)  # planned-upload
    write_file(local_dir, "husk.md", b"local body", mtime=4000)
    fake.put("husk.md", b"", mtime=4000)  # 0-byte remote husk -> SETTLE_WAIT

    before_rows = store.all()
    before_calls = dict(fake.calls)
    keys = ("last_sync", "settle_counts", "vault_uuid", "ignore_hash")
    before_meta = {k: store.get_meta(k) for k in keys}

    plan = syncer.plan()

    assert not plan.is_clean  # there genuinely is drift to report
    for io in ("upload", "download", "delete", "mkdir", "ensure_remote_root"):
        assert fake.calls[io] == before_calls[io], f"{io} happened during a read-only audit"
    assert store.all() == before_rows
    for k in keys:
        assert store.get_meta(k) == before_meta[k], f"meta {k} changed under read-only doctor"
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


def test_local_scan_failure_aborts_with_no_false_orphans(make_syncer, fake, tmp_path):
    """AT-005 (local half of invariant #2): a missing vault root with a non-empty baseline
    aborts the audit (the more dangerous guard — os.walk silently skips unreadable dirs).
    The baseline is left intact and NOTHING is classified as orphan — no false orphan list."""
    syncer, store = make_syncer()
    store.upsert(BaselineEntry("x.md", "file", 7, 1000.0, 7, 1000.0))
    store.commit()
    syncer.local_root = tmp_path / "vanished"  # non-existent root + non-empty baseline -> abort

    with pytest.raises(RuntimeError):
        syncer.plan()

    assert "x.md" in store.all()
    store.close()


def test_missing_remote_root_aborts_not_mass_delete(make_syncer, fake, local_dir):
    """The HIGH finding's regression: a genuinely-absent remote root must ABORT
    (RemoteScanError), never read as an empty remote that reports the whole live vault as
    planned-delete and steers the user toward `sync --force-delete` (bypassing invariant #3)."""
    syncer, store = make_syncer()
    write_file(local_dir, "keep1.md", b"a", mtime=1000)
    write_file(local_dir, "keep2.md", b"b", mtime=1000)
    syncer.sync_once()  # populate remote + baseline

    fake.root_missing = True  # the configured remote folder is gone -> walk() returns {}
    with pytest.raises(RemoteScanError):
        syncer.plan()
    store.close()


def test_would_conflict_via_plan(make_syncer, fake, local_dir):
    """End-to-end: both sides edited since baseline (mismatched) -> Op.CONFLICT -> a
    would-conflict row carrying the policy reason."""
    syncer, store = make_syncer(policy="newer")
    write_file(local_dir, "c.md", b"base", mtime=5000)
    syncer.sync_once()  # baseline both

    write_file(local_dir, "c.md", b"local-edit", mtime=6000)
    fake.put("c.md", b"remote-different-edit", mtime=7000)

    conflicts = [r for r in syncer.plan().rows if r.state == "would-conflict"]
    assert [r.relpath for r in conflicts] == ["c.md"]
    assert conflicts[0].reason.startswith("policy=")
    store.close()


def test_suppressed_delete_via_plan(make_syncer, fake, local_dir):
    """End-to-end: deletions over the threshold are reported as planned-delete with the
    suppressed reason, and the pass-level suppressed_deletes banner counts them."""
    syncer, store = make_syncer(delete_threshold_count=1, delete_threshold_pct=1)
    for n in range(4):
        write_file(local_dir, f"f{n}.md", b"x", mtime=1000)
    syncer.sync_once()  # baseline 4 files
    for n in range(4):
        (local_dir / f"f{n}.md").unlink()  # 4 local deletes -> 4 DELETE_REMOTE > threshold

    plan = syncer.plan()
    assert plan.suppressed_deletes >= 4
    deletes = [r for r in plan.rows if r.state == "planned-delete"]
    assert deletes and all(r.reason == "suppressed (over delete threshold)" for r in deletes)
    store.close()


def test_kind_conflict_counts_as_error_via_plan(make_syncer, fake, local_dir):
    """End-to-end: a file-on-one-side / dir-on-the-other is counted in plan.errors and is
    EXCLUDED before decide, so it produces no row (only the count flows through)."""
    syncer, store = make_syncer()
    write_file(local_dir, "x", b"file-here", mtime=1000)  # local: file named "x"
    fake.mkdir("x")  # remote: dir named "x"

    plan = syncer.plan()
    assert plan.errors == 1
    assert all(r.relpath != "x" for r in plan.rows)
    store.close()


def test_classify_maps_cover_every_decision_op():
    """Closure guard: every Op the decide phase can return is either mapped to a report state
    or is an intended in-sync no-op. A future Op added to decide without a plan-state entry
    would otherwise be SILENTLY dropped from the doctor report — this turns that into a CI
    failure (mirroring the _FILE_DECISION_OPS closure intent in syncer.py)."""
    assert _FILE_DECISION_OPS <= set(_FILE_PLAN_STATE) | {Op.RECORD}
    # dir create-side and cleanup-side deciders, against their maps + the dir no-ops
    assert {Op.MKDIR_REMOTE, Op.MKDIR_LOCAL} <= set(_DIR_PLAN_STATE)
    assert {Op.RMDIR_REMOTE, Op.RMDIR_LOCAL, Op.DROP_BASELINE_DIR} <= set(_CLEANUP_PLAN_STATE)


def test_cmd_doctor_json_is_read_only(tmp_path, monkeypatch, capsys, fake):
    """The CLI entrypoint end-to-end: `doctor --json` against an injected fake client emits
    the schema-1 envelope and performs no write IO and no remote-root mkdir."""
    sandbox_home(tmp_path, monkeypatch)
    local = tmp_path / "vault"
    local.mkdir()
    write_file(local, "a.md", b"a", mtime=1000)
    cfg = Config(apple_id="x@y.com", remote_folder="", local_folder=str(local))
    cfg.save(config_path("default"))
    monkeypatch.setattr(
        "ifolder_sync.icloud_client.ICloudClient.from_config",
        classmethod(lambda cls, c: fake),
    )

    args = argparse.Namespace(profile="default", json=True, non_interactive=True)
    cmd_doctor(args)

    data = json.loads(capsys.readouterr().out)
    assert data["schema"] == SCHEMA
    assert any(r["state"] == "planned-upload" and r["relpath"] == "a.md" for r in data["rows"])
    for io in ("upload", "download", "delete", "mkdir", "ensure_remote_root"):
        assert fake.calls[io] == 0, f"{io} happened during a read-only doctor"


# ------------------------------------------------ --fix-orphans (Phase 3 remediation) ---
def _setup_doctor_cli(tmp_path, monkeypatch, fake):
    sandbox_home(tmp_path, monkeypatch)
    local = tmp_path / "vault"
    local.mkdir()
    Config(apple_id="x@y.com", local_folder=str(local)).save(config_path("default"))
    monkeypatch.setattr(
        "ifolder_sync.icloud_client.ICloudClient.from_config",
        classmethod(lambda cls, c: fake),
    )
    return local


def test_fix_orphans_unit_drops_only_orphans_and_backs_up(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    db = baseline_path("default")
    with StateStore(db) as s:
        s.upsert(BaselineEntry("ghost.md", "file", 7, 1.0, 7, 1.0))
        s.upsert(BaselineEntry("keep.md", "file", 1, 1000.0, 1, 1000.0))
        s.set_meta("walk_cache", "stale")

    plan = Plan(rows=[SyncRow("ghost.md", "orphan-baseline"), SyncRow("keep.md", "planned-delete")])
    with StateStore(db) as s:
        count, bak = _fix_orphans(plan, "default", s)

    assert count == 1 and bak.exists()  # only the orphan, with a backup taken first
    with StateStore(db, read_only=True) as s:
        rows = s.all()
        assert "ghost.md" not in rows  # orphan dropped
        assert "keep.md" in rows  # the non-orphan row is untouched
        assert s.get_meta("walk_cache") == ""  # stale cache cleared
    # the backup is a USABLE recovery net: a real pre-drop copy holding the dropped orphan
    with StateStore(bak, read_only=True) as b:
        assert "ghost.md" in b.all() and "keep.md" in b.all()


def test_fix_orphans_via_cli_drops_orphan_keeps_synced(tmp_path, monkeypatch, fake):
    local = _setup_doctor_cli(tmp_path, monkeypatch, fake)
    write_file(local, "keep.md", b"k", mtime=1000)
    fake.put("keep.md", b"k", mtime=1000)  # in sync on both sides
    db = baseline_path("default")
    with StateStore(db) as s:
        s.upsert(BaselineEntry("keep.md", "file", 1, 1000.0, 1, 1000.0))
        s.upsert(BaselineEntry("Music/song.md", "file", 7, 1.0, 7, 1.0))  # orphan
        s.set_meta("walk_cache", "stale")

    args = argparse.Namespace(profile="default", json=False, non_interactive=True, fix_orphans=True)
    cmd_doctor(args)

    with StateStore(db, read_only=True) as s:
        rows = s.all()
        assert "Music/song.md" not in rows  # orphan dropped
        assert "keep.md" in rows  # the in-sync row survives
        assert s.get_meta("walk_cache") == ""
    assert len(list(db.parent.glob("baseline.sqlite3.pre-fix-orphans-*"))) == 1  # backup made


def test_fix_orphans_refuses_while_daemon_running(tmp_path, monkeypatch, fake, capsys):
    _setup_doctor_cli(tmp_path, monkeypatch, fake)
    with StateStore(baseline_path("default")) as s:
        s.upsert(BaselineEntry("ghost.md", "file", 7, 1.0, 7, 1.0))
        s.commit()
    monkeypatch.setattr("ifolder_sync.cli.holder_pid", lambda _p: 4242)  # daemon "running"

    args = argparse.Namespace(profile="default", json=False, non_interactive=True, fix_orphans=True)
    with pytest.raises(SystemExit) as exc:
        cmd_doctor(args)

    assert exc.value.code != 0
    assert "daemon is running" in capsys.readouterr().err
    # refused BEFORE any work: the orphan is still present
    with StateStore(baseline_path("default"), read_only=True) as s:
        assert "ghost.md" in s.all()


def test_fix_orphans_json_reports_count_and_backup(tmp_path, monkeypatch, fake, capsys):
    _setup_doctor_cli(tmp_path, monkeypatch, fake)
    with StateStore(baseline_path("default")) as s:
        s.upsert(BaselineEntry("ghost.md", "file", 7, 1.0, 7, 1.0))
        s.commit()

    args = argparse.Namespace(profile="default", json=True, non_interactive=True, fix_orphans=True)
    cmd_doctor(args)

    data = json.loads(capsys.readouterr().out)
    assert data["fixed_orphans"] == 1
    assert data["backup"] is not None


def test_fix_orphans_is_idempotent(tmp_path, monkeypatch, fake, capsys):
    _setup_doctor_cli(tmp_path, monkeypatch, fake)
    with StateStore(baseline_path("default")) as s:
        s.upsert(BaselineEntry("ghost.md", "file", 7, 1.0, 7, 1.0))
        s.commit()

    args = argparse.Namespace(profile="default", json=True, non_interactive=True, fix_orphans=True)
    cmd_doctor(args)  # first run drops the orphan
    assert json.loads(capsys.readouterr().out)["fixed_orphans"] == 1

    cmd_doctor(args)  # second run: nothing left to fix
    data = json.loads(capsys.readouterr().out)
    assert data["fixed_orphans"] == 0 and data["backup"] is None
    # the clean run wrote exactly one backup (from the first run), none from the second
    assert (
        len(list(baseline_path("default").parent.glob("baseline.sqlite3.pre-fix-orphans-*"))) == 1
    )


def test_fix_orphans_aborts_on_scan_failure_drops_nothing(tmp_path, monkeypatch, fake):
    """The headline safety claim, through the WRITE path: a failing scan aborts --fix-orphans
    BEFORE any drop or backup — a partial scan can never mislabel a live path as orphan."""
    _setup_doctor_cli(tmp_path, monkeypatch, fake)
    db = baseline_path("default")
    with StateStore(db) as s:
        s.upsert(BaselineEntry("ghost.md", "file", 7, 1.0, 7, 1.0))
        s.commit()
    fake.fail_walk = True  # the remote walk raises -> plan() aborts before _fix_orphans

    args = argparse.Namespace(profile="default", json=False, non_interactive=True, fix_orphans=True)
    with pytest.raises(RuntimeError):
        cmd_doctor(args)

    with StateStore(db, read_only=True) as s:
        assert "ghost.md" in s.all()  # untouched
    assert list(db.parent.glob("baseline.sqlite3.pre-fix-orphans-*")) == []  # no backup written


def test_fix_orphans_backup_failure_aborts_drop(tmp_path, monkeypatch, fake):
    """Atomicity: if the backup fails, the drop must NOT happen (backup ALWAYS precedes drop)."""
    _setup_doctor_cli(tmp_path, monkeypatch, fake)
    db = baseline_path("default")
    with StateStore(db) as s:
        s.upsert(BaselineEntry("ghost.md", "file", 7, 1.0, 7, 1.0))
        s.commit()
    monkeypatch.setattr(
        StateStore, "backup_to", lambda self, dest: (_ for _ in ()).throw(OSError("disk full"))
    )

    args = argparse.Namespace(profile="default", json=False, non_interactive=True, fix_orphans=True)
    with pytest.raises(OSError):
        cmd_doctor(args)

    monkeypatch.undo()
    with StateStore(db, read_only=True) as s:
        assert "ghost.md" in s.all()  # the drop never ran


def test_fix_orphans_keeps_planned_delete_and_conflict_rows(tmp_path, monkeypatch, fake):
    """Drops ONLY the orphan: a planned-delete row and a would-conflict row (both real engine
    classifications, not orphans) must survive --fix-orphans."""
    local = _setup_doctor_cli(tmp_path, monkeypatch, fake)
    write_file(local, "conf.md", b"local-edit", mtime=6000)  # local changed
    fake.put("conf.md", b"remote-edit-differs", mtime=7000)  # remote changed -> would-conflict
    fake.put("del.md", b"d", mtime=1000)  # remote-only present (local deleted) -> planned-delete
    db = baseline_path("default")
    with StateStore(db) as s:
        s.upsert(BaselineEntry("ghost.md", "file", 7, 1.0, 7, 1.0))  # orphan
        s.upsert(BaselineEntry("del.md", "file", 1, 1000.0, 1, 1000.0))  # -> DELETE_REMOTE
        s.upsert(BaselineEntry("conf.md", "file", 4, 5000.0, 4, 5000.0))  # -> CONFLICT
        s.commit()

    args = argparse.Namespace(profile="default", json=False, non_interactive=True, fix_orphans=True)
    cmd_doctor(args)

    with StateStore(db, read_only=True) as s:
        rows = s.all()
        assert "ghost.md" not in rows  # only the orphan dropped
        assert "del.md" in rows and "conf.md" in rows  # the real-action rows survive


def test_fix_orphans_skips_present_but_ignored_file(tmp_path, monkeypatch, fake):
    """A file still on disk but newly-ignored is absent from the FILTERED scans (so it looks
    orphan) yet is NOT a ghost — --fix-orphans keeps its row rather than discarding a live
    file's baseline."""
    sandbox_home(tmp_path, monkeypatch)
    local = tmp_path / "vault"
    local.mkdir()
    Config(apple_id="x@y.com", local_folder=str(local), ignore=[".DS_Store", "*.tmp"]).save(
        config_path("default")
    )
    monkeypatch.setattr(
        "ifolder_sync.icloud_client.ICloudClient.from_config", classmethod(lambda cls, c: fake)
    )
    write_file(local, "junk.tmp", b"x", mtime=1000)  # present locally, but matched by ignore
    db = baseline_path("default")
    with StateStore(db) as s:
        s.upsert(BaselineEntry("junk.tmp", "file", 1, 1000.0, 1, 1000.0))
        s.commit()

    args = argparse.Namespace(profile="default", json=False, non_interactive=True, fix_orphans=True)
    cmd_doctor(args)

    with StateStore(db, read_only=True) as s:
        assert "junk.tmp" in s.all()  # not dropped (present-but-ignored, not a ghost)
    assert list(db.parent.glob("baseline.sqlite3.pre-fix-orphans-*")) == []  # nothing to back up


def test_fix_orphans_refuses_when_lock_held(tmp_path, monkeypatch, fake, capsys):
    """The TOCTOU fix: even if holder_pid reads stale/None (the boot-jitter window), the real
    SingleInstanceLock is held, so --fix-orphans refuses instead of racing the baseline."""
    _setup_doctor_cli(tmp_path, monkeypatch, fake)
    with StateStore(baseline_path("default")) as s:
        s.upsert(BaselineEntry("ghost.md", "file", 7, 1.0, 7, 1.0))
        s.commit()
    held = SingleInstanceLock(lock_path("default"))
    held.acquire()
    monkeypatch.setattr("ifolder_sync.cli.holder_pid", lambda _p: None)  # stale-pid window

    args = argparse.Namespace(profile="default", json=False, non_interactive=True, fix_orphans=True)
    try:
        with pytest.raises(SystemExit):
            cmd_doctor(args)
        assert "race the baseline" in capsys.readouterr().err
        with StateStore(baseline_path("default"), read_only=True) as s:
            assert "ghost.md" in s.all()  # never dropped
    finally:
        held.release()


def test_fix_orphans_drops_dir_orphan(tmp_path, monkeypatch, fake):
    """A directory orphan (DROP_BASELINE_DIR) is dropped via --fix-orphans like a file one."""
    _setup_doctor_cli(tmp_path, monkeypatch, fake)
    db = baseline_path("default")
    with StateStore(db) as s:
        s.upsert(BaselineEntry("olddir", "dir", 0, 0.0, 0, 0.0))
        s.commit()

    args = argparse.Namespace(profile="default", json=False, non_interactive=True, fix_orphans=True)
    cmd_doctor(args)

    with StateStore(db, read_only=True) as s:
        assert "olddir" not in s.all()
