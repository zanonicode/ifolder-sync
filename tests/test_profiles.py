"""Multi-folder profiles: path resolution, legacy migration, isolation, launchd label
(AT-13 isolation, AT-14 default back-compat, AT-15 per-profile launchd).

All tests redirect XDG_CONFIG_HOME to a temp dir so the real ~/.config is never touched.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

import ifolder_sync.cli as cli
from ifolder_sync.cli import _agent_label, _write_agent_plist, main
from ifolder_sync.config import (
    Config,
    baseline_path,
    config_path,
    list_profiles,
    lock_path,
    migrate_legacy,
    sessions_dir,
    state_dir,
    trash_dir,
)
from ifolder_sync.state import StateStore
from ifolder_sync.syncer import Syncer

from .helpers import PERMISSIVE_THRESHOLDS, FakeICloud, sandbox_home, write_file


@pytest.fixture(autouse=True)
def _no_real_launchctl(monkeypatch):
    """The suite must never shell out to real launchctl. Default `_lc` to a not-loaded job
    (print rc 113); tests that assert command construction or liveness override it."""
    monkeypatch.setattr(
        cli,
        "_lc",
        lambda *a: MagicMock(returncode=113, stdout="", stderr="not found"),
    )


def test_profile_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    root = tmp_path / "ifolder-sync"
    assert config_path("work") == root / "profiles" / "work.json"
    assert state_dir("work") == root / "state" / "work"
    assert (root / "state" / "work").is_dir()  # state_dir mkdirs
    assert baseline_path("work") == root / "state" / "work" / "baseline.sqlite3"
    assert lock_path("work") == root / "state" / "work" / "daemon.lock"
    assert trash_dir("work") == root / "state" / "work" / "trash"
    assert sessions_dir() == root / "state" / "sessions"  # shared across profiles
    assert state_dir("a") != state_dir("b")


def test_list_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    pdir = tmp_path / "ifolder-sync" / "profiles"
    pdir.mkdir(parents=True)
    (pdir / "default.json").write_text("{}")
    (pdir / "work.json").write_text("{}")
    assert list_profiles() == ["default", "work"]


def test_migrate_legacy_to_default(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    home = tmp_path / "ifolder-sync"
    legacy_state = home / "state"
    legacy_state.mkdir(parents=True)
    (home / "config.json").write_text(json.dumps({"apple_id": "a@b.com", "local_folder": "/tmp/v"}))
    (legacy_state / "baseline.sqlite3").write_text("db")
    (legacy_state / "zanoni.session").write_text("s")
    (legacy_state / "zanoni.cookiejar").write_text("c")
    (legacy_state / "trash").mkdir()
    (legacy_state / "trash" / "old.md").write_text("x")

    assert migrate_legacy() is True

    assert config_path("default").exists()
    assert not (home / "config.json").exists()
    assert baseline_path("default").exists()
    assert (sessions_dir() / "zanoni.session").exists()
    assert (sessions_dir() / "zanoni.cookiejar").exists()
    assert (trash_dir("default") / "old.md").exists()
    # AT-14: the migrated default config loads and is usable
    cfg = Config.load(config_path("default"))
    assert cfg.apple_id == "a@b.com"
    # idempotent: a second run moves nothing
    assert migrate_legacy() is False


def test_profiles_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    local_a = tmp_path / "vault_a"
    local_b = tmp_path / "vault_b"
    local_a.mkdir()
    local_b.mkdir()
    fake_a, fake_b = FakeICloud(), FakeICloud()
    perm = PERMISSIVE_THRESHOLDS
    cfg_a = Config(apple_id="a@b.com", local_folder=str(local_a), **perm)
    cfg_b = Config(apple_id="a@b.com", local_folder=str(local_b), **perm)
    store_a = StateStore(baseline_path("a"))
    store_b = StateStore(baseline_path("b"))
    sync_a = Syncer(cfg_a, fake_a, store_a, trash_dir=trash_dir("a"))
    sync_b = Syncer(cfg_b, fake_b, store_b, trash_dir=trash_dir("b"))

    write_file(local_a, "note.md", b"hi", mtime=1000)
    sync_a.sync_once()
    sync_b.sync_once()  # profile b is a real but empty sync -> stays empty

    assert baseline_path("a") != baseline_path("b")
    assert "note.md" in store_a.all()  # profile a tracked it
    assert store_b.all() == {}  # profile b untouched
    assert "note.md" in fake_a.files
    assert fake_b.files == {}
    store_a.close()
    store_b.close()


def test_agent_label():
    assert _agent_label("work") == "com.ifolder-sync.work"
    assert _agent_label("default") == "com.ifolder-sync.default"


# --- background start/stop via launchd, and status-all ------------------------


_sandbox = sandbox_home


def _make_profile_config(profile: str, **overrides) -> None:
    """Persist a minimal valid config (validate() needs apple_id + local_folder)."""
    Config(apple_id="x@y.com", local_folder="/tmp/vault", **overrides).save(config_path(profile))


_PRINT_RUNNING = "\tstate = running\n\tpid = {pid}\n\tlast exit code = (never exited)\n"


def _fake_lc(running_pid: int | None = None, bootstrap_rc: int = 0):
    """A fake `_lc` recording every launchctl arg-vector. `running_pid` makes `print` report
    a running daemon (so a verify after start succeeds); None makes `print` return rc 113
    (not loaded). Other verbs return rc 0 unless bootstrap_rc overrides bootstrap."""
    calls: list[list[str]] = []

    def lc(*args: str):
        calls.append(list(args))
        verb = args[0]
        if verb == "print":
            if running_pid is None:
                return MagicMock(returncode=113, stdout="", stderr="not found")
            return MagicMock(returncode=0, stdout=_PRINT_RUNNING.format(pid=running_pid), stderr="")
        if verb == "bootstrap":
            err = "boom" if bootstrap_rc else ""
            return MagicMock(returncode=bootstrap_rc, stdout="", stderr=err)
        return MagicMock(returncode=0, stdout="", stderr="")

    lc.calls = calls  # type: ignore[attr-defined]
    return lc


def _fast_launchd_timing(monkeypatch):
    """Collapse the bounded launchd waits (bootout-settle, bootstrap-retry, throttle-aware
    verify floor) to zero so these command-FLOW tests exercise the logic without real sleeps.
    The real bounded-wait behavior is unit-tested in test_lifecycle.py."""
    monkeypatch.setattr(cli, "_BOOTOUT_SETTLE_SECONDS", 0.0)
    monkeypatch.setattr(cli, "_BOOTSTRAP_RETRY_SECONDS", 0.0)
    monkeypatch.setattr(cli, "_THROTTLE_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(cli, "_VERIFY_BUFFER_SECONDS", 0.0)


def test_write_agent_plist(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    plist = _write_agent_plist("work")
    assert plist == tmp_path / "Library" / "LaunchAgents" / "com.ifolder-sync.work.plist"
    assert plist.exists()
    body = plist.read_text()
    assert "<string>com.ifolder-sync.work</string>" in body
    assert "<string>--profile</string>" in body
    assert "<string>work</string>" in body


def _verbs(lc) -> list[str]:
    return [c[0] for c in lc.calls]


def test_start_background_converges_and_verifies(tmp_path, monkeypatch):
    """`start --background` runs the modern converge chain (bootout -> enable -> bootstrap ->
    kickstart -k) against gui/<uid>/<label>, then verifies via `print` before claiming success."""
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    _fast_launchd_timing(monkeypatch)
    lc = _fake_lc(running_pid=4321)
    monkeypatch.setattr(cli, "_lc", lc)

    main(["start", "--background", "--profile", "work"])

    target = f"gui/{__import__('os').getuid()}/com.ifolder-sync.work"
    domain = f"gui/{__import__('os').getuid()}"
    # The converge order: bootout, enable, bootstrap, kickstart -k (print(s) for verify last).
    # enable precedes bootstrap so a legacy `unload -w` disabled label does not fail with EIO.
    converge = [c for c in lc.calls if c[0] != "print"]
    assert converge[0] == ["bootout", target]
    assert converge[1] == ["enable", target]
    assert converge[2][0] == "bootstrap" and converge[2][1] == domain
    assert converge[2][2].endswith("com.ifolder-sync.work.plist")
    assert converge[3] == ["kickstart", "-k", target]
    assert "print" in _verbs(lc)  # the post-condition was actually observed


def test_start_background_failed_verify_exits(tmp_path, monkeypatch):
    """AT-003: a daemon that never comes up (preflight exit 0, invariant 9) makes verify time
    out -> the command reports failure and exits non-zero, never false success."""
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work", lifecycle_verify_timeout_seconds=0.05)
    _fast_launchd_timing(monkeypatch)
    lc = _fake_lc(running_pid=None)  # print always 113 -> never running
    monkeypatch.setattr(cli, "_lc", lc)

    with pytest.raises(SystemExit) as exc:
        main(["start", "--background", "--profile", "work"])
    assert exc.value.code == cli.Exit.ERROR


def test_stop_boots_out_and_verifies(tmp_path, monkeypatch, capsys):
    """`stop` issues `bootout gui/<uid>/<label>` and verifies the job is gone."""
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    lc = _fake_lc(running_pid=None)  # print 113 -> already not loaded after bootout
    monkeypatch.setattr(cli, "_lc", lc)

    main(["stop", "--profile", "work"])

    target = f"gui/{__import__('os').getuid()}/com.ifolder-sync.work"
    assert ["bootout", target] in lc.calls
    assert ["print", target] in lc.calls  # the verify post-condition step was exercised
    assert "stopped" in capsys.readouterr().out


def test_stop_bootout_rc3_is_success(tmp_path, monkeypatch):
    """bootout rc 3 ("No such process") = the job was not loaded -> already-stopped success,
    no SystemExit."""
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")

    calls = []

    def lc(*args):
        calls.append(list(args))
        if args[0] == "bootout":
            return MagicMock(returncode=3, stdout="", stderr="Boot-out failed: 3: No such process")
        if args[0] == "print":
            return MagicMock(returncode=113, stdout="", stderr="not found")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli, "_lc", lc)
    main(["stop", "--profile", "work"])  # rc 3 tolerated -> no raise
    target = f"gui/{__import__('os').getuid()}/com.ifolder-sync.work"
    assert ["bootout", target] in calls and ["print", target] in calls


def test_start_bootstrap_failure_exits(tmp_path, monkeypatch):
    """A non-zero `bootstrap` is a real failure: report it and exit non-zero (no false success)."""
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    _fast_launchd_timing(monkeypatch)
    lc = _fake_lc(running_pid=None, bootstrap_rc=5)
    monkeypatch.setattr(cli, "_lc", lc)

    with pytest.raises(SystemExit) as exc:
        main(["start", "--background", "--profile", "work"])
    assert exc.value.code == cli.Exit.ERROR


def test_restart_converges_and_verifies(tmp_path, monkeypatch, capsys):
    """`restart` is a first-class verb running the same converge+verify chain (force-respawn)."""
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    _fast_launchd_timing(monkeypatch)
    lc = _fake_lc(running_pid=777)
    monkeypatch.setattr(cli, "_lc", lc)

    main(["restart", "--profile", "work"])

    target = f"gui/{__import__('os').getuid()}/com.ifolder-sync.work"
    converge = [c for c in lc.calls if c[0] != "print"]
    assert converge[0] == ["bootout", target]
    assert converge[-1] == ["kickstart", "-k", target]
    assert "restarted" in capsys.readouterr().out


def test_uninstall_stops_and_removes_plist(tmp_path, monkeypatch, capsys):
    """`uninstall` boots out the job and removes the .plist; idempotent when nothing exists."""
    _sandbox(tmp_path, monkeypatch)
    plist = _write_agent_plist("work")
    lc = _fake_lc(running_pid=None)
    monkeypatch.setattr(cli, "_lc", lc)

    main(["uninstall", "--profile", "work"])

    target = f"gui/{__import__('os').getuid()}/com.ifolder-sync.work"
    assert ["bootout", target] in lc.calls
    assert not plist.exists()  # the .plist was removed
    assert "Uninstalled" in capsys.readouterr().out

    main(["uninstall", "--profile", "work"])  # second run: nothing to remove, still clean
    assert "nothing to uninstall" in capsys.readouterr().out


def test_status_lists_all_profiles(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("default")
    _make_profile_config("work")

    main(["status"])  # bare status -> iterate every profile

    out = capsys.readouterr().out
    assert "Profiles:      default, work" in out
    assert "Profile:       default" in out
    assert "Profile:       work" in out


def test_status_single_profile_detail(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("default")
    _make_profile_config("work")

    main(["status", "--profile", "work"])  # one profile in detail only

    out = capsys.readouterr().out
    assert "Profile:       work" in out
    assert "Profile:       default" not in out


def test_status_shows_daemon_stopped(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    monkeypatch.setattr(cli, "_lc", _fake_lc(running_pid=None))  # print 113 + no lock -> stopped

    main(["status", "--profile", "work"])

    out = capsys.readouterr().out  # captured output is not a TTY -> no ANSI codes
    assert "Daemon:        stopped" in out


def test_status_shows_daemon_running_with_pid(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    # launchd reports the managed daemon running (the supervisor's own pid).
    monkeypatch.setattr(cli, "_lc", _fake_lc(running_pid=99468))

    main(["status", "--profile", "work"])

    out = capsys.readouterr().out
    assert "Daemon:        running (pid 99468)" in out


def test_status_shows_foreground_daemon_via_lock_fallback(tmp_path, monkeypatch, capsys):
    """A foreground daemon (no launchd job, print rc 113) but a live lock holder is reported
    running (foreground), not stopped — Decision 5."""
    import os

    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    lock_path("work").write_text(str(os.getpid()))  # a live pid holds the lock
    monkeypatch.setattr(cli, "_lc", _fake_lc(running_pid=None))  # no launchd job

    main(["status", "--profile", "work"])

    out = capsys.readouterr().out
    assert f"running (pid {os.getpid()}, foreground)" in out


# --- session / auth state in status -------------------------------------------

_LWP_TRUST = (
    "#LWP-Cookies-2.0\n"
    'Set-Cookie3: X-APPLE-WEBAUTH-HSA-TRUST="x"; path="/"; domain=".icloud.com"; '
    'path_spec; domain_dot; secure; expires="{exp}"; version=0\n'
)


def _write_session(trust_token: bool = True, cookie_expires: str = ""):
    from ifolder_sync.config import session_paths

    session_file, cookie_file = session_paths("x@y.com")  # matches _make_profile_config
    payload = {"session_token": "s"}
    if trust_token:
        payload["trust_token"] = "t"
    session_file.write_text(json.dumps(payload))
    if cookie_expires:
        cookie_file.write_text(_LWP_TRUST.format(exp=cookie_expires))


def _status_out(capsys) -> str:
    main(["status", "--profile", "work"])
    return capsys.readouterr().out


def test_status_session_valid(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    _write_session(cookie_expires="2035-01-01 00:00:00Z")
    assert "Session:       valid — trusted until" in _status_out(capsys)


def test_status_session_expired(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    _write_session(cookie_expires="2020-01-01 00:00:00Z")
    out = _status_out(capsys)
    assert "Session:       expired on" in out
    assert "run `ifolder-sync auth`" in out


def test_status_session_poisoned(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    _write_session(trust_token=False)
    assert "Session:       poisoned" in _status_out(capsys)


def test_status_session_not_found(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    assert "Session:       not found" in _status_out(capsys)


def test_logs_shows_tail(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    log_dir = state_dir("work") / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "daemon.err.log").write_text("".join(f"line{i}\n" for i in range(10)))

    main(["logs", "--profile", "work", "-n", "3"])

    out = capsys.readouterr().out
    assert "line9" in out and "line7" in out
    assert "line6" not in out  # only the last 3 lines


def test_logs_missing_file_is_friendly(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    main(["logs", "--profile", "work"])
    assert "No log file" in capsys.readouterr().out


def test_logs_follow_stops_on_interrupt(tmp_path, monkeypatch, capsys):
    _sandbox(tmp_path, monkeypatch)
    log_dir = state_dir("work") / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "daemon.err.log").write_text("old\n")

    def fake_sleep(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", fake_sleep)
    with pytest.raises(SystemExit) as exc:
        main(["logs", "--follow", "--profile", "work"])
    assert exc.value.code == 130  # main()'s clean Ctrl-C exit


def test_init_obsidian_flag_is_authoritative(tmp_path, monkeypatch):
    """`init --obsidian` sets the flag and skips the interactive question."""
    _sandbox(tmp_path, monkeypatch)
    prompts = []

    def fake_input(prompt):
        prompts.append(prompt)
        if "Apple ID" in prompt:
            return "x@y.com"
        if "Folder inside iCloud" in prompt:
            return "Notes"
        if "Local folder" in prompt:
            return str(tmp_path / "vault")
        return ""

    monkeypatch.setattr("builtins.input", fake_input)
    main(["init", "--obsidian", "--profile", "work"])

    assert not any("Obsidian" in p for p in prompts)
    cfg = Config.load(config_path("work"))
    assert cfg.obsidian is True


# --- Phase C Batch 1: CLI guards (plist grace, sync lock, root-scope opt-in) ----


def test_plist_sets_exit_timeout(tmp_path, monkeypatch):
    """P1-7f: the generated plist sets ExitTimeOut (graceful-shutdown window) while
    keeping the invariant-9 crash-loop keys."""
    _sandbox(tmp_path, monkeypatch)
    body = cli._write_agent_plist("work").read_text()
    assert "<key>ExitTimeOut</key>" in body
    assert "<integer>30</integer>" in body
    assert "<key>SuccessfulExit</key>" in body
    assert "<key>ThrottleInterval</key>" in body


def test_manual_sync_refused_while_lock_held(tmp_path, monkeypatch, capsys):
    """P1-8: a non-dry-run sync must not run while the single-instance lock is held."""
    from ifolder_sync.locking import SingleInstanceLock

    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", remote_folder="Notes", local_folder=str(vault)).save(
        config_path("work")
    )

    other = SingleInstanceLock(lock_path("work"))
    other.acquire()
    try:
        with pytest.raises(SystemExit):
            main(["sync", "--profile", "work"])
    finally:
        other.release()
    err = capsys.readouterr().err
    assert "baseline" in err and ("running" in err or "already running" in err)


def test_dry_run_sync_allowed_while_lock_held(tmp_path, monkeypatch):
    """P1-8: --dry-run never acquires the lock, so a preview runs even while held."""
    from ifolder_sync.locking import SingleInstanceLock

    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", remote_folder="Notes", local_folder=str(vault)).save(
        config_path("work")
    )

    held = SingleInstanceLock(lock_path("work"))
    held.acquire()
    try:
        connected = {"n": 0}

        class _StubClient:
            @classmethod
            def from_config(cls, _cfg):
                return cls()

            def connect(self, *a, **k):
                connected["n"] += 1

        import ifolder_sync.icloud_client as ic

        monkeypatch.setattr(ic, "ICloudClient", _StubClient)

        import ifolder_sync.syncer as sy

        def _stub_sync_once(self, *a, **k):
            return sy.SyncStats()

        monkeypatch.setattr(sy.Syncer, "sync_once", _stub_sync_once)

        main(["sync", "--dry-run", "--profile", "work"])
        assert connected["n"] == 1
    finally:
        held.release()


def _init_answers(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(it))


def test_init_root_requires_confirmation(tmp_path, monkeypatch):
    """P1-16: an empty remote_folder without --allow-root or the token errors out and
    writes no config."""
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    _init_answers(monkeypatch, "x@y.com", "", str(vault), "60", "newer", "n", "n", "no thanks")
    with pytest.raises(SystemExit):
        main(["init", "--profile", "work"])
    assert not config_path("work").exists()


def test_init_root_allowed_with_flag(tmp_path, monkeypatch):
    """P1-16: --allow-root accepts an empty remote_folder without a typed token."""
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    _init_answers(monkeypatch, "x@y.com", "", str(vault), "60", "newer", "n", "n")
    main(["init", "--allow-root", "--profile", "work"])
    assert Config.load(config_path("work")).remote_folder == ""


def test_init_root_confirmed_by_typed_token(tmp_path, monkeypatch):
    """P1-16: typing the exact token accepts root scope (no flag needed)."""
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    _init_answers(
        monkeypatch, "x@y.com", "", str(vault), "60", "newer", "n", "n", "SYNC ENTIRE ICLOUD"
    )
    main(["init", "--profile", "work"])
    assert Config.load(config_path("work")).remote_folder == ""


def test_init_nonempty_remote_folder_unaffected(tmp_path, monkeypatch):
    """P1-16: a normal subfolder needs no flag and no extra prompt."""
    _sandbox(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    _init_answers(monkeypatch, "x@y.com", "Notes", str(vault), "60", "newer", "n", "n")
    main(["init", "--profile", "work"])
    assert Config.load(config_path("work")).remote_folder == "Notes"
