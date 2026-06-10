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


def _ok_run() -> MagicMock:
    return MagicMock(return_value=MagicMock(returncode=0, stderr="", stdout=""))


def test_write_agent_plist(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    plist = _write_agent_plist("work")
    assert plist == tmp_path / "Library" / "LaunchAgents" / "com.ifolder-sync.work.plist"
    assert plist.exists()
    body = plist.read_text()
    assert "<string>com.ifolder-sync.work</string>" in body
    assert "<string>--profile</string>" in body
    assert "<string>work</string>" in body


def test_start_background_loads_agent(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    run = _ok_run()
    monkeypatch.setattr(cli.subprocess, "run", run)

    main(["start", "--background", "--profile", "work"])

    cmd = run.call_args[0][0]
    assert cmd[:3] == ["launchctl", "load", "-w"]
    assert cmd[3].endswith("com.ifolder-sync.work.plist")
    assert str(tmp_path) in cmd[3]  # wrote into the sandbox, not the real ~/Library
    assert run.call_args[1]["check"] is False
    assert run.call_args[1]["capture_output"] is True


def test_stop_unloads_agent(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    _write_agent_plist("work")  # the plist must exist for stop to act
    run = _ok_run()
    monkeypatch.setattr(cli.subprocess, "run", run)

    main(["stop", "--profile", "work"])

    cmd = run.call_args[0][0]
    assert cmd[:3] == ["launchctl", "unload", "-w"]
    assert cmd[3].endswith("com.ifolder-sync.work.plist")


def test_stop_without_plist_is_graceful(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    run = _ok_run()
    monkeypatch.setattr(cli.subprocess, "run", run)

    main(["stop", "--profile", "work"])  # no plist -> nothing to unload

    run.assert_not_called()


def test_launchctl_benign_already_loaded_does_not_exit(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    run = MagicMock(
        return_value=MagicMock(returncode=1, stderr="/x.plist: service already loaded", stdout="")
    )
    monkeypatch.setattr(cli.subprocess, "run", run)

    main(["start", "--background", "--profile", "work"])  # benign stderr -> no SystemExit


def test_launchctl_real_failure_exits(tmp_path, monkeypatch):
    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    run = MagicMock(
        return_value=MagicMock(returncode=1, stderr="Bootstrap failed: 5: I/O error", stdout="")
    )
    monkeypatch.setattr(cli.subprocess, "run", run)

    with pytest.raises(SystemExit):
        main(["start", "--background", "--profile", "work"])


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

    main(["status", "--profile", "work"])

    out = capsys.readouterr().out  # captured output is not a TTY -> no ANSI codes
    assert "Daemon:        stopped" in out


def test_status_shows_daemon_running_with_pid(tmp_path, monkeypatch, capsys):
    import os

    from ifolder_sync.config import lock_path

    _sandbox(tmp_path, monkeypatch)
    _make_profile_config("work")
    lock_path("work").write_text(str(os.getpid()))  # a live pid holds the lock

    main(["status", "--profile", "work"])

    out = capsys.readouterr().out
    assert f"Daemon:        running (pid {os.getpid()})" in out


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
        if "Local folder" in prompt:
            return str(tmp_path / "vault")
        return ""

    monkeypatch.setattr("builtins.input", fake_input)
    main(["init", "--obsidian", "--profile", "work"])

    assert not any("Obsidian" in p for p in prompts)
    cfg = Config.load(config_path("work"))
    assert cfg.obsidian is True
