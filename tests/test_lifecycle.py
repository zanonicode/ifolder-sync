"""Modern launchd control plane (feature 06): command construction, code-classification,
`launchctl print` parsing, and the verify-post-condition.

The suite cannot run launchd, so it asserts the EXACT arg-vectors the lifecycle commands
hand to launchctl (by recording a stubbed `_lc`), the per-verb exit-code classification
(bootout rc 3 = already-stopped; print rc 113 = not loaded), the 3-state parse from REAL
`launchctl print` output captured on macOS 26.5, and that `_verify` times out to a
not-running result for a daemon that never comes up (invariant-9 safe, AT-003). No test
shells out to real launchctl.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

import ifolder_sync.cli as cli
from ifolder_sync.cli import (
    DaemonState,
    _converge_start,
    _converge_stop,
    _observe_daemon,
    _target,
    _verify,
)

from .helpers import sandbox_home

# Real `launchctl print gui/<uid>/<label>` body for a running daemon, captured 2026-06-20
# on macOS 26.5. Trimmed to the fields the parser reads (it tolerates the rest).
PRINT_RUNNING = """\
com.ifolder-sync.work = {
	active count = 1
	path = /Users/x/Library/LaunchAgents/com.ifolder-sync.work.plist
	state = running
	program = /usr/bin/python3
	pid = 99468
	last exit code = (never exited)
}
"""

# A transitioning/odd state: loaded but not running (e.g. waiting to spawn). rc 0, no pid.
PRINT_WAITING = """\
com.ifolder-sync.work = {
	state = waiting
	last exit code = 0
}
"""


def _recording_lc(responder):
    """A fake `_lc` that records every arg-vector and delegates the response to `responder`
    (verb -> CompletedProcess-like). Exposes `.calls` for ordering/target assertions."""
    calls: list[list[str]] = []

    def lc(*args: str):
        calls.append(list(args))
        return responder(args)

    lc.calls = calls  # type: ignore[attr-defined]
    return lc


def _ok(*, returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


# ----------------------------------------------------------------- _target ---
def test_target_uses_uid_and_label():
    domain, target = _target("work")
    assert domain == f"gui/{os.getuid()}"
    assert target == f"gui/{os.getuid()}/com.ifolder-sync.work"


# ------------------------------------------------- converge command construction ---
def _settled_responder(extra=None):
    """Default `_lc` responder for converge tests: `print` reports NOT loaded (rc 113) so the
    async bootout-settle wait returns immediately; every other verb succeeds. `extra(args)` may
    override specific verbs (return a CompletedProcess-like, or None to fall through)."""

    def responder(args):
        if extra is not None:
            r = extra(args)
            if r is not None:
                return r
        if args[0] == "print":
            return _ok(returncode=113)  # not loaded -> settle wait returns at once
        return _ok()

    return responder


def test_converge_start_issues_modern_chain_in_order(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    lc = _recording_lc(_settled_responder())
    monkeypatch.setattr(cli, "_lc", lc)

    _converge_start("work")

    domain, target = _target("work")
    verbs = [c[0] for c in lc.calls]
    # bootout, a settle-poll (print rc 113), enable BEFORE bootstrap, bootstrap, kickstart -k.
    assert verbs == ["bootout", "print", "enable", "bootstrap", "kickstart"]
    assert lc.calls[0] == ["bootout", target]
    assert verbs.index("enable") < verbs.index("bootstrap")  # EIO-5 regression guard (FIX #27)
    bootstrap = next(c for c in lc.calls if c[0] == "bootstrap")
    assert bootstrap[1] == domain and bootstrap[2].endswith("com.ifolder-sync.work.plist")
    assert lc.calls[-1] == ["kickstart", "-k", target]


def test_converge_start_ignores_bootout_rc3(tmp_path, monkeypatch):
    """A not-loaded prior job (bootout rc 3) must not abort the start chain."""
    sandbox_home(tmp_path, monkeypatch)

    def extra(args):
        if args[0] == "bootout":
            return _ok(returncode=3, stderr="Boot-out failed: 3: No such process")
        return None

    lc = _recording_lc(_settled_responder(extra))
    monkeypatch.setattr(cli, "_lc", lc)

    _converge_start("work")  # must not raise despite rc 3

    assert [c[0] for c in lc.calls] == ["bootout", "print", "enable", "bootstrap", "kickstart"]


def test_converge_start_waits_for_bootout_to_settle(tmp_path, monkeypatch):
    """bootout is async: _converge_start polls `print` until the label unloads (rc 113) before
    bootstrapping, so a slow teardown never races the EIO-5 that would leave the job down."""
    sandbox_home(tmp_path, monkeypatch)
    state = {"prints": 0}

    def extra(args):
        if args[0] == "print":
            state["prints"] += 1
            # still loaded for the first two polls, then unloaded
            if state["prints"] < 3:
                return _ok(returncode=0, stdout=PRINT_RUNNING)
            return _ok(returncode=113)
        return None

    lc = _recording_lc(_settled_responder(extra))
    monkeypatch.setattr(cli, "_lc", lc)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)

    _converge_start("work")

    verbs = [c[0] for c in lc.calls]
    bootstrap_idx = verbs.index("bootstrap")
    settle_prints = [i for i, c in enumerate(lc.calls) if c[0] == "print" and i < bootstrap_idx]
    assert len(settle_prints) >= 3  # waited for the label to unload before bootstrapping


def test_converge_start_recovers_when_bootstrap_races_but_loaded(tmp_path, monkeypatch):
    """A post-bootout EIO-5 where the label is nonetheless LOADED must NOT exit / leave the
    daemon down: _bootstrap_with_retry treats loaded-despite-error as success so the trailing
    `kickstart -k` force-respawns it. A restart is atomic — it never ends stopped."""
    sandbox_home(tmp_path, monkeypatch)
    state = {"prints": 0}

    def extra(args):
        if args[0] == "bootstrap":
            return _ok(returncode=5, stderr="Bootstrap failed: 5: Input/output error")
        if args[0] == "print":
            state["prints"] += 1
            # settle wait: not loaded (113); post-bootstrap probe: LOADED (rc 0)
            if state["prints"] == 1:
                return _ok(returncode=113)
            return _ok(returncode=0, stdout=PRINT_RUNNING)
        return None

    lc = _recording_lc(_settled_responder(extra))
    monkeypatch.setattr(cli, "_lc", lc)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)

    _converge_start("work")  # must NOT raise

    assert lc.calls[-1][0] == "kickstart"  # recovered -> force-respawn happened


def test_converge_start_exits_when_bootstrap_never_loads(tmp_path, monkeypatch):
    """A genuine bootstrap failure where the label never loads still fails loud (exit ERROR)
    after the bounded retry — truthful, never a false success."""
    sandbox_home(tmp_path, monkeypatch)

    def extra(args):
        if args[0] == "bootstrap":
            return _ok(returncode=5, stderr="Bootstrap failed: 5: Input/output error")
        return None  # print falls through to rc 113 (never loads)

    monkeypatch.setattr(cli, "_lc", _recording_lc(_settled_responder(extra)))
    clock = {"t": 0.0}

    def tick() -> float:
        clock["t"] += 1.0
        return clock["t"]

    monkeypatch.setattr(cli.time, "monotonic", tick)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)

    with pytest.raises(SystemExit) as exc:
        _converge_start("work")
    assert exc.value.code == cli.Exit.ERROR


def test_converge_stop_issues_bootout_only(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    lc = _recording_lc(lambda args: _ok())
    monkeypatch.setattr(cli, "_lc", lc)

    assert _converge_stop("work") is True

    _, target = _target("work")
    assert lc.calls == [["bootout", target]]


def test_converge_stop_treats_rc3_as_success(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(
        cli, "_lc", lambda *a: _ok(returncode=3, stderr="Boot-out failed: 3: No such process")
    )
    assert _converge_stop("work") is True  # not loaded == already stopped


def test_converge_stop_reports_unexpected_failure(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_lc", lambda *a: _ok(returncode=9, stderr="permission denied"))
    assert _converge_stop("work") is False


# --------------------------------------------- _observe_daemon parse (3 states) ---
def test_observe_running_from_real_print(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_lc", lambda *a: _ok(stdout=PRINT_RUNNING))

    st = _observe_daemon("work")
    assert st.state == "running" and st.pid == 99468 and st.foreground is False
    assert st.is_running is True


def test_observe_not_loaded_no_lock_is_stopped(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_lc", lambda *a: _ok(returncode=113, stderr="not found"))
    monkeypatch.setattr(cli, "holder_pid", lambda _p: None)

    st = _observe_daemon("work")
    assert st.state == "stopped" and st.pid is None


def test_observe_not_loaded_with_lock_is_foreground(tmp_path, monkeypatch):
    """print rc 113 but a live lock holder = a foreground daemon (Decision 5)."""
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_lc", lambda *a: _ok(returncode=113, stderr="not found"))
    monkeypatch.setattr(cli, "holder_pid", lambda _p: 4321)

    st = _observe_daemon("work")
    assert st.state == "running" and st.pid == 4321 and st.foreground is True


def test_observe_odd_state_is_unknown(tmp_path, monkeypatch):
    """rc 0 but a non-running/transitioning state -> unknown, never a false 'stopped'."""
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_lc", lambda *a: _ok(stdout=PRINT_WAITING))

    st = _observe_daemon("work")
    assert st.state == "unknown" and "waiting" in st.detail


def test_observe_other_rc_is_unknown(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_lc", lambda *a: _ok(returncode=1, stderr="boom"))

    st = _observe_daemon("work")
    assert st.state == "unknown" and "rc=1" in st.detail


# ------------------------------------------------------------- _verify timeout ---
def test_verify_times_out_for_never_up_daemon(tmp_path, monkeypatch):
    """AT-003: a daemon that exits 0 on preflight (invariant 9) never comes up, so verify must
    TIME OUT to a not-running observation (the caller then reports failure), never hang."""
    sandbox_home(tmp_path, monkeypatch)
    observations: list[int] = []

    def never_up(_profile):
        observations.append(1)
        return DaemonState.stopped()

    monkeypatch.setattr(cli, "_observe_daemon", never_up)

    # Fake clock: advances 0.1s per read so the bounded poll terminates deterministically.
    clock = {"t": 0.0}

    def tick() -> float:
        clock["t"] += 0.1
        return clock["t"]

    monkeypatch.setattr(cli.time, "monotonic", tick)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)

    st = _verify("work", want_running=True, timeout=0.5)
    assert st.is_running is False
    assert len(observations) >= 1  # it polled, then gave up at the deadline


def test_verify_returns_running_when_post_condition_holds(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_observe_daemon", lambda _p: DaemonState.running(123))
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)

    st = _verify("work", want_running=True, timeout=5.0)
    assert st.is_running and st.pid == 123


def test_verify_stop_returns_stopped_when_gone(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_observe_daemon", lambda _p: DaemonState.stopped())
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)

    st = _verify("work", want_running=False, timeout=5.0)
    assert st.is_running is False


# --------------------------------------------------- DaemonState status contract ---
def test_daemonstate_to_status_keeps_legacy_keys():
    """The dashboard/`--json` contract keeps the legacy running/pid keys and adds state."""
    running = DaemonState.running(42).to_status()
    assert running == {"running": True, "pid": 42, "state": "running", "foreground": False}
    fg = DaemonState.running(7, foreground=True).to_status()
    assert fg["foreground"] is True and fg["running"] is True
    stopped = DaemonState.stopped().to_status()
    assert stopped == {"running": False, "pid": None, "state": "stopped", "foreground": False}
    unknown = DaemonState.unknown("state='waiting'").to_status()
    assert unknown["state"] == "unknown" and unknown["running"] is False


# ----------------------------------------------- throttle-aware (re)start verify ---
def test_start_verify_timeout_outlasts_throttle():
    """The (re)start post-condition wait must OUTLAST launchd's ThrottleInterval, or a throttled
    fresh spawn is falsely reported as 'failed to start' (the daemon comes up ~ThrottleInterval
    seconds later). The floor follows the CONFIGURED throttle; a longer user verify timeout wins."""
    from ifolder_sync.config import Config

    cfg = Config()  # default throttle dominates the short default verify timeout
    assert cli._start_verify_timeout(cfg) == (
        cfg.throttle_interval_seconds + cli._VERIFY_BUFFER_SECONDS
    )
    # tracks the configured throttle, not a hardcoded constant
    assert cli._start_verify_timeout(Config(throttle_interval_seconds=42)) == (
        42 + cli._VERIFY_BUFFER_SECONDS
    )
    # a longer user-configured verify timeout is still honored
    assert (
        cli._start_verify_timeout(
            Config(throttle_interval_seconds=15, lifecycle_verify_timeout_seconds=120.0)
        )
        == 120.0
    )


def test_throttle_interval_reads_config(tmp_path, monkeypatch):
    """The plist's ThrottleInterval is single-sourced from Config (not hardcoded), defaulting
    cleanly when the config is absent/unreadable."""
    from ifolder_sync.config import Config, config_path

    sandbox_home(tmp_path, monkeypatch)
    assert cli._throttle_interval("work") == Config().throttle_interval_seconds  # absent -> default
    Config(apple_id="a@b.com", local_folder=str(tmp_path), throttle_interval_seconds=42).save(
        config_path("work")
    )
    assert cli._throttle_interval("work") == 42


def test_restart_accepts_background_flag():
    """`restart --background` must parse (symmetry with `start`) instead of erroring
    'unrecognized arguments: --background'."""
    args = cli.build_parser().parse_args(["restart", "--background", "--profile", "work"])
    assert args.background is True and args.profile == "work" and args.func is cli.cmd_restart
