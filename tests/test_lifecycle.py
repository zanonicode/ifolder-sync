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
def test_converge_start_issues_modern_chain_in_order(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    lc = _recording_lc(lambda args: _ok())  # every verb succeeds
    monkeypatch.setattr(cli, "_lc", lc)

    _converge_start("work")

    domain, target = _target("work")
    verbs = [c[0] for c in lc.calls]
    assert verbs == ["bootout", "enable", "bootstrap", "kickstart"]
    assert lc.calls[0] == ["bootout", target]
    # enable BEFORE bootstrap: a legacy `unload -w` leaves the label disabled in launchd's
    # store, and bootstrapping a disabled label fails with "Bootstrap failed: 5: I/O error".
    assert lc.calls[1] == ["enable", target]
    assert verbs.index("enable") < verbs.index("bootstrap")  # regression guard for the EIO-5 bug
    assert lc.calls[2][0] == "bootstrap" and lc.calls[2][1] == domain
    assert lc.calls[2][2].endswith("com.ifolder-sync.work.plist")
    assert lc.calls[3] == ["kickstart", "-k", target]


def test_converge_start_ignores_bootout_rc3(tmp_path, monkeypatch):
    """A not-loaded prior job (bootout rc 3) must not abort the start chain."""
    sandbox_home(tmp_path, monkeypatch)

    def responder(args):
        if args[0] == "bootout":
            return _ok(returncode=3, stderr="Boot-out failed: 3: No such process")
        return _ok()

    lc = _recording_lc(responder)
    monkeypatch.setattr(cli, "_lc", lc)

    _converge_start("work")  # must not raise despite rc 3

    assert [c[0] for c in lc.calls] == ["bootout", "enable", "bootstrap", "kickstart"]


def test_converge_start_fails_loud_on_bootstrap_error(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)

    def responder(args):
        if args[0] == "bootstrap":
            return _ok(returncode=5, stderr="Bootstrap failed: 5: Input/output error")
        return _ok()

    monkeypatch.setattr(cli, "_lc", _recording_lc(responder))

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
