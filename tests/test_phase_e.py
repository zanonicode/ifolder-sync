"""Phase E regression anchors (CLI/UX surface + test debt).

E1: exit-code taxonomy + PyiCloudException catch in main (P4-1, P4-4), and the
--launchd plist flag that keeps the daemon at exit 0 on deliberate stops (invariant 9).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pyicloud.exceptions import (
    PyiCloud2FARequiredException,
    PyiCloudAPIResponseException,
    PyiCloudAuthRequiredException,
    PyiCloudFailedLoginException,
    PyiCloudServiceNotActivatedException,
)

import ifolder_sync.icloud_client as ic_module
from ifolder_sync import cli
from ifolder_sync.cli import main
from ifolder_sync.config import Config, baseline_path, config_path, lock_path
from ifolder_sync.exitcodes import Exit
from ifolder_sync.icloud_client import AuthError, ICloudClient
from ifolder_sync.locking import SingleInstanceLock
from ifolder_sync.state import CorruptBaselineError
from ifolder_sync.syncer import LocalScanError, SyncStats, VaultIdentityError

from .helpers import sandbox_home


@pytest.fixture
def isolate_home(tmp_path, monkeypatch):
    """Redirect every config/state/home path under tmp so a test can run main() and
    write a launchd plist without touching the real ~/.config or ~/Library."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    return tmp_path


# ---------------------------------------------------- P4-1 outcome -> code ---
def test_exit_code_values_are_stable():
    # The numeric values are a public contract (scripts/monitoring); pin them.
    assert (Exit.OK, Exit.ERROR, Exit.USAGE, Exit.AUTH_REQUIRED) == (0, 1, 2, 3)
    assert (Exit.SCAN_GUARD, Exit.VAULT_IDENTITY) == (4, 5)
    assert (Exit.DELETES_SUPPRESSED, Exit.SYNC_ERRORS, Exit.INTERRUPTED) == (6, 7, 130)


def test_outcome_clean_pass_is_ok():
    assert cli._outcome_exit_code(SyncStats()) == Exit.OK


def test_outcome_errors_maps_to_sync_errors():
    assert cli._outcome_exit_code(SyncStats(errors=1)) == Exit.SYNC_ERRORS


def test_outcome_skipped_deletes_maps_to_suppressed():
    assert cli._outcome_exit_code(SyncStats(skipped_deletes=3)) == Exit.DELETES_SUPPRESSED


def test_outcome_errors_outrank_suppressed():
    stats = SyncStats(errors=1, skipped_deletes=3)
    assert cli._outcome_exit_code(stats) == Exit.SYNC_ERRORS


# -------------------------------------------------- P4-1 exception -> code ---
def _auth_exc(cls):
    # PyiCloud2FARequired/AuthRequired need a requests.Response; bypass __init__ since
    # only the type matters to the mapper.
    if cls in (PyiCloud2FARequiredException, PyiCloudAuthRequiredException):
        return cls.__new__(cls)
    if cls is PyiCloudFailedLoginException:
        return cls("bad password")
    return cls("not activated")  # PyiCloudServiceNotActivatedException


@pytest.mark.parametrize(
    "cls",
    [
        PyiCloud2FARequiredException,
        PyiCloudFailedLoginException,
        PyiCloudAuthRequiredException,
        PyiCloudServiceNotActivatedException,
    ],
)
def test_exception_auth_required(cls):
    assert cli._exception_exit_code(_auth_exc(cls)) == Exit.AUTH_REQUIRED


def test_exception_autherror_maps_to_auth_required():
    # AuthError subclasses RuntimeError; it must reach AUTH_REQUIRED, not the generic
    # RuntimeError->ERROR branch. This is the fix for the inconsistency where a rejected/
    # absent password (flattened to RuntimeError in connect()) used to exit 1, not 3.
    assert cli._exception_exit_code(AuthError("rejected")) == Exit.AUTH_REQUIRED


def test_exception_vault_identity():
    assert cli._exception_exit_code(VaultIdentityError("marker mismatch")) == Exit.VAULT_IDENTITY


def test_exception_scan_guard():
    assert cli._exception_exit_code(LocalScanError("permission denied")) == Exit.SCAN_GUARD


def test_exception_generic_pyicloud_is_error():
    # P4-4: a 503/429 is caught (returns a code, not None) so main prints one clean line.
    exc = PyiCloudAPIResponseException("Service Unavailable", code=503)
    assert cli._exception_exit_code(exc) == Exit.ERROR


def test_exception_corrupt_baseline_is_error():
    assert cli._exception_exit_code(CorruptBaselineError("malformed")) == Exit.ERROR


@pytest.mark.parametrize("exc", [ValueError("x"), RuntimeError("y"), OSError("z")])
def test_exception_value_runtime_os_is_error(exc):
    assert cli._exception_exit_code(exc) == Exit.ERROR


def test_exception_unknown_returns_none():
    # An unrecognized type yields None so main() re-raises it with a full traceback —
    # only known, explained failures get the clean treatment.
    assert cli._exception_exit_code(KeyError("surprise")) is None


def test_specific_beats_base_class_ordering():
    # LocalScanError/VaultIdentityError subclass RuntimeError; the auth exceptions subclass
    # PyiCloudException. The mapper must reach the specific code, not the base ERROR.
    assert cli._exception_exit_code(LocalScanError("x")) == Exit.SCAN_GUARD
    assert cli._exception_exit_code(_auth_exc(PyiCloudFailedLoginException)) == Exit.AUTH_REQUIRED


# ----------------------------------------------------- P4-4 main() wiring ---
def _raise(exc):
    def _f(_args):
        raise exc

    return _f


def test_main_catches_pyicloud_without_traceback(isolate_home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "cmd_status", _raise(PyiCloudAPIResponseException("503", code=503)))
    with pytest.raises(SystemExit) as ei:
        cli.main(["status"])
    assert ei.value.code == Exit.ERROR
    err = capsys.readouterr().err
    assert "Error:" in err
    assert "Traceback" not in err


def test_main_auth_exception_exits_3_with_hint(isolate_home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "cmd_status", _raise(PyiCloudFailedLoginException("nope")))
    with pytest.raises(SystemExit) as ei:
        cli.main(["status"])
    assert ei.value.code == Exit.AUTH_REQUIRED
    err = capsys.readouterr().err
    # Pin the exact remediation line (in addition to the Error: line), so a regression in
    # the hint text or its emission is caught, not just any mention of "auth".
    assert "Error:" in err
    assert "Run `ifolder-sync auth` to (re)authenticate." in err


def test_main_verbose_reraises_for_traceback(isolate_home, monkeypatch):
    monkeypatch.setattr(cli, "cmd_status", _raise(PyiCloudAPIResponseException("503", code=503)))
    # -v means "show me everything": the exception propagates instead of a clean exit.
    with pytest.raises(PyiCloudAPIResponseException):
        cli.main(["-v", "status"])


def test_main_unknown_exception_propagates(isolate_home, monkeypatch):
    monkeypatch.setattr(cli, "cmd_status", _raise(KeyError("surprise")))
    with pytest.raises(KeyError):
        cli.main(["status"])


# ------------------------------------------- P4-1 invariant-9 launchd mode ---
def test_start_is_launchd_true_with_flag():
    assert cli._start_is_launchd(SimpleNamespace(launchd=True)) is True


def test_start_is_launchd_true_when_stderr_not_tty(monkeypatch):
    # Old agents predate --launchd; launchd redirects stderr to a file (never a TTY), so
    # the fallback still keeps them at exit 0.
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: False, raising=False)
    assert cli._start_is_launchd(SimpleNamespace(launchd=False)) is True


def test_start_is_launchd_false_in_interactive_tty(monkeypatch):
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True, raising=False)
    assert cli._start_is_launchd(SimpleNamespace(launchd=False)) is False


def test_agent_plist_passes_launchd_flag(isolate_home):
    # invariant 9: the generated agent must carry --launchd so KeepAlive never crash-loops
    # a deliberate exit-0 stop.
    import plistlib

    plist_path = cli._write_agent_plist("default")
    payload = plistlib.loads(plist_path.read_bytes())
    args = payload["ProgramArguments"]
    assert "--launchd" in args
    assert args[-3:] == ["--profile", "default", "--launchd"]
    assert payload["KeepAlive"] == {"SuccessfulExit": False}


def test_launchd_flag_parsed_by_argparse():
    # Close the plist -> argparse -> predicate chain: the plist passes --launchd, so argparse
    # must populate args.launchd for _start_is_launchd to read it (default False).
    assert cli.build_parser().parse_args(["start", "--launchd", "--profile", "default"]).launchd
    assert not cli.build_parser().parse_args(["start", "--profile", "default"]).launchd


# ----------------------------------------- P4-1 source: connect -> AuthError ---
def test_connect_no_password_raises_autherror(tmp_path, monkeypatch):
    # The most common auth failure (no env var, no keychain, non-interactive) must raise
    # AuthError so the CLI exits AUTH_REQUIRED(3), not a bare RuntimeError -> ERROR(1).
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.delenv("IFOLDER_SYNC_PASSWORD", raising=False)
    monkeypatch.setattr(ic_module, "password_exists_in_keyring", lambda *a, **k: False)
    client = ICloudClient.from_config(Config(apple_id="x@y.com", local_folder=str(tmp_path)))
    with pytest.raises(AuthError):
        client.connect(interactive=False)


# --------------------------- P4-1 invariant-9: cmd_start interactive vs launchd ---
def _save_config(profile, vault):
    vault.mkdir(parents=True, exist_ok=True)
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path(profile))


def _corrupt_baseline(profile):
    bp = baseline_path(profile)
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_bytes(b"garbage" * 50)


def test_cmd_start_interactive_corrupt_baseline_exits_error(tmp_path, monkeypatch, capsys):
    # On an interactive TTY (no --launchd), an operator-actionable stop surfaces a non-zero
    # code so a human/monitor sees it.
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True, raising=False)
    _save_config("corrupt", tmp_path / "vault")
    _corrupt_baseline("corrupt")
    with pytest.raises(SystemExit) as ei:
        main(["start", "--profile", "corrupt"])
    assert ei.value.code == Exit.ERROR
    assert "rebaseline" in capsys.readouterr().err


def test_cmd_start_interactive_already_running_exits_error(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True, raising=False)
    _save_config("work", tmp_path / "vault")
    held = SingleInstanceLock(lock_path("work"))
    held.acquire()
    try:
        with pytest.raises(SystemExit) as ei:
            main(["start", "--profile", "work"])
        assert ei.value.code == Exit.ERROR
    finally:
        held.release()


def test_cmd_start_launchd_flag_keeps_corrupt_baseline_at_exit_0(tmp_path, monkeypatch, capsys):
    # invariant 9: even on an interactive TTY, the explicit --launchd flag keeps a deliberate
    # stop at exit 0 so KeepAlive cannot crash-loop it. (The no-TTY fallback is covered in
    # test_drift's test_cmd_start_clean_exits_on_corrupt_baseline.)
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True, raising=False)
    _save_config("corrupt", tmp_path / "vault")
    _corrupt_baseline("corrupt")
    main(["start", "--launchd", "--profile", "corrupt"])  # no SystemExit
    assert "rebaseline" in capsys.readouterr().err
