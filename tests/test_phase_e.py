"""Phase E regression anchors (CLI/UX surface + test debt).

E1: exit-code taxonomy + PyiCloudException catch in main (P4-1, P4-4), and the
--launchd plist flag that keeps the daemon at exit 0 on deliberate stops (invariant 9).
E2: --json for status and sync (P4-2), NO_COLOR honoring, and the data/presentation
split that keeps the human status output byte-identical.
"""

from __future__ import annotations

import json
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
from ifolder_sync.config import (
    CONFLICT_POLICIES,
    Config,
    baseline_path,
    config_path,
    lock_path,
    trash_dir,
)
from ifolder_sync.exitcodes import Exit
from ifolder_sync.icloud_client import AuthError, ICloudClient
from ifolder_sync.locking import SingleInstanceLock
from ifolder_sync.state import CorruptBaselineError
from ifolder_sync.syncer import LocalScanError, SyncStats, VaultIdentityError
from ifolder_sync.trash import trash_count

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


# =============================================================== E2 (P4-2) ===
# ------------------------------------------------------------- NO_COLOR ---
def test_no_color_env_disables_color(monkeypatch):
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli._color("running", "32;1") == "running"  # no ANSI escape


def test_color_wraps_on_tty_without_no_color(monkeypatch):
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert cli._color("running", "32;1") == "\033[32;1mrunning\033[0m"


def test_no_color_present_even_empty_disables(monkeypatch):
    # no-color.org: presence disables regardless of value, so "" still means off.
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("NO_COLOR", "")
    assert cli._color("x", "31") == "x"


# ------------------------------------------------------- status --json ---
def test_profile_status_data_shape(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(
        apple_id="x@y.com",
        remote_folder="Notes",
        local_folder=str(vault),
        conflict_policy="newer",
        obsidian=True,
    ).save(config_path("work"))

    data = cli._profile_status_data("work")
    assert data["configured"] is True
    assert data["profile"] == "work"
    assert data["apple_id"] == "x@y.com"
    assert data["remote_folder"] == "Notes"
    assert data["conflict_policy"] == "newer"
    assert data["obsidian"] is True
    assert data["daemon"] == {"running": False, "pid": None}
    # No session saved -> the structured session state, not a colored string.
    assert data["session"]["state"] == "not found"
    assert data["baseline"] == "absent"
    assert data["last_sync"] is None


def test_profile_status_data_unconfigured(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    data = cli._profile_status_data("ghost")
    assert data == {"profile": "ghost", "configured": False}


def test_status_json_emits_valid_json_to_stdout(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", remote_folder="Notes", local_folder=str(vault)).save(
        config_path("work")
    )
    main(["status", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)  # stdout is pure JSON (no human lines)
    assert [p["profile"] for p in payload["profiles"]] == ["work"]
    assert payload["profiles"][0]["configured"] is True


def test_status_json_single_profile(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    for prof in ("default", "work"):
        Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path(prof))
    main(["status", "--json", "--profile", "work"])
    payload = json.loads(capsys.readouterr().out)
    assert [p["profile"] for p in payload["profiles"]] == ["work"]


def test_status_text_output_unchanged_by_refactor(tmp_path, monkeypatch, capsys):
    # The data/presentation split must not move the human lines the existing suite pins.
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", local_folder=str(vault)).save(config_path("work"))
    main(["status", "--profile", "work"])
    out = capsys.readouterr().out
    assert "Daemon:        stopped" in out
    assert "Session:       not found" in out
    assert "{" not in out  # text mode emits no JSON


# --------------------------------------------------------- sync --json ---
def test_sync_json_serializes_stats():
    stats = SyncStats(uploaded=3, downloaded=1, conflicts=2, skipped_deletes=5)
    payload = cli._sync_json(stats, dry_run=True)
    assert payload["dry_run"] is True
    assert payload["uploaded"] == 3
    assert payload["downloaded"] == 1
    assert payload["conflicts"] == 2
    assert payload["skipped_deletes"] == 5
    assert payload["exit_code"] == int(Exit.DELETES_SUPPRESSED)


def test_sync_json_clean_pass_exit_code_zero():
    assert cli._sync_json(SyncStats(), dry_run=False)["exit_code"] == int(Exit.OK)


def test_sync_dry_run_json_end_to_end(tmp_path, monkeypatch, capsys):
    # Drive `sync --dry-run --json` through main with a stub client + stub pass; stdout must
    # be pure JSON carrying the outcome.
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", remote_folder="Notes", local_folder=str(vault)).save(
        config_path("work")
    )

    class _StubClient:
        @classmethod
        def from_config(cls, _cfg):
            return cls()

        def connect(self, *a, **k):
            pass

    monkeypatch.setattr(ic_module, "ICloudClient", _StubClient)

    import ifolder_sync.syncer as sy

    monkeypatch.setattr(sy.Syncer, "sync_once", lambda self, *a, **k: SyncStats(downloaded=2))

    main(["sync", "--dry-run", "--json", "--profile", "work"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["dry_run"] is True
    assert payload["downloaded"] == 2
    assert payload["exit_code"] == int(Exit.OK)


def _connect_spy(seen):
    class _StubClient:
        @classmethod
        def from_config(cls, _cfg):
            return cls()

        def connect(self, *a, interactive=True, **k):
            seen["interactive"] = interactive

    return _StubClient


def test_sync_json_forces_non_interactive_connect(tmp_path, monkeypatch, capsys):
    # The pure-JSON contract: a 2FA/password prompt prints to stdout and would precede the
    # JSON. --json must force connect non-interactive so an auth gap fails to stderr+exit 3
    # instead of polluting stdout.
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", remote_folder="Notes", local_folder=str(vault)).save(
        config_path("work")
    )
    seen: dict = {}
    monkeypatch.setattr(ic_module, "ICloudClient", _connect_spy(seen))
    import ifolder_sync.syncer as sy

    monkeypatch.setattr(sy.Syncer, "sync_once", lambda self, *a, **k: SyncStats())
    main(["sync", "--dry-run", "--json", "--profile", "work"])
    assert seen["interactive"] is False
    json.loads(capsys.readouterr().out)  # stdout stays pure JSON


def test_sync_without_json_stays_interactive(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", remote_folder="Notes", local_folder=str(vault)).save(
        config_path("work")
    )
    seen: dict = {}
    monkeypatch.setattr(ic_module, "ICloudClient", _connect_spy(seen))
    import ifolder_sync.syncer as sy

    monkeypatch.setattr(sy.Syncer, "sync_once", lambda self, *a, **k: SyncStats())
    main(["sync", "--dry-run", "--profile", "work"])
    assert seen["interactive"] is True


# =============================================================== E3 (P4-5/6/7) ===
def _answers(monkeypatch, *seq):
    it = iter(seq)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(it))


# --------------------------------------------------- P4-6 init re-prompt ---
def test_ask_int_reprompts_on_typo(monkeypatch, capsys):
    _answers(monkeypatch, "60s", "60")
    assert cli._ask_int("Interval", 30) == 60
    assert "not a whole number" in capsys.readouterr().out


def test_ask_int_empty_keeps_default(monkeypatch):
    _answers(monkeypatch, "")
    assert cli._ask_int("Interval", 45) == 45


def test_ask_choice_reprompts_until_valid(monkeypatch, capsys):
    _answers(monkeypatch, "bogus", "remote")
    assert cli._ask_choice("Policy", "newer", CONFLICT_POLICIES) == "remote"
    assert "not one of" in capsys.readouterr().out


def test_ask_required_reprompts_on_empty(monkeypatch, capsys):
    _answers(monkeypatch, "", "x@y.com")
    assert cli._ask_required("Apple ID", "") == "x@y.com"
    assert "required" in capsys.readouterr().out


def test_init_survives_interval_and_policy_typos(tmp_path, monkeypatch):
    # P4-6: a typo in a validated field re-prompts instead of discarding the interview.
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    # apple_id, remote, local, interval(typo->valid), conflict(typo->valid), watch, obsidian
    _answers(monkeypatch, "x@y.com", "Notes", str(vault), "60s", "90", "bad", "newer", "n", "n")
    main(["init", "--profile", "work"])
    cfg = Config.load(config_path("work"))
    assert cfg.interval_seconds == 90
    assert cfg.conflict_policy == "newer"


# ------------------------------------------------ P4-7 purge-trash confirm ---
def _make_trash(profile, n):
    td = trash_dir(profile)
    td.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (td / f"deleted{i}.md").write_text("x")
    return td


def test_purge_trash_empty_is_noop(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    main(["purge-trash", "--profile", "work"])
    assert "already empty" in capsys.readouterr().out


def test_purge_trash_yes_skips_prompt(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    _make_trash("work", 2)
    main(["purge-trash", "--yes", "--profile", "work"])
    assert "Purged 2 file(s)" in capsys.readouterr().out
    assert trash_count(trash_dir("work")) == 0


def test_purge_trash_interactive_abort_keeps_files(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    _make_trash("work", 3)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    _answers(monkeypatch, "n")
    main(["purge-trash", "--profile", "work"])
    assert "Aborted" in capsys.readouterr().out
    assert trash_count(trash_dir("work")) == 3  # kept — the safety net survives


def test_purge_trash_interactive_confirm_purges(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    _make_trash("work", 2)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    _answers(monkeypatch, "y")
    main(["purge-trash", "--profile", "work"])
    assert trash_count(trash_dir("work")) == 0


def test_purge_trash_non_interactive_without_yes_refuses(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    _make_trash("work", 2)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as ei:
        main(["purge-trash", "--profile", "work"])
    assert ei.value.code == Exit.ERROR
    assert trash_count(trash_dir("work")) == 2  # not purged
    assert "--yes" in capsys.readouterr().err


def test_purge_trash_eof_declines_and_keeps_files(tmp_path, monkeypatch, capsys):
    # Ctrl-D at the confirm prompt = decline; the safety net survives and no traceback.
    sandbox_home(tmp_path, monkeypatch)
    _make_trash("work", 3)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)

    def _eof(*_a, **_k):
        raise EOFError

    monkeypatch.setattr("builtins.input", _eof)
    main(["purge-trash", "--profile", "work"])  # no SystemExit, no traceback
    assert "Aborted; trash kept." in capsys.readouterr().out
    assert trash_count(trash_dir("work")) == 3


def test_main_eof_exits_cleanly_without_traceback(isolate_home, monkeypatch, capsys):
    # EOFError at any prompt must exit cleanly (like Ctrl-C), not dump a traceback.
    monkeypatch.setattr(cli, "cmd_status", _raise(EOFError()))
    with pytest.raises(SystemExit) as ei:
        cli.main(["status"])
    assert ei.value.code == Exit.INTERRUPTED
    assert "Traceback" not in capsys.readouterr().err


# ------------------------------------------------ P4-5 first-sync feedback ---
def test_sync_progress_to_stderr_on_tty(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", remote_folder="Notes", local_folder=str(vault)).save(
        config_path("work")
    )
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(ic_module, "ICloudClient", _connect_spy({}))
    import ifolder_sync.syncer as sy

    monkeypatch.setattr(sy.Syncer, "sync_once", lambda self, *a, **k: SyncStats())
    main(["sync", "--dry-run", "--profile", "work"])
    cap = capsys.readouterr()
    assert "Connecting to iCloud" in cap.err
    assert "Scanning" in cap.err
    assert "Connecting" not in cap.out  # progress never pollutes stdout


def test_sync_progress_suppressed_in_json_mode(tmp_path, monkeypatch, capsys):
    sandbox_home(tmp_path, monkeypatch)
    vault = tmp_path / "vault"
    vault.mkdir()
    Config(apple_id="x@y.com", remote_folder="Notes", local_folder=str(vault)).save(
        config_path("work")
    )
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(ic_module, "ICloudClient", _connect_spy({}))
    import ifolder_sync.syncer as sy

    monkeypatch.setattr(sy.Syncer, "sync_once", lambda self, *a, **k: SyncStats())
    main(["sync", "--dry-run", "--json", "--profile", "work"])
    cap = capsys.readouterr()
    assert "Connecting" not in cap.err  # quiet for machine consumers
    json.loads(cap.out)


# =============================================================== E4 (P4-8/9) ===
# ----------------------------------------------- P4-8 plist program shim ---
def _make_exe(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def test_agent_program_prefers_external_shim(tmp_path, monkeypatch):
    # An absolute, executable shim OUTSIDE the current venv is stable across upgrades; use it.
    monkeypatch.setattr(cli.sys, "prefix", str(tmp_path / "venv"))
    shim = _make_exe(tmp_path / "external" / "ifolder-sync")
    monkeypatch.setattr(cli.shutil, "which", lambda _n: str(shim))
    assert cli._agent_program() == [str(shim)]


def test_agent_program_skips_venv_internal_shim(tmp_path, monkeypatch):
    # A shim INSIDE the running venv is recreated/destroyed with it; prefer `python -m`,
    # which does not depend on the shim file surviving a rebuild.
    fake_prefix = tmp_path / "venv"
    shim = _make_exe(fake_prefix / "bin" / "ifolder-sync")
    monkeypatch.setattr(cli.sys, "prefix", str(fake_prefix))
    monkeypatch.setattr(cli.shutil, "which", lambda _n: str(shim))
    assert cli._agent_program() == [cli.sys.executable, "-m", "ifolder_sync"]


def test_agent_program_rejects_relative_shim(monkeypatch):
    # A relative which() result (a '.'/empty PATH segment) cannot be exec'd by launchd.
    monkeypatch.setattr(cli.shutil, "which", lambda _n: "relbin/ifolder-sync")
    assert cli._agent_program() == [cli.sys.executable, "-m", "ifolder_sync"]


def test_agent_program_no_shim_uses_module(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda _n: None)
    assert cli._agent_program() == [cli.sys.executable, "-m", "ifolder_sync"]


def test_agent_program_never_freezes_nonshim_argv0(monkeypatch):
    # No shim + a non-shim executable argv[0] (pytest, a wrapper) must NOT be frozen as the
    # launchd program — launchd would crash-loop the wrong binary with sync args.
    monkeypatch.setattr(cli.shutil, "which", lambda _n: None)
    monkeypatch.setattr(cli.sys, "argv", ["/usr/bin/pytest"])
    assert cli._agent_program() == [cli.sys.executable, "-m", "ifolder_sync"]


def test_agent_plist_uses_program_from_agent_program(isolate_home, tmp_path, monkeypatch):
    import plistlib

    monkeypatch.setattr(cli.sys, "prefix", str(tmp_path / "venv"))
    shim = _make_exe(tmp_path / "external" / "ifolder-sync")
    monkeypatch.setattr(cli.shutil, "which", lambda _n: str(shim))
    payload = plistlib.loads(cli._write_agent_plist("default").read_bytes())
    # The shim leads the ProgramArguments; the invariant-9 tail is preserved.
    assert payload["ProgramArguments"][0] == str(shim)
    assert payload["ProgramArguments"][-4:] == ["start", "--profile", "default", "--launchd"]


# ----------------------------------------------- P4-9 shtab completion ---
def test_print_completion_zsh_emits_script(capsys):
    # shtab is in the dev/test deps, so the flag is present and prints a #compdef script.
    with pytest.raises(SystemExit) as ei:
        main(["--print-completion", "zsh"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "#compdef" in out
    assert "ifolder-sync" in out


def test_print_completion_bash_emits_script(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--print-completion", "bash"])
    assert ei.value.code == 0
    assert "ifolder-sync" in capsys.readouterr().out


def test_completion_flag_absent_without_shtab(monkeypatch):
    # Without shtab installed the flag is simply not added (base install stays dep-free).
    import builtins

    real_import = builtins.__import__

    def _no_shtab(name, *a, **k):
        if name == "shtab":
            raise ImportError("no shtab")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_shtab)
    parser = cli.build_parser()
    assert "--print-completion" not in parser._option_string_actions
