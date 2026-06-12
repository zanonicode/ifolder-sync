"""ifolder-sync command-line interface.

Every subcommand operates on a named profile (`--profile`, default `default`); each
profile has its own config, state, lock, and launchd agent. Sessions are shared per
Apple ID.

Subcommands:
  init           create/edit a profile's config
  auth           authenticate with iCloud (one-time 2FA, then a saved session)
  sync           run one sync pass and exit
  start          run the daemon (foreground); `--background` detaches via launchd
  stop           stop a profile's background (launchd) daemon
  status         show all profiles' state, or one in detail with `--profile`
  logs           tail a profile's daemon log (`-f` to follow, `-n` lines)
  rebaseline     reset a profile's baseline (backup first) after the vault moved/drifted
  purge-trash    empty a profile's local soft-delete trash
  install-agent  generate a launchd LaunchAgent .plist for a profile
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from collections import deque
from datetime import datetime
from http.cookiejar import LoadError, LWPCookieJar
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from . import __version__
from .config import (
    DEFAULT_PROFILE,
    Config,
    baseline_path,
    config_path,
    list_profiles,
    lock_path,
    log_file,
    migrate_legacy,
    read_vault_marker,
    session_paths,
    sessions_dir,
    state_dir,
    tcc_protected,
    trash_dir,
    write_vault_marker,
)
from .exitcodes import Exit
from .locking import holder_pid
from .trash import purge_trash, trash_count


def _color(text: str, code: str) -> str:
    """ANSI-wrap only on a TTY so piped/captured output stays plain."""
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _daemon_state(profile: str) -> str:
    pid = holder_pid(lock_path(profile))
    if pid:
        return _color("running", "32;1") + f" (pid {pid})"
    return _color("stopped", "31")


def _trust_cookie_expiry(cookie_file: Path) -> Optional[float]:
    """Expiry of the HSA trust cookie — the window in which the daemon can connect
    without 2FA. Values are never read or printed, only names and expiry dates."""
    jar = LWPCookieJar()
    try:
        jar.load(str(cookie_file), ignore_discard=True, ignore_expires=True)
    except (OSError, LoadError):
        return None
    expiries = [
        float(c.expires)
        for c in jar
        if c.name.startswith("X-APPLE-WEBAUTH-HSA-TRUST") and c.expires
    ]
    return max(expiries, default=None)


def _auth_state(apple_id: str) -> str:
    if not apple_id:
        return _color("unknown", "33") + " (no apple_id in config)"
    session_file, cookie_file = session_paths(apple_id)
    try:
        data = json.loads(session_file.read_text())
    except FileNotFoundError:
        return _color("not found", "31") + " — run `ifolder-sync auth`"
    except (OSError, ValueError):
        return _color("corrupted", "31") + " — run `ifolder-sync auth --fresh`"
    if data.get("session_token") and not data.get("trust_token"):
        return _color("poisoned", "33") + " — 2FA never trusted; run `ifolder-sync auth --fresh`"
    expires = _trust_cookie_expiry(cookie_file)
    if expires is None:
        return _color("untrusted", "33") + " — daemon would need 2FA; run `ifolder-sync auth`"
    when = datetime.fromtimestamp(expires).strftime("%Y-%m-%d")
    if expires > time.time():
        return _color("valid", "32;1") + f" — trusted until {when}"
    return _color("expired", "31") + f" on {when} — run `ifolder-sync auth`"


def _warn_tcc(path: Path) -> None:
    if tcc_protected(path):
        print(
            f"WARNING: {path} is under a macOS-protected folder (Downloads/Desktop/"
            "Documents). A launchd background daemon cannot read it without Full Disk "
            "Access — it would see an empty vault. Move the vault (e.g. ~/vaults/) or "
            "grant Full Disk Access before running in the background.",
            file=sys.stderr,
        )


def _setup_logging(verbose: bool, log_path: Optional[Path] = None):
    """Configure logging. One-shot CLI commands stream to the console (log_path None).
    The daemon passes log_path to add a RotatingFileHandler (bounded size, the log of
    record under ~/Library/Logs). The console StreamHandler is added only on a TTY: under
    launchd, stderr is redirected to a file, so streaming there would duplicate every line
    into the launchd capture — the rotating file is authoritative. force=True because
    main() already configured a stream-only logger before the command ran."""
    handlers: list[logging.Handler] = []
    if log_path is None or sys.stderr.isatty():
        handlers.append(logging.StreamHandler())
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        )
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S" if log_path is not None else "%H:%M:%S",
        handlers=handlers,
        force=True,
    )
    # pyicloud logs "Session file does not exist" at INFO on the first auth (benign:
    # there is no cached session yet). Without -v, raise it to WARNING.
    if not verbose:
        logging.getLogger("pyicloud").setLevel(logging.WARNING)


def _profile(args) -> str:
    return getattr(args, "profile", DEFAULT_PROFILE) or DEFAULT_PROFILE


# A profile names config/state files AND a launchd label, so path separators or
# dot-traversal would escape both namespaces.
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _profile_name(value: str) -> str:
    if not _PROFILE_RE.match(value):
        raise argparse.ArgumentTypeError(
            f"invalid profile name {value!r} (allowed: letters, digits, '.', '_', '-')"
        )
    return value


def _load_profile(args) -> tuple[str, Config]:
    profile = _profile(args)
    cfg = Config.load(config_path(profile))
    cfg.validate()
    return profile, cfg


# ----------------------------------------------------------------- commands ---
_ROOT_CONFIRM_TOKEN = "SYNC ENTIRE ICLOUD"


def _confirm_root_scope(args) -> None:
    """An empty remote_folder means the WHOLE iCloud Drive root: every app container
    is mirrored into the vault and a local deletion propagates to iCloud. Require an
    explicit opt-in (--allow-root or a typed confirmation) so root scope is never
    accidental."""
    if getattr(args, "allow_root", False):
        return
    print(
        "WARNING: an empty folder means the ENTIRE iCloud Drive root. Every app's\n"
        "iCloud container (Pages, Numbers, Shortcuts, ...) would be mirrored into the\n"
        "local vault, AND a local deletion would propagate to iCloud. This is almost\n"
        "never what you want -- pick a dedicated subfolder instead.",
        file=sys.stderr,
    )
    typed = input(f'Type "{_ROOT_CONFIRM_TOKEN}" to sync the whole Drive root: ').strip()
    if typed != _ROOT_CONFIRM_TOKEN:
        raise ValueError("root sync not confirmed; set a remote folder or pass --allow-root.")


def cmd_init(args):
    profile = _profile(args)
    path = config_path(profile)
    cfg = Config.load(path) if path.exists() else Config()

    def ask(prompt, current):
        val = input(f"{prompt} [{current}]: ").strip()
        return val or current

    print(f"== ifolder-sync configuration (profile: {profile}) ==")
    cfg.apple_id = ask("Apple ID (email of the iCloud account to sync)", cfg.apple_id)
    cfg.remote_folder = ask("Folder inside iCloud Drive (empty = root)", cfg.remote_folder)
    cfg.local_folder = ask(
        "Local folder to mirror", cfg.local_folder or str(Path.home() / "iCloudSync")
    )
    cfg.interval_seconds = int(ask("Poll interval (seconds)", cfg.interval_seconds))
    cfg.conflict_policy = ask("Conflict policy (newer/local/remote/both)", cfg.conflict_policy)
    watch = ask("Watch local changes in real time? (y/n)", "y" if cfg.watch_local else "n")
    cfg.watch_local = watch.lower().startswith("y")
    if args.obsidian:
        cfg.obsidian = True
        print("Is this an Obsidian vault? yes (--obsidian)")
    else:
        obs_default = "y" if cfg.obsidian else "n"
        cfg.obsidian = ask("Is this an Obsidian vault? (y/n)", obs_default).lower().startswith("y")

    if not cfg.remote_folder.strip():
        _confirm_root_scope(args)

    cfg.validate()
    saved = cfg.save(path)
    Path(cfg.local_folder).expanduser().mkdir(parents=True, exist_ok=True)
    _warn_tcc(cfg.local_path)
    print(f"\nConfig saved at {saved}")
    print(f"Next step: `ifolder-sync auth --profile {profile}` to authenticate with iCloud.")


def cmd_auth(args):
    from .icloud_client import ICloudClient

    profile, cfg = _load_profile(args)
    client = ICloudClient.from_config(cfg)
    client.connect(interactive=True, fresh=args.fresh)
    print(f"\nAuthenticated as {cfg.apple_id}.")
    client.print_diagnostics(include_phones=False)
    if client.api.is_trusted_session:
        print(f"Trusted session stored at {sessions_dir()}.")
        print(f"The daemon (`ifolder-sync start --profile {profile}`) now connects without 2FA.")
    else:
        print(
            "WARNING: the session was NOT marked trusted. The daemon will still ask "
            "for 2FA. Try `ifolder-sync auth --fresh` again."
        )


def cmd_sync(args):
    from .icloud_client import ICloudClient
    from .locking import AlreadyRunning, SingleInstanceLock
    from .state import StateStore
    from .syncer import Syncer

    profile, cfg = _load_profile(args)
    lock = None
    if not args.dry_run:
        # A non-dry-run sync mutates the baseline; it must hold the same single-instance
        # lock the daemon uses, or a daemon start (or a second manual sync) racing in
        # right after a plain holder_pid check would corrupt the baseline (TOCTOU).
        pid = holder_pid(lock_path(profile))
        if pid:
            print(
                f"Error: the daemon is running (pid {pid}) and a manual sync would race "
                f"its baseline. Stop it first (`ifolder-sync stop --profile {profile}`) "
                "or preview with --dry-run.",
                file=sys.stderr,
            )
            sys.exit(1)
        lock = SingleInstanceLock(lock_path(profile))
        try:
            lock.acquire()
        except AlreadyRunning as exc:
            print(
                f"Error: {exc} — a manual sync would race the baseline. Stop it first "
                f"(`ifolder-sync stop --profile {profile}`) or preview with --dry-run.",
                file=sys.stderr,
            )
            sys.exit(1)
    try:
        client = ICloudClient.from_config(cfg)
        client.connect(interactive=not args.non_interactive)
        with StateStore(baseline_path(profile)) as store:
            store.quick_check()  # corrupt baseline -> clear RuntimeError, exit 1 (no traceback)
            syncer = Syncer(cfg, client, store, trash_dir=trash_dir(profile))
            stats = syncer.sync_once(dry_run=args.dry_run, force_delete=args.force_delete)
        prefix = "Dry-run (no changes written)" if args.dry_run else "Sync done"
        print(f"{prefix}: {stats.summary()}")
    finally:
        if lock is not None:
            lock.release()
    # A pass can "succeed" yet leave work unfinished: the safety threshold suppressed
    # deletions, or some file operations failed. Surface that as a distinct exit code so
    # cron/monitoring can react instead of trusting a blanket 0. (Reached only on success;
    # an exception above propagates straight to main's taxonomy.)
    code = _outcome_exit_code(stats)
    if code:
        sys.exit(code)


def cmd_start(args):
    from .daemon import Daemon
    from .locking import AlreadyRunning
    from .state import CorruptBaselineError

    profile, cfg = _load_profile(args)
    if getattr(args, "background", False):
        _start_background(profile)
        return
    # The foreground daemon (also the process launchd runs) owns a rotating file log.
    _setup_logging(getattr(args, "verbose", False), log_path=log_file(profile))
    # invariant 9: under launchd (KeepAlive SuccessfulExit=false) a non-zero exit on an
    # operator-actionable stop becomes a restart loop. The agent passes --launchd; agents
    # written before the flag are caught by the TTY fallback (launchd redirects stderr to a
    # file, so it is never a TTY). An interactive terminal gets a real code so a human or a
    # monitor sees the failure.
    launchd_mode = _start_is_launchd(args)
    try:
        Daemon(cfg, profile).run()
    except AlreadyRunning as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if not launchd_mode:
            sys.exit(Exit.ERROR)
    except CorruptBaselineError as exc:
        # A corrupt baseline is operator-actionable (rebaseline), not transient. Under
        # launchd, exit clean (0) so KeepAlive=SuccessfulExit:false does not crash-loop;
        # interactively, surface a code. Either way the message says what to run.
        print(f"Error: {exc}", file=sys.stderr)
        if not launchd_mode:
            sys.exit(Exit.ERROR)


def _start_background(profile: str) -> None:
    """Detach the daemon by handing it to launchd (load -w the profile's LaunchAgent)."""
    cfg = Config.load(config_path(profile))
    _warn_tcc(cfg.local_path)
    if not _has_session(cfg.apple_id):
        # launchd KeepAlive would restart a daemon that can't pass 2FA in a tight loop.
        print(
            "WARNING: no saved iCloud session found. The background daemon runs "
            f"non-interactively and cannot pass 2FA. Run `ifolder-sync auth --profile "
            f"{profile}` FIRST, otherwise launchd will restart it in a failing loop.",
            file=sys.stderr,
        )
    plist = _write_agent_plist(profile)
    _launchctl("load", plist)
    print(f"Background daemon started via launchd ({_agent_label(profile)}).")
    print("It runs now, restarts on crash, and starts again at each login.")
    print(f"Logs:    {log_file(profile)}")
    print(f"Stop it: ifolder-sync stop --profile {profile}")


def cmd_stop(args):
    profile = _profile(args)
    label = _agent_label(profile)
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    if not plist_path.exists():
        print(f"No LaunchAgent for profile '{profile}' (nothing to stop).")
        return
    _launchctl("unload", plist_path)
    print(f"Background daemon stopped ({label}).")


def _has_session(apple_id: str) -> bool:
    return session_paths(apple_id)[0].exists()


def _print_profile_status(profile: str) -> None:
    from .state import CorruptBaselineError, StateStore

    path = config_path(profile)
    if not path.exists():
        print(f"Profile '{profile}': no config. Run `ifolder-sync init --profile {profile}`.")
        return
    cfg = Config.load(path)

    print(f"Profile:       {profile}")
    print(f"Daemon:        {_daemon_state(profile)}")
    print(f"Config:        {path}")
    print(f"Apple ID:      {cfg.apple_id}")
    print(f"Remote folder: {cfg.remote_folder or '(iCloud Drive root)'}")
    print(f"Local folder:  {cfg.local_path}")
    print(f"Interval:      {cfg.interval_seconds}s")
    print(f"Watch local:   {'yes' if cfg.watch_local else 'no'}")
    print(f"Conflict:      {cfg.conflict_policy}")
    print(f"Obsidian:      {'on' if cfg.obsidian else 'off'}")
    print(f"Remote trash:  {'on' if cfg.remote_trash else 'off'}")
    print(f"State:         {state_dir(profile)}")
    print(f"Session:       {_auth_state(cfg.apple_id)}")
    print(f"Local trash:   {trash_count(trash_dir(profile))} file(s)")

    db = baseline_path(profile)
    if db.exists():
        try:
            with StateStore(db) as store:
                last_sync = store.get_meta("last_sync")
                last_error = store.get_meta("last_error")
                last_stats = store.get_meta("last_stats")
        except CorruptBaselineError:
            print(
                f"Baseline:      {_color('corrupt', '31')} — run "
                f"`ifolder-sync rebaseline --profile {profile}`"
            )
            return
        if last_sync:
            ts = datetime.fromtimestamp(float(last_sync)).strftime("%Y-%m-%d %H:%M:%S")
            print(f"Last sync:     {ts} ({last_stats or ''})")
        if last_error:
            print(f"Last error:    {last_error}")


def cmd_status(args):
    profiles = list_profiles()
    if profiles:
        print(f"Profiles:      {', '.join(profiles)}\n")
    # --profile omitted (None) -> show every profile; given -> that one in detail.
    if args.profile is not None:
        _print_profile_status(args.profile)
        return
    if not profiles:
        print("No profiles yet. Run `ifolder-sync init` to create one.")
        return
    for i, prof in enumerate(profiles):
        if i:
            print()
        _print_profile_status(prof)


def cmd_purge_trash(args):
    profile = _profile(args)
    n = purge_trash(trash_dir(profile))
    print(f"Purged {n} file(s) from the local trash of profile '{profile}'.")


def cmd_logs(args):
    profile = _profile(args)
    primary = log_file(profile)
    legacy = state_dir(profile) / "logs" / "daemon.err.log"  # pre-D4 launchd-redirected log
    target = primary if primary.exists() else legacy
    if not target.exists():
        print(
            f"No log file at {primary} — the background daemon writes it. "
            f"Start one with `ifolder-sync start --background --profile {profile}`."
        )
        return
    with open(target, errors="replace") as fh:
        for line in deque(fh, maxlen=args.lines):
            print(line, end="")
    if args.follow:
        _follow(target)


def _follow(path: Path) -> None:
    """Stream lines appended to path until Ctrl-C (main turns it into exit 130)."""
    with open(path, errors="replace") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if line:
                print(line, end="", flush=True)
            else:
                time.sleep(0.5)


def cmd_rebaseline(args):
    """Reset the three-way baseline after the vault moved, was recreated, or drifted.

    With an empty baseline the next pass is purely additive (downloads what is missing,
    uploads local-only files, never deletes) — the sanctioned recovery from drift.
    """
    from .state import CorruptBaselineError, StateStore

    profile, cfg = _load_profile(args)
    pid = holder_pid(lock_path(profile))
    if pid:
        print(
            f"Error: the daemon is running (pid {pid}). Stop it first: "
            f"`ifolder-sync stop --profile {profile}`.",
            file=sys.stderr,
        )
        sys.exit(1)

    db = baseline_path(profile)
    if db.exists():
        bak = db.with_name(f"{db.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        try:
            # WAL-safe consistent copy: a raw file copy would miss committed rows still
            # in the -wal of a daemon killed (SIGKILL) without a clean checkpoint.
            with StateStore(db) as store:
                store.backup_to(bak)
        except CorruptBaselineError:
            # The DB is unreadable anyway; salvage the raw bytes for forensics.
            shutil.copy2(db, bak)
        # Unlink the main file AND its WAL siblings: orphaned -wal/-shm would otherwise
        # attach stale frames to the next (fresh) baseline.
        for sib in (db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")):
            sib.unlink(missing_ok=True)
        print(f"Baseline backed up to {bak} and reset.")
    else:
        print("No baseline to reset (fresh profile).")

    root = cfg.local_path
    if root.is_dir():
        removed = 0
        for p in root.rglob("*.part"):
            p.unlink()
            removed += 1
        if removed:
            print(f"Removed {removed} orphan .part file(s) from the vault.")
        if read_vault_marker(root) is None:
            write_vault_marker(root, profile)
            print("Vault identity marker created.")
        else:
            # Identity belongs to the vault, not the profile: a vault that still has
            # its marker keeps it (other profiles may share it).
            print("Existing vault identity marker kept.")
    else:
        print(f"Local folder {root} not found — marker will be created on first sync.")

    print("\nNext steps:")
    print(f"  ifolder-sync sync --dry-run --profile {profile}   # preview (additive only)")
    print(f"  ifolder-sync sync --profile {profile}             # apply")


def _agent_label(profile: str) -> str:
    return f"com.ifolder-sync.{profile}"


def _write_agent_plist(profile: str) -> Path:
    """Write (overwrite) the profile's launchd LaunchAgent .plist; return its path.

    The agent runs `start --profile <profile>` in the foreground *inside* launchd; launchd
    provides the detachment, restart-on-crash (KeepAlive), and start-at-login (RunAtLoad).
    Shared by `install-agent` and `start --background`.

    KeepAlive uses SuccessfulExit=false: restart only on a non-zero exit, so a daemon
    that exits cleanly on purpose (failed preflight/auth) cannot crash-loop;
    ThrottleInterval spaces out genuine crash restarts.
    """
    label = _agent_label(profile)
    plist_dir = Path.home() / "Library" / "LaunchAgents"
    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_path = plist_dir / f"{label}.plist"
    log_dir = state_dir(profile) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    exe = Path(sys.argv[0]).resolve()
    if exe.suffix == ".py" or not os.access(exe, os.X_OK):
        # Started via `python -m ifolder_sync`: argv[0] is not an executable entry
        # point, so the agent must go through the interpreter.
        program = [sys.executable, "-m", "ifolder_sync"]
    else:
        program = [str(exe)]

    payload = {
        "Label": label,
        # --launchd: keep deliberate stops at exit 0 so KeepAlive cannot crash-loop them.
        "ProgramArguments": [*program, "start", "--profile", profile, "--launchd"],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 60,
        # Grace period for SIGTERM (stop/logout) to finish the current apply action
        # and commit before launchd SIGKILLs. Does not delay a clean exit.
        "ExitTimeOut": 30,
        "StandardOutPath": str(log_dir / "daemon.out.log"),
        "StandardErrorPath": str(log_dir / "daemon.err.log"),
        "ProcessType": "Background",
    }
    with open(plist_path, "wb") as fh:
        plistlib.dump(payload, fh)
    return plist_path


# launchctl's returncode is unreliable across macOS releases (it can exit 0 on
# "already loaded"); classify by known stderr substrings, not by returncode alone.
_LAUNCHCTL_BENIGN = (
    "already loaded",
    "could not find specified service",
    "no such file or directory",
)


def _launchctl(action: str, plist: Path) -> None:
    """Run `launchctl <action> -w <plist>`, treating already-in-state as informational."""
    proc = subprocess.run(
        ["launchctl", action, "-w", str(plist)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return
    stderr = proc.stderr.strip()
    if any(token in stderr.lower() for token in _LAUNCHCTL_BENIGN):
        print(f"launchd already in the desired state ({action}): {stderr}")
        return
    print(f"launchctl {action} failed: {stderr or proc.stdout.strip()!r}", file=sys.stderr)
    sys.exit(1)


def cmd_install_agent(args):
    """Generate a launchd LaunchAgent .plist to run a profile's daemon at login."""
    profile = _profile(args)
    cfg = Config.load(config_path(profile))
    _warn_tcc(cfg.local_path)
    plist_path = _write_agent_plist(profile)
    print(f"LaunchAgent generated at {plist_path}")
    print("To enable (starts now and at each login):")
    print(f"  launchctl load -w {plist_path}")
    print(f"  (or simply: ifolder-sync start --background --profile {profile})")
    print("To stop/remove:")
    print(f"  launchctl unload -w {plist_path}")
    print(f"  (or simply: ifolder-sync stop --profile {profile})")
    print(f"Logs in {log_file(profile)}")
    print(f"\nIMPORTANT: run `ifolder-sync auth --profile {profile}` BEFORE loading the agent,")
    print("otherwise the daemon cannot pass 2FA (it runs non-interactively).")


# -------------------------------------------------------------------- main ---
def _add_profile(p: argparse.ArgumentParser):
    p.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        type=_profile_name,
        help="profile name (default: default)",
    )


_EXIT_CODE_HELP = """\
exit codes:
  0   success
  1   error (unexpected/uncategorized)
  2   usage error (bad arguments)
  3   authentication required (run `ifolder-sync auth`)
  4   scan guard aborted the pass (zero deletions; check permissions/network)
  5   vault identity mismatch (run `ifolder-sync rebaseline`)
  6   sync ran but deletions were suppressed by the safety threshold
  7   sync ran but some file operations failed
  130 interrupted (Ctrl-C)
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ifolder-sync",
        description=__doc__,
        epilog=_EXIT_CODE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"ifolder-sync {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="create/edit a profile's config")
    pi.add_argument(
        "--obsidian",
        action="store_true",
        help="mark this vault as Obsidian and skip that prompt "
        "(excludes the .obsidian per-device config from sync)",
    )
    pi.add_argument(
        "--allow-root",
        action="store_true",
        help="allow an empty remote folder = sync the entire iCloud Drive root "
        "(dangerous: mirrors every app container and propagates local deletes)",
    )
    _add_profile(pi)
    pi.set_defaults(func=cmd_init)

    pa = sub.add_parser("auth", help="authenticate with iCloud (2FA)")
    pa.add_argument(
        "--fresh",
        action="store_true",
        help="discard the saved session and log in clean (use if 2FA is stuck)",
    )
    _add_profile(pa)
    pa.set_defaults(func=cmd_auth)

    ps = sub.add_parser("sync", help="run one pass and exit")
    ps.add_argument(
        "--non-interactive",
        action="store_true",
        help="fail instead of prompting for 2FA (for cron/launchd)",
    )
    ps.add_argument("--dry-run", action="store_true", help="preview without writing anything")
    ps.add_argument(
        "--force-delete",
        action="store_true",
        help="apply deletions even if they exceed the safety threshold",
    )
    _add_profile(ps)
    ps.set_defaults(func=cmd_sync)

    pst = sub.add_parser("start", help="run the daemon (foreground, or --background via launchd)")
    pst.add_argument(
        "--background",
        action="store_true",
        help="detach via launchd: restarts on crash, starts at each login",
    )
    # Set by the generated launchd plist. Keeps operator-actionable stops at exit 0 so
    # KeepAlive cannot turn them into a restart loop (invariant 9). Hidden: not for humans.
    pst.add_argument("--launchd", action="store_true", help=argparse.SUPPRESS)
    _add_profile(pst)
    pst.set_defaults(func=cmd_start)

    psp = sub.add_parser("stop", help="stop a profile's background (launchd) daemon")
    _add_profile(psp)
    psp.set_defaults(func=cmd_stop)

    pstat = sub.add_parser("status", help="show all profiles, or one in detail with --profile")
    pstat.add_argument(
        "--profile",
        default=None,
        type=_profile_name,
        help="show one profile in detail; omit to show all profiles",
    )
    pstat.set_defaults(func=cmd_status)

    ppt = sub.add_parser("purge-trash", help="empty a profile's local soft-delete trash")
    _add_profile(ppt)
    ppt.set_defaults(func=cmd_purge_trash)

    plg = sub.add_parser("logs", help="tail the daemon log (-f to follow)")
    plg.add_argument(
        "-n", "--lines", type=int, default=50, help="lines of history to show (default: 50)"
    )
    plg.add_argument(
        "-f", "--follow", action="store_true", help="keep streaming new lines (Ctrl-C stops)"
    )
    _add_profile(plg)
    plg.set_defaults(func=cmd_logs)

    prb = sub.add_parser(
        "rebaseline",
        help="reset a profile's baseline (backup first) after the vault moved or drifted",
    )
    _add_profile(prb)
    prb.set_defaults(func=cmd_rebaseline)

    pia = sub.add_parser("install-agent", help="generate a launchd LaunchAgent")
    _add_profile(pia)
    pia.set_defaults(func=cmd_install_agent)
    return p


def _start_is_launchd(args) -> bool:
    """True when `start` is being run by launchd, where invariant 9 requires exit 0 on a
    deliberate stop. The plist passes --launchd; agents written before the flag are still
    caught because launchd redirects stderr to a file (never a TTY)."""
    return getattr(args, "launchd", False) or not sys.stderr.isatty()


def _outcome_exit_code(stats) -> Exit:
    """Map a completed pass to an exit code: errors outrank a threshold suppression, both
    outrank a clean pass. Pure so the contract is unit-testable without a real sync."""
    if stats.errors:
        return Exit.SYNC_ERRORS
    if stats.skipped_deletes:
        return Exit.DELETES_SUPPRESSED
    return Exit.OK


def _exception_exit_code(exc: BaseException) -> Optional[Exit]:
    """Map an exception to an exit code, most-specific first (LocalScanError/
    VaultIdentityError subclass RuntimeError; the auth exceptions subclass PyiCloudException).
    Returns None for an unrecognized type so main() re-raises it with a full traceback —
    only known, explained failures get the clean one-line treatment."""
    from pyicloud.exceptions import (
        PyiCloud2FARequiredException,
        PyiCloudAuthRequiredException,
        PyiCloudException,
        PyiCloudFailedLoginException,
        PyiCloudServiceNotActivatedException,
    )

    from .icloud_client import AuthError
    from .state import CorruptBaselineError
    from .syncer import LocalScanError, VaultIdentityError

    if isinstance(
        exc,
        (
            AuthError,
            PyiCloud2FARequiredException,
            PyiCloudFailedLoginException,
            PyiCloudAuthRequiredException,
            PyiCloudServiceNotActivatedException,
        ),
    ):
        # AuthError (a RuntimeError) is checked here, before the generic RuntimeError
        # branch below, so a rejected/absent password and a cancelled 2FA all exit 3.
        return Exit.AUTH_REQUIRED
    if isinstance(exc, VaultIdentityError):
        return Exit.VAULT_IDENTITY
    if isinstance(exc, LocalScanError):
        return Exit.SCAN_GUARD
    if isinstance(exc, (PyiCloudException, CorruptBaselineError)):
        # P4-4: a 503/429/service error must not dump a multi-screen traceback.
        return Exit.ERROR
    if isinstance(exc, (ValueError, RuntimeError, OSError)):
        return Exit.ERROR
    return None


def main(argv=None):
    args = build_parser().parse_args(argv)
    verbose = getattr(args, "verbose", False)
    _setup_logging(verbose)
    migrate_legacy()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(Exit.INTERRUPTED)
    except Exception as exc:  # noqa: BLE001
        code = _exception_exit_code(exc)
        if code is None or verbose:
            # Unknown failure, or the operator asked for the traceback with -v.
            raise
        print(f"Error: {exc}", file=sys.stderr)
        if code == Exit.AUTH_REQUIRED:
            print("Run `ifolder-sync auth` to (re)authenticate.", file=sys.stderr)
        sys.exit(code)


if __name__ == "__main__":
    main()
