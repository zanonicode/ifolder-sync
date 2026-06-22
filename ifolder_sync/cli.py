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
  restart        restart a profile's background (launchd) daemon (force-respawn)
  status         show all profiles' state, or one in detail with `--profile`
  doctor         audit baseline vs local vs remote consistency (read-only)
  logs           tail a profile's daemon log (`-f` to follow, `-n` lines)
  rebaseline     reset a profile's baseline (backup first) after the vault moved/drifted
  purge-trash    empty a profile's local soft-delete trash
  install-agent  generate a launchd LaunchAgent .plist for a profile
  uninstall      stop and remove a profile's launchd agent (.plist)
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
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime
from http.cookiejar import LoadError, LWPCookieJar
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from . import __version__
from .config import (
    CONFLICT_POLICIES,
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
    status_path,
    tcc_protected,
    trash_dir,
    write_vault_marker,
)
from .exitcodes import Exit
from .locking import AlreadyRunning, SingleInstanceLock, holder_pid
from .trash import purge_trash, trash_count


def _color(text: str, code: str) -> str:
    """ANSI-wrap only on a TTY so piped/captured output stays plain; never when NO_COLOR
    is set (no-color.org: presence disables color regardless of value)."""
    if "NO_COLOR" in os.environ or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


@dataclass(frozen=True)
class DaemonState:
    """Observed daemon liveness: a three-state model (running / stopped / unknown) that
    replaces the old liveness bool. `running` carries the pid; `foreground` marks a daemon
    started in the foreground (no launchd job — observed via the lock fallback, Decision 5);
    `detail` carries the reason an observation is `unknown` (an odd launchctl state, a
    non-zero print rc) so `status` never collapses ambiguity to a false "stopped"."""

    state: str  # "running" | "stopped" | "unknown"
    pid: Optional[int] = None
    foreground: bool = False
    detail: str = ""

    @classmethod
    def running(cls, pid: int, foreground: bool = False) -> "DaemonState":
        return cls("running", pid=pid, foreground=foreground)

    @classmethod
    def stopped(cls) -> "DaemonState":
        return cls("stopped")

    @classmethod
    def unknown(cls, detail: str = "") -> "DaemonState":
        return cls("unknown", detail=detail)

    @property
    def is_running(self) -> bool:
        return self.state == "running"

    def to_status(self) -> dict[str, Any]:
        """The dashboard/`--json` contract: keep the legacy `running`/`pid` keys (renderers
        read them) and add the explicit `state` (running/stopped/unknown) + `foreground`."""
        return {
            "running": self.is_running,
            "pid": self.pid,
            "state": self.state,
            "foreground": self.foreground,
        }


def _daemon_status(profile: str) -> dict[str, Any]:
    """Raw daemon liveness for both the text and --json renderers, observed from launchd
    (`launchctl print`) with the lock/holder_pid path kept only as the foreground fallback."""
    return _observe_daemon(profile).to_status()


def _daemon_state(profile: str) -> str:
    st = _observe_daemon(profile)
    if st.state == "running":
        suffix = ", foreground" if st.foreground else ""
        return _color("running", "32;1") + f" (pid {st.pid}{suffix})"
    if st.state == "unknown":
        detail = f" ({st.detail})" if st.detail else ""
        return _color("unknown", "33") + detail
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


def _auth_status(apple_id: str) -> dict[str, Any]:
    """Raw session/auth state for both the text and --json renderers. `detail` is the
    human suffix (kept so the text output is byte-identical); `trusted_until` is the cookie
    expiry date (YYYY-MM-DD) or None."""

    def s(state: str, color: str, detail: str, trusted_until: Optional[str] = None):
        return {"state": state, "color": color, "detail": detail, "trusted_until": trusted_until}

    if not apple_id:
        return s("unknown", "33", " (no apple_id in config)")
    session_file, cookie_file = session_paths(apple_id)
    try:
        data = json.loads(session_file.read_text())
    except FileNotFoundError:
        return s("not found", "31", " — run `ifolder-sync auth`")
    except (OSError, ValueError):
        return s("corrupted", "31", " — run `ifolder-sync auth --fresh`")
    if data.get("session_token") and not data.get("trust_token"):
        return s("poisoned", "33", " — 2FA never trusted; run `ifolder-sync auth --fresh`")
    expires = _trust_cookie_expiry(cookie_file)
    if expires is None:
        return s("untrusted", "33", " — daemon would need 2FA; run `ifolder-sync auth`")
    when = datetime.fromtimestamp(expires).strftime("%Y-%m-%d")
    if expires > time.time():
        return s("valid", "32;1", f" — trusted until {when}", when)
    return s("expired", "31", f" on {when} — run `ifolder-sync auth`", when)


def _auth_state(apple_id: str) -> str:
    st = _auth_status(apple_id)
    return _color(st["state"], st["color"]) + st["detail"]


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


def _ask(prompt: str, current: Any) -> str:
    """Free-text prompt: empty input keeps the current value."""
    return input(f"{prompt} [{current}]: ").strip() or str(current)


def _ask_required(prompt: str, current: str) -> str:
    """Re-prompt until a non-empty value is given (empty keeps a non-empty default)."""
    while True:
        val = input(f"{prompt} [{current}]: ").strip() or current
        if val:
            return val
        print("  This value is required — please enter it.")


def _ask_int(prompt: str, current: int) -> int:
    """Re-prompt until the input parses as an integer, instead of aborting the interview
    on a typo like '60s'."""
    while True:
        raw = input(f"{prompt} [{current}]: ").strip()
        if not raw:
            return current
        try:
            return int(raw)
        except ValueError:
            print(f"  '{raw}' is not a whole number — please try again.")


def _ask_choice(prompt: str, current: str, choices: tuple[str, ...]) -> str:
    """Re-prompt until the input is one of `choices`."""
    while True:
        val = input(f"{prompt} [{current}]: ").strip() or current
        if val in choices:
            return val
        print(f"  '{val}' is not one of {'/'.join(choices)} — please try again.")


def cmd_init(args):
    profile = _profile(args)
    path = config_path(profile)
    cfg = Config.load(path) if path.exists() else Config()

    print(f"== ifolder-sync configuration (profile: {profile}) ==")
    cfg.apple_id = _ask_required("Apple ID (email of the iCloud account to sync)", cfg.apple_id)
    cfg.remote_folder = _ask("Folder inside iCloud Drive (empty = root)", cfg.remote_folder)
    cfg.local_folder = _ask(
        "Local folder to mirror", cfg.local_folder or str(Path.home() / "iCloudSync")
    )
    cfg.interval_seconds = _ask_int("Poll interval (seconds)", cfg.interval_seconds)
    cfg.conflict_policy = _ask_choice(
        "Conflict policy (newer/local/remote/both)", cfg.conflict_policy, CONFLICT_POLICIES
    )
    watch = _ask("Watch local changes in real time? (y/n)", "y" if cfg.watch_local else "n")
    cfg.watch_local = watch.lower().startswith("y")
    if args.obsidian:
        cfg.obsidian = True
        print("Is this an Obsidian vault? yes (--obsidian)")
    else:
        obs_default = "y" if cfg.obsidian else "n"
        cfg.obsidian = _ask("Is this an Obsidian vault? (y/n)", obs_default).lower().startswith("y")

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


@contextmanager
def _daemon_lock(profile: str, action: str):
    """Hold the single-instance lock for the whole of a baseline-writing command, or refuse.

    sync, doctor --fix-orphans, and rebaseline all mutate the baseline, so each must HOLD the
    lock the daemon uses for the entire write — not merely snapshot holder_pid (a TOCTOU: a
    daemon can start during the multi-second network walk/backup and write the baseline
    concurrently). SystemExit is raised before the yield, so a refused command never enters
    the body and nothing is released.
    """
    pid = holder_pid(lock_path(profile))
    if pid:
        print(
            f"Error: the daemon is running (pid {pid}); {action} would race its baseline. "
            f"Stop it first: `ifolder-sync stop --profile {profile}`.",
            file=sys.stderr,
        )
        sys.exit(Exit.ERROR)
    lock = SingleInstanceLock(lock_path(profile))
    try:
        lock.acquire()
    except AlreadyRunning as exc:
        print(
            f"Error: {exc} — {action} would race the baseline. "
            f"Stop the daemon first: `ifolder-sync stop --profile {profile}`.",
            file=sys.stderr,
        )
        sys.exit(Exit.ERROR)
    try:
        yield lock
    finally:
        lock.release()


def cmd_sync(args):
    from .icloud_client import ICloudClient
    from .inflight import InflightSurface
    from .state import StateStore
    from .syncer import Syncer

    profile, cfg = _load_profile(args)
    # Progress to stderr (never stdout — keeps --json clean) so the user sees the slow
    # connect+scan is working and is not tempted to Ctrl-C mid-bootstrap (the worst moment).
    json_mode = getattr(args, "json", False)
    show_progress = sys.stderr.isatty() and not json_mode

    def progress(msg: str) -> None:
        if show_progress:
            print(msg, file=sys.stderr)

    # Feed the live `status --watch` surface for a foreground sync too — without this a manual
    # sync uploads invisibly (the daemon used to be the only producer). --dry-run writes
    # nothing, so it takes no surface (and no lock).
    surface = (
        InflightSurface(
            status_path(profile),
            min_write_interval_ms=int(getattr(cfg, "inflight_min_write_interval_ms", 200)),
        )
        if not args.dry_run and getattr(cfg, "inflight_surface", True)
        else None
    )

    # A non-dry-run sync mutates the baseline, so it holds the daemon's lock for the whole
    # pass; --dry-run writes nothing and is allowed to run even while the daemon holds it.
    lock_cm = nullcontext() if args.dry_run else _daemon_lock(profile, "a manual sync")
    with lock_cm:
        client = ICloudClient.from_config(cfg)
        # --json is a machine contract: a 2FA/password prompt can't be answered by a
        # consumer and its text would land on stdout before the JSON, so force
        # non-interactive when --json is set (an auth gap then fails fast to stderr + exit 3).
        interactive = not args.non_interactive and not json_mode
        progress(f"Connecting to iCloud as {cfg.apple_id}…")
        # Connect outside the surface/StateStore scope: a connect failure writes no snapshot.
        client.connect(interactive=interactive)
        with StateStore(baseline_path(profile)) as store:
            store.quick_check()  # corrupt baseline -> clear RuntimeError, exit 1 (no traceback)
            syncer = Syncer(
                cfg,
                client,
                store,
                trash_dir=trash_dir(profile),
                on_event=(surface.record if surface else None),
            )
            progress("Scanning local and remote… (the first sync can take ~1 minute)")
            if surface:
                _inflight_start(surface, store)
            try:
                stats = syncer.sync_once(dry_run=args.dry_run, force_delete=args.force_delete)
            finally:
                # Always clear the live rows (a mid-pass failure must not leave "uploading X"
                # stuck in status.json); also stamps the just-finished pass's meta.
                if surface:
                    _inflight_finish(surface, store)
        if getattr(args, "json", False):
            print(json.dumps(_sync_json(stats, args.dry_run), indent=2))
        else:
            prefix = "Dry-run (no changes written)" if args.dry_run else "Sync done"
            print(f"{prefix}: {stats.summary()}")
    # A pass can "succeed" yet leave work unfinished: the safety threshold suppressed
    # deletions, or some file operations failed. Surface that as a distinct exit code so
    # cron/monitoring can react instead of trusting a blanket 0. (Reached only on success;
    # an exception above propagates straight to main's taxonomy. The lock is already
    # released by the with-block, so the exit code is computed daemon-mutex-free.)
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
    """Detach the daemon by handing it to launchd: converge the job (bootout/bootstrap/
    enable/kickstart -k), then VERIFY it actually came up before reporting the outcome."""
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
    _converge_start(profile)
    st = _verify(profile, want_running=True, timeout=_start_verify_timeout(cfg))
    if not st.is_running:
        # A daemon that failed preflight/auth exits 0 by design (invariant 9), so it never
        # comes up and verify times out — report the truth, never false success.
        print(
            f"Background daemon failed to start ({_agent_label(profile)}) — see logs.",
            file=sys.stderr,
        )
        print(f"Logs: {log_file(profile)}", file=sys.stderr)
        sys.exit(Exit.ERROR)
    print(f"Background daemon started via launchd ({_agent_label(profile)}, pid {st.pid}).")
    print("It runs now, restarts on crash, and starts again at each login.")
    print(f"Logs:    {log_file(profile)}")
    print(f"Stop it: ifolder-sync stop --profile {profile}")


def cmd_stop(args):
    """Stop a profile's background (launchd) daemon, keyed off the job state, not a plist
    file's presence. Idempotent: an already-stopped job is success. A foreground daemon (a
    live lock holder with no launchd job) is reported, not falsely claimed stopped."""
    profile = _profile(args)
    label = _agent_label(profile)
    before = _observe_daemon(profile)
    if before.state == "running" and before.foreground:
        # A foreground `start` (no launchd job): bootout cannot reach it. Don't lie.
        print(
            f"A foreground daemon holds profile '{profile}' (pid {before.pid}); there is no "
            "launchd job to stop. Stop it where it runs (Ctrl-C) or send it SIGTERM.",
            file=sys.stderr,
        )
        sys.exit(Exit.ERROR)
    if not _converge_stop(profile):
        print(f"launchctl bootout failed for {label}.", file=sys.stderr)
        sys.exit(Exit.ERROR)
    timeout = _lifecycle_timeout(profile)
    st = _verify(profile, want_running=False, timeout=timeout)
    if st.is_running:
        print(f"Background daemon did not stop ({label}, pid {st.pid}).", file=sys.stderr)
        sys.exit(Exit.ERROR)
    if before.state == "stopped":
        print(f"No running daemon for profile '{profile}' (already stopped).")
    else:
        print(f"Background daemon stopped ({label}).")


def _lifecycle_timeout(profile: str) -> float:
    """The verify-post-condition bound for a profile, defaulting cleanly when the config is
    absent/unreadable (stop/restart must still work on a half-configured profile)."""
    try:
        return float(Config.load(config_path(profile)).lifecycle_verify_timeout_seconds)
    except Exception:  # noqa: BLE001 — no/invalid config: use the dataclass default
        return Config().lifecycle_verify_timeout_seconds


def _start_verify_timeout(cfg: Config) -> float:
    """Post-condition wait for a (re)start. launchd can delay a fresh spawn up to
    ThrottleInterval, so the success-poll must OUTLAST the throttle or a throttled-but-fine
    start reads as a false 'failed to start'. The poll returns the instant the daemon is
    running, so a fast start stays fast — only a throttled or genuinely-failed start waits.
    Stop/uninstall keep the short lifecycle_verify_timeout_seconds (teardown is not throttled)."""
    return max(
        cfg.lifecycle_verify_timeout_seconds,
        _THROTTLE_INTERVAL_SECONDS + _VERIFY_BUFFER_SECONDS,
    )


def cmd_restart(args):
    """Restart a profile's background daemon as a first-class verb (not `stop && start`):
    the same converge chain force-respawns it immediately (kickstart -k bypasses the
    ~60s ThrottleInterval), then verifies it came back up."""
    profile = _profile(args)
    cfg = Config.load(config_path(profile))
    _warn_tcc(cfg.local_path)
    _converge_start(profile)
    st = _verify(profile, want_running=True, timeout=_start_verify_timeout(cfg))
    if not st.is_running:
        print(f"Daemon failed to restart ({_agent_label(profile)}) — see logs.", file=sys.stderr)
        print(f"Logs: {log_file(profile)}", file=sys.stderr)
        sys.exit(Exit.ERROR)
    print(f"Background daemon restarted ({_agent_label(profile)}, pid {st.pid}).")


def cmd_uninstall(args):
    """Stop the profile's launchd job (idempotent) and remove its LaunchAgent .plist. Safe to
    run when nothing is installed."""
    profile = _profile(args)
    label = _agent_label(profile)
    if not _converge_stop(profile):
        print(f"launchctl bootout failed for {label}.", file=sys.stderr)
        sys.exit(Exit.ERROR)
    # Verify the daemon actually stopped before removing its job definition, so we never report
    # "uninstalled" while the process is still draining (same post-condition gate as `stop`).
    _verify(profile, want_running=False, timeout=_lifecycle_timeout(profile))
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    existed = plist_path.exists()
    plist_path.unlink(missing_ok=True)
    if existed:
        print(f"Uninstalled launchd agent {label} (stopped and removed {plist_path}).")
    else:
        print(f"No launchd agent for profile '{profile}' (nothing to uninstall).")


def _has_session(apple_id: str) -> bool:
    return session_paths(apple_id)[0].exists()


def _baseline_meta(profile: str) -> tuple[str, dict[str, Any]]:
    """(state, meta) where state is 'absent' | 'ok' | 'corrupt' and meta carries
    last_sync/last_error/last_stats (empty unless 'ok'). Single source for both the text
    and --json status views so they cannot drift."""
    from .state import CorruptBaselineError, StateStore

    db = baseline_path(profile)
    if not db.exists():
        return "absent", {}
    try:
        with StateStore(db) as store:
            return "ok", {
                "last_sync": store.get_meta("last_sync"),
                "last_error": store.get_meta("last_error"),
                "last_stats": store.get_meta("last_stats"),
            }
    except CorruptBaselineError:
        return "corrupt", {}


def _profile_status_data(profile: str) -> dict[str, Any]:
    """Presentation-free profile status for `status --json`. The text view below is the
    human renderer; both read the same low-level helpers."""
    path = config_path(profile)
    if not path.exists():
        return {"profile": profile, "configured": False}
    cfg = Config.load(path)
    auth = _auth_status(cfg.apple_id)
    state, meta = _baseline_meta(profile)
    last_sync = meta.get("last_sync")
    return {
        "profile": profile,
        "configured": True,
        "daemon": _daemon_status(profile),
        "config": str(path),
        "apple_id": cfg.apple_id,
        "remote_folder": cfg.remote_folder,
        "local_folder": str(cfg.local_path),
        "interval_seconds": cfg.interval_seconds,
        "watch_local": cfg.watch_local,
        "conflict_policy": cfg.conflict_policy,
        "obsidian": cfg.obsidian,
        "remote_trash": cfg.remote_trash,
        "state_dir": str(state_dir(profile)),
        "session": {"state": auth["state"], "trusted_until": auth["trusted_until"]},
        "local_trash_files": trash_count(trash_dir(profile)),
        "baseline": state,
        "last_sync": float(last_sync) if last_sync else None,
        "last_stats": meta.get("last_stats"),
        "last_error": meta.get("last_error"),
        "attention": [r.to_dict() for r in _attention_rows(profile)] if state == "ok" else [],
    }


def _print_profile_status(profile: str) -> None:
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

    state, meta = _baseline_meta(profile)
    if state == "corrupt":
        print(
            f"Baseline:      {_color('corrupt', '31')} — run "
            f"`ifolder-sync rebaseline --profile {profile}`"
        )
        return
    if state == "ok":
        if meta["last_sync"]:
            ts = datetime.fromtimestamp(float(meta["last_sync"])).strftime("%Y-%m-%d %H:%M:%S")
            print(f"Last sync:     {ts} ({meta['last_stats'] or ''})")
        if meta["last_error"]:
            print(f"Last error:    {meta['last_error']}")
        if _stats_has_trouble(meta.get("last_stats")) or meta.get("last_error"):
            # Cheap, network-free pointer: the last pass logged errors/suppressed deletes,
            # so a read-only `doctor` audit would have something to show.
            print(
                f"               {_color('→', '33')} run "
                f"`ifolder-sync doctor --profile {profile}` to inspect inconsistencies"
            )


def _stats_has_trouble(last_stats: Optional[str]) -> bool:
    """True when the last pass summary shows counted errors or suppressed deletions — the
    signal that `doctor` would have something to report. A cheap string scan of the meta
    field already in hand, so `status` stays a fast liveness peek (no scan, no network)."""
    if not last_stats:
        return False
    for key in ("errors=", "skipped_deletes="):
        m = re.search(rf"\b{key}(\d+)", last_stats)
        if m and int(m.group(1)) > 0:
            return True
    return False


def cmd_status(args):
    if getattr(args, "watch", False):
        # No --profile + multiple profiles -> a compact multi-profile overview; otherwise the
        # single-profile live frame.
        profile = args.profile
        _watch_dashboard(profile, _watch_interval(profile or DEFAULT_PROFILE, args))
        return
    profiles = list_profiles()
    if getattr(args, "json", False):
        # JSON to stdout as a stable contract; human messaging (none here) would go to
        # stderr. --profile selects one; otherwise every profile.
        selected = [args.profile] if args.profile is not None else profiles
        print(json.dumps({"profiles": [_profile_status_data(p) for p in selected]}, indent=2))
        return
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


_DOCTOR_LABELS = {
    "would-conflict": "Would conflict (both sides changed since baseline)",
    "drift": "Unsettled / pending (empty-husk wait, adopt-verify)",
    "planned-delete": "Planned deletions",
    "planned-download": "Planned downloads (remote -> local)",
    "planned-upload": "Planned uploads (local -> remote)",
}
# Cap each group's listing so a fresh/rebaselined vault (thousands of planned uploads)
# stays legible; the "... and N more" line keeps the truncation explicit, never silent.
_DOCTOR_MAX_LIST = 20


def _doctor_json(plan, profile: str) -> dict[str, Any]:
    """Serialize a doctor audit. Shares the `schema` + `rows` envelope with the dashboard's
    `status.json` (the parity contract) so one reader can consume both."""
    from .syncstate import make_envelope

    return make_envelope(
        plan.rows,
        profile=profile,
        suppressed_deletes=plan.suppressed_deletes,
        decide_errors=plan.errors,
        inconsistencies=len(plan.rows),
    )


def _print_doctor_report(plan, profile: str) -> None:
    if plan.is_clean:
        print("No inconsistencies found — baseline, local, and remote agree.")
        return
    orphans = plan.orphans
    if orphans:
        print(_color(f"Orphan baseline rows ({len(orphans)})", "31;1") + ":")
        for r in orphans:
            print(f"  {r.relpath}  ({r.reason})")
        print(
            "  -> stale rows present only in the baseline. Recover with "
            f"`ifolder-sync rebaseline --profile {profile}` (backup + additive re-sync)."
        )
    groups: dict[str, list] = {}
    for r in plan.rows:
        if r.state != "orphan-baseline":
            groups.setdefault(r.state, []).append(r)
    for state, label in _DOCTOR_LABELS.items():
        rows = groups.get(state)
        if not rows:
            continue
        print(f"\n{label} ({len(rows)}):")
        for r in rows[:_DOCTOR_MAX_LIST]:
            suffix = f"  ({r.reason})" if r.reason else ""
            print(f"  {r.relpath}{suffix}")
        if len(rows) > _DOCTOR_MAX_LIST:
            print(f"  ... and {len(rows) - _DOCTOR_MAX_LIST} more")
    if plan.suppressed_deletes:
        print(
            f"\n{plan.suppressed_deletes} deletion(s) would be withheld by the safety "
            "threshold; review them, then `sync --force-delete` to apply."
        )
    if plan.errors:
        print(
            f"\n{plan.errors} path(s) cannot be reconciled this pass (live case-collision "
            "or file/dir kind-conflict); rename one side to resolve."
        )


def _fix_orphans(plan, profile: str, store, is_ignored=None):
    """Drop ONLY the provably-orphan baseline rows (present in the baseline, absent from a
    SUCCESSFUL local+remote scan — `plan()` already guaranteed both scans succeeded or it
    raised). Backs up the baseline first (the recovery net) and clears the stale walk_cache.
    Touches NO local or remote content. Returns (count, backup_path). The exact manual repair
    the 2026-06-20 incident needed, now a guarded command.

    A path matched by the current ignore set is skipped: it is present-but-filtered (a
    newly-ignored file still on disk), not an absent ghost — keeping a harmless stale row beats
    discarding a live file's baseline (which would later surface as a conflict, not a clean
    sync)."""
    orphans = [r.relpath for r in plan.orphans if is_ignored is None or not is_ignored(r.relpath)]
    if not orphans:
        return 0, None
    src = baseline_path(profile)
    base = f"{src.name}.pre-fix-orphans-{time.strftime('%Y%m%d-%H%M%S')}"
    bak = src.with_name(base)
    n = 1
    while bak.exists():  # collision-safe: never silently overwrite a prior backup
        bak = src.with_name(f"{base}-{n}")
        n += 1
    store.backup_to(bak)  # WAL-safe consistent copy, taken BEFORE any drop
    store.drop_rows(orphans)
    store.set_meta("walk_cache", "")  # a stale etag cache may still carry the orphan subtree
    return len(orphans), bak


def cmd_doctor(args):
    """Read-only audit of baseline vs local vs remote. Runs the engine's decide phase with
    NO apply (`Syncer.plan()`): it changes no user files, never writes the baseline, and
    makes no remote change. (It does a network walk and may persist the iCloud session, like
    every command.) `--fix-orphans` is the one opt-in write: it backs up the baseline and
    drops only the orphan rows."""
    from .icloud_client import ICloudClient
    from .state import StateStore
    from .syncer import Syncer

    profile, cfg = _load_profile(args)
    json_mode = getattr(args, "json", False)
    fix = getattr(args, "fix_orphans", False)
    show_progress = sys.stderr.isatty() and not json_mode

    def progress(msg: str) -> None:
        if show_progress:
            print(msg, file=sys.stderr)

    # --fix-orphans WRITES the baseline (same gate as sync), so it holds the daemon's lock for
    # the whole write; the read-only audit takes no lock and runs alongside a live daemon.
    lock_cm = _daemon_lock(profile, "--fix-orphans") if fix else nullcontext()
    with lock_cm:
        client = ICloudClient.from_config(cfg)
        interactive = not getattr(args, "non_interactive", False) and not json_mode
        progress(f"Connecting to iCloud as {cfg.apple_id}…")
        client.connect(interactive=interactive)
        with StateStore(baseline_path(profile)) as store:
            store.quick_check()  # corrupt baseline -> clear RuntimeError, exit 1 (no traceback)
            syncer = Syncer(cfg, client, store, trash_dir=trash_dir(profile))
            progress("Auditing baseline / local / remote… (read-only; no changes to your files)")
            # plan() raises on a scan failure -> aborts here, so --fix-orphans can NEVER act on
            # a partial scan (which could mislabel a live path as orphan).
            plan = syncer.plan()
            if json_mode:
                payload = _doctor_json(plan, profile)
                if fix:
                    count, bak = _fix_orphans(plan, profile, store, syncer._ignored)
                    payload["fixed_orphans"] = count
                    payload["backup"] = str(bak) if bak else None
                print(json.dumps(payload, indent=2))
                return
            _print_doctor_report(plan, profile)
            if fix:
                count, bak = _fix_orphans(plan, profile, store, syncer._ignored)
                if count:
                    print(f"\nFixed: dropped {count} orphan baseline row(s). Backup at {bak}.")
                else:
                    print("\nNothing to fix: no orphan baseline rows.")


# ---------------------------------------------------- live dashboard (status --watch) ---
_DASH_W = 64  # frame inner width
_DASH_MAX = 15  # cap the attention list; "... and N more" keeps the truncation explicit


def _parse_json_meta(raw: Optional[str]) -> dict:
    try:
        data = json.loads(raw or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _attention_rows(profile: str) -> list:
    """The engine's persisted 'stuck' registries folded into attention rows. Read-only by
    construction: opens the baseline with a mode=ro connection and reads meta only
    (settle_counts husks + unreadable_counts propagation-lag backoffs), never the daemon's
    writer path. Degrades to [] on any read problem — an observer must never crash the way a
    writer would."""
    from .state import StateStore
    from .syncstate import stuck_rows

    db = baseline_path(profile)
    if not db.exists():
        return []
    try:
        with StateStore(db, read_only=True) as store:
            settle = _parse_json_meta(store.get_meta("settle_counts"))
            unreadable = _parse_json_meta(store.get_meta("unreadable_counts"))
    except Exception:  # noqa: BLE001 — a bad/locked read must not crash the dashboard
        return []
    return stuck_rows(settle, unreadable)


def _inflight_header(store) -> dict[str, Any]:
    """Header a foreground sync stamps into status.json, mirroring the daemon's
    (daemon.py `_inflight_header`): the live pid plus the persisted last-pass meta."""
    return {
        "pid": os.getpid(),
        "last_sync": store.get_meta("last_sync"),
        "last_stats": store.get_meta("last_stats"),
        "last_error": store.get_meta("last_error"),
    }


def _inflight_stuck(store) -> list:
    """The engine's persisted stuck registries as rows, read from the open writer store
    (the daemon reads the same two meta keys for `pass_finished`)."""
    from .syncstate import stuck_rows

    return stuck_rows(
        _parse_json_meta(store.get_meta("settle_counts")),
        _parse_json_meta(store.get_meta("unreadable_counts")),
    )


def _inflight_start(surface, store) -> None:
    """Best-effort: the live surface must never break a sync pass (mirrors the daemon guards)."""
    try:
        surface.pass_started(**_inflight_header(store))
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("ifolder-sync.inflight").debug("pass_started skipped: %s", exc)


def _inflight_finish(surface, store) -> None:
    try:
        surface.pass_finished(_inflight_stuck(store), **_inflight_header(store))
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("ifolder-sync.inflight").debug("pass_finished skipped: %s", exc)


def _read_status_snapshot(profile: str) -> Optional[dict[str, Any]]:
    """Read the daemon's live status.json snapshot (feature 04 Phase 2), or None when absent/
    unreadable. It carries the in-flight transfer rows the daemon is moving RIGHT NOW plus a
    header it stamped — so the observer never opens the baseline at all when it is present.
    Best-effort: a torn/missing/corrupt snapshot just falls back to the meta fold."""
    path = status_path(profile)
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("schema") == 1 else None


def _dashboard_view(profile: str) -> dict[str, Any]:
    """Presentation-free dashboard snapshot: daemon liveness + the last-pass meta + attention
    rows. Prefers the daemon's live status.json (in-flight transfers) when present, falling
    back to the read-only meta fold (the persisted stuck set). Both the live renderer and
    `status --json` read this, so they cannot drift."""
    from .syncstate import SyncRow

    state, meta = _baseline_meta(profile)
    last_sync = meta.get("last_sync")
    daemon = _daemon_status(profile)
    # Trust the live snapshot only when its writer is the CURRENT lock holder: a snapshot whose
    # `pid` differs from the live holder is stale (a dead daemon's file, or one a prior process
    # left behind) and its in-flight rows ("uploading X") must NOT render as live activity.
    # Otherwise fall back to the persisted stuck set (the meta fold), which is still valid.
    snap = _read_status_snapshot(profile) if daemon["running"] else None
    if snap is not None and snap.get("pid") != daemon["pid"]:
        snap = None
    if snap is not None:
        # Live path: the daemon's snapshot is authoritative for the rows (in-flight + stuck)
        # and the header it stamped; the meta read above still supplies the baseline state.
        ls = snap.get("last_sync")
        return {
            "profile": profile,
            "daemon": daemon,
            "baseline": state,
            "last_sync": float(ls) if ls else (float(last_sync) if last_sync else None),
            "last_stats": snap.get("last_stats") or meta.get("last_stats"),
            "last_error": snap.get("last_error") or meta.get("last_error"),
            "attention": [SyncRow.from_dict(r) for r in snap.get("rows", [])],
        }
    return {
        "profile": profile,
        "daemon": daemon,
        "baseline": state,
        "last_sync": float(last_sync) if last_sync else None,
        "last_stats": meta.get("last_stats"),
        "last_error": meta.get("last_error"),
        "attention": _attention_rows(profile) if state == "ok" else [],
    }


def _fmt_age(last_sync: Optional[float], now: float) -> str:
    if not last_sync:
        return "never"
    d = max(0, int(now - last_sync))
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else "…" + s[-(n - 1) :]


def _box(title: str, rows: list[str]) -> list[str]:
    """Render rows inside a fixed-width Unicode box. Rows are plain (no ANSI) so the visible
    width is exact; color is applied to the attention lines below the box, where trailing
    color never breaks alignment."""
    inner = _DASH_W - 2
    out = ["┌─ " + title + " " + "─" * max(3, _DASH_W - len(title) - 5) + "┐"]
    for r in rows:
        out.append("│ " + r[: inner - 2].ljust(inner - 2) + " │")
    out.append("└" + "─" * inner + "┘")
    return out


# Per-state label + ANSI color for the activity pane. Covers both the live in-flight
# transfers (status.json) and the persisted stuck registries (the meta fold).
_STATE_LABEL = {
    "queued": ("• queued", "90"),
    "uploading": ("↑ uploading", "36"),
    "downloading": ("↓ downloading", "36"),
    "deleting-local": ("✗ del local", "31"),
    "deleting-remote": ("✗ del remote", "31"),
    "conflict": ("⚠ conflict", "31"),
    "error": ("⚠ error", "31"),
    "deferred-settle": ("settling", "33"),
    "pending-unreadable": ("pending", "33"),
}

# Render order in the activity/files table: active transfers on top, then the queue, then the
# persisted stuck states. A path's queue position is otherwise dict-insertion (emit) order.
_STATE_ORDER = {
    "uploading": 0,
    "downloading": 0,
    "deleting-local": 0,
    "deleting-remote": 0,
    "conflict": 0,
    "error": 1,
    "deferred-settle": 2,
    "pending-unreadable": 2,
    "queued": 3,
}


def _ordered_rows(rows: list) -> list:
    """Stable sort for the files table: active first, queue last (ties keep arrival order)."""
    return sorted(rows, key=lambda r: _STATE_ORDER.get(r.state, 5))


_RECENT_TTL = 6.0  # seconds a just-completed file lingers on the "recently synced" rail
_FLAP_THRESHOLD = 3  # completions within the window before a path is flagged as flapping
_FLAP_WINDOW = 60.0  # only completions in the last this-many seconds count toward flapping


class _WatchState:
    """View-side memory across redraws (a live `status --watch` loop only). Diffs successive
    frames to surface (a) files that JUST completed — a short 'recently synced' rail so a fast
    transfer is not invisible — and (b) flapping paths that complete repeatedly WITHIN a moving
    window (a re-sync loop), which would otherwise scroll away unseen. Both decay with time, so
    a path that stabilizes drops off and the per-path state stays bounded on a long watch.
    Pure: `observe` is the only state change."""

    def __init__(
        self,
        recent_ttl: float = _RECENT_TTL,
        flap_threshold: int = _FLAP_THRESHOLD,
        flap_window: float = _FLAP_WINDOW,
    ):
        self.recent_ttl = recent_ttl
        self.flap_threshold = flap_threshold
        self.flap_window = flap_window
        self._prev: set[str] = set()
        self._recent: dict[str, float] = {}
        self._completions: dict[str, deque] = {}  # relpath -> recent completion timestamps

    def observe(self, view: dict[str, Any], now: float) -> dict[str, Any]:
        cur = {r.relpath for r in view["attention"]}
        for path in self._prev - cur:  # vanished since the last frame == completed
            self._recent[path] = now
            self._completions.setdefault(path, deque()).append(now)
        self._recent = {p: t for p, t in self._recent.items() if now - t < self.recent_ttl}
        # Decay completions to the moving window and drop emptied paths (bounds memory; the
        # flag reflects CURRENT looping, not something that flapped once an hour ago).
        for path in list(self._completions):
            stamps = self._completions[path]
            while stamps and now - stamps[0] >= self.flap_window:
                stamps.popleft()
            if not stamps:
                del self._completions[path]
        self._prev = cur
        flapping = sorted(
            p for p, stamps in self._completions.items() if len(stamps) >= self.flap_threshold
        )
        # Tiebreak ties (same-frame completions share `now`) by path so the order is stable.
        recent = [p for p, _ in sorted(self._recent.items(), key=lambda kv: (-kv[1], kv[0]))]
        return {**view, "recently_synced": recent, "flapping": flapping}


def _dashboard_banner(last_stats: Optional[str]) -> Optional[str]:
    """A prominent line for the one signal the stats row buries: deletions withheld by the
    safety threshold (the drift symptom that needs `doctor`/`rebaseline`)."""
    m = re.search(r"\bskipped_deletes=(\d+)", last_stats or "")
    if m and int(m.group(1)) > 0:
        return _color(
            f"⚠ {m.group(1)} deletion(s) suppressed by the safety threshold — run `doctor`",
            "33;1",
        )
    return None


def _summary_list(label: str, items: list[str], color: str, width: int = 28) -> str:
    names = ", ".join(_truncate(p, width) for p in items[:5])
    more = f" +{len(items) - 5}" if len(items) > 5 else ""
    return "  " + _color(f"{label}: {names}{more}", color)


def _dashboard_extra_lines(view: dict[str, Any]) -> list[str]:
    """The supplementary signal lines (suppressed-deletes banner, flapping, recently synced),
    shared by BOTH the ANSI and the rich renderers so the `[dashboard]` extra can never hide a
    signal the plain frame shows (a parity contract, not duplicated per-renderer logic)."""
    out: list[str] = []
    banner = _dashboard_banner(view.get("last_stats"))
    if banner:
        out.append("  " + banner)
    flapping = view.get("flapping") or []
    if flapping:
        out.append(_summary_list("⚠ flapping (re-syncing repeatedly)", flapping, "31"))
    recent = view.get("recently_synced") or []
    if recent:
        out.append(_summary_list("✓ recently synced", recent, "32"))
    return out


def _render_dashboard_frame(view: dict[str, Any], now: float) -> str:
    daemon = view["daemon"]
    dstate = f"running (pid {daemon['pid']})" if daemon["running"] else "stopped"
    header = [
        f"{'Daemon:   ' + dstate:<34}Last sync: {_fmt_age(view['last_sync'], now)}",
        f"Stats:    {view['last_stats'] or '—'}",
    ]
    if view.get("last_error"):
        header.append(f"Error:    {view['last_error']}")
    lines = _box(f"ifolder-sync · {view['profile']}", header)
    lines.append("")

    rows = view["attention"]
    if not rows:
        lines.append("  " + _color("✓ all synced — nothing in flight or stuck", "32"))
    else:
        queued = sum(1 for r in rows if r.state == "queued")
        label = f"  Sync activity ({len(rows) - queued} active"
        label += f", {queued} queued" if queued else ""
        lines.append(label + "):")
        for r in _ordered_rows(rows)[:_DASH_MAX]:
            n = f"{r.passes_stuck}×" if r.passes_stuck else ""
            text, col = _STATE_LABEL.get(r.state, (r.state, "0"))
            lines.append(f"  {n:>4}  {_truncate(r.relpath, 42):<42} {_color(text, col)}")
        if len(rows) > _DASH_MAX:
            lines.append(f"  … and {len(rows) - _DASH_MAX} more")

    lines.extend(_dashboard_extra_lines(view))
    return "\n".join(lines)


def _render_multiprofile_frame(profiles: list[str], now: float) -> str:
    """A compact one-line-per-profile overview for `status --watch` with no --profile: daemon
    liveness + last-sync age + the stuck count, so a multi-vault setup is legible at a glance."""
    body = []
    for prof in profiles:
        view = _dashboard_view(prof)
        d = view["daemon"]
        state = f"running ({d['pid']})" if d["running"] else "stopped"
        stuck = len(view["attention"])
        flag = f" · {stuck} stuck" if stuck else ""
        body.append(f"{prof:<16}{state:<16}{_fmt_age(view['last_sync'], now):<12}{flag}")
    return "\n".join(_box("ifolder-sync · all profiles", body))


_RICH_STATE_STYLE = {
    "queued": "dim",
    "uploading": "cyan",
    "downloading": "cyan",
    "deleting-local": "red",
    "deleting-remote": "red",
    "conflict": "red",
    "error": "red",
    "deferred-settle": "yellow",
    "pending-unreadable": "yellow",
}


def _render_rich(view: dict[str, Any], now: float) -> Optional[str]:
    """A richer frame when the optional `rich` extra is installed (truecolor + real boxes).
    Returns None when rich is absent so the caller falls back to the ANSI frame. TWO frames: a
    header panel (daemon/stats/error) and, below it, a separate files table (the live queue +
    in-flight transfers). Renders the SAME signal set as the ANSI frame (the shared extra lines)
    so the `[dashboard]` extra can never hide a signal the plain frame shows."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:
        return None
    d = view["daemon"]
    dstate = f"[green]running[/] (pid {d['pid']})" if d["running"] else "[red]stopped[/]"
    head = [
        f"Daemon: {dstate}    last sync {_fmt_age(view['last_sync'], now)}",
        f"Stats:  {view['last_stats'] or '—'}",
    ]
    if view.get("last_error"):
        head.append(f"[red]Error:[/]  {view['last_error']}")
    header = Panel("\n".join(head), title=f"ifolder-sync · {view['profile']}", expand=True)

    rows = view["attention"]
    queued = sum(1 for r in rows if r.state == "queued")
    title = f"syncing — {len(rows) - queued} active" + (f", {queued} queued" if queued else "")
    files = Table(title=title, expand=True)
    files.add_column("file")
    files.add_column("state", justify="right")
    for r in _ordered_rows(rows)[:_DASH_MAX]:
        text, _ = _STATE_LABEL.get(r.state, (r.state, "0"))
        style = _RICH_STATE_STYLE.get(r.state, "")
        n = f"{r.passes_stuck}× " if r.passes_stuck else ""
        files.add_row(_truncate(r.relpath, 50), f"[{style}]{n}{text}[/]" if style else f"{n}{text}")
    if not rows:
        files.add_row("[green]✓ all synced — nothing in flight or stuck[/]", "")
    if len(rows) > _DASH_MAX:
        files.add_row(f"… and {len(rows) - _DASH_MAX} more", "")

    console = Console(force_terminal=True)
    with console.capture() as cap:
        console.print(header)
        console.print(files)
    # Parity: the supplementary signals are appended from the shared helper, never re-derived.
    extras = _dashboard_extra_lines(view)
    return cap.get() + ("\n".join(extras) + "\n" if extras else "")


def _watch_route(profile: Optional[str], profiles: list[str]) -> tuple[str, Optional[str]]:
    """Decide the watch mode (pure, so the forever loop stays a thin shell): an explicit
    --profile is always single; no --profile with >1 profile is the multi overview; otherwise
    single on the lone profile (or `default` when none exist yet)."""
    if profile is None and len(profiles) > 1:
        return "multi", None
    return "single", profile or (profiles[0] if profiles else DEFAULT_PROFILE)


def _watch_dashboard(profile: Optional[str], interval: float) -> None:
    """Live loop: redraw every `interval` seconds until Ctrl-C (main turns the KeyboardInterrupt
    into exit 130, like `logs -f`). Read-only and network-free — polls the daemon's persisted
    state, holds no engine handle, never acquires the lock. With no --profile and >1 profile it
    shows a compact multi-profile overview; otherwise a single-profile frame with a live
    'recently synced' rail + flapping detection accumulated across redraws (the `rich` extra
    upgrades the look when installed)."""
    mode, one = _watch_route(profile, list_profiles())
    watch = _WatchState()
    while True:
        now = time.time()
        if mode == "multi":
            frame = _render_multiprofile_frame(list_profiles(), now)
        else:
            assert one is not None  # single mode always carries a concrete profile
            view = watch.observe(_dashboard_view(one), now)
            frame = _render_rich(view, now) or _render_dashboard_frame(view, now)
        if sys.stdout.isatty():
            sys.stdout.write("\033[2J\033[H")  # clear + home, so the frame redraws in place
        print(frame)
        print(f"\n  refreshing every {interval:g}s · Ctrl-C to exit")
        time.sleep(interval)


def _watch_interval(profile: str, args) -> float:
    override = getattr(args, "interval", None)
    if override is not None:
        return max(0.2, float(override))
    try:
        return max(0.2, float(Config.load(config_path(profile)).dashboard_interval_seconds))
    except Exception:  # noqa: BLE001 — no/invalid config: fall back to the default cadence
        return 1.0


def cmd_purge_trash(args):
    profile = _profile(args)
    td = trash_dir(profile)
    count = trash_count(td)
    if count == 0:
        print(f"Local trash of profile '{profile}' is already empty.")
        return
    # The soft-delete trash IS the recovery net for a wrongly-propagated deletion, so this
    # is the one zero-friction destructive command — confirm before emptying it.
    if not getattr(args, "yes", False):
        if not sys.stdin.isatty():
            print(
                f"Refusing to purge {count} file(s) non-interactively. Re-run with --yes.",
                file=sys.stderr,
            )
            sys.exit(Exit.ERROR)
        try:
            answer = input(
                f"Delete {count} file(s) from the local trash of '{profile}'? [y/N]: "
            ).strip()
        except EOFError:
            answer = ""  # Ctrl-D / closed stdin = decline; never empty the safety net
        if not answer.lower().startswith("y"):
            print("Aborted; trash kept.")
            return
    n = purge_trash(td)
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
    # rebaseline DELETES the baseline DB (+ its -wal/-shm), so it holds the daemon's lock for
    # the whole backup+delete — a bare holder_pid snapshot is a TOCTOU (a daemon could start
    # mid-delete and write the baseline we are tearing down). Same gate as sync.
    with _daemon_lock(profile, "rebaseline"):
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


def _shim_in_current_venv(shim: str) -> bool:
    """True if `shim` resolves inside the running interpreter's environment (sys.prefix).
    Such a shim is recreated/destroyed with that venv, so freezing its path into the plist
    would ENOENT-crash-loop launchd after a rebuild — `python -m` is the stabler target."""
    try:
        return Path(shim).resolve().is_relative_to(Path(sys.prefix).resolve())
    except OSError:
        return True


def _agent_program() -> list[str]:
    """The command launchd should exec, chosen to survive a venv rebuild / upgrade.

    Prefer an `ifolder-sync` shim on PATH ONLY when it is absolute, executable, and lives
    OUTSIDE the current venv — a pipx/uv-tool/Homebrew shim (~/.local/bin, /opt/homebrew/
    bin) is a stable name across upgrades. It is taken UNRESOLVED (a Homebrew symlink points
    into a version-specific Cellar dir; resolving would re-break on `brew upgrade`).
    Otherwise fall back to `[sys.executable, "-m", "ifolder_sync"]`, which is always correct
    in the running interpreter and stable across rebuilds — never a bare argv[0] (which
    could be pytest, a wrapper, or a throwaway launcher that launchd would crash-loop)."""
    shim = shutil.which("ifolder-sync")
    if (
        shim
        and os.path.isabs(shim)
        and os.access(shim, os.X_OK)
        and not _shim_in_current_venv(shim)
    ):
        return [shim]
    return [sys.executable, "-m", "ifolder_sync"]


# launchd throttles a job's respawn by this many seconds (the plist `ThrottleInterval`).
# Single-sourced so the start/restart post-condition wait can outlast it (a throttled fresh
# spawn must not read as "failed to start").
_THROTTLE_INTERVAL_SECONDS = 60
_VERIFY_BUFFER_SECONDS = 5.0
# bootout is asynchronous; let a prior job finish unloading before re-bootstrapping (a
# still-loaded label bootstraps with "5: Input/output error"). Bounded so a stuck teardown
# never hangs the command.
_BOOTOUT_SETTLE_SECONDS = 5.0
_BOOTSTRAP_RETRY_SECONDS = 5.0


def _write_agent_plist(profile: str) -> Path:
    """Write (overwrite) the profile's launchd LaunchAgent .plist; return its path.

    The agent runs `start --profile <profile>` in the foreground *inside* launchd; launchd
    provides the detachment, restart-on-crash (KeepAlive), and start-at-login (RunAtLoad).
    Shared by `install-agent` and `start --background`, both of which regenerate it every
    run so an upgrade that moves the interpreter refreshes the embedded path.

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

    program = _agent_program()

    payload = {
        "Label": label,
        # --launchd: keep deliberate stops at exit 0 so KeepAlive cannot crash-loop them.
        "ProgramArguments": [*program, "start", "--profile", profile, "--launchd"],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": _THROTTLE_INTERVAL_SECONDS,
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


# Modern domain-target launchctl verbs return documented exit codes, so the control plane
# classifies by code per verb instead of matching English stderr substrings (the legacy
# `load`/`unload` band-aid). Values verified live on macOS 26.5.
_BOOTOUT_NOT_LOADED = 3  # "Boot-out failed: 3: No such process" — the job was not loaded
_PRINT_NOT_FOUND = 113  # `launchctl print` on an unknown label — the job is not loaded


def _target(profile: str) -> tuple[str, str]:
    """The launchd (domain, target) pair for a profile, computed from the running uid:
    domain `gui/<uid>` and target `gui/<uid>/com.ifolder-sync.<profile>`."""
    domain = f"gui/{os.getuid()}"
    return domain, f"{domain}/{_agent_label(profile)}"


def _lc(*args: str) -> subprocess.CompletedProcess[str]:
    """Thin `launchctl` runner. Returns the completed process so callers classify by the
    per-verb return code (never check=True, never stderr-substring matching)."""
    return subprocess.run(["launchctl", *args], capture_output=True, text=True, check=False)


def _await_not_loaded(target: str, timeout: float) -> None:
    """Block until `launchctl print <target>` reports the job not loaded (rc 113) or `timeout`
    elapses. bootout is asynchronous: a daemon slow to exit may still be unloading, and
    bootstrapping a still-loaded label fails with EIO-5 — which would leave the job down."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _lc("print", target).returncode == _PRINT_NOT_FOUND:
            return
        time.sleep(0.2)


def _bootstrap_with_retry(domain: str, target: str, plist: str) -> bool:
    """Bootstrap the job, tolerating the transient post-bootout race ("5: Input/output error"
    while the prior job finishes unloading): retry within a bounded window, and treat an
    already-loaded label (print rc != 113 despite a non-zero bootstrap) as success so the
    caller's `kickstart -k` force-respawns it rather than leaving the daemon down. Returns
    True once the label is loaded."""
    deadline = time.monotonic() + _BOOTSTRAP_RETRY_SECONDS
    while True:
        if _lc("bootstrap", domain, plist).returncode == 0:
            return True
        if _lc("print", target).returncode != _PRINT_NOT_FOUND:
            return True  # loaded despite the error (raced / already present) — recoverable
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def _converge_start(profile: str) -> None:
    """Idempotently (re)start the profile's launchd job and force an immediate fresh spawn.

    Regenerates the plist (keys unchanged), boots out any prior job (ignoring rc 3 = not
    loaded), WAITS for that async bootout to finish (_await_not_loaded), enables the label
    (clears any legacy `unload -w` disabled override; persists across reboots), bootstraps
    with bounded retry (tolerating the post-bootout EIO-5 race WITHOUT leaving the job down —
    _bootstrap_with_retry), then `kickstart -k`s a fresh spawn (force-respawn for operator
    intent; the throttle still spaces genuine crash restarts). Atomic: a restart never ends
    with the daemon stopped. Auto-migrates a user previously on `load -w`/`unload -w`."""
    domain, target = _target(profile)
    plist = _write_agent_plist(profile)
    _lc("bootout", target)  # ignore rc (3 == was not loaded; any prior state is fine)
    _await_not_loaded(target, _BOOTOUT_SETTLE_SECONDS)
    # enable BEFORE bootstrap: a legacy `unload -w` leaves the label DISABLED in launchd's
    # store, and bootstrapping a disabled label fails with "5: Input/output error".
    _lc("enable", target)
    if not _bootstrap_with_retry(domain, target, str(plist)):
        print(f"launchctl bootstrap failed for {target} — see logs.", file=sys.stderr)
        sys.exit(Exit.ERROR)
    _lc("kickstart", "-k", target)


def _converge_stop(profile: str) -> bool:
    """Idempotently stop the profile's launchd job. `bootout` rc 3 ("No such process") means
    the job was already not loaded — treated as already-stopped success. Returns True when
    the job is (now) not loaded, False on an unexpected launchctl failure."""
    _, target = _target(profile)
    r = _lc("bootout", target)
    return r.returncode in (0, _BOOTOUT_NOT_LOADED)


def _parse_print_field(body: str, key: str) -> Optional[str]:
    """Pull a scalar `key = value` line out of a `launchctl print` body (e.g. `state` or
    `pid`). launchctl indents these as `\\tkey = value`; returns None when absent."""
    m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(\S+)", body, re.MULTILINE)
    return m.group(1) if m else None


def _observe_daemon(profile: str) -> DaemonState:
    """Ground-truth liveness via `launchctl print` (Decision 2), with the lock/holder_pid
    path kept only as the foreground fallback (Decision 5):

    - print rc 113 (not loaded) -> a live lock holder means a foreground daemon (running,
      foreground); otherwise stopped.
    - print rc 0 with `state = running` and a `pid` -> running (the supervisor's own pid).
    - print rc 0 with any other state -> unknown (report it; never a false "stopped").
    - any other non-zero print rc -> unknown.
    """
    _, target = _target(profile)
    r = _lc("print", target)
    if r.returncode == _PRINT_NOT_FOUND:
        pid = holder_pid(lock_path(profile))
        return DaemonState.running(pid, foreground=True) if pid else DaemonState.stopped()
    if r.returncode != 0:
        return DaemonState.unknown(f"launchctl print rc={r.returncode}")
    state = _parse_print_field(r.stdout, "state")
    pid_str = _parse_print_field(r.stdout, "pid")
    pid = int(pid_str) if pid_str and pid_str.isdigit() else None
    if state == "running" and pid:
        return DaemonState.running(pid)
    return DaemonState.unknown(f"state={state!r}")


def _verify(profile: str, want_running: bool, timeout: float) -> DaemonState:
    """Poll `_observe_daemon` (~0.2s cadence) until the post-condition (`want_running`) holds
    or `timeout` elapses; return the final observation (the caller reports the true outcome).

    Invariant-9 safe: a daemon that fails preflight exits 0 by design and never comes up, so
    this MUST time out and return a not-running observation — the caller then prints "failed
    — see logs" and exits non-zero. It never hangs and never prints false success."""
    deadline = time.monotonic() + timeout
    st = _observe_daemon(profile)
    while st.is_running != want_running and time.monotonic() < deadline:
        time.sleep(0.2)
        st = _observe_daemon(profile)
    return st


def cmd_install_agent(args):
    """Generate a launchd LaunchAgent .plist to run a profile's daemon at login."""
    profile = _profile(args)
    cfg = Config.load(config_path(profile))
    _warn_tcc(cfg.local_path)
    plist_path = _write_agent_plist(profile)
    domain, target = _target(profile)
    print(f"LaunchAgent generated at {plist_path}")
    print("To enable (starts now and at each login):")
    print(f"  launchctl bootstrap {domain} {plist_path} && launchctl kickstart -k {target}")
    print(f"  (or simply: ifolder-sync start --background --profile {profile})")
    print("To stop:")
    print(f"  launchctl bootout {target}")
    print(f"  (or simply: ifolder-sync stop --profile {profile})")
    print("To remove the agent entirely:")
    print(f"  ifolder-sync uninstall --profile {profile}")
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
    ps.add_argument(
        "--json",
        action="store_true",
        help="emit the pass outcome as JSON to stdout (pair with --dry-run for a preview)",
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

    prs = sub.add_parser("restart", help="restart a profile's background (launchd) daemon")
    prs.add_argument(
        "--background",
        action="store_true",
        help="accepted for symmetry with `start`; restart always manages the launchd daemon",
    )
    _add_profile(prs)
    prs.set_defaults(func=cmd_restart)

    pun = sub.add_parser("uninstall", help="stop and remove a profile's launchd agent (.plist)")
    _add_profile(pun)
    pun.set_defaults(func=cmd_uninstall)

    pstat = sub.add_parser("status", help="show all profiles, or one in detail with --profile")
    pstat.add_argument(
        "--profile",
        default=None,
        type=_profile_name,
        help="show one profile in detail; omit to show all profiles",
    )
    pstat.add_argument("--json", action="store_true", help="emit machine-readable JSON to stdout")
    pstat.add_argument(
        "--watch",
        action="store_true",
        help="live dashboard: redraw daemon state + what's stuck until Ctrl-C",
    )
    pstat.add_argument(
        "--interval",
        type=float,
        default=None,
        help="seconds between redraws in --watch (default: dashboard_interval_seconds)",
    )
    pstat.set_defaults(func=cmd_status)

    pdoc = sub.add_parser(
        "doctor", help="audit baseline vs local vs remote consistency (read-only)"
    )
    pdoc.add_argument(
        "--json", action="store_true", help="emit the audit as JSON to stdout (schema 1)"
    )
    pdoc.add_argument(
        "--non-interactive",
        action="store_true",
        help="fail instead of prompting for 2FA (for cron/scripts)",
    )
    pdoc.add_argument(
        "--fix-orphans",
        action="store_true",
        help="drop orphan baseline rows (backs up the baseline first; never touches your "
        "files or iCloud; refuses while the daemon is running)",
    )
    _add_profile(pdoc)
    pdoc.set_defaults(func=cmd_doctor)

    ppt = sub.add_parser("purge-trash", help="empty a profile's local soft-delete trash")
    ppt.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
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

    _add_completion_arg(p)
    return p


def _add_completion_arg(parser: argparse.ArgumentParser) -> None:
    """Add `--print-completion {bash,zsh,...}` when shtab is installed. shtab is an optional
    dependency (`ifolder-sync[completion]`), so without it the flag is simply absent — the
    base install keeps zero non-essential deps."""
    try:
        import shtab
    except ImportError:
        return
    shtab.add_argument_to(
        parser, ["--print-completion"], help="print a shell completion script and exit"
    )


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


def _sync_json(stats, dry_run: bool) -> dict[str, Any]:
    """Serialize a pass outcome for `sync --json`. The per-action plan is not exposed yet
    (no Plan object — P3-2 deferred), so these aggregate counts are the structured view;
    in dry-run they are the would-be plan tallies."""
    return {
        "dry_run": dry_run,
        "uploaded": stats.uploaded,
        "downloaded": stats.downloaded,
        "deleted_local": stats.deleted_local,
        "deleted_remote": stats.deleted_remote,
        "conflicts": stats.conflicts,
        "skipped_deletes": stats.skipped_deletes,
        "deferred_deletes": stats.deferred_deletes,
        "errors": stats.errors,
        "exit_code": int(_outcome_exit_code(stats)),
    }


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
    from .syncer import LocalScanError, RemoteScanError, VaultIdentityError

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
    if isinstance(exc, (LocalScanError, RemoteScanError)):
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
    except (KeyboardInterrupt, EOFError):
        # Ctrl-C or Ctrl-D/closed stdin at any prompt: a clean line, never a traceback.
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
