"""Daemon main loop: interval polling (remote changes) plus local watcher events
(local changes, immediately). One lock serializes syncs so poll and watch never run
at the same time; a single-instance lock stops two daemons from racing the baseline.
SIGINT/SIGTERM shut down cleanly.

Startup posture: a preflight verifies the vault is reachable before any sync (a blind
scan must never masquerade as mass deletion), and the first pass runs additive-only
(deletions deferred to the next pass).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
from typing import Optional

from pyicloud.exceptions import (
    PyiCloud2FARequiredException,
    PyiCloudAPIResponseException,
    PyiCloudAuthRequiredException,
    PyiCloudFailedLoginException,
    PyiCloudServiceNotActivatedException,
)

from .config import (
    DEFAULT_PROFILE,
    Config,
    baseline_path,
    lock_path,
    status_path,
    trash_dir,
    vault_access_error,
)
from .icloud_client import PART_SUFFIX, ICloudClient, is_session_relapse
from .inflight import InflightSurface
from .locking import SingleInstanceLock
from .state import CorruptBaselineError, StateStore
from .syncer import LocalScanError, Syncer, VaultIdentityError
from .syncstate import stuck_rows
from .watcher import LocalWatcher

log = logging.getLogger("ifolder-sync.daemon")

# An idle daemon still logs an INFO "sync done" at least this often, so the log shows the
# daemon is alive even when no-op passes are demoted to DEBUG.
_HEARTBEAT_SECONDS = 3600


class Daemon:
    def __init__(self, config: Config, profile: str = DEFAULT_PROFILE):
        self.cfg = config
        self.profile = profile
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._sync_lock = threading.Lock()
        self.client = ICloudClient.from_config(config)
        self.store = StateStore(baseline_path(profile))
        # Live dashboard surface (feature 04): the daemon owns it and feeds the engine's
        # per-path events into it, flushing status.json for `status --watch`. None disables
        # all producer-side work. Best-effort throughout — it never affects a sync pass.
        self.inflight: Optional[InflightSurface] = (
            InflightSurface(
                status_path(profile),
                min_write_interval_ms=int(getattr(config, "inflight_min_write_interval_ms", 200)),
            )
            if getattr(config, "inflight_surface", True)
            else None
        )
        self.syncer = Syncer(
            config,
            self.client,
            self.store,
            trash_dir=trash_dir(profile),
            stop_check=self._stop.is_set,
            on_event=(self.inflight.record if self.inflight else None),
        )
        self.lock = SingleInstanceLock(lock_path(profile))
        self.watcher: Optional[LocalWatcher] = None

        self._interval = max(10, int(config.interval_seconds))
        self._apply_passes = 0
        self._trips = 0
        self._backoff: Optional[int] = None
        self._last_activity = 0.0
        self._last_heartbeat = 0.0  # last INFO "sync done" timestamp (hourly heartbeat)
        # Session-relapse self-heal (a lapsed login token, HTTP 421): bounded reconnects.
        self._relapse_count = 0
        self._last_reconnect_at = 0.0
        self._max_session_reconnects = max(0, int(getattr(config, "max_session_reconnects", 5)))
        self._min_reconnect_interval = max(
            0, int(getattr(config, "min_reconnect_interval_seconds", 120))
        )

    # ----------------------------------------------------------- preflight ---
    def _preflight(self) -> bool:
        """Verify the vault is reachable before entering the loop. os.stat is used
        instead of Path.is_dir(), which swallows PermissionError and makes a
        TCC-denied root look missing."""
        root = self.cfg.local_path
        try:
            os.stat(root)
        except FileNotFoundError:
            if self.store.all():
                return self._fail_preflight(
                    f"vault root missing: {root} — if the vault moved, update "
                    f"local_folder and run `ifolder-sync rebaseline --profile {self.profile}`"
                )
            try:
                root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                return self._fail_preflight(f"cannot create vault root {root}: {exc}")
        except PermissionError as exc:
            return self._fail_preflight(self._access_msg(root, exc))
        try:
            os.listdir(root)
            probe = root / (".ifolder-sync-probe" + PART_SUFFIX)
            probe.write_text("")
            probe.unlink()
        except OSError as exc:
            return self._fail_preflight(self._access_msg(root, exc))
        return True

    def _access_msg(self, root, exc: OSError) -> str:
        return vault_access_error(root, exc)

    def _fail_preflight(self, msg: str) -> bool:
        log.critical("preflight failed: %s", msg)
        self._set_last_error(f"preflight: {msg}")
        return False

    # --------------------------------------------------------------- cycle ---
    def _run_sync(self, reason: str, defer_deletes: bool = False):
        if not self._sync_lock.acquire(blocking=False):
            log.debug("sync already running; ignoring trigger (%s)", reason)
            self._wake.set()
            return
        try:
            log.debug("sync started (%s)", reason)
            if not defer_deletes:
                self._apply_passes += 1
            self._inflight_pass_started()
            stats = self.syncer.sync_once(defer_deletes=defer_deletes)
            # A pass that completed proves the session is healthy: reset the reconnect
            # budget and clear any stale error so `status` reflects the recovery, not a ghost.
            self._relapse_count = 0
            self._clear_last_error()
            changed = bool(
                stats.uploaded or stats.downloaded or stats.deleted_local or stats.deleted_remote
            )
            # No-op passes used to log 2 INFO lines each (~3k/day on an idle vault). Log the
            # summary at INFO only when the pass did something or errored; otherwise DEBUG,
            # with an hourly INFO heartbeat so the log still proves liveness.
            now = time.time()
            if (
                changed
                or stats.errors
                or stats.conflicts
                or stats.skipped_deletes
                or stats.deferred_deletes
                or (now - self._last_heartbeat) >= _HEARTBEAT_SECONDS
            ):
                self._last_heartbeat = now
                log.info("sync done (%s): %s", reason, stats.summary())
            else:
                log.debug("sync done (%s): %s", reason, stats.summary())
            # A watch trigger implies local activity even when the pass moved nothing.
            had_activity = reason == "watch" or changed
            if had_activity:
                self._last_activity = time.time()
            self._track_drift(stats)
            if changed and not stats.errors:
                self._rotate_backup()
        except VaultIdentityError as exc:
            # Unrecoverable without operator action (rebaseline); retrying every
            # interval would only spam. Clean stop -> no launchd restart loop.
            log.critical("%s — stopping daemon", exc)
            self._set_last_error(str(exc))
            self._stop.set()
            self._wake.set()
        except (
            PyiCloud2FARequiredException,
            PyiCloudFailedLoginException,
            PyiCloudAuthRequiredException,
            PyiCloudServiceNotActivatedException,
        ) as exc:
            # Trust expiry / invalidated session mid-run surfaces from the data path as
            # one of these: 2FA-required (409), failed-login, auth-required (450
            # FIND_MY_REAUTH_REQUIRED), or service-not-activated (auth-failed). Replaying
            # SRP logins every poll risks an Apple lockout (the scenario the startup path
            # also avoids). Clean stop -> exit(0) -> launchd SuccessfulExit=false does not
            # restart. A plain transient PyiCloudAPIResponseException (503) is NOT here, so
            # it still falls through to the generic handler and retries.
            log.critical(
                "iCloud authentication failed mid-run: %s — run "
                "`ifolder-sync auth --profile %s`; stopping daemon",
                exc,
                self.profile,
            )
            self._set_last_error(f"auth: {exc}")
            self._stop.set()
            self._wake.set()
        except LocalScanError as exc:
            # Transient (a brief permission blip); the next poll retries. Must be
            # caught before the broad RuntimeError below so it never stops the daemon.
            log.exception("sync failed (%s): %s", reason, exc)
            self._set_last_error(str(exc))
        except CorruptBaselineError as exc:
            # Operator-actionable (rebaseline), not transient; retrying would spin on a
            # bad DB. Clean stop, same posture as auth expiry. Caught before RuntimeError
            # (it subclasses it) so the message points at the baseline, not auth.
            log.critical("%s — stopping daemon", exc)
            self._set_last_error(str(exc))
            self._stop.set()
            self._wake.set()
        except RuntimeError as exc:
            # The connect/2FA helpers raise RuntimeError on auth-shaped failures; the
            # data path raises typed pyicloud/OS errors instead, so a RuntimeError here
            # is unrecoverable auth. Clean stop, same posture as a login failure.
            log.critical(
                "cannot reach iCloud: %s — run `ifolder-sync auth --profile %s`; stopping daemon",
                exc,
                self.profile,
            )
            self._set_last_error(f"auth: {exc}")
            self._stop.set()
            self._wake.set()
        except Exception as exc:  # noqa: BLE001
            # A lapsed login token (HTTP 421) surfaces here as a generic
            # PyiCloudAPIResponseException; reconnect in place instead of looping. Genuine
            # transient errors (e.g. 503) keep the plain log + retry-next-poll posture.
            if is_session_relapse(exc):
                self._handle_session_relapse(exc)
            else:
                log.exception("sync failed (%s): %s", reason, exc)
                self._set_last_error(str(exc))
        finally:
            # Rebuild the live surface to the authoritative stuck set on EVERY pass exit —
            # not just success — so a pass that raised mid-apply never strands phantom
            # "uploading X" rows that a still-running daemon would render as live.
            self._inflight_pass_finished()
            self._sync_lock.release()

    # ----------------------------------------------------- live dashboard surface ---
    def _inflight_header(self) -> dict:
        return {
            "pid": os.getpid(),
            "last_sync": self.store.get_meta("last_sync"),
            "last_stats": self.store.get_meta("last_stats"),
            "last_error": self.store.get_meta("last_error"),
        }

    def _json_meta(self, key: str) -> dict:
        try:
            data = json.loads(self.store.get_meta(key) or "{}")
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def _stuck_rows(self):
        return stuck_rows(self._json_meta("settle_counts"), self._json_meta("unreadable_counts"))

    def _inflight_pass_started(self) -> None:
        if not self.inflight:
            return
        try:
            self.inflight.pass_started(**self._inflight_header())
        except Exception as exc:  # noqa: BLE001 — the surface never breaks a sync pass
            log.debug("inflight pass_started skipped (non-fatal): %s", exc)

    def _inflight_pass_finished(self) -> None:
        if not self.inflight:
            return
        try:
            self.inflight.pass_finished(self._stuck_rows(), **self._inflight_header())
        except Exception as exc:  # noqa: BLE001
            log.debug("inflight pass_finished skipped (non-fatal): %s", exc)

    def _track_drift(self, stats):
        if stats.skipped_deletes:
            self._trips += 1
            if self._apply_passes <= 1:
                msg = (
                    f"DRIFT SUSPECTED: {stats.skipped_deletes} deletion(s) suppressed "
                    f"right after startup; run `ifolder-sync rebaseline --profile "
                    f"{self.profile}` or check permissions"
                )
                log.critical(msg)
                self._set_last_error(msg)
            if self._trips >= 3 and self._backoff is None:
                self._backoff = int(min(self._interval * 10, 3600))
                log.warning(
                    "delete threshold tripped on %d consecutive passes; slowing poll "
                    "to %ds until a clean pass",
                    self._trips,
                    self._backoff,
                )
        else:
            if self._backoff is not None:
                log.info("clean pass; restoring poll interval (%ds)", self._interval)
            self._trips = 0
            self._backoff = None

    # --------------------------------------------------------- baseline backup ---
    def _rotate_backup(self) -> None:
        """Snapshot the baseline into a ring of `baseline_backups` rotated copies (a
        recovery net for corruption; restored manually, never auto-loaded). Best-effort:
        a failed backup must never fail the sync pass."""
        n = max(0, int(getattr(self.cfg, "baseline_backups", 5)))
        if n == 0:
            return
        bdir = baseline_path(self.profile).parent / "baseline-backups"
        try:
            bdir.mkdir(parents=True, exist_ok=True)

            def ring() -> list:
                # Ignore any file whose suffix is not a parseable index so junk can't
                # skew the next index or the prune window.
                items = [p for p in bdir.glob("autobak-*.sqlite3") if self._backup_index(p) >= 0]
                return sorted(items, key=self._backup_index)

            existing = ring()
            nxt = (self._backup_index(existing[-1]) + 1) if existing else 1
            self.store.backup_to(bdir / f"autobak-{nxt:06d}.sqlite3")
            for old in ring()[:-n]:
                old.unlink()
        except Exception as exc:  # noqa: BLE001
            log.warning("baseline backup failed (non-fatal): %s", exc)

    @staticmethod
    def _backup_index(p) -> int:
        try:
            return int(p.stem.rsplit("-", 1)[1])
        except (ValueError, IndexError):
            return -1

    def _poll_timeout(self) -> int:
        """Drift backoff > active cadence > base interval. While changes are flowing
        between devices, poll faster so the other side's edits land sooner."""
        if self._backoff is not None:
            return self._backoff
        if time.time() - self._last_activity < self.cfg.active_window_seconds:
            return max(10, int(self.cfg.interval_active_seconds))
        return self._interval

    def _set_last_error(self, msg: str):
        try:
            self.store.set_meta("last_error", f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}")
        except Exception:  # noqa: BLE001
            pass

    def _clear_last_error(self):
        """Reset last_error to empty so `status` stops showing a resolved error. Stored as
        "" (not via _set_last_error, which prepends a timestamp) so the status renderer's
        truthy check treats it as 'no error'."""
        try:
            self.store.set_meta("last_error", "")
        except Exception:  # noqa: BLE001
            pass

    def _handle_session_relapse(self, exc) -> None:
        """The iCloud login token lapsed mid-run (HTTP 421): the in-memory session is stale
        but the trust token is still valid, so a fresh connect() heals it WITHOUT 2FA.
        Reconnect in place and let the next pass resume. Two guards against an Apple lockout:
        never replay SRP more than once per `min_reconnect_interval_seconds`, and clean-stop
        after `max_session_reconnects` reconnects with no clean pass between (a completed pass
        resets the counter). If the reconnect itself needs interactive re-auth, clean-stop
        with a `run auth` hint (exit 0 -> launchd SuccessfulExit=false does not restart)."""
        now = time.time()
        if (
            self._min_reconnect_interval
            and self._last_reconnect_at
            and (now - self._last_reconnect_at) < self._min_reconnect_interval
        ):
            log.warning(
                "iCloud session still lapsing (%s); throttling reconnects, retrying next poll",
                exc,
            )
            self._set_last_error(f"session expired (reconnect throttled): {exc}")
            return
        self._relapse_count += 1
        if self._relapse_count > self._max_session_reconnects:
            log.critical(
                "iCloud session kept lapsing across %d reconnects — run "
                "`ifolder-sync auth --profile %s`; stopping daemon",
                self._max_session_reconnects,
                self.profile,
            )
            self._set_last_error(f"auth: session expired repeatedly: {exc}")
            self._stop.set()
            self._wake.set()
            return
        log.warning(
            "iCloud session expired mid-run (%s); reconnecting (%d/%d)",
            exc,
            self._relapse_count,
            self._max_session_reconnects,
        )
        self._last_reconnect_at = now
        try:
            self.client.connect(interactive=False)
        except (
            PyiCloud2FARequiredException,
            PyiCloudFailedLoginException,
            PyiCloudAuthRequiredException,
            PyiCloudServiceNotActivatedException,
            RuntimeError,
        ) as rexc:
            log.critical(
                "reconnect needs interactive re-auth (%s) — run "
                "`ifolder-sync auth --profile %s`; stopping daemon",
                rexc,
                self.profile,
            )
            self._set_last_error(f"auth: reconnect failed: {rexc}")
            self._stop.set()
            self._wake.set()
            return
        except PyiCloudAPIResponseException as rexc:
            # A transient blip during the reconnect login (e.g. 503) — do NOT crash the
            # daemon or clean-stop; the next poll re-attempts the pass (and reconnect) within
            # the same bounded budget. (PyiCloudServiceNotActivatedException is a subclass but
            # is caught by the clause above, so it still clean-stops.)
            log.warning("transient error during reconnect (%s); retrying next poll", rexc)
            self._set_last_error(f"reconnect transient: {rexc}")
            return
        log.info("iCloud session re-established; resuming sync next pass")
        self._set_last_error(f"session re-established after token expiry ({self._relapse_count})")

    def _on_local_change(self):
        self._wake.set()

    def run(self):
        self.lock.acquire()  # raises AlreadyRunning if another instance holds it
        try:
            # A corrupt baseline raises CorruptBaselineError -> propagates to the caller
            # (cmd_start) which exits cleanly (0): launchd must not crash-loop on it, and
            # an empty re-create would read as mass create/delete. Recovery is rebaseline.
            try:
                self.store.quick_check()
            except CorruptBaselineError as exc:
                self._set_last_error(str(exc))  # so `status` and logs show why it stopped
                raise
            if not self._preflight():
                # KeepAlive SuccessfulExit=false: launchd restarts only on a non-zero
                # exit, so returning cleanly here cannot crash-loop a misconfigured
                # daemon (crashes still exit non-zero and restart).
                return
            try:
                self.client.connect(interactive=False)
            except RuntimeError as exc:
                # Auth-shaped failures (no password, rejected login, untrusted 2FA)
                # cannot heal without the operator; restarting would replay a full
                # SRP login every minute and risk an Apple lockout. Stop cleanly.
                log.critical("cannot authenticate: %s — run `ifolder-sync auth`", exc)
                self._set_last_error(f"auth: {exc}")
                return
            log.info("connected to iCloud as %s", self.cfg.apple_id)
            # Restore the etag walk cache from the last clean shutdown so the first pass can
            # serve unchanged subtrees from cache instead of repaying the uncached full walk.
            # Best-effort: a corrupt/foreign cache blob must never crash startup (invariant 9).
            try:
                self.client.import_walk_cache(self.store.get_meta("walk_cache"))
            except Exception as exc:  # noqa: BLE001
                log.warning("could not restore the walk cache (non-fatal): %s", exc)

            if self.cfg.watch_local:
                self.watcher = LocalWatcher(
                    self.cfg.local_path,
                    self._on_local_change,
                    self.cfg.debounce_seconds,
                    is_ignored=self.syncer._ignored,
                )
                self.watcher.start()

            self._install_signals()
            self._run_sync("initial", defer_deletes=True)

            if self.cfg.interval_seconds < 30:
                log.warning(
                    "interval_seconds=%d is aggressive; >=30 recommended (the local "
                    "watcher already catches local edits)",
                    self.cfg.interval_seconds,
                )
            log.info(
                "daemon running: poll every %ss (%ss while active)%s",
                self._interval,
                self.cfg.interval_active_seconds,
                " + local watch" if self.cfg.watch_local else "",
            )

            while not self._stop.is_set():
                triggered = self._wake.wait(timeout=self._poll_timeout())
                if self._stop.is_set():
                    break
                self._wake.clear()
                self._run_sync("watch" if triggered else "poll")
        finally:
            self._shutdown()

    # ------------------------------------------------------------- signals ---
    def _install_signals(self):
        def handler(signum, _frame):
            log.info("signal %s received, shutting down...", signum)
            self._stop.set()
            self._wake.set()

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _shutdown(self):
        if self.watcher:
            self.watcher.stop()
        # Persist the etag walk cache on a clean shutdown so the next start skips the
        # uncached full walk. Best-effort: a failure here must never block shutdown. (A
        # SIGKILL crash skips this and the next start simply walks uncached, as before.)
        try:
            self.store.set_meta("walk_cache", self.client.export_walk_cache() or "")
        except Exception as exc:  # noqa: BLE001
            log.warning("could not persist the walk cache (non-fatal): %s", exc)
        self.store.close()
        self.lock.release()
        log.info("daemon stopped.")
