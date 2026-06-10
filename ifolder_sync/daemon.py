"""Daemon main loop: interval polling (remote changes) plus local watcher events
(local changes, immediately). One lock serializes syncs so poll and watch never run
at the same time; a single-instance lock stops two daemons from racing the baseline.
SIGINT/SIGTERM shut down cleanly.

Startup posture: a preflight verifies the vault is reachable before any sync (a blind
scan must never masquerade as mass deletion), and the first pass runs additive-only
(deletions deferred to the next pass).
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from typing import Optional

from .config import (
    DEFAULT_PROFILE,
    Config,
    baseline_path,
    lock_path,
    tcc_protected,
    trash_dir,
)
from .icloud_client import PART_SUFFIX, ICloudClient
from .locking import SingleInstanceLock
from .state import StateStore
from .syncer import Syncer, VaultIdentityError
from .watcher import LocalWatcher

log = logging.getLogger("ifolder-sync.daemon")


class Daemon:
    def __init__(self, config: Config, profile: str = DEFAULT_PROFILE):
        self.cfg = config
        self.profile = profile
        self.client = ICloudClient.from_config(config)
        self.store = StateStore(baseline_path(profile))
        self.syncer = Syncer(config, self.client, self.store, trash_dir=trash_dir(profile))
        self.lock = SingleInstanceLock(lock_path(profile))

        self._wake = threading.Event()
        self._stop = threading.Event()
        self._sync_lock = threading.Lock()
        self.watcher: Optional[LocalWatcher] = None

        self._interval = max(10, int(config.interval_seconds))
        self._apply_passes = 0
        self._trips = 0
        self._backoff: Optional[int] = None
        self._last_activity = 0.0

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
        hint = ""
        if isinstance(exc, PermissionError) and tcc_protected(root):
            hint = (
                " — macOS TCC blocks launchd daemons from Downloads/Desktop/Documents; "
                "move the vault or grant Full Disk Access"
            )
        return f"vault not accessible: {exc}{hint}"

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
            log.info("sync started (%s)", reason)
            if not defer_deletes:
                self._apply_passes += 1
            stats = self.syncer.sync_once(defer_deletes=defer_deletes)
            log.info("sync done (%s): %s", reason, stats.summary())
            # A watch trigger implies local activity even when the pass moved nothing.
            had_activity = reason == "watch" or bool(
                stats.uploaded or stats.downloaded or stats.deleted_local or stats.deleted_remote
            )
            if had_activity:
                self._last_activity = time.time()
            self._track_drift(stats)
        except VaultIdentityError as exc:
            # Unrecoverable without operator action (rebaseline); retrying every
            # interval would only spam. Clean stop -> no launchd restart loop.
            log.critical("%s — stopping daemon", exc)
            self._set_last_error(str(exc))
            self._stop.set()
            self._wake.set()
        except Exception as exc:  # noqa: BLE001
            log.exception("sync failed (%s): %s", reason, exc)
            self._set_last_error(str(exc))
        finally:
            self._sync_lock.release()

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

    def _on_local_change(self):
        self._wake.set()

    def run(self):
        self.lock.acquire()  # raises AlreadyRunning if another instance holds it
        try:
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

            if self.cfg.watch_local:
                self.watcher = LocalWatcher(
                    self.cfg.local_path, self._on_local_change, self.cfg.debounce_seconds
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
        self.store.close()
        self.lock.release()
        log.info("daemon stopped.")
