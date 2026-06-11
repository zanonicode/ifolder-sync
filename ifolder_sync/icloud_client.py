"""Thin layer over pyicloud: authentication (2FA + persisted session) and
path-oriented iCloud Drive operations.

pyicloud exposes the Drive as a tree of DriveNode navigable by __getitem__
(api.drive['folder']['file']). We wrap that in path helpers ("a/b/c.txt") because
the sync engine reasons in relative paths, not nodes. One folder listing
(get_children) returns all of a folder's children with metadata in a single network
call, so walk() costs one call per folder, not per node.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timezone
from pathlib import PurePosixPath
from shutil import copyfileobj
from typing import Callable, NamedTuple, Optional, TypeVar

from pyicloud import PyiCloudService
from pyicloud.exceptions import (
    PyiCloudAPIResponseException,
    PyiCloudFailedLoginException,
)
from pyicloud.utils import (
    get_password_from_keyring,
    password_exists_in_keyring,
    store_password_in_keyring,
)

from .config import Config, session_paths, sessions_dir
from .retry import with_retry

try:
    from pyicloud.session import NON_PERSISTED_SESSION_KEYS
except ImportError:  # pragma: no cover - upstream renamed/removed the symbol
    NON_PERSISTED_SESSION_KEYS = frozenset()

log = logging.getLogger("ifolder-sync.icloud")


def _replace_atomic(dest: str, write) -> None:
    """Run `write(tmp)` then atomically `os.replace(tmp, dest)`. The tmp name carries
    the pid so two daemon processes sharing one Apple ID's files never collide on it
    (cross-process safety without a lock — os.replace is atomic, so last-writer-wins
    installs a complete file either way). A failed write leaves `dest` untouched."""
    tmp = f"{dest}.{os.getpid()}.tmp"
    try:
        write(tmp)
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_session_atomic(session) -> None:
    """Write pyicloud's session JSON and cookiejar atomically, each born 0600 (no
    world-readable window for the cookie tokens). Replaces pyicloud's in-place
    truncate-write so a concurrent reader/writer never sees a torn file (which would drop
    the trust token -> a silent re-2FA). Modes are set explicitly per file (not via a
    process-global umask), so this stays safe even if the caller is ever multi-threaded."""
    data = {k: v for k, v in dict(session.data).items() if k not in NON_PERSISTED_SESSION_KEYS}

    def _dump(path: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

    _replace_atomic(session.session_path, _dump)

    cookies = session.cookies
    if getattr(cookies, "filename", None):

        def _save(path: str) -> None:
            # Pre-create the tmp at 0600; LWPCookieJar.save open()s it "w", which
            # truncates but preserves an existing file's mode, so the tokens never pass
            # through a world-readable inode.
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
            cookies.save(filename=path)
            # PyiCloudCookieJar.save swallows RuntimeError and can write nothing; never
            # replace a good cookiejar with a missing/empty snapshot.
            if not os.path.exists(path) or os.path.getsize(path) <= 0:
                raise OSError("cookiejar save produced no/empty file")

        _replace_atomic(session.cookiejar_path, _save)


# Apple's error code for "wrong verification code" (covers device AND SMS).
APPLE_WRONG_CODE = -21669

# Download tempfile suffix. The syncer hard-ignores it so an in-flight or orphaned
# tempfile can never be scanned and uploaded back to iCloud.
PART_SUFFIX = ".part"

T = TypeVar("T")


@dataclass
class RemoteEntry:
    """Snapshot of one iCloud Drive item."""

    relpath: str
    kind: str  # "file" | "dir"
    size: int
    mtime: float  # epoch UTC
    etag: str = ""  # iCloud entity tag (content fingerprint); "" if unavailable


class _WalkCacheMiss(Exception):
    """A cached folder's subtree listing is gone; the walk must restart uncached."""


class _CachedChild(NamedTuple):
    """One entry of a cached folder listing (etag is set for subfolders only)."""

    name: str
    kind: str  # "file" | "dir"
    size: int
    mtime: float
    etag: Optional[str]


class ICloudClient:
    def __init__(
        self,
        apple_id: str,
        remote_folder: str = "",
        *,
        remote_trash: bool = True,
        max_retries: int = 3,
        retry_base: float = 1.0,
        walk_workers: int = 4,
        full_walk_interval: int = 600,
        request_timeout: int = 60,
        strict_child_count: bool = False,
    ):
        self.apple_id = apple_id
        self.remote_root = remote_folder.strip("/")
        self.remote_trash = remote_trash
        self.max_retries = max_retries
        self.retry_base = retry_base
        self.walk_workers = max(1, int(walk_workers))
        self.full_walk_interval = max(0, int(full_walk_interval))
        self.request_timeout = int(request_timeout)
        self.strict_child_count = bool(strict_child_count)
        self.api: Optional[PyiCloudService] = None
        # Etag-keyed walk cache: folder relpath -> subtree fingerprint, and
        # folder relpath -> its (already ignore-pruned) children entries.
        self._etag_cache: dict[str, str] = {}
        self._children_cache: dict[str, list[_CachedChild]] = {}
        self._last_full_walk = 0.0

    @classmethod
    def from_config(cls, cfg: Config) -> "ICloudClient":
        """Single source of truth for the Config -> client wiring (used by the CLI
        and the daemon, so a new tunable cannot silently drift between them)."""
        return cls(
            cfg.apple_id,
            cfg.remote_folder,
            remote_trash=cfg.remote_trash,
            max_retries=cfg.max_retries,
            retry_base=cfg.retry_base_delay,
            walk_workers=cfg.walk_workers,
            full_walk_interval=cfg.full_walk_interval_seconds,
            request_timeout=cfg.request_timeout_seconds,
            strict_child_count=cfg.strict_child_count,
        )

    def _retry(self, fn: Callable[[], T]) -> T:
        return with_retry(fn, attempts=self.max_retries, base=self.retry_base)

    def _drive(self):
        """The authenticated Drive service. Raises clearly instead of AttributeError
        when connect() has not run."""
        if self.api is None:
            raise RuntimeError("not connected to iCloud — call connect() first")
        return self.api.drive

    # ----------------------------------------------------------------- auth ---
    def connect(self, interactive: bool = True, fresh: bool = False) -> None:
        """Authenticate and, if needed, run 2FA. The trusted session (cookies +
        trust token) lives in state_dir, so after one successful 2FA the daemon
        connects without a code (Apple trusts the session ~90 days observed). Password
        from env IFOLDER_SYNC_PASSWORD, the Keychain, or a prompt, in that order; a
        prompt-sourced password is stored in the Keychain for the non-interactive
        daemon.

        fresh=True discards any saved session first. Even without fresh, an
        incomplete 2FA session (no trust token) is discarded automatically
        (see _has_poisoned_session)."""
        cookie_dir = sessions_dir()
        if fresh:
            self._clear_session()
            if interactive:
                print("Previous session discarded (--fresh): starting a clean login.")
        elif self._has_poisoned_session():
            # A saved session WITHOUT a trust token is a 2FA login that never
            # completed. It carries scnt/session_id/cookies of a DEAD challenge;
            # pyicloud resends them and Apple treats the next login as a
            # CONTINUATION of the old one, so it never issues a new code.
            # Discarding forces a clean SRP and the code push works again.
            self._clear_session()
            if interactive:
                print(
                    "Detected an incomplete 2FA session from a previous attempt and "
                    "discarded it\n(it would stop Apple from sending a fresh code)."
                )

        password, source = self._resolve_password(interactive)
        # pyicloud writes session/cookie files at default umask (world-readable);
        # they hold bearer credentials, so tighten the umask for the whole login.
        old_umask = os.umask(0o077)
        try:
            self.api = PyiCloudService(self.apple_id, password, cookie_directory=str(cookie_dir))
        except PyiCloudFailedLoginException as exc:
            raise RuntimeError("Apple ID or password rejected by Apple.") from exc
        finally:
            os.umask(old_umask)

        if source == "prompt" and interactive:
            try:
                store_password_in_keyring(self.apple_id, password)
                print("Password stored in the macOS Keychain (the daemon will use it).")
            except Exception as exc:  # noqa: BLE001
                print(f"(Warning: could not store the password in the Keychain: {exc})")

        self._handle_2fa(interactive=interactive)
        self._secure_session_files()
        self._install_request_timeout()
        self._install_atomic_session_save()

    def _install_request_timeout(self) -> None:
        """Wrap session.request so any call without an explicit timeout gets a
        (connect, read) timeout. pyicloud passes timeout=None everywhere, so one hung
        socket would block the poll loop forever; with a timeout the hang becomes a
        requests.Timeout that the retry + walk guard handle (pass aborts, zero
        deletions). Idempotent; <=0 disables."""
        if self.api is None or self.request_timeout <= 0:
            return
        session = self.api.session
        if getattr(session, "_ifolder_timeout_wrapped", False):
            return
        original = session.request
        t = (float(self.request_timeout), float(self.request_timeout))

        def _with_timeout(method, url, **kwargs):
            if kwargs.get("timeout") is None:
                kwargs["timeout"] = t
            return original(method, url, **kwargs)

        session.request = _with_timeout
        session._ifolder_timeout_wrapped = True

    def _install_atomic_session_save(self) -> None:
        """Replace pyicloud's `_save_session_data` (it runs after EVERY request) with an
        atomic version. pyicloud truncate-writes the session JSON and the cookiejar in
        place; the parallel walk's threads (in-process) and other daemons on the same
        Apple ID (cross-process) can interleave those writes and tear the file -> a
        dropped trust token -> a silent re-2FA. A per-process tmp + os.replace makes each
        write all-or-nothing and collision-free across processes; a threading.Lock
        serializes the in-process walk threads. Best-effort: a save failure never breaks
        the triggering request (the prior atomic file stays valid)."""
        if self.api is None:
            return
        session = self.api.session
        if getattr(session, "_ifolder_atomic_save", False):
            return
        lock = threading.Lock()

        def _atomic_save() -> None:
            try:
                with lock:
                    _write_session_atomic(session)
            except Exception as exc:  # noqa: BLE001
                log.warning("could not persist session this request (will retry): %s", exc)

        session._save_session_data = _atomic_save
        session._ifolder_atomic_save = True

    # --- on-disk session management ------------------------------------------
    def _clear_session(self) -> None:
        for p in session_paths(self.apple_id):
            try:
                p.unlink()
            except FileNotFoundError:
                pass

    def _has_poisoned_session(self) -> bool:
        """True if a saved .session has a session_token but NO trust_token -- a login
        that reached 2FA and was never trusted. A good (trusted) session has a
        trust_token and is preserved (otherwise we'd force 2FA needlessly)."""
        session_path, _ = session_paths(self.apple_id)
        try:
            data = json.loads(session_path.read_text())
        except (OSError, ValueError):
            return False
        return bool(data.get("session_token")) and not data.get("trust_token")

    def _secure_session_files(self) -> None:
        """Bearer credentials (cookies + trust token): tighten to 0600/0700."""
        try:
            os.chmod(sessions_dir(), 0o700)
            for p in session_paths(self.apple_id):
                if p.exists():
                    os.chmod(p, 0o600)
        except OSError as exc:
            log.warning("could not tighten session file permissions: %s", exc)

    def _resolve_password(self, interactive: bool):
        """Returns (password, source). source in {"env","keyring","prompt"}.
        Resolves the password explicitly instead of relying on pyicloud's implicit
        keyring, so the 'no password' case fails with a clear message rather than
        reaching the 2FA stage confused."""
        pw = os.environ.get("IFOLDER_SYNC_PASSWORD")
        if pw:
            return pw, "env"
        try:
            if password_exists_in_keyring(self.apple_id):
                return get_password_from_keyring(self.apple_id), "keyring"
        except Exception:  # noqa: BLE001
            pass  # keyring unavailable -> fall back to prompt
        if interactive:
            return getpass.getpass(f"iCloud password for {self.apple_id}: "), "prompt"
        raise RuntimeError(
            "No password available (neither IFOLDER_SYNC_PASSWORD nor Keychain). "
            "Run `ifolder-sync auth` in a terminal first."
        )

    def _handle_2fa(self, interactive: bool) -> None:
        api = self.api
        if api is None:
            raise RuntimeError("Connection not initialized.")
        if not (api.requires_2fa or api.requires_2sa):
            return  # session already trusted (valid cached trust token)
        if not interactive:
            raise RuntimeError(
                "iCloud requires 2FA verification, but the daemon runs "
                "non-interactively. Run `ifolder-sync auth` in a terminal to validate "
                "the code and trust the session; then `start` connects on its own."
            )
        # Precedence matters: on a modern HSA2 account requires_2fa AND requires_2sa
        # are both True, and only the 2FA (idmsa) flow works. The legacy 2SA path
        # (send_verification_code) is only for HSA1 accounts (requires_2fa False).
        if api.requires_2fa:
            self._prompt_2fa(api)
        else:
            self._prompt_2sa(api)
        if not api.is_trusted_session:
            if not api.trust_session():
                print(
                    "Warning: could not trust the session; the daemon may ask for "
                    "2FA again next time."
                )

    # --- modern 2FA (HSA2 / idmsa) -------------------------------------------
    def _auth_headers(self, api) -> dict[str, str]:
        return api._get_auth_headers({"Accept": "application/json"})

    def _trigger_device_push(self, api) -> bool:
        """Raw fallback: ask Apple to PUSH a 6-digit code to trusted devices.
        Since ~iOS 26/2026 Apple no longer sends the code automatically on API
        logins. pyicloud >=2.5 owns this push (sent inside authenticate(), and
        re-requestable via the public request_2fa_code()); this raw PUT stays only
        as a fallback for upstreams that lack it. PUT asks, POST validates."""
        headers = self._auth_headers(api)
        try:
            api.session.put(
                f"{api.auth_endpoint}/verify/trusteddevice/securitycode",
                headers=headers,
            )
            return True
        except PyiCloudAPIResponseException as exc_put:
            try:
                api.session.get(f"{api.auth_endpoint}/verify/trusteddevice", headers=headers)
                return True
            except PyiCloudAPIResponseException:
                print(f"(Warning: could not trigger the 2FA push: {exc_put})")
                return False

    def _resend_push(self, api) -> bool:
        """Re-request the 2FA push. Prefer upstream's request_2fa_code() (it knows
        the active challenge type: trusted-device bridge, sms, security key);
        fall back to the raw PUT for upstreams that lack it."""
        try:
            return bool(api.request_2fa_code())
        except AttributeError:
            return self._trigger_device_push(api)
        except Exception as exc:  # noqa: BLE001
            print(f"(Warning: could not re-request the 2FA push: {exc})")
            return False

    def _prompt_2fa(self, api) -> None:
        # pyicloud >=2.5 already pushed the code inside authenticate(); pushing
        # again here would land a second, confusing prompt on the user's devices.
        print("\n== Apple two-factor verification (2FA) ==")
        print(
            "A 6-digit code request should appear NOW as a pop-up ('Sign-In Request')\n"
            "on your Apple devices signed into THIS account -- tap 'Allow' to see the\n"
            "6 digits (check Notification Center if it does not pop). It expires in\n"
            "~1 minute. If nothing arrived, use [r]esend or [s]ms."
        )
        self._code_loop(api)

    def _code_loop(self, api) -> None:
        """Interactive 2FA loop. Accepts the code OR commands: [r]esend push, [s]ms to
        a trusted phone, [d]iagnostics. Only CODE attempts count toward the limit."""
        channel = "device"
        sms_phone_id = None
        attempts, max_attempts = 0, 5
        while attempts < max_attempts:
            choice = input("2FA code | [r]esend push | [s]ms | [d]iag | Enter=cancel: ").strip()
            if not choice:
                raise RuntimeError("2FA cancelled by the user.")
            low = choice.lower()
            if low == "r":
                if self._resend_push(api):
                    print("Push resent to trusted devices.")
                else:
                    print("Could not resend the push; try [s]ms.")
                channel = "device"
                continue
            if low == "s":
                phone_id = self._choose_and_send_sms(api)
                if phone_id is not None:
                    channel, sms_phone_id = "sms", phone_id
                continue
            if low == "d":
                self.print_diagnostics()
                continue

            code = choice
            if channel == "sms" and sms_phone_id is not None:
                ok = self._validate_sms(api, sms_phone_id, code)
            else:
                ok = api.validate_2fa_code(code)
            if ok:
                print("Code accepted.")
                return
            attempts += 1
            if attempts < max_attempts:
                print(
                    f"Invalid code (attempt {attempts}/{max_attempts}). "
                    "If nothing arrived, try [r]esend or [s]ms."
                )
        raise RuntimeError(
            "2FA code invalid too many times. Run `ifolder-sync auth --fresh` to start over."
        )

    # --- SMS to a trusted phone (fallback when the push does not arrive) ------
    def _trusted_phone_numbers(self, api) -> list[dict]:
        try:
            resp = api.session.get(api.auth_endpoint, headers=self._auth_headers(api))
            data = resp.json()
        except (PyiCloudAPIResponseException, ValueError):
            return []
        return self._extract_phone_numbers(data)

    @staticmethod
    def _extract_phone_numbers(data) -> list[dict]:
        """Extract trustedPhoneNumbers from the JSON. Apple has varied the nesting
        (2026 moved it under ...bridgeInitiateData...), so search the key recursively."""
        found: list[dict] = []

        def dig(node):
            if isinstance(node, dict):
                tpn = node.get("trustedPhoneNumbers")
                if isinstance(tpn, list):
                    found.extend(tpn)
                for v in node.values():
                    dig(v)
            elif isinstance(node, list):
                for v in node:
                    dig(v)

        dig(data)
        out, seen = [], set()
        for p in found:
            if not isinstance(p, dict) or "id" not in p or p["id"] in seen:
                continue
            seen.add(p["id"])
            label = p.get("numberWithDialCode") or p.get("obfuscatedNumber") or f"phone #{p['id']}"
            out.append({"id": p["id"], "label": label})
        return out

    def _choose_and_send_sms(self, api) -> Optional[int]:
        phones = self._trusted_phone_numbers(api)
        if not phones:
            print("No trusted phone found on this account for SMS.")
            return None
        for i, p in enumerate(phones):
            print(f"  [{i}] {p['label']}")
        raw = input("Send SMS to which? [0]: ").strip() or "0"
        try:
            phone = phones[int(raw)]
        except (ValueError, IndexError):
            print("Invalid choice.")
            return None
        if self._request_sms(api, phone["id"]):
            print(f"SMS sent to {phone['label']}. Type the code you received.")
            return phone["id"]
        print("Failed to send the SMS.")
        return None

    def _request_sms(self, api, phone_id: int) -> bool:
        body = {"phoneNumber": {"id": phone_id}, "mode": "sms"}
        try:
            api.session.put(
                f"{api.auth_endpoint}/verify/phone",
                json=body,
                headers=self._auth_headers(api),
            )
            return True
        except PyiCloudAPIResponseException as exc:
            print(f"(Warning sending SMS: {exc})")
            return False

    def _validate_sms(self, api, phone_id: int, code: str) -> bool:
        body = {
            "phoneNumber": {"id": phone_id},
            "securityCode": {"code": code},
            "mode": "sms",
        }
        try:
            api.session.post(
                f"{api.auth_endpoint}/verify/phone/securitycode",
                json=body,
                headers=self._auth_headers(api),
            )
        except PyiCloudAPIResponseException as exc:
            if str(getattr(exc, "code", "")) == str(APPLE_WRONG_CODE):
                return False
            print(f"(Warning validating SMS: {exc})")
            return False
        api.trust_session()
        return True

    # --- diagnostics ----------------------------------------------------------
    def print_diagnostics(self, include_phones: bool = True) -> None:
        """Print what Apple thinks the auth state is -- turns 'it doesn't work' into
        concrete signals (hsaVersion, 2fa/2sa flags, trusted phones)."""
        api = self.api
        if api is None:
            print("(no connection)")
            return
        hsa = api.data.get("dsInfo", {}).get("hsaVersion", "?")
        print("\n-- Authentication diagnostics --")
        print(f"  hsaVersion:         {hsa}")
        print(f"  requires_2fa:       {api.requires_2fa}")
        print(f"  requires_2sa:       {api.requires_2sa}")
        print(f"  is_trusted_session: {api.is_trusted_session}")
        if include_phones:
            phones = self._trusted_phone_numbers(api)
            if phones:
                print("  Trusted phones (SMS):")
                for p in phones:
                    print(f"    - {p['label']}")
            else:
                print("  Trusted phones (SMS): none/unavailable")
        print("---------------------------------\n")

    def _prompt_2sa(self, api) -> None:
        print("\n== Two-step verification (legacy 2SA) ==")
        devices = api.trusted_devices
        if not devices:
            raise RuntimeError("No trusted device available for 2SA.")
        for i, d in enumerate(devices):
            label = d.get("deviceName") or f"SMS to {d.get('phoneNumber', '?')}"
            print(f"  [{i}] {label}")
        idx = int(input("Device [0]: ").strip() or "0")
        device = devices[idx]
        if not api.send_verification_code(device):
            raise RuntimeError("Failed to send the verification code.")
        for attempt in range(3):
            code = input("Code received (empty = cancel): ").strip()
            if not code:
                raise RuntimeError("2SA cancelled by the user.")
            if api.validate_verification_code(device, code):
                print("Code accepted.")
                return
            remaining = 2 - attempt
            if remaining:
                print(f"Invalid code. Try again ({remaining} left).")
        raise RuntimeError("2SA code invalid 3 times.")

    # -------------------------------------------------------------- drive io ---
    def refresh(self) -> None:
        """Discard the Drive cache and re-read the root from the network. MUST run at
        the start of each sync pass, otherwise pyicloud serves a stale remote tree
        (cached in DriveService._root + DriveNode._children) and polling never sees
        remote changes."""
        self._retry(self._drive().refresh_root)

    def _root_node(self):
        node = self._drive().root
        if not self.remote_root:
            return node
        for part in PurePosixPath(self.remote_root).parts:
            node = self._child(node, part)
        return node

    def ensure_remote_root(self) -> None:
        """Ensure the base remote folder exists (create the chain if missing)."""
        node = self._drive().root
        if not self.remote_root:
            return
        for part in PurePosixPath(self.remote_root).parts:
            try:
                node = self._child(node, part)
            except (KeyError, IndexError):
                node.mkdir(part)
                node = self._fresh_child(node, part)

    @staticmethod
    def _child(node, name: str):
        """Resolve a child by name, NFC-insensitively. iCloud usually stores NFC, but a
        file placed by Apple's NATIVE client can be NFD; the engine navigates by an NFC
        identity key, so an exact-only match would miss the NFD node -> KeyError -> a
        phantom 'remote deleted' or (post-rebaseline) a duplicate. Fall back to comparing
        NFC-normalized names so the reverse key->node trip always finds the real node."""
        try:
            return node[name]
        except (KeyError, IndexError):
            target = unicodedata.normalize("NFC", name)
            for child in node.get_children():
                if unicodedata.normalize("NFC", child.name) == target:
                    return child
            raise KeyError(name) from None

    @staticmethod
    def _fresh_child(parent, name):
        """Re-resolve a child FORCING a network refetch. Needed after mkdir/delete/
        upload: clearing _children is not enough because get_children reuses cached
        parent.data['items']; get_children(force=True) redoes the call."""
        for child in parent.get_children(force=True):
            if child.name == name:
                return child
        raise KeyError(name)

    @staticmethod
    def _node_mtime(node) -> float:
        dt = node.date_modified
        if dt is None:
            return 0.0
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

    def walk(self, is_ignored: Optional[Callable[[str], bool]] = None) -> dict[str, RemoteEntry]:
        """Recursively list the remote folder as {relpath: RemoteEntry}, relative to
        remote_root (POSIX separators). One network listing per CHANGED folder:
        folders whose etag matches the cache are served from it with zero calls
        (iCloud folder etags fingerprint the whole subtree — a descendant edit
        bumps every ancestor's etag, while untouched folders stay stable; verified
        empirically on 2026-06-10). A full uncached walk still runs every
        full_walk_interval seconds. Listings on the same depth level run
        concurrently (walk_workers). Ignored subtrees are pruned (never listed).
        Raises on a network error rather than returning an empty tree, so a failed
        scan never looks like 'all deleted'."""
        allow_cache = (
            self.full_walk_interval > 0
            and bool(self._etag_cache)
            and (time.time() - self._last_full_walk) < self.full_walk_interval
        )
        try:
            return self._walk_impl(is_ignored, allow_cache)
        except _WalkCacheMiss:
            # A cached subtree lost its listing (should not happen). Never guess:
            # drop the cache and walk uncached.
            self._etag_cache.clear()
            self._children_cache.clear()
            return self._walk_impl(is_ignored, allow_cache=False)

    def _walk_impl(
        self, is_ignored: Optional[Callable[[str], bool]], allow_cache: bool
    ) -> dict[str, RemoteEntry]:
        out: dict[str, RemoteEntry] = {}
        try:
            root = self._root_node()
        except (KeyError, IndexError):
            return out  # remote folder does not exist yet
        # The shared requests.Session is safe for these read-only POSTs (urllib3's
        # pool is thread-safe; drivews listings do not mutate cookies); the pool is
        # kept small to stay under Apple's rate limits. fut.result() re-raises any
        # listing error -> the whole walk aborts (guard).
        frontier = [("", root, root.data.get("etag"))]
        with ThreadPoolExecutor(max_workers=self.walk_workers) as ex:
            while frontier:
                to_list = []
                for rel, node, etag in frontier:
                    if allow_cache and etag and self._etag_cache.get(rel) == etag:
                        self._emit_cached(rel, out)
                    else:
                        to_list.append((rel, node, etag))
                futures = [
                    (rel, node, etag, ex.submit(self._retry, node.get_children))
                    for rel, node, etag in to_list
                ]
                frontier = []
                for rel, node, etag, fut in futures:
                    # fut.result() re-raises listing errors here, keeping the
                    # abort-on-failure guard visible at the walk level.
                    frontier += self._ingest_children(rel, node, fut.result(), is_ignored, out)
                    if etag:
                        self._etag_cache[rel] = etag
        if not allow_cache:
            self._last_full_walk = time.time()
        return out

    def _ingest_children(self, rel, node, children, is_ignored, out) -> list[tuple]:
        """Record one fresh listing into `out` and the cache; return the subfolder
        (relpath, node, etag) tuples that form the next BFS level."""
        children = list(children)
        self._check_child_count(rel, node, len(children))
        entries: list[_CachedChild] = []
        frontier: list[tuple] = []
        for child in children:
            crel = f"{rel}/{child.name}" if rel else child.name
            if is_ignored is not None and is_ignored(crel):
                continue  # prune: never listed, never cached
            mtime = self._node_mtime(child)
            child_etag = self._child_etag(child)
            if child.type == "folder":
                out[crel] = RemoteEntry(crel, "dir", 0, mtime, child_etag or "")
                entries.append(_CachedChild(child.name, "dir", 0, mtime, child_etag))
                frontier.append((crel, child, child_etag))
            else:
                size = int(child.size or 0)
                out[crel] = RemoteEntry(crel, "file", size, mtime, child_etag or "")
                entries.append(_CachedChild(child.name, "file", size, mtime, child_etag))
        self._children_cache[rel] = entries
        return frontier

    @staticmethod
    def _child_etag(child) -> Optional[str]:
        data = getattr(child, "data", None)
        return data.get("etag") if isinstance(data, dict) else None

    def _check_child_count(self, rel: str, node, got: int) -> None:
        """Guard against a silently-truncated listing: drivews returns each folder's
        directChildrenCount alongside its items, so fewer items than that count signals
        truncation (which would read as deletions). The items and the count come from the
        same response, so they should agree. strict_child_count escalates to an abort."""
        expected = getattr(node, "data", {}).get("directChildrenCount")
        if not isinstance(expected, int) or expected <= 0 or got >= expected:
            return
        msg = (
            f"remote folder '{rel or '(root)'}' listed {got} of {expected} items "
            "(directChildrenCount) — the listing may be truncated"
        )
        if self.strict_child_count:
            raise RuntimeError(msg)  # walk guard -> pass aborts, zero deletions
        log.warning(
            "%s; treating the listed items as authoritative (set strict_child_count "
            "to abort the pass instead)",
            msg,
        )

    def _emit_cached(self, rel: str, out: dict[str, RemoteEntry]) -> None:
        """Emit a folder's whole subtree from cache, zero network calls: its etag
        matched, so by the verified propagation property nothing below changed."""
        cached = self._children_cache.get(rel)
        if cached is None:
            raise _WalkCacheMiss(rel)
        for child in cached:
            crel = f"{rel}/{child.name}" if rel else child.name
            out[crel] = RemoteEntry(crel, child.kind, child.size, child.mtime, child.etag or "")
            if child.kind == "dir":
                self._emit_cached(crel, out)

    # --- path operations (used by the syncer) ---------------------------------
    def _navigate(self, relpath: str, create_dirs: bool = False):
        """Return the PARENT directory node of relpath and the final name.
        If create_dirs, create missing intermediate folders."""
        node = self._root_node()
        parts = PurePosixPath(relpath).parts
        for part in parts[:-1]:
            try:
                node = self._child(node, part)
            except (KeyError, IndexError):
                if not create_dirs:
                    raise
                node.mkdir(part)
                node = self._fresh_child(node, part)
        return node, parts[-1]

    def download(self, relpath: str, dest: "os.PathLike") -> None:
        parent, name = self._navigate(relpath)
        node = self._child(parent, name)
        tmp = str(dest) + PART_SUFFIX
        # The listing size for a real file equals its byte count; 0/unknown skips the
        # check by design (0-byte notes stream empty; folders are never downloaded).
        expected = int(getattr(node, "size", None) or 0)

        def _fetch():
            with node.open(stream=True) as resp:
                with open(tmp, "wb") as fh:
                    copyfileobj(resp.raw, fh)
            # Never install a truncated download: a dropped connection mid-stream leaves
            # a short .part. Compare bytes written to the listing size before os.replace;
            # a mismatch is retried (transient), and on final failure the .part is removed
            # so the old local file is kept (no half-file ever lands in the vault).
            got = os.path.getsize(tmp)
            if expected and got != expected:
                raise OSError(
                    f"download size mismatch for {relpath}: got {got} bytes, expected {expected}"
                )

        try:
            self._retry(_fetch)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, dest)

    def upload(self, relpath: str, src: "os.PathLike", mtime: float) -> None:
        """Upload a local file to relpath, stamping the remote mtime = local mtime so
        the baseline can record it without a follow-up stat() call. If it already
        exists remotely, the old version is moved aside first (the upload API does not
        overwrite; it creates a new entry named after file_object.name)."""
        parent, name = self._navigate(relpath, create_dirs=True)
        self._remove_existing(parent, name)

        def _send():
            with open(src, "rb") as fh:
                parent.upload(fh, mtime=mtime)

        self._retry(_send)

    def mkdir(self, relpath: str) -> None:
        parent, name = self._navigate(relpath, create_dirs=True)
        try:
            self._child(parent, name)
            return  # already exists
        except (KeyError, IndexError):
            self._retry(lambda: parent.mkdir(name))

    def delete(self, relpath: str) -> None:
        try:
            parent, name = self._navigate(relpath)
            node = self._child(parent, name)
        except (KeyError, IndexError):
            return  # already gone
        self._retry(lambda: self._remove_node(node))

    def _remove_existing(self, parent, name) -> None:
        try:
            node = self._child(parent, name)
        except (KeyError, IndexError):
            return
        try:
            self._retry(lambda: self._remove_node(node))
        except (KeyError, IndexError):
            pass

    def _remove_node(self, node) -> None:
        """Remote delete: move to iCloud 'Recently Deleted' (recoverable ~30 days)
        when remote_trash is on, otherwise a hard delete."""
        if self.remote_trash:
            node.move_to_trash()
        else:
            node.delete()
