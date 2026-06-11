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
import random
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
from pyicloud.const import AppleAuthError
from pyicloud.exceptions import (
    PyiCloudAPIResponseException,
    PyiCloudFailedLoginException,
)
from pyicloud.utils import (
    get_password_from_keyring,
    password_exists_in_keyring,
    store_password_in_keyring,
)

from . import twofa
from .config import Config, session_paths, sessions_dir
from .retry import with_retry

try:
    from pyicloud.session import NON_PERSISTED_SESSION_KEYS
except ImportError:  # pragma: no cover - upstream renamed/removed the symbol
    NON_PERSISTED_SESSION_KEYS = frozenset()

try:
    from pyicloud.exceptions import PyiCloud2SARequiredException
except ImportError:  # pragma: no cover - upstream renamed/removed the symbol
    PyiCloud2SARequiredException = ()  # isinstance(..., ()) is always False

log = logging.getLogger("ifolder-sync.icloud")


def is_session_relapse(exc: BaseException) -> bool:
    """True for a RECOVERABLE expired-session signal — the iCloud login token lapsed
    mid-run (HTTP 421 ``AppleAuthError.LOGIN_TOKEN_EXPIRED``, which pyicloud surfaces as a
    GENERIC ``PyiCloudAPIResponseException``, or the ``code=None`` variant whose reason is
    exactly "Missing X-APPLE-WEBAUTH-TOKEN cookie"). A fresh ``connect()`` re-establishes
    the session WITHOUT 2FA while the trust token is still valid, so the daemon reconnects
    in place rather than looping (transient retry) or clean-stopping (real re-auth).

    Anchored to the 421 code and the WEBAUTH-cookie string — NOT to the shared
    "Authentication required for Account." reason, which pyicloud ALSO emits for 409/450/500
    (those genuinely need 2FA and must keep clean-stopping). Total and never raises, so it is
    safe to call from inside a broad ``except``."""
    try:
        if PyiCloud2SARequiredException and isinstance(exc, PyiCloud2SARequiredException):
            return True
        if isinstance(exc, PyiCloudAPIResponseException):
            code = getattr(exc, "code", None)
            if code == AppleAuthError.LOGIN_TOKEN_EXPIRED or str(code) == "421":
                return True
            # Anchor to the exception's REASON (mirroring pyicloud's own _raise_error), NOT
            # str(exc): str folds in the raw server body, so a terminal 409/450/500 whose
            # response text happened to contain this string would misclassify as recoverable.
            return getattr(exc, "reason", "") == "Missing X-APPLE-WEBAUTH-TOKEN cookie"
    except Exception:  # noqa: BLE001 - a classifier must never throw into the caller's except
        return False
    return False


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
        # Per-instance jitter (up to ~10%, capped at 5 min) added to the full-walk cadence
        # so several profiles or a fleet that restart together do not all do their uncached
        # full walk at the same wall-clock moment.
        self._full_walk_jitter = random.uniform(0, min(300.0, 0.1 * self.full_walk_interval))

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

        twofa.handle_2fa(self.api, interactive=interactive)
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

    def print_diagnostics(self, include_phones: bool = True) -> None:
        """Print Apple's view of the auth state (hsaVersion, 2fa/2sa flags, trusted
        phones). Thin delegator to twofa.print_diagnostics, kept as a method because the
        CLI `status`/`auth` paths call it on the client."""
        twofa.print_diagnostics(self.api, include_phones)

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
        cadence = self.full_walk_interval + self._full_walk_jitter
        allow_cache = (
            self.full_walk_interval > 0
            and bool(self._etag_cache)
            and (time.time() - self._last_full_walk) < cadence
        )
        try:
            return self._walk_impl(is_ignored, allow_cache)
        except _WalkCacheMiss:
            # A cached subtree lost its listing (should not happen). Never guess:
            # drop the cache and walk uncached.
            self._etag_cache.clear()
            self._children_cache.clear()
            return self._walk_impl(is_ignored, allow_cache=False)

    # --- cache persistence across restarts ------------------------------------
    def export_walk_cache(self) -> Optional[str]:
        """Serialize the etag-keyed walk cache (JSON) so a restart need not repay the
        uncached full walk. Returns None when empty. Safe to persist: correctness rests on
        the next walk re-fetching the root etag and comparing each folder's etag, so a stale
        cache (the remote changed while the daemon was down) is detected and re-listed."""
        if not self._etag_cache:
            return None
        return json.dumps(
            {
                "etags": self._etag_cache,
                "children": {
                    rel: [list(c) for c in kids] for rel, kids in self._children_cache.items()
                },
            }
        )

    def import_walk_cache(self, blob: Optional[str]) -> None:
        """Restore a cache produced by export_walk_cache. Ignores absent/corrupt data (the
        next walk just runs uncached). _last_full_walk is set to now so the restored cache is
        eligible immediately; the per-folder etag comparison still guards every served entry."""
        if not blob:
            return
        try:
            data = json.loads(blob)
            if not isinstance(data.get("etags"), dict) or not isinstance(
                data.get("children"), dict
            ):
                return  # not a cache blob we wrote; ignore rather than crash startup
            etags = data["etags"]
            children = {
                rel: [_CachedChild(*c) for c in kids] for rel, kids in data["children"].items()
            }
        except (ValueError, KeyError, TypeError, AttributeError):
            return
        self._etag_cache = etags
        self._children_cache = children
        self._last_full_walk = time.time()

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
