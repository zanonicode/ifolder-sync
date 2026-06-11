"""Bidirectional sync engine.

One pass: snapshot the local side and the remote side, compare each against the
three-way baseline, decide an action per path, then apply. Decisions are computed
before any IO so we can count destructive actions (delete threshold), preview without
writing (dry-run), and route deletions to a recoverable trash.

Decision per path vs baseline:
  - changed on one side only        -> copy to the other
  - changed on both sides           -> conflict (policy resolves)
  - gone from one side (unchanged)  -> delete on the other

mtime comparison uses a tolerance (MTIME_TOL) because local FS and iCloud clocks do
not agree to the second.
"""

from __future__ import annotations

import filecmp
import fnmatch
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from .config import (
    VAULT_MARKER_NAME,
    Config,
    read_vault_marker,
    write_vault_marker,
)
from .config import trash_dir as default_trash_dir
from .icloud_client import PART_SUFFIX, ICloudClient, RemoteEntry
from .state import BaselineEntry, StateStore
from .trash import trash_local

log = logging.getLogger("ifolder-sync.syncer")

# Remote mtime tolerance: iCloud rounds to the second and its clock skews from the
# local one, so a remote file within this window of the baseline is "unchanged".
MTIME_TOL = 2.0  # seconds
# Local mtime tolerance is EXACT (0): the local side is the same filesystem we stamped,
# so any mtime difference is a real edit. A 2s window here would silently miss a
# same-size edit made within 2s of a pass (e.g. a checkbox toggle right after sync),
# which would then be overwritten by the other side.
MTIME_TOL_LOCAL = 0.0


class Op(str, Enum):
    """Every per-path action the engine can decide. A str-Enum so members ARE their wire
    string (Op.UPLOAD == "upload"): existing comparisons, sets, and the destructive-op
    guards keep working unchanged, while the apply dispatchers gain a terminal `else: raise`
    so an unhandled op is a loud error, never a silent drop or baseline fall-through."""

    # Render as the wire value, not "Op.UPLOAD": on Python 3.10/3.11 the default Enum
    # __str__ shows the member name, so an `%s`/f-string interpolation (a log line, a future
    # persisted field) would silently diverge from the "upload" string. This pins it to value.
    __str__ = str.__str__

    # file ops (decide_file)
    UPLOAD = "upload"
    DOWNLOAD = "download"
    CONFLICT = "conflict"
    RESCUE_UPLOAD = "rescue_upload"
    RESCUE_DOWNLOAD = "rescue_download"
    DELETE_LOCAL = "delete_local"
    DELETE_REMOTE = "delete_remote"
    SETTLE_WAIT = "settle_wait"
    RECORD = "record"
    VERIFY_ADOPT = "verify_adopt"
    DROP_BASELINE = "drop_baseline"
    # dir ops (decide_dir)
    RECORD_DIR = "record_dir"
    LEAVE_DIR = "leave_dir"
    MKDIR_REMOTE = "mkdir_remote"
    MKDIR_LOCAL = "mkdir_local"
    # cleanup ops (decide_dir_cleanup)
    DROP_BASELINE_DIR = "drop_baseline_dir"
    RMDIR_REMOTE = "rmdir_remote"
    RMDIR_LOCAL = "rmdir_local"


_FILE_DESTRUCTIVE = {Op.DELETE_LOCAL, Op.DELETE_REMOTE}
_DIR_DESTRUCTIVE = {Op.RMDIR_LOCAL, Op.RMDIR_REMOTE}

# After this many consecutive download failures for an UNCHANGED remote signature, stop
# re-attempting that file every pass. iCloud can serve a broken blob (HTTP 200 +
# Content-Length N + 0 bytes); without a backoff the pass re-decides "download" forever,
# each attempt writing a .part that re-triggers the local watcher — a tight retry loop.
DOWNLOAD_MAX_FAILS = 3


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


class LocalScanError(RuntimeError):
    """The local snapshot is unreliable (permission denied, missing root). The pass
    must abort: a partial local tree is indistinguishable from mass deletion."""


class VaultIdentityError(RuntimeError):
    """The folder at local_root is not the vault this baseline knows (marker missing
    or mismatched after a move/recreate). Recover with `ifolder-sync rebaseline`."""


# --------------------------------------------------------- ignore matching ---
def _seg_match(pat_segs: list[str], segs: list[str]) -> bool:
    """True if pat_segs appears as a CONTIGUOUS sublist of segs (each segment matched
    by fnmatch). Excluding 'a/b' this way catches the item AND everything below it, at
    any depth."""
    m, n = len(pat_segs), len(segs)
    if m == 0 or m > n:
        return False
    return any(
        all(fnmatch.fnmatch(segs[i + j], pat_segs[j]) for j in range(m)) for i in range(n - m + 1)
    )


def path_is_ignored(pattern: str, segs: list[str]) -> bool:
    """Decide whether ONE pattern matches a path (already split into POSIX segments).

    - simple name, no '/' (e.g. '.DS_Store', '*.icloud') -> matches that name in any
      segment (covers the file OR the folder + its contents).
    - path with '/' (e.g. '.obsidian/workspace.json', '.trash/') -> matches that span
      at any depth, INCLUDING everything below it. A trailing '/' is just readability.

    fnmatch does not treat '/' specially, but since we split into segments and match
    segment by segment, a '*' never crosses a folder boundary.
    """
    pat = pattern.strip().rstrip("/")
    if not pat:
        return False
    pat_segs = pat.split("/")
    if len(pat_segs) == 1:
        return any(fnmatch.fnmatch(s, pat) for s in segs)
    return _seg_match(pat_segs, segs)


@dataclass
class LocalEntry:
    relpath: str
    kind: str  # "file" | "dir"
    size: int
    mtime: float


@dataclass
class SyncStats:
    uploaded: int = 0
    downloaded: int = 0
    deleted_local: int = 0
    deleted_remote: int = 0
    conflicts: int = 0
    skipped_deletes: int = 0
    deferred_deletes: int = 0
    errors: int = 0

    def summary(self) -> str:
        return (
            f"up={self.uploaded} down={self.downloaded} "
            f"del_local={self.deleted_local} del_remote={self.deleted_remote} "
            f"conflicts={self.conflicts} skipped_deletes={self.skipped_deletes} "
            f"deferred={self.deferred_deletes} errors={self.errors}"
        )


class Syncer:
    def __init__(
        self,
        config: Config,
        client: ICloudClient,
        store: StateStore,
        trash_dir: Optional[Path] = None,
        stop_check: Optional[Callable[[], bool]] = None,
    ):
        self.cfg = config
        self.client = client
        self.store = store
        self.local_root = config.local_path
        self.trash_dir = trash_dir or default_trash_dir()
        self.ignore_patterns = config.effective_ignore
        self._symlink_warned: set[str] = set()
        self._nfc_active: Optional[bool] = None  # probed once (volume normalization)
        # relpath -> (remote_size, remote_mtime, consecutive_failures): backs off a
        # download that keeps failing against an unchanged remote (a broken iCloud blob).
        self._download_fail: dict[str, tuple[int, float, int]] = {}
        # The daemon passes its _stop predicate so a SIGTERM mid-apply breaks the loop
        # promptly; per-action commits keep what was already applied durable.
        self._stop_check = stop_check

    def _should_stop(self) -> bool:
        return bool(self._stop_check and self._stop_check())

    def _commit(self, dry_run: bool) -> None:
        """Per-action durability: with one commit only at pass end, a SIGKILL mid-pass
        rolls back every transferred file's baseline row, turning each into a spurious
        conflict next pass. Committing after each applied action makes progress survive
        a crash (paired with WAL + the plist ExitTimeOut grace window)."""
        if not dry_run:
            self.store.commit()

    # ----------------------------------------------------------- snapshots ---
    def _ident(self, relpath: str) -> str:
        """The canonical identity key for a path. NFC-normalized so a macOS NFD name and
        the iCloud NFC name of the same note map to ONE key (no phantom create/delete).
        Used as the dict/baseline key; IO resolves it on APFS (normalization-insensitive)."""
        return _nfc(relpath) if self._normalize_active() else relpath

    def _normalize_active(self) -> bool:
        """NFC identity is only safe on a normalization-INSENSITIVE volume (APFS), where
        an NFC key resolves the NFD on-disk file for IO. On a sensitive volume (some
        network / case-sensitive mounts) it would create NFC/NFD duplicate files, so fall
        back to raw keys there. Config opt-out wins; otherwise probe the volume once."""
        if not self.cfg.normalize_unicode:
            return False
        if self._nfc_active is None:
            self._nfc_active = self._probe_nfc_insensitive()
        return self._nfc_active

    def _probe_nfc_insensitive(self) -> bool:
        root = self.local_root
        nfd = ".ifolder-nfc-probe" + unicodedata.normalize("NFD", "é") + PART_SUFFIX
        nfc = ".ifolder-nfc-probe" + unicodedata.normalize("NFC", "é") + PART_SUFFIX
        try:
            (root / nfd).write_text("")
            try:
                insensitive = (root / nfc).exists()
            finally:
                for n in (nfd, nfc):
                    try:
                        (root / n).unlink()
                    except OSError:
                        pass
        except OSError:
            return False  # cannot probe (e.g. TCC) -> conservative: no normalization
        if not insensitive:
            log.warning(
                "vault volume is Unicode-normalization-sensitive; filename normalization "
                "disabled (NFC and NFD names are treated as distinct on this volume)"
            )
        return insensitive

    def _ignored(self, relpath: str) -> bool:
        segs = _nfc(relpath).split("/")
        # Engine-internal exclusions, independent of the user's ignore list: configs
        # saved by older versions never pick up new DEFAULT_IGNORE entries. The vault
        # marker is matched case-insensitively so a remote `.IFOLDER-SYNC-VAULT` can never
        # sync and clobber the local marker; `*.part` stays exact-case (the only .part the
        # engine creates is lowercase) so a real user file `foo.PART` is not hidden.
        name = segs[-1]
        if name.casefold() == _nfc(VAULT_MARKER_NAME).casefold() or name.endswith(PART_SUFFIX):
            return True
        return any(path_is_ignored(pat, segs) for pat in self.ignore_patterns)

    def _skip_symlink(self, rel: str, p: Path) -> bool:
        """Symlinks are not synced: a symlinked file would be replaced by a regular
        file on the next remote download (destroying the link), and a symlinked dir
        would sync as a forever-empty folder (os.walk does not descend it). Skip with
        a once-per-path warning."""
        if not os.path.islink(p):
            return False
        if rel not in self._symlink_warned:
            self._symlink_warned.add(rel)
            log.warning("skipping symlink (symlinks are not synced): %s", rel)
        return True

    def _is_safe_rel(self, relpath: str) -> bool:
        """True if local_root/relpath stays inside local_root (no traversal)."""
        try:
            target = (self.local_root / relpath).resolve()
        except (OSError, ValueError, RuntimeError):
            return False
        root = self.local_root.resolve()
        return target == root or root in target.parents

    def _preflight_local(self, baseline: dict[str, BaselineEntry], dry_run: bool) -> None:
        """Root-existence and vault-identity gates, run before any scan.

        A missing root with a non-empty baseline must abort (never fabricate an empty
        vault: it would read as mass deletion). A marker mismatch means the folder is
        not the vault this baseline knows. Path.is_dir() is avoided because it swallows
        PermissionError and a TCC-denied root would look "missing".
        """
        root = self.local_root
        try:
            os.stat(root)
        except FileNotFoundError:
            if baseline:
                raise LocalScanError(
                    f"vault root missing: {root} — if the vault moved, update "
                    "local_folder and run `ifolder-sync rebaseline`"
                ) from None
            if not dry_run:
                root.mkdir(parents=True, exist_ok=True)
                self.store.set_meta("vault_uuid", write_vault_marker(root))
            return
        except PermissionError as exc:
            raise LocalScanError(f"vault root not accessible: {exc}") from exc

        marker = read_vault_marker(root)
        expected = self.store.get_meta("vault_uuid")
        if baseline and expected and marker != expected:
            raise VaultIdentityError(
                f"vault identity mismatch at {root} — this folder is not the vault "
                "this baseline knows; run `ifolder-sync rebaseline`"
            )
        if dry_run:
            return
        if marker is None:
            marker = write_vault_marker(root)
        if expected != marker:
            self.store.set_meta("vault_uuid", marker)

    def _scan_local(self) -> dict[str, LocalEntry]:
        out: dict[str, LocalEntry] = {}
        root = self.local_root

        def _fail(err: OSError) -> None:
            # os.walk's default silently skips unreadable dirs; a partial tree is
            # indistinguishable from mass deletion, so abort instead (the local
            # counterpart of the remote walk guard).
            raise LocalScanError(f"local scan failed: {err}") from err

        for dirpath, dirnames, filenames in os.walk(root, onerror=_fail):
            rel_dir = os.path.relpath(dirpath, root)
            rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
            for d in list(dirnames):
                rel = f"{rel_dir}/{d}" if rel_dir else d
                if self._ignored(rel):
                    dirnames.remove(d)
                    continue
                p = Path(dirpath) / d
                if self._skip_symlink(rel, p):
                    dirnames.remove(d)  # do not descend a symlinked directory
                    continue
                try:
                    st = p.stat()
                except FileNotFoundError:
                    dirnames.remove(d)
                    continue
                except OSError as exc:
                    raise LocalScanError(f"local scan failed at {rel}: {exc}") from exc
                key = self._ident(rel)
                out[key] = LocalEntry(key, "dir", 0, st.st_mtime)
            for f in filenames:
                rel = f"{rel_dir}/{f}" if rel_dir else f
                if self._ignored(rel):
                    continue
                p = Path(dirpath) / f
                if self._skip_symlink(rel, p):
                    continue
                try:
                    st = p.stat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise LocalScanError(f"local scan failed at {rel}: {exc}") from exc
                key = self._ident(rel)
                out[key] = LocalEntry(key, "file", st.st_size, st.st_mtime)
        return out

    def _scan_remote(self) -> dict[str, RemoteEntry]:
        remote = self.client.walk(self._ignored)
        safe: dict[str, RemoteEntry] = {}
        for rel, entry in remote.items():
            if not self._is_safe_rel(rel):
                log.warning("skipping unsafe remote path: %s", rel)
                continue
            key = self._ident(rel)
            safe[key] = RemoteEntry(key, entry.kind, entry.size, entry.mtime, entry.etag)
        return safe

    # ----------------------------------------------------- change detection ---
    @staticmethod
    def _changed(
        cur_size: int, cur_mtime: float, base_size: int, base_mtime: float, tol: float
    ) -> bool:
        if cur_size != base_size:
            return True
        return abs(cur_mtime - base_mtime) > tol

    @staticmethod
    def _is_dir(relpath, local, remote, baseline) -> bool:
        if relpath in local:
            return local[relpath].kind == "dir"
        if relpath in remote:
            return remote[relpath].kind == "dir"
        b = baseline.get(relpath)
        return bool(b and b.kind == "dir")

    # ------------------------------------------------------------ main pass ---
    def sync_once(
        self,
        dry_run: bool = False,
        force_delete: bool = False,
        defer_deletes: bool = False,
    ) -> SyncStats:
        stats = SyncStats()
        self.client.refresh()
        self.client.ensure_remote_root()

        baseline = self.store.all()
        self._preflight_local(baseline, dry_run)  # raises -> pass aborts, zero actions
        baseline = self._migrate_baseline_nfc(baseline, dry_run)
        if not defer_deletes and self._ignore_changed(dry_run):
            log.warning(
                "ignore set changed since the last pass; deferring deletions this pass "
                "(a widened ignore would otherwise read as mass deletion)"
            )
            defer_deletes = True
        if not defer_deletes and self._normalization_downgraded():
            # Unlike a filter edit, this does not self-heal: the baseline is NFC-keyed but
            # the volume now reports raw (NFD) names, so accented files would read as
            # deletions every pass. Defer deletions PERSISTENTLY until the volume is
            # restored (probe re-passes) or the operator rebaselines.
            log.critical(
                "baseline is NFC-migrated but the vault volume is now normalization-"
                "sensitive; deferring deletions until resolved (restore the original "
                "volume, or run `ifolder-sync rebaseline`)"
            )
            defer_deletes = True
        local = self._scan_local()  # raises on permission errors -> pass aborts
        remote = self._scan_remote()  # raises on a failed remote walk -> pass aborts
        if defer_deletes:
            self._log_direction(local, remote)
        all_paths = set(local) | set(remote) | set(baseline)
        all_paths = self._exclude_kind_conflicts(all_paths, local, remote, stats)
        all_paths = self._exclude_case_collisions(all_paths, stats)

        dirs = sorted(
            (p for p in all_paths if self._is_dir(p, local, remote, baseline)),
            key=lambda p: p.count("/"),
        )
        dir_set = set(dirs)
        files = sorted(p for p in all_paths if p not in dir_set)

        dir_actions = [(p, self._decide_dir(p, local, remote, baseline)) for p in dirs]
        file_actions = [(p, self._decide_file(p, local, remote, baseline)) for p in files]
        file_actions = self._escalate_settle(file_actions, dry_run)
        cleanup_actions = [
            (p, self._decide_dir_cleanup(p, local, remote, baseline))
            for p in sorted(dirs, key=lambda p: -p.count("/"))
        ]

        suppress_deletes = self._suppress_deletes(
            file_actions, defer_deletes, force_delete, baseline, stats
        )

        tree_roots: list[str] = []
        covered: set = set()
        kept: set = set()
        if not suppress_deletes:
            tree_roots, covered, kept = self._coalesce_remote_deletes(
                dir_actions, file_actions, cleanup_actions
            )

        for relpath, op in dir_actions:
            if self._should_stop():
                break
            self._apply_dir(relpath, op, stats, dry_run)
            self._commit(dry_run)
        for root in tree_roots:
            if self._should_stop():
                break
            self._delete_remote_tree(root, covered, stats, dry_run)
            self._commit(dry_run)
        for relpath, op in file_actions:
            if self._should_stop():
                break
            if relpath in covered or (suppress_deletes and op in _FILE_DESTRUCTIVE):
                continue
            self._apply_file(relpath, op, local, remote, stats, dry_run)
            self._commit(dry_run)
        for relpath, cleanup_op in cleanup_actions:
            if self._should_stop():
                break
            if cleanup_op is None or relpath in covered:
                continue
            if suppress_deletes and cleanup_op in _DIR_DESTRUCTIVE:
                continue
            if cleanup_op in _DIR_DESTRUCTIVE and any(k.startswith(relpath + "/") for k in kept):
                continue  # something below survives this pass; removing the dir would take it along
            self._apply_cleanup(relpath, cleanup_op, stats, dry_run)
            self._commit(dry_run)

        if not dry_run:
            self.store.commit()
            # A pass cut short by a stop signal is partial: don't advance last_sync (it
            # would read as a clean completion in `status`); last_stats still reflects
            # what was applied.
            if not self._should_stop():
                self.store.set_meta("last_sync", str(time.time()))
            self.store.set_meta("last_stats", stats.summary())
        return stats

    def _log_direction(self, local: dict[str, LocalEntry], remote: dict[str, RemoteEntry]) -> None:
        """Startup visibility: which side has the most recent write. Timestamps are the
        only available signal — devices syncing via Apple's native iCloud never run this
        code, and the Drive API exposes no device attribution."""
        local_files = [e for e in local.values() if e.kind == "file"]
        remote_files = [e for e in remote.values() if e.kind == "file"]
        if not local_files and not remote_files:
            return

        def fmt(entry) -> str:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.mtime))
            return f"{entry.relpath} @ {ts}"

        newest_local = max(local_files, key=lambda e: e.mtime) if local_files else None
        newest_remote = max(remote_files, key=lambda e: e.mtime) if remote_files else None
        local_mtime = newest_local.mtime if newest_local else 0.0
        remote_mtime = newest_remote.mtime if newest_remote else 0.0
        log.info(
            "freshest local: %s | freshest remote: %s -> most recent activity: %s",
            fmt(newest_local) if newest_local else "(none)",
            fmt(newest_remote) if newest_remote else "(none)",
            "local" if local_mtime >= remote_mtime else "remote",
        )

    def _over_threshold(self, count: int, baseline) -> bool:
        if count > self.cfg.delete_threshold_count:
            return True
        tracked = len(baseline)
        return bool(tracked and (count / tracked) * 100 > self.cfg.delete_threshold_pct)

    def _suppress_deletes(self, file_actions, defer_deletes, force_delete, baseline, stats) -> bool:
        """True = withhold every destructive op this pass. Two guards share the same
        mechanism: the bootstrap deferral (content first, destruction next pass) and
        the delete threshold. Baseline rows of withheld deletions are not touched, so
        the next pass re-derives them under the normal rules."""
        delete_count = sum(1 for _, op in file_actions if op in _FILE_DESTRUCTIVE)
        if not delete_count or force_delete:
            return False
        if defer_deletes:
            stats.deferred_deletes = delete_count
            log.info("bootstrap pass: deferring %d deletion(s) to the next pass", delete_count)
            return True
        if self._over_threshold(delete_count, baseline):
            stats.skipped_deletes = delete_count
            log.warning(
                "delete count %d exceeds threshold (pct=%d count=%d); skipping all "
                "deletions this pass (use --force-delete to override)",
                delete_count,
                self.cfg.delete_threshold_pct,
                self.cfg.delete_threshold_count,
            )
            return True
        return False

    @staticmethod
    def _coalesce_remote_deletes(dir_actions, file_actions, cleanup_actions):
        """Collapse fully-deleted remote subtrees into one folder deletion each.

        iCloud's move-to-trash on a folder is recursive (one network call, and the
        folder lands in Recently Deleted as a single restorable item), so deleting
        the topmost dir replaces one call per descendant. Only prunes a dir when
        NOTHING below it survives the pass. The threshold still counts per file.
        """
        effective: dict[str, str] = {}
        for p, op in dir_actions:
            effective[p] = op
        for p, op in file_actions:
            effective[p] = op
        for p, cop in cleanup_actions:
            if cop is not None:
                effective[p] = cop

        doomed = {Op.DELETE_REMOTE, Op.RMDIR_REMOTE, Op.DROP_BASELINE, Op.DROP_BASELINE_DIR}
        kept = {p for p, op in effective.items() if op not in doomed and op != Op.LEAVE_DIR}

        def under(parent: str, p: str) -> bool:
            return p.startswith(parent + "/")

        prunable = [
            d
            for d, op in effective.items()
            if op == Op.RMDIR_REMOTE and not any(under(d, k) for k in kept)
        ]
        roots = sorted(d for d in prunable if not any(under(a, d) for a in prunable))
        covered = {p for d in roots for p in effective if under(d, p)} | set(roots)
        return roots, covered, kept

    def _delete_remote_tree(self, root: str, covered: set, stats, dry_run):
        items = [p for p in covered if p.startswith(root + "/")]
        stats.deleted_remote += len(items) + 1
        log.info("DEL_REMOTE %s/ (whole subtree, %d items, one call)", root, len(items) + 1)
        if dry_run:
            return
        try:
            self.client.delete(root)
        except Exception as exc:  # noqa: BLE001
            log.error("remote tree delete failed %s: %s", root, exc)
            stats.errors += 1
            return
        self.store.delete(root)
        for p in items:
            self.store.delete(p)

    def _migrate_baseline_nfc(self, baseline: dict, dry_run: bool) -> dict:
        """P1-2 one-time migration: re-key any baseline relpath that is not NFC so it
        aligns with the NFC-keyed scans. Without it, an accented file recorded by the old
        engine under its NFD name would not match the NFC scan key and read as a delete +
        re-create on the first pass. Idempotent (a meta flag), returns the migrated dict."""
        if not self._normalize_active() or self.store.get_meta("nfc_migrated") == "1":
            return baseline
        for rel in [r for r in baseline if _nfc(r) != r]:
            nfc = _nfc(rel)
            entry = baseline.pop(rel)
            if not dry_run:
                self.store.delete(rel)
            if nfc in baseline:
                # Collision: an NFC row already exists. Drop BOTH and let the next pass
                # re-derive the truth (both-present, base None -> verify_adopt) rather than
                # guess which stale signature to keep.
                baseline.pop(nfc, None)
                if not dry_run:
                    self.store.delete(nfc)
                continue
            entry.relpath = nfc
            baseline[nfc] = entry
            if not dry_run:
                self.store.upsert(entry)
        if not dry_run:
            self.store.set_meta("nfc_migrated", "1")
        return baseline

    def _normalization_downgraded(self) -> bool:
        """True when the baseline was NFC-migrated on a previous (insensitive-volume) run
        but the volume is no longer normalization-insensitive — an inconsistent state that
        would phantom-delete accented files, so deletions must defer until it is fixed."""
        return self.store.get_meta("nfc_migrated") == "1" and not self._normalize_active()

    def _ignore_changed(self, dry_run: bool) -> bool:
        """F-P1-14: if the effective ignore set changed since the last pass, a previously
        synced file may now be ignored and read as a deletion. Returns True (→ defer
        deletes one pass, the rclone-bisync 'filters changed' safeguard) and records the
        new hash. The very first pass never trips it (no prior hash)."""
        # Fold in the active normalization policy: flipping it (config opt-out, or the
        # volume probe) re-keys every accented path — a bigger upheaval than a filter edit
        # — so it must defer deletes one pass exactly like a changed ignore set.
        state = "\n".join(self.ignore_patterns) + f"\x00normalize={self._normalize_active()}"
        h = hashlib.sha256(state.encode("utf-8")).hexdigest()
        prev = self.store.get_meta("ignore_hash")
        if not dry_run and prev != h:
            self.store.set_meta("ignore_hash", h)
        return prev is not None and prev != h

    def _exclude_case_collisions(self, all_paths: set, stats) -> set:
        """P1-2: two distinct identity keys that casefold to the same value (local
        `note.md` vs remote `Note.md`) are a collision the engine cannot reconcile on
        case-insensitive macOS — guessing risks clobbering the local original. Skip every
        variant this pass (no transfer, no delete, baseline untouched) and warn; the user
        renames to one canonical form to resolve."""
        groups: dict[str, list[str]] = {}
        for p in all_paths:
            groups.setdefault(_nfc(p).casefold(), []).append(p)
        collided = {p for variants in groups.values() if len(variants) > 1 for p in variants}
        if not collided:
            return all_paths
        for variants in groups.values():
            if len(variants) > 1:
                log.warning(
                    "name collision (differ only by case/normalization): %s — skipping all "
                    "this pass; rename to a single canonical form",
                    ", ".join(sorted(variants)),
                )
                stats.errors += 1
        return all_paths - collided

    def _exclude_kind_conflicts(self, all_paths: set, local, remote, stats) -> set:
        """P1-9: a path that is a file on one side and a directory on the other cannot be
        reconciled (downloading the dir would clobber the file, or the file decide would
        settle_wait forever on the dir's 0 bytes). Warn, count it, and drop it AND its
        subtree from this pass — no transfer, no delete, baseline rows untouched — so the
        user can rename one side. Surfacing it beats silently never-syncing it."""
        conflicts = {p for p in (set(local) & set(remote)) if local[p].kind != remote[p].kind}
        if not conflicts:
            return all_paths
        for c in sorted(conflicts):
            log.warning(
                "kind conflict at '%s' (local=%s, remote=%s); skipping it and its subtree "
                "this pass — rename one side to resolve",
                c,
                local[c].kind,
                remote[c].kind,
            )
            stats.errors += 1
        return {p for p in all_paths if not any(p == c or p.startswith(c + "/") for c in conflicts)}

    def _escalate_settle(self, file_actions, dry_run):
        """P1-10: a 0-byte remote husk shadowing a non-empty local file is deferred
        (settle_wait) so an in-flight upload is not trampled. But a genuinely-empty remote
        would livelock forever, and a one-shot `sync` could never resolve it. Count
        consecutive settle passes per path in the meta table; after settle_max_passes,
        escalate to a conflict so the policy resolves it. Counts persist across runs."""
        counts = self._load_settle_counts()
        threshold = max(1, int(self.cfg.settle_max_passes))
        new_counts: dict[str, int] = {}
        out = []
        for relpath, op in file_actions:
            if op != Op.SETTLE_WAIT:
                out.append((relpath, op))  # resolved/other -> its count drops out below
                continue
            n = counts.get(relpath, 0) + 1
            # Keep the count even when escalating: if the escalated conflict fails
            # transiently and the path is still a husk next pass, it re-escalates at once
            # rather than restarting the countdown (no re-livelock).
            new_counts[relpath] = n
            if n >= threshold:
                log.warning(
                    "%s stayed an empty/unsettled remote for %d passes; escalating to conflict",
                    relpath,
                    n,
                )
                out.append((relpath, Op.CONFLICT))
            else:
                out.append((relpath, op))
        if not dry_run and new_counts != counts:
            self.store.set_meta("settle_counts", json.dumps(new_counts))
        return out

    def _load_settle_counts(self) -> dict[str, int]:
        try:
            data = json.loads(self.store.get_meta("settle_counts") or "{}")
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    # ------------------------------------------------------------ decisions ---
    def _decide_file(self, relpath, local, remote, baseline) -> Op:
        lentry: Optional[LocalEntry] = local.get(relpath)
        rentry: Optional[RemoteEntry] = remote.get(relpath)
        base: Optional[BaselineEntry] = baseline.get(relpath)
        local_changed = lentry is not None and (
            base is None
            or self._changed(
                lentry.size, lentry.mtime, base.local_size, base.local_mtime, MTIME_TOL_LOCAL
            )
        )
        remote_changed = rentry is not None and (
            base is None
            or self._changed(
                rentry.size, rentry.mtime, base.remote_size, base.remote_mtime, MTIME_TOL
            )
        )
        if lentry and rentry:
            if local_changed and remote_changed:
                if base is None:
                    # First sight of a path present on both sides (prepopulated vault or
                    # the post-rebaseline first pass). Adopt-identical kills the rebaseline
                    # conflict storm — but only after VERIFYING the bytes match: equal
                    # size + close mtime is not proof of equal content (same-length notes
                    # collide), and recording a false "they agree" would freeze a real
                    # divergence with no backup. verify_adopt downloads + byte-compares,
                    # then records (truly identical) or resolves as a conflict (different).
                    if lentry.size == rentry.size and abs(lentry.mtime - rentry.mtime) <= MTIME_TOL:
                        return Op.VERIFY_ADOPT
                    # Simultaneous create where the remote is an empty husk: iCloud
                    # publishes the record before the content finishes uploading from the
                    # other device. Wait rather than back up 0 bytes over the live file.
                    if rentry.size == 0 and lentry.size > 0:
                        return Op.SETTLE_WAIT
                return Op.CONFLICT
            if local_changed:
                return Op.UPLOAD
            if remote_changed:
                # Publish-before-content on an EDIT: the remote record dropped to 0 bytes
                # while its new content uploads from another device. Downloading the husk
                # now would truncate the local file — wait (settle escalation resolves it
                # if the remote is genuinely empty).
                if (
                    rentry.size == 0
                    and lentry.size > 0
                    and base is not None
                    and base.remote_size > 0
                ):
                    return Op.SETTLE_WAIT
                return Op.DOWNLOAD
            if (
                self.cfg.verify_remote_etag
                and base is not None
                and base.remote_etag
                and rentry.etag
                and base.remote_etag != rentry.etag
            ):
                # Same size+mtime but the iCloud etag moved: the remote content changed
                # under an identical signature (a same-size edit, or publish-before-
                # content). Rescue it; _do_download records the new etag so this fires once.
                return Op.DOWNLOAD
            return Op.RECORD
        if lentry and not rentry:
            if base is None:
                return Op.UPLOAD
            return Op.RESCUE_UPLOAD if local_changed else Op.DELETE_LOCAL
        if rentry and not lentry:
            if base is None:
                return Op.DOWNLOAD
            return Op.RESCUE_DOWNLOAD if remote_changed else Op.DELETE_REMOTE
        return Op.DROP_BASELINE

    @staticmethod
    def _decide_dir(relpath, local, remote, baseline) -> Op:
        in_local = relpath in local
        in_remote = relpath in remote
        if in_local and in_remote:
            return Op.RECORD_DIR
        # Known in the baseline but gone from one side = a deletion in progress; the
        # cleanup phase owns it. Recreating it here (two-way logic) resurrects every
        # directory the user deletes.
        if relpath in baseline:
            return Op.LEAVE_DIR
        if in_local:
            return Op.MKDIR_REMOTE
        return Op.MKDIR_LOCAL

    @staticmethod
    def _decide_dir_cleanup(relpath, local, remote, baseline) -> Optional[Op]:
        if relpath not in baseline:
            return None
        in_local = relpath in local
        in_remote = relpath in remote
        if not in_local and not in_remote:
            return Op.DROP_BASELINE_DIR
        if not in_local and in_remote:
            return Op.RMDIR_REMOTE
        if in_local and not in_remote:
            return Op.RMDIR_LOCAL
        return None

    # ------------------------------------------------------------- apply io ---
    def _apply_file(self, relpath, op, local, remote, stats, dry_run):
        lentry = local.get(relpath)
        rentry = remote.get(relpath)
        try:
            if op == Op.UPLOAD:
                self._do_upload(relpath, stats, dry_run)
            elif op == Op.DOWNLOAD:
                self._do_download(relpath, rentry, stats, dry_run)
            elif op == Op.CONFLICT:
                self._resolve_conflict(relpath, lentry, rentry, stats, dry_run)
            elif op == Op.RESCUE_UPLOAD:
                log.warning("remote deleted but local edited; re-uploading %s", relpath)
                self._do_upload(relpath, stats, dry_run)
                stats.conflicts += 1
            elif op == Op.RESCUE_DOWNLOAD:
                log.warning("local deleted but remote edited; downloading %s", relpath)
                self._do_download(relpath, rentry, stats, dry_run)
                stats.conflicts += 1
            elif op == Op.DELETE_LOCAL:
                self._delete_local(relpath, stats, dry_run)
            elif op == Op.DELETE_REMOTE:
                self._delete_remote(relpath, stats, dry_run)
            elif op == Op.SETTLE_WAIT:
                log.info(
                    "remote %s is empty and unknown to the baseline (likely still "
                    "uploading from another device); deferring to the next pass",
                    relpath,
                )
            elif op == Op.RECORD:
                self._record(relpath, lentry, rentry, dry_run)
            elif op == Op.VERIFY_ADOPT:
                self._verify_adopt(relpath, lentry, rentry, stats, dry_run)
            elif op == Op.DROP_BASELINE:
                if not dry_run:
                    self.store.delete(relpath)
            else:
                raise ValueError(f"unhandled file op {op!r}")
        except Exception as exc:  # noqa: BLE001
            log.error("error reconciling %s: %s", relpath, exc)
            stats.errors += 1

    def _apply_dir(self, relpath, op, stats, dry_run):
        if op == Op.LEAVE_DIR:
            return
        if op == Op.MKDIR_REMOTE:
            stats.uploaded += 1
            if not dry_run:
                try:
                    self.client.mkdir(relpath)
                except Exception as exc:  # noqa: BLE001
                    log.error("remote mkdir failed %s: %s", relpath, exc)
                    stats.errors += 1
                    return
        elif op == Op.MKDIR_LOCAL:
            if not dry_run:
                try:
                    (self.local_root / relpath).mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    # e.g. a regular file already occupies the path (kind conflict). Record
                    # nothing: a dir that was not created must not enter the baseline.
                    log.error("local mkdir failed %s: %s", relpath, exc)
                    stats.errors += 1
                    return
        elif op != Op.RECORD_DIR:
            # RECORD_DIR falls through to the shared upsert (both sides already have it);
            # any other op reaching here is a bug, not a silent baseline write.
            raise ValueError(f"unhandled dir op {op!r}")
        if not dry_run:
            self.store.upsert(BaselineEntry(relpath, "dir", 0, 0, 0, 0))

    def _apply_cleanup(self, relpath, op, stats, dry_run):
        if op == Op.DROP_BASELINE_DIR:
            if not dry_run:
                self.store.delete(relpath)
        elif op == Op.RMDIR_REMOTE:
            stats.deleted_remote += 1
            if not dry_run:
                try:
                    self.client.delete(relpath)
                    self.store.delete(relpath)
                except Exception as exc:  # noqa: BLE001
                    log.error("remote dir delete failed %s: %s", relpath, exc)
                    stats.errors += 1
        elif op == Op.RMDIR_LOCAL:
            if dry_run:
                stats.deleted_local += 1
            else:
                self._rmdir_local(relpath, stats)
        else:
            raise ValueError(f"unhandled cleanup op {op!r}")

    def _rmdir_local(self, relpath: str, stats) -> None:
        """Remove a locally-surviving dir whose remote was deleted, dropping the baseline
        row ONLY when the dir is actually gone (P1-3). If it lingers with non-ignored
        entries, dropping the row would make it look new and resurrect the folder remotely
        next pass; ignored-only residue (e.g. .DS_Store) is trashed along with the dir."""
        p = self.local_root / relpath
        try:
            if not p.exists():
                self.store.delete(relpath)
                stats.deleted_local += 1
            elif not any(p.iterdir()):
                p.rmdir()
                self.store.delete(relpath)
                stats.deleted_local += 1
            elif self._only_ignored_residue(relpath, p):
                trash_local(self.local_root, relpath, self.trash_dir)
                self.store.delete(relpath)
                stats.deleted_local += 1
            else:
                # Real entries survive (their own deletes are pending, or the user kept
                # them). Keep the dir AND its baseline row so it is not resurrected; the
                # rmdir retries once they are gone.
                log.info("rmdir_local deferred: %s still has non-ignored entries", relpath)
        except OSError as exc:
            log.error("local dir delete failed %s: %s", relpath, exc)
            stats.errors += 1

    def _only_ignored_residue(self, relpath: str, p: Path) -> bool:
        """True only if every immediate child of p is an engine-ignored regular FILE
        (e.g. .DS_Store, *.part) — so trashing the dir loses no real data. A subdirectory
        is an OPAQUE container: even an engine-ignored one (.Trash, a user dir-ignore) can
        hide real untracked files, and `_ignored` matches an ignore name in any segment,
        so a name match alone is not proof the subtree is junk. Any subdir, symlink, or
        non-ignored file therefore means defer, never trash."""
        for child in p.iterdir():
            if child.is_symlink() or child.is_dir():
                return False
            if not self._ignored(f"{relpath}/{child.name}"):
                return False
        return True

    def _verify_adopt(self, relpath, lentry: LocalEntry, rentry: RemoteEntry, stats, dry_run):
        """Adopt-identical with proof: fetch the remote to a temp and byte-compare to the
        local file. Identical → record the baseline (no transfer; kills the rebaseline
        conflict storm). Different → resolve as a real conflict (preserve both). The fetch
        is verification only, not a vault write, so it is not counted as a download."""
        if dry_run:
            return
        src = self.local_root / relpath
        with tempfile.TemporaryDirectory(prefix="ifolder-sync-vfy-") as td:
            tmp = Path(td) / "remote"
            try:
                self.client.download(relpath, tmp)
                identical = src.exists() and filecmp.cmp(src, tmp, shallow=False)
            except Exception as exc:  # noqa: BLE001
                log.warning("adopt verify failed for %s; resolving as conflict: %s", relpath, exc)
                self._resolve_conflict(relpath, lentry, rentry, stats, dry_run)
                return
        if identical:
            self._record(relpath, lentry, rentry, dry_run)
        else:
            log.warning("%s: equal size but different content; resolving as conflict", relpath)
            self._resolve_conflict(relpath, lentry, rentry, stats, dry_run)

    # ------------------------------------------------------------ conflicts ---
    def _resolve_conflict(self, relpath, lentry: LocalEntry, rentry: RemoteEntry, stats, dry_run):
        stats.conflicts += 1
        policy = self.cfg.conflict_policy
        log.warning("CONFLICT on %s (policy=%s)", relpath, policy)
        if dry_run:
            return
        # Engine-wide safety invariant: a 0-byte side NEVER overwrites a non-empty side,
        # regardless of policy or mtime. An empty file is almost always a publish-before-
        # content husk or an accidental/observed truncation, and its mtime is set by the
        # other device — so without this, `newer`/`remote` could download emptiness over a
        # real note (content loss). A genuinely-cleared note can be re-cleared by the user;
        # lost content cannot be recovered.
        if rentry.size == 0 and lentry.size > 0:
            log.warning("  remote is empty; keeping local content (an empty side never wins)")
            self._do_upload(relpath, stats, False)
            return
        if lentry.size == 0 and rentry.size > 0:
            log.warning("  local is empty; keeping remote content (an empty side never wins)")
            self._do_download(relpath, rentry, stats, False)
            return
        if policy == "local":
            self._do_upload(relpath, stats, False)
        elif policy == "remote":
            self._do_download(relpath, rentry, stats, False)
        elif policy == "newer":
            if lentry.mtime >= rentry.mtime:
                self._backup_remote_then(
                    relpath, rentry, lambda: self._do_upload(relpath, stats, False)
                )
            else:
                self._backup_local_then(
                    relpath, lambda: self._do_download(relpath, rentry, stats, False)
                )
        elif policy == "both":
            conflict_rel = self._conflict_name(relpath)
            dest = self.local_root / conflict_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            self.client.download(relpath, dest)
            self._do_upload(relpath, stats, False)
            log.warning("conflict preserved as %s", conflict_rel)

    def _conflict_name(self, relpath: str) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        p = Path(relpath)
        return str(p.with_name(f"{p.stem}.conflict-{stamp}{p.suffix}"))

    def _backup_local_then(self, relpath, action):
        src = self.local_root / relpath
        if src.exists():
            bkp = self.local_root / self._conflict_name(relpath)
            bkp.parent.mkdir(parents=True, exist_ok=True)
            os.replace(src, bkp)
        action()

    def _backup_remote_then(self, relpath, rentry, action):
        bkp = self.local_root / self._conflict_name(relpath)
        bkp.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.client.download(relpath, bkp)
        except Exception as exc:  # noqa: BLE001
            try:
                bkp.unlink()  # remove the partial/empty backup
            except OSError:
                pass
            fails = self._note_download_failure(relpath, rentry)
            if fails < DOWNLOAD_MAX_FAILS:
                # Transient: never run action() (which removes the remote loser) without a
                # saved backup — a network blip would otherwise drop the only copy of the
                # losing version. Abort; the conflict re-derives next pass.
                log.error(
                    "could not save remote backup of %s; aborting conflict resolution this "
                    "pass (will retry): %s",
                    relpath,
                    exc,
                )
                return
            # Persistent: a remote blob that cannot be downloaded after several tries (a
            # broken iCloud blob) has NO recoverable content to protect, and blocking
            # forever loops the conflict every pass. Resolve WITHOUT the backup — the prior
            # remote goes to iCloud Recently Deleted via the upload's move-to-trash when
            # remote_trash is on.
            log.warning(
                "remote backup of %s failed %d times (broken/undownloadable remote blob); "
                "resolving the conflict WITHOUT a backup so the good local copy can win",
                relpath,
                fails,
            )
            action()
            return
        self._download_fail.pop(relpath, None)  # success clears the backoff
        action()

    # -------------------------------------------------------------- actions ---
    def _do_upload(self, relpath, stats, dry_run):
        stats.uploaded += 1
        log.info("UP   %s", relpath)
        if dry_run:
            return
        src = self.local_root / relpath
        # Upload a frozen snapshot, not the live file: under continuous editing
        # (editor autosave) the file changes between the scan and the send, so the
        # scan-time signature would describe bytes other than the ones uploaded —
        # the size drift then reads as a phantom remote edit and conflicts forever.
        # The snapshot keeps the source basename because pyicloud names the remote
        # entry after the uploaded file object. mtime is stamped remotely (no
        # follow-up stat round-trip; also prevents upload->download ping-pong).
        with tempfile.TemporaryDirectory(prefix="ifolder-sync-up-") as td:
            snap = Path(td) / src.name
            try:
                shutil.copy2(src, snap)
            except FileNotFoundError:
                log.warning("vanished before upload, skipping: %s", relpath)
                stats.errors += 1
                return
            st = snap.stat()
            self.client.upload(relpath, snap, mtime=st.st_mtime)
        self.store.upsert(
            BaselineEntry(relpath, "file", st.st_size, st.st_mtime, st.st_size, st.st_mtime)
        )

    # --- download-failure backoff (a broken iCloud blob: 200 + Content-Length N + 0 bytes)
    def _download_backed_off(self, relpath, rentry) -> bool:
        prev = self._download_fail.get(relpath)
        return bool(
            prev
            and prev[0] == rentry.size
            and abs(prev[1] - rentry.mtime) <= MTIME_TOL
            and prev[2] >= DOWNLOAD_MAX_FAILS
        )

    def _note_download_failure(self, relpath, rentry) -> int:
        prev = self._download_fail.get(relpath)
        same = bool(prev and prev[0] == rentry.size and abs(prev[1] - rentry.mtime) <= MTIME_TOL)
        fails = (prev[2] if same and prev else 0) + 1
        self._download_fail[relpath] = (rentry.size, rentry.mtime, fails)
        return fails

    def _do_download(self, relpath, rentry: RemoteEntry, stats, dry_run):
        if self._download_backed_off(relpath, rentry):
            # The remote has failed to download repeatedly without changing (a broken
            # blob). Skip without re-attempting; auto-retries when the remote changes.
            log.debug("skipping %s: download backed off", relpath)
            return
        stats.downloaded += 1
        log.info("DOWN %s", relpath)
        if dry_run:
            return
        dest = self.local_root / relpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.client.download(relpath, dest)
        except Exception:
            if self._note_download_failure(relpath, rentry) == DOWNLOAD_MAX_FAILS:
                log.warning(
                    "download of %s failed %d times against an unchanged remote (iCloud "
                    "is serving fewer bytes than its listed size — a broken remote blob); "
                    "backing off until the remote changes",
                    relpath,
                    DOWNLOAD_MAX_FAILS,
                )
            raise
        self._download_fail.pop(relpath, None)  # success clears the backoff
        st = dest.stat()
        self.store.upsert(
            BaselineEntry(
                relpath, "file", st.st_size, st.st_mtime, rentry.size, rentry.mtime, rentry.etag
            )
        )

    def _delete_local(self, relpath, stats, dry_run):
        stats.deleted_local += 1
        log.info("DEL_LOCAL %s", relpath)
        if dry_run:
            return
        if (self.local_root / relpath).exists():
            trash_local(self.local_root, relpath, self.trash_dir)
        # Row drop only after a successful trash move: dropping it on failure would
        # make the surviving file look new and resurrect it remotely next pass.
        self.store.delete(relpath)

    def _delete_remote(self, relpath, stats, dry_run):
        stats.deleted_remote += 1
        log.info("DEL_REMOTE %s", relpath)
        if dry_run:
            return
        self.client.delete(relpath)
        self.store.delete(relpath)

    def _record(self, relpath, lentry: LocalEntry, rentry: RemoteEntry, dry_run):
        if dry_run:
            return
        self.store.upsert(
            BaselineEntry(
                relpath, "file", lentry.size, lentry.mtime, rentry.size, rentry.mtime, rentry.etag
            )
        )
