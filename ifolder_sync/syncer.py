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
import json
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
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

_FILE_DESTRUCTIVE = {"delete_local", "delete_remote"}
_DIR_DESTRUCTIVE = {"rmdir_local", "rmdir_remote"}


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
    def _ignored(self, relpath: str) -> bool:
        segs = relpath.split("/")
        # Engine-internal exclusions, independent of the user's ignore list: configs
        # saved by older versions never pick up new DEFAULT_IGNORE entries.
        name = segs[-1]
        if name == VAULT_MARKER_NAME or name.endswith(PART_SUFFIX):
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
                out[rel] = LocalEntry(rel, "dir", 0, st.st_mtime)
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
                out[rel] = LocalEntry(rel, "file", st.st_size, st.st_mtime)
        return out

    def _scan_remote(self) -> dict[str, RemoteEntry]:
        remote = self.client.walk(self._ignored)
        safe: dict[str, RemoteEntry] = {}
        for rel, entry in remote.items():
            if self._is_safe_rel(rel):
                safe[rel] = entry
            else:
                log.warning("skipping unsafe remote path: %s", rel)
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
        local = self._scan_local()  # raises on permission errors -> pass aborts
        remote = self._scan_remote()  # raises on a failed remote walk -> pass aborts
        if defer_deletes:
            self._log_direction(local, remote)
        all_paths = set(local) | set(remote) | set(baseline)
        all_paths = self._exclude_kind_conflicts(all_paths, local, remote, stats)

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

        doomed = {"delete_remote", "rmdir_remote", "drop_baseline", "drop_baseline_dir"}
        kept = {p for p, op in effective.items() if op not in doomed and op != "leave_dir"}

        def under(parent: str, p: str) -> bool:
            return p.startswith(parent + "/")

        prunable = [
            d
            for d, op in effective.items()
            if op == "rmdir_remote" and not any(under(d, k) for k in kept)
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
            if op != "settle_wait":
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
                out.append((relpath, "conflict"))
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
    def _decide_file(self, relpath, local, remote, baseline) -> str:
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
                        return "verify_adopt"
                    # Simultaneous create where the remote is an empty husk: iCloud
                    # publishes the record before the content finishes uploading from the
                    # other device. Wait rather than back up 0 bytes over the live file.
                    if rentry.size == 0 and lentry.size > 0:
                        return "settle_wait"
                return "conflict"
            if local_changed:
                return "upload"
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
                    return "settle_wait"
                return "download"
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
                return "download"
            return "record"
        if lentry and not rentry:
            if base is None:
                return "upload"
            return "rescue_upload" if local_changed else "delete_local"
        if rentry and not lentry:
            if base is None:
                return "download"
            return "rescue_download" if remote_changed else "delete_remote"
        return "drop_baseline"

    @staticmethod
    def _decide_dir(relpath, local, remote, baseline) -> str:
        in_local = relpath in local
        in_remote = relpath in remote
        if in_local and in_remote:
            return "record_dir"
        # Known in the baseline but gone from one side = a deletion in progress; the
        # cleanup phase owns it. Recreating it here (two-way logic) resurrects every
        # directory the user deletes.
        if relpath in baseline:
            return "leave_dir"
        if in_local:
            return "mkdir_remote"
        return "mkdir_local"

    @staticmethod
    def _decide_dir_cleanup(relpath, local, remote, baseline) -> Optional[str]:
        if relpath not in baseline:
            return None
        in_local = relpath in local
        in_remote = relpath in remote
        if not in_local and not in_remote:
            return "drop_baseline_dir"
        if not in_local and in_remote:
            return "rmdir_remote"
        if in_local and not in_remote:
            return "rmdir_local"
        return None

    # ------------------------------------------------------------- apply io ---
    def _apply_file(self, relpath, op, local, remote, stats, dry_run):
        lentry = local.get(relpath)
        rentry = remote.get(relpath)
        try:
            if op == "upload":
                self._do_upload(relpath, stats, dry_run)
            elif op == "download":
                self._do_download(relpath, rentry, stats, dry_run)
            elif op == "conflict":
                self._resolve_conflict(relpath, lentry, rentry, stats, dry_run)
            elif op == "rescue_upload":
                log.warning("remote deleted but local edited; re-uploading %s", relpath)
                self._do_upload(relpath, stats, dry_run)
                stats.conflicts += 1
            elif op == "rescue_download":
                log.warning("local deleted but remote edited; downloading %s", relpath)
                self._do_download(relpath, rentry, stats, dry_run)
                stats.conflicts += 1
            elif op == "delete_local":
                self._delete_local(relpath, stats, dry_run)
            elif op == "delete_remote":
                self._delete_remote(relpath, stats, dry_run)
            elif op == "settle_wait":
                log.info(
                    "remote %s is empty and unknown to the baseline (likely still "
                    "uploading from another device); deferring to the next pass",
                    relpath,
                )
            elif op == "record":
                self._record(relpath, lentry, rentry, dry_run)
            elif op == "verify_adopt":
                self._verify_adopt(relpath, lentry, rentry, stats, dry_run)
            elif op == "drop_baseline" and not dry_run:
                self.store.delete(relpath)
        except Exception as exc:  # noqa: BLE001
            log.error("error reconciling %s: %s", relpath, exc)
            stats.errors += 1

    def _apply_dir(self, relpath, op, stats, dry_run):
        if op == "leave_dir":
            return
        if op == "mkdir_remote":
            stats.uploaded += 1
            if not dry_run:
                try:
                    self.client.mkdir(relpath)
                except Exception as exc:  # noqa: BLE001
                    log.error("remote mkdir failed %s: %s", relpath, exc)
                    stats.errors += 1
                    return
        elif op == "mkdir_local" and not dry_run:
            try:
                (self.local_root / relpath).mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                # e.g. a regular file already occupies the path (kind conflict). Record
                # nothing: a dir that was not created must not enter the baseline.
                log.error("local mkdir failed %s: %s", relpath, exc)
                stats.errors += 1
                return
        if not dry_run:
            self.store.upsert(BaselineEntry(relpath, "dir", 0, 0, 0, 0))

    def _apply_cleanup(self, relpath, op, stats, dry_run):
        if op == "drop_baseline_dir":
            if not dry_run:
                self.store.delete(relpath)
        elif op == "rmdir_remote":
            stats.deleted_remote += 1
            if not dry_run:
                try:
                    self.client.delete(relpath)
                    self.store.delete(relpath)
                except Exception as exc:  # noqa: BLE001
                    log.error("remote dir delete failed %s: %s", relpath, exc)
                    stats.errors += 1
        elif op == "rmdir_local":
            stats.deleted_local += 1
            if not dry_run:
                try:
                    p = self.local_root / relpath
                    if p.exists() and not any(p.iterdir()):
                        p.rmdir()
                    self.store.delete(relpath)
                except Exception as exc:  # noqa: BLE001
                    log.error("local dir delete failed %s: %s", relpath, exc)
                    stats.errors += 1

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
            # Never run action() (which removes the remote loser) without a saved
            # backup: a transient download error would otherwise hard-delete the only
            # copy of the losing version. Abort; the conflict re-derives next pass.
            log.error(
                "could not save remote backup of %s; aborting conflict resolution this "
                "pass (will retry): %s",
                relpath,
                exc,
            )
            return
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

    def _do_download(self, relpath, rentry: RemoteEntry, stats, dry_run):
        stats.downloaded += 1
        log.info("DOWN %s", relpath)
        if dry_run:
            return
        dest = self.local_root / relpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        self.client.download(relpath, dest)
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
