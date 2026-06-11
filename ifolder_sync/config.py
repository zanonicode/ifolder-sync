"""Configuration loading and persistence for ifolder-sync.

The config lives at ~/.config/ifolder-sync/config.json. The password is NOT stored
here: it comes from the macOS Keychain (via pyicloud) or the IFOLDER_SYNC_PASSWORD
environment variable as a fallback.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .obsidian import OBSIDIAN_VOLATILE

APP_NAME = "ifolder-sync"

# OS/iCloud noise applied to every vault. The Obsidian per-device config
# (OBSIDIAN_VOLATILE) is applied on top only when Config.obsidian is true --
# see Config.effective_ignore. (*.part and the vault marker are additionally
# hard-ignored by the engine itself, independent of this list.)
DEFAULT_IGNORE = [".DS_Store", ".Trash", "*.icloud", "*.conflict-*", "*.part"]

# Engine-critical patterns whose absence is a data-safety problem, merged into
# effective_ignore at load time so a config saved before a pattern entered
# DEFAULT_IGNORE still gains it without rewriting the saved file (the saved
# `ignore` list is frozen at init; only DEFAULT_IGNORE moves forward). Keep this
# minimal -- only patterns that are genuinely unsafe to sync, not user taste.
ENGINE_IGNORE = ("*.conflict-*",)

# Identity marker written at the vault root. Local-only: if it ever synced, a
# vault re-downloaded from iCloud would carry the same UUID and "recreated
# vault" detection could never fire.
VAULT_MARKER_NAME = ".ifolder-sync-vault"

# launchd-started daemons cannot read these without Full Disk Access (macOS TCC),
# while a Terminal-started one can -- which masks the problem during testing.
_TCC_PROTECTED = ("Downloads", "Desktop", "Documents")


def tcc_protected(path: Path) -> bool:
    try:
        rel = Path(path).expanduser().resolve().relative_to(Path.home())
    except (ValueError, OSError):
        return False
    return bool(rel.parts) and rel.parts[0] in _TCC_PROTECTED


def write_vault_marker(root: Path, profile: str = "") -> str:
    marker = root / VAULT_MARKER_NAME
    payload = {"uuid": str(uuid.uuid4()), "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
    if profile:
        payload["profile"] = profile
    # .part tempname: even a torn write is engine-ignored and can never sync.
    tmp = marker.with_name(marker.name + ".part")
    tmp.write_text(json.dumps(payload, indent=2))
    os.replace(tmp, marker)
    return payload["uuid"]


def read_vault_marker(root: Path) -> Optional[str]:
    try:
        data = json.loads((root / VAULT_MARKER_NAME).read_text())
    except (OSError, ValueError):
        return None
    val = data.get("uuid")
    return val if isinstance(val, str) and val else None


DEFAULT_PROFILE = "default"


def config_home() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / APP_NAME


def profiles_dir() -> Path:
    return config_home() / "profiles"


def config_path(profile: str = DEFAULT_PROFILE) -> Path:
    return profiles_dir() / f"{profile}.json"


def state_dir(profile: str = DEFAULT_PROFILE) -> Path:
    """Per-profile state (baseline, trash, lock)."""
    d = config_home() / "state" / profile
    d.mkdir(parents=True, exist_ok=True)
    return d


def trash_dir(profile: str = DEFAULT_PROFILE) -> Path:
    """Local soft-delete area, kept outside the synced vault."""
    return state_dir(profile) / "trash"


def baseline_path(profile: str = DEFAULT_PROFILE) -> Path:
    return state_dir(profile) / "baseline.sqlite3"


def lock_path(profile: str = DEFAULT_PROFILE) -> Path:
    return state_dir(profile) / "daemon.lock"


def sessions_dir() -> Path:
    """Shared iCloud session store. pyicloud names session files by Apple ID, so
    profiles on the same account share one trusted session (one 2FA). The dir holds
    bearer credentials, so it is kept 0700 from the moment it exists."""
    d = config_home() / "state" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def session_basename(apple_id: str) -> str:
    """pyicloud's session filename derivation (session.py): only the \\w characters
    of the Apple ID. 'zanoni.av@gmail.com' -> 'zanoniavgmailcom'."""
    return "".join(c for c in apple_id if re.match(r"\w", c))


def session_paths(apple_id: str) -> tuple[Path, Path]:
    base = session_basename(apple_id)
    d = sessions_dir()
    return d / f"{base}.session", d / f"{base}.cookiejar"


def list_profiles() -> list[str]:
    pdir = profiles_dir()
    if not pdir.is_dir():
        return []
    return sorted(p.stem for p in pdir.glob("*.json"))


def migrate_legacy() -> bool:
    """Move a pre-profiles layout to the `default` profile, once. Idempotent.

    config.json -> profiles/default.json; state/baseline.sqlite3 and state/trash ->
    state/default/; state/*.session and *.cookiejar -> state/sessions/.
    """
    home = config_home()
    moved = False
    legacy_cfg = home / "config.json"
    if legacy_cfg.exists() and not config_path().exists():
        config_path().parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(legacy_cfg), str(config_path()))
        moved = True
    legacy_state = home / "state"
    if legacy_state.is_dir():
        dflt, sess = state_dir(), sessions_dir()
        for item in list(legacy_state.iterdir()):
            if item.name in (DEFAULT_PROFILE, "sessions"):
                continue
            if item.suffix in (".session", ".cookiejar"):
                dest = sess / item.name
            elif item.name in ("baseline.sqlite3", "trash"):
                dest = dflt / item.name
            else:
                continue  # logs, daemon.lock, *.part: leave as-is
            if not dest.exists():
                shutil.move(str(item), str(dest))
                moved = True
    return moved


@dataclass
class Config:
    apple_id: str = ""
    remote_folder: str = ""
    local_folder: str = ""
    interval_seconds: int = 60
    watch_local: bool = True
    debounce_seconds: float = 3.0
    conflict_policy: str = "newer"
    # Obsidian vault? When true, the .obsidian per-device config is excluded on top
    # of `ignore`. Off by default so a plain folder syncs everything.
    obsidian: bool = False
    max_retries: int = 3
    retry_base_delay: float = 1.0
    # (connect, read) timeout in seconds for every iCloud request. pyicloud passes
    # timeout=None by default, so one hung socket would wedge the daemon forever; a
    # timeout turns the hang into a retryable error. <=0 disables (no timeout).
    request_timeout_seconds: int = 60
    # The iCloud login token (web-auth cookie) lapses after some hours of uptime; a drive
    # call then raises HTTP 421 LOGIN_TOKEN_EXPIRED. The daemon reconnects in place (no 2FA
    # while the trust token is still valid) instead of looping every poll. This caps the
    # consecutive reconnects (with no clean pass between) before it clean-stops with a "run
    # auth" hint; 0 disables auto-reconnect (clean-stop on the first relapse).
    max_session_reconnects: int = 5
    # Minimum seconds between two SRP reconnects, so a pathological relapse storm cannot
    # replay logins every poll (Apple lockout risk); within the window the daemon retries
    # without reconnecting.
    min_reconnect_interval_seconds: int = 120
    # After each successful pass that changed something, the daemon snapshots the
    # baseline DB into a ring of this many rotated copies (recovery net for corruption;
    # never auto-recreated). 0 disables.
    baseline_backups: int = 5
    # Remote walk = one listing call per folder; folders on the same depth level are
    # listed concurrently with this many workers (1 = serial).
    walk_workers: int = 4
    # iCloud folder etags fingerprint the whole subtree (verified empirically:
    # a child edit propagates to every ancestor; untouched folders stay stable), so
    # unchanged folders can be served from cache. A full uncached walk still runs
    # every this-many seconds as belt-and-suspenders (0 disables caching).
    full_walk_interval_seconds: int = 600
    # Adaptive polling: while changes flowed in the last active_window_seconds, poll
    # every interval_active_seconds instead of interval_seconds.
    interval_active_seconds: int = 20
    active_window_seconds: int = 300
    remote_trash: bool = True
    # Normalize filenames to NFC for identity (Syncthing's "normalize for identity, not
    # for I/O"). macOS may store accented names decomposed (NFD) while iCloud reports
    # them composed (NFC); without this the same note reads as two paths -> phantom
    # create+delete -> deletion of accented files. On by default; relies on APFS being
    # normalization-insensitive for lookups.
    normalize_unicode: bool = True
    # A 0-byte remote file shadowing a non-empty local file is usually a publish-before-
    # content upload from another device, so the engine waits (settle_wait). If it stays
    # empty this many passes it is judged genuinely empty and escalated to a conflict.
    settle_max_passes: int = 3
    # Treat a same-size/same-mtime remote file whose iCloud etag differs from the
    # baseline as a remote change (download it). Safe: the loser is the local copy only
    # when local is otherwise unchanged, and the new etag is recorded so it cannot loop.
    verify_remote_etag: bool = True
    # A folder listing whose item count is below iCloud's reported directChildrenCount
    # may be silently truncated (would read as deletions). False = log a warning (the
    # delete threshold still backstops mass deletion); True = abort the pass (zero
    # deletions) like the rest of the walk guard.
    strict_child_count: bool = False
    # Skip uploading a local file larger than this many MB. pyicloud buffers the whole
    # file in memory to build the multipart body, so a multi-GB file would spike the
    # daemon's RSS (OOM risk under launchd). 0 = no limit (default; unchanged behavior).
    # Note: an over-limit file that is also in a both-sides conflict cannot be pushed, so
    # the conflict stays unresolved until the limit is raised or the file shrinks.
    max_file_size_mb: int = 0
    delete_threshold_pct: int = 50
    delete_threshold_count: int = 100
    ignore: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE))

    @staticmethod
    def load(path: Optional[Path] = None) -> "Config":
        path = path or config_path()
        if not path.exists():
            raise FileNotFoundError(f"Config not found at {path}. Run `ifolder-sync init` first.")
        data = json.loads(path.read_text())
        known = set(Config().__dict__)
        clean = {k: v for k, v in data.items() if k in known}
        return Config(**clean)

    def save(self, path: Optional[Path] = None) -> Path:
        path = path or config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False))
        return path

    def validate(self) -> None:
        if not self.apple_id:
            raise ValueError("apple_id is empty in the config.")
        if not self.local_folder:
            raise ValueError("local_folder is empty in the config.")
        if self.conflict_policy not in {"newer", "local", "remote", "both"}:
            raise ValueError(f"invalid conflict_policy: {self.conflict_policy}")
        if not isinstance(self.ignore, list):
            raise ValueError("`ignore` must be a list of patterns.")
        for name in (
            "interval_seconds",
            "max_retries",
            "delete_threshold_pct",
            "delete_threshold_count",
            "walk_workers",
            "interval_active_seconds",
            "active_window_seconds",
            "full_walk_interval_seconds",
            "request_timeout_seconds",
            "baseline_backups",
            "settle_max_passes",
            "max_file_size_mb",
        ):
            if not isinstance(getattr(self, name), int):
                raise ValueError(f"`{name}` must be an integer.")

    @property
    def local_path(self) -> Path:
        return Path(self.local_folder).expanduser()

    @property
    def effective_ignore(self) -> list[str]:
        """Patterns actually applied: base `ignore`, the engine-critical set merged in
        (old configs predate newer DEFAULT_IGNORE entries), plus the Obsidian set when
        enabled. Deduplicated, order-stable."""
        extra = list(OBSIDIAN_VOLATILE) if self.obsidian else []
        merged = list(self.ignore) + list(ENGINE_IGNORE) + extra
        seen: set[str] = set()
        out: list[str] = []
        for pat in merged:
            if pat not in seen:
                seen.add(pat)
                out.append(pat)
        return out
