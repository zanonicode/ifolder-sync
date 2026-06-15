"""Shared test helpers: an in-memory iCloud Drive fake and small utilities.

FakeICloud implements the interface the Syncer uses, with a flat in-memory store.
It counts network-style calls (so a test can assert no post-upload stat happens) and
can simulate a failed remote walk.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from ifolder_sync.errors import UnreadableRemoteError
from ifolder_sync.icloud_client import RemoteEntry

if TYPE_CHECKING:
    from ifolder_sync.syncer import SyncClient

FAR = 10000.0  # mtime offset well above the 2s tolerance

# Delete thresholds high enough that plain-sync tests are never suppressed.
PERMISSIVE_THRESHOLDS = {"delete_threshold_pct": 100, "delete_threshold_count": 10**9}


def sandbox_home(tmp_path, monkeypatch) -> None:
    """Redirect HOME (LaunchAgents) and XDG_CONFIG_HOME (config/state) to tmp_path."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


class FakeICloud:
    def __init__(self) -> None:
        self.files: dict[str, dict] = {}
        self.fail_walk = False
        # Paths whose record reports size N>0 in walk()/stat() but whose download() raises
        # UnreadableRemoteError — a faithful publish-before-content fixture (the blob is not
        # yet materialized).
        self.unreadable: set[str] = set()
        self.calls = {
            k: 0
            for k in ("refresh", "walk", "upload", "download", "delete", "stat", "mkdir", "connect")
        }

    def connect(self, interactive: bool = True, fresh: bool = False) -> None:
        self.calls["connect"] += 1

    def refresh(self) -> None:
        self.calls["refresh"] += 1

    def ensure_remote_root(self) -> None:
        pass

    def walk(self, is_ignored: Optional[Callable[[str], bool]] = None) -> dict[str, RemoteEntry]:
        self.calls["walk"] += 1
        if self.fail_walk:
            raise RuntimeError("simulated remote walk failure")
        out = {}
        for rel, m in self.files.items():
            if is_ignored is not None and is_ignored(rel):
                continue
            out[rel] = RemoteEntry(rel, m["kind"], m.get("size", 0), m["mtime"], m.get("etag", ""))
        return out

    def download(self, relpath: str, dest: os.PathLike[str]) -> None:
        self.calls["download"] += 1
        m = self.files[relpath]
        if relpath in self.unreadable:
            raise UnreadableRemoteError(
                f"remote blob for {relpath} not materialized: got 0 bytes, "
                f"expected {m.get('size', 0)}"
            )
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(m["content"])

    def upload(self, relpath: str, src: os.PathLike[str], mtime: float) -> None:
        self.calls["upload"] += 1
        data = Path(src).read_bytes()
        self.files[relpath] = {"kind": "file", "content": data, "mtime": mtime, "size": len(data)}

    def mkdir(self, relpath: str) -> None:
        self.calls["mkdir"] += 1
        self.files[relpath] = {"kind": "dir", "mtime": 0, "size": 0}

    def delete(self, relpath: str) -> None:
        self.calls["delete"] += 1
        self.files.pop(relpath, None)
        for k in [k for k in self.files if k.startswith(relpath + "/")]:
            self.files.pop(k, None)

    def stat(self, relpath: str) -> Optional[RemoteEntry]:
        self.calls["stat"] += 1
        m = self.files.get(relpath)
        if not m:
            return None
        return RemoteEntry(relpath, m["kind"], m.get("size", 0), m["mtime"], m.get("etag", ""))

    def put(self, relpath: str, content: bytes, mtime: float, etag: str = "") -> None:
        self.files[relpath] = {
            "kind": "file",
            "content": content,
            "mtime": mtime,
            "size": len(content),
            "etag": etag,
        }
        self.unreadable.discard(relpath)  # writing real content heals an unreadable path

    def put_unreadable(self, relpath: str, size: int, mtime: float, etag: str = "") -> None:
        """Publish-before-content: the record lists size N>0 (so walk/stat see a real file)
        but download() raises UnreadableRemoteError (the blob has not materialized)."""
        self.files[relpath] = {
            "kind": "file",
            "content": b"",
            "mtime": mtime,
            "size": size,
            "etag": etag,
        }
        self.unreadable.add(relpath)


if TYPE_CHECKING:
    # Compile-time proof that the in-memory fake honors the engine's SyncClient contract.
    # If a SyncClient method is renamed or its signature drifts, mypy fails HERE rather
    # than the fake silently diverging from the real ICloudClient it stands in for.
    _fake_is_sync_client: SyncClient = FakeICloud()


def write_file(local: Path, rel: str, content: bytes, mtime: float | None = None):
    p = local / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    if mtime is not None:
        os.utime(p, (mtime, mtime))
