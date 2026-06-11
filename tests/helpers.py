"""Shared test helpers: an in-memory iCloud Drive fake and small utilities.

FakeICloud implements the interface the Syncer uses, with a flat in-memory store.
It counts network-style calls (so a test can assert no post-upload stat happens) and
can simulate a failed remote walk.
"""

from __future__ import annotations

import os
from pathlib import Path

from ifolder_sync.icloud_client import RemoteEntry

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
        self.calls = {
            k: 0 for k in ("refresh", "walk", "upload", "download", "delete", "stat", "mkdir")
        }

    def refresh(self):
        self.calls["refresh"] += 1

    def ensure_remote_root(self):
        pass

    def walk(self, is_ignored=None):
        self.calls["walk"] += 1
        if self.fail_walk:
            raise RuntimeError("simulated remote walk failure")
        out = {}
        for rel, m in self.files.items():
            if is_ignored is not None and is_ignored(rel):
                continue
            out[rel] = RemoteEntry(rel, m["kind"], m.get("size", 0), m["mtime"], m.get("etag", ""))
        return out

    def download(self, relpath, dest):
        self.calls["download"] += 1
        m = self.files[relpath]
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(m["content"])

    def upload(self, relpath, src, mtime):
        self.calls["upload"] += 1
        data = Path(src).read_bytes()
        self.files[relpath] = {"kind": "file", "content": data, "mtime": mtime, "size": len(data)}

    def mkdir(self, relpath):
        self.calls["mkdir"] += 1
        self.files[relpath] = {"kind": "dir", "mtime": 0, "size": 0}

    def delete(self, relpath):
        self.calls["delete"] += 1
        self.files.pop(relpath, None)
        for k in [k for k in self.files if k.startswith(relpath + "/")]:
            self.files.pop(k, None)

    def stat(self, relpath):
        self.calls["stat"] += 1
        m = self.files.get(relpath)
        if not m:
            return None
        return RemoteEntry(relpath, m["kind"], m.get("size", 0), m["mtime"], m.get("etag", ""))

    def put(self, relpath, content: bytes, mtime: float, etag: str = ""):
        self.files[relpath] = {
            "kind": "file",
            "content": content,
            "mtime": mtime,
            "size": len(content),
            "etag": etag,
        }


def write_file(local: Path, rel: str, content: bytes, mtime: float | None = None):
    p = local / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    if mtime is not None:
        os.utime(p, (mtime, mtime))
