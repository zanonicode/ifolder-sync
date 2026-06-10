"""Local soft-delete: move vault files into a timestamped trash outside the vault.

The trash lives under the state dir (never inside the synced vault), so recovered or
pending-deletion files are not picked up by a scan and cannot ping-pong back.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path


def trash_local(local_root: Path, relpath: str, trash_dir: Path) -> Path:
    """Move local_root/relpath into trash_dir/<timestamp>/relpath. Returns the dest."""
    src = local_root / relpath
    dest = trash_dir / time.strftime("%Y%m%d-%H%M%S") / relpath
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    return dest


def trash_count(trash_dir: Path) -> int:
    if not trash_dir.exists():
        return 0
    return sum(1 for p in trash_dir.rglob("*") if p.is_file())


def purge_trash(trash_dir: Path) -> int:
    """Delete the whole trash dir. Returns how many files were removed."""
    n = trash_count(trash_dir)
    if trash_dir.exists():
        shutil.rmtree(trash_dir)
    return n
