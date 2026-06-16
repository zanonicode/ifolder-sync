"""Scope and size-bound the PR diff the Guardian reviews.

`changed_diff` returns the unified patch for the changed files under `ifolder_sync/`
(the engine — the only code the data-loss invariants protect), or None when there is
nothing in scope to review or the diff is too large to send to the model. Stdlib-only:
importing this needs no google-genai / pydantic, so the unit-test job exercises it on a
base install (Testing Strategy).
"""

from __future__ import annotations

import subprocess

# Cap the diff handed to the model: a huge diff is costly and low-signal, and a
# multi-hundred-KB prompt risks truncation. Measured in BYTES, not characters
# (DESIGN_03 Decision 6).
MAX_DIFF_BYTES = 200_000


def changed_diff(
    base: str = "origin/main",
    paths: tuple[str, ...] = ("ifolder_sync/",),
) -> str | None:
    """Return the unified diff of `paths` between `base` and HEAD, or None.

    None when the in-scope range is empty (nothing to review) OR the diff exceeds
    MAX_DIFF_BYTES. The git invocation is a list of args (never `shell=True`), with the
    path scope passed as explicit pathspecs after a `--` separator and a three-dot
    `base...HEAD` range so only the PR's own changes are considered. `check=False`: a
    missing base ref or any git error yields empty output -> None (skip), never a raise,
    so the caller's always-exit-0 advisory contract holds.
    """
    cmd = ["git", "diff", "--patch", f"{base}...HEAD", "--", *paths]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    diff = proc.stdout
    if not diff.strip():
        return None
    if len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
        return None
    return diff
