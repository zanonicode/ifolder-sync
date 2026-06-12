"""Process exit codes for the CLI — a stable contract for scripts and monitoring.

A bare 0/1 cannot tell a wedged auth from a suppressed-deletion safety stop, so `sync`
used to exit 0 even when every upload failed (monitoring could never fire). These codes
let a caller distinguish *why* a command ended.

argparse owns USAGE (2). The daemon (`start`) deliberately stays at 0 on operator-
actionable stops under launchd (invariant 9: KeepAlive SuccessfulExit=false must not be
turned into a restart loop); the codes below are for the one-shot commands and an
interactive `start`.
"""

from __future__ import annotations

from enum import IntEnum


class Exit(IntEnum):
    OK = 0
    ERROR = 1  # unexpected or uncategorized failure
    USAGE = 2  # bad arguments (emitted by argparse itself)
    AUTH_REQUIRED = 3  # not authenticated, 2FA needed, or the session expired
    SCAN_GUARD = 4  # a scan guard aborted the pass with zero deletions (invariant 2)
    VAULT_IDENTITY = 5  # the vault identity marker mismatched (invariant 8)
    DELETES_SUPPRESSED = 6  # deletions held back by the safety threshold (invariant 3)
    SYNC_ERRORS = 7  # the pass ran but some file operations failed
    INTERRUPTED = 130  # Ctrl-C (128 + SIGINT)
