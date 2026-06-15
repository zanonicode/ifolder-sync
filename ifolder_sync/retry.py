"""Retry transient iCloud/network failures with exponential backoff."""

from __future__ import annotations

import errno
import logging
import time
from typing import Callable, TypeVar

import requests
from pyicloud.exceptions import PyiCloudAPIResponseException

from .errors import UnreadableRemoteError

log = logging.getLogger("ifolder-sync.retry")

T = TypeVar("T")

# HTTP statuses worth retrying; 4xx logic errors are not.
_TRANSIENT_STATUS = {429, 500, 502, 503, 504}

# Local-disk failures that retrying cannot fix (permissions, disk full, missing path).
_NON_TRANSIENT_ERRNO = {errno.EACCES, errno.EPERM, errno.ENOSPC, errno.EROFS, errno.ENOENT}


def _is_transient(exc: Exception) -> bool:
    # Publish-before-content lag lasts far longer than the in-call 1/2/4s backoff; surface
    # it immediately so the engine owns the long, quiet per-pass deferral instead of burning
    # ~6s and logging "transient error; retry" on every pass.
    if isinstance(exc, UnreadableRemoteError):
        return False
    if isinstance(exc, PyiCloudAPIResponseException):
        try:
            return int(exc.code) in _TRANSIENT_STATUS  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
    if isinstance(exc, OSError) and exc.errno in _NON_TRANSIENT_ERRNO:
        return False
    return True  # connection-level errors (requests/socket/timeout) are transient


def with_retry(
    fn: Callable[[], T],
    *,
    attempts: int = 3,
    base: float = 1.0,
    retry_on: tuple[type[Exception], ...] = (
        PyiCloudAPIResponseException,
        OSError,
        requests.exceptions.RequestException,
    ),
) -> T:
    """Call ``fn``; retry on transient errors with delays base*2**i (1s, 2s, 4s...)."""
    for i in range(attempts):
        try:
            return fn()
        except retry_on as exc:
            if i == attempts - 1 or not _is_transient(exc):
                raise
            delay = base * (2**i)
            log.warning("transient error (%s); retry %d/%d in %.1fs", exc, i + 1, attempts, delay)
            time.sleep(delay)
    raise AssertionError("unreachable: the last attempt either returned or raised")
