"""Typed exceptions shared across the iCloud client, retry layer, and sync engine.

Kept in a neutral module so both icloud_client (the raiser) and retry (the classifier)
can import it without a cycle: icloud_client imports from retry, so the exception cannot
live in icloud_client.
"""

from __future__ import annotations


class UnreadableRemoteError(OSError):
    """The remote published metadata size N>0 but the body materialized as 0 bytes.

    This is iCloud's publish-before-content lag: Apple's web API exposes a file's record
    (with its final size) before the blob finishes propagating, so a body fetch returns an
    empty stream. Distinct from a genuine truncated/partial read (0<got<N), which stays a
    plain transient OSError. Subclasses OSError so the existing `.part` cleanup and every
    `except OSError` site keep working; the engine catches this type first to DEFER rather
    than error or clobber.
    """
