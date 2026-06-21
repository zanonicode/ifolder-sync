"""Fail-fast safety net for the non-interactive Keychain read.

Under launchd a venv python is ad-hoc signed, so a non-interactive Keychain
authorization cannot be auto-granted and the underlying `security` read blocks
forever (observed wedging the daemon ~17h). `_resolve_password(interactive=False)`
bounds that read with `keyring_timeout_seconds` and raises AuthError instead of
hanging. An interactive read stays unbounded (a human can answer the OS prompt).
"""

from __future__ import annotations

import threading
import time

import pytest

import ifolder_sync.icloud_client as ic_module
from ifolder_sync.config import Config
from ifolder_sync.icloud_client import AuthError, ICloudClient

from .helpers import sandbox_home


def _client(tmp_path, keyring_timeout: float) -> ICloudClient:
    cfg = Config(
        apple_id="x@y.com",
        local_folder=str(tmp_path),
        keyring_timeout_seconds=keyring_timeout,
    )
    return ICloudClient.from_config(cfg)


def test_blocked_keychain_fails_fast_non_interactive(tmp_path, monkeypatch):
    monkeypatch.delenv("IFOLDER_SYNC_PASSWORD", raising=False)
    block = threading.Event()

    def _blocking_read(*_a, **_k):
        block.wait()
        return "never-returned"

    monkeypatch.setattr(ic_module, "get_password_from_keyring", _blocking_read)
    client = _client(tmp_path, keyring_timeout=0.1)

    start = time.monotonic()
    try:
        with pytest.raises(AuthError, match="timed out"):
            client._resolve_password(interactive=False)
        elapsed = time.monotonic() - start
        # Bounded at 0.1s; a generous wall-clock guard proves it did not hang.
        assert elapsed < 5.0
    finally:
        block.set()  # release the leaked daemon thread so the suite stays clean


def test_keyring_timeout_disabled_is_unbounded(tmp_path, monkeypatch):
    # keyring_timeout <= 0 restores the legacy unbounded read even non-interactively.
    monkeypatch.delenv("IFOLDER_SYNC_PASSWORD", raising=False)
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "pw-direct")
    client = _client(tmp_path, keyring_timeout=0.0)

    password, source = client._resolve_password(interactive=False)
    assert (password, source) == ("pw-direct", "keyring")


def test_interactive_keychain_read_is_unbounded(tmp_path, monkeypatch):
    # Interactive: the read runs directly on the calling thread (no bounding thread), so a
    # small keyring_timeout must NOT apply. A read that briefly outlasts the timeout still
    # returns its value rather than raising.
    monkeypatch.delenv("IFOLDER_SYNC_PASSWORD", raising=False)

    def _slow_read(*_a, **_k):
        time.sleep(0.2)
        return "pw-interactive"

    monkeypatch.setattr(ic_module, "get_password_from_keyring", _slow_read)
    client = _client(tmp_path, keyring_timeout=0.05)

    password, source = client._resolve_password(interactive=True)
    assert (password, source) == ("pw-interactive", "keyring")


def test_fast_keyring_returns_normally_non_interactive(tmp_path, monkeypatch):
    monkeypatch.delenv("IFOLDER_SYNC_PASSWORD", raising=False)
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "pw-fast")
    client = _client(tmp_path, keyring_timeout=5.0)

    password, source = client._resolve_password(interactive=False)
    assert (password, source) == ("pw-fast", "keyring")


def test_keyring_error_falls_back_to_prompt_or_raise(tmp_path, monkeypatch):
    # A keyring backend ERROR (not a timeout) must keep the old behavior: non-interactive
    # with no password falls through to the clear "no password" AuthError, NOT the timeout
    # message.
    monkeypatch.delenv("IFOLDER_SYNC_PASSWORD", raising=False)

    def _raise(*_a, **_k):
        raise RuntimeError("keyring backend unavailable")

    monkeypatch.setattr(ic_module, "get_password_from_keyring", _raise)
    client = _client(tmp_path, keyring_timeout=5.0)

    with pytest.raises(AuthError, match="No password available"):
        client._resolve_password(interactive=False)


def test_sandboxed(tmp_path, monkeypatch):
    # Guard: keep these tests off any real user Keychain/home.
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.delenv("IFOLDER_SYNC_PASSWORD", raising=False)
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: None)
    client = _client(tmp_path, keyring_timeout=5.0)
    with pytest.raises(AuthError, match="No password available"):
        client._resolve_password(interactive=False)
