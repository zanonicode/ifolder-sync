"""Lazy-password auth flow: the Keychain is read ONLY for a real from-scratch SRP login.

connect() constructs pyicloud token-only (authenticate=False, no keyring read) and tries
authenticate() once. pyicloud validates the saved trusted session first (no password); only
when that fails does it reach _srp_authentication(), which raises PyiCloudFailedLoginException
("No password set") BEFORE any Apple request when _password_raw is None. So:
  - a valid session reconnects with ZERO Keychain access, and
  - a real re-login resolves the password exactly once and retries authenticate().

These tests substitute pyicloud with a fake that honors authenticate=False and a settable
_password_raw, and fail loudly if the password is read on the token-valid path.
"""

from __future__ import annotations

import pytest
from pyicloud.exceptions import PyiCloudFailedLoginException

import ifolder_sync.icloud_client as ic_module
from ifolder_sync.config import Config
from ifolder_sync.icloud_client import AuthError, ICloudClient

from .helpers import sandbox_home


class _FakeSession:
    """Minimal stand-in for pyicloud's session: the connect() wrappers wrap request and
    replace _save_session_data, so both must exist and be settable."""

    def __init__(self) -> None:
        self._ifolder_timeout_wrapped = False
        self._ifolder_atomic_save = False

    def request(self, method, url, **kwargs):  # pragma: no cover - never actually called
        raise AssertionError("no real request expected in unit tests")

    def _save_session_data(self) -> None:  # pragma: no cover - replaced by the wrapper
        pass


class _FakePyiCloud:
    """Fake PyiCloudService honoring authenticate=False and a settable _password_raw.

    `auth_script` is a list of callables consumed one per authenticate() call; each either
    returns (success) or raises. This lets a test drive 'valid token' (one success) or
    'token gone then SRP login' (raise, then success). 2FA flags are False so handle_2fa is a
    no-op on every path."""

    auth_script: list = []  # set per test before connect()

    def __init__(self, apple_id, password=None, cookie_directory=None, *, authenticate=True):
        self.apple_id = apple_id
        self._password_raw = password
        self.session = _FakeSession()
        self.requires_2fa = False
        self.requires_2sa = False
        self._authenticate_calls = 0
        if password is None and authenticate:
            # Mirror pyicloud: only a non-token-only construct reads the keyring. Token-only
            # (authenticate=False) must NOT — asserting that here catches a regression at the
            # construction boundary, not just at _resolve_password.
            raise AssertionError("token-only construction must not read the keyring")
        if authenticate:  # pragma: no cover - connect() always passes authenticate=False
            self.authenticate()

    def authenticate(self, force_refresh: bool = False, service=None) -> None:
        step = type(self).auth_script[self._authenticate_calls]
        self._authenticate_calls += 1
        step(self)


def _client(tmp_path) -> ICloudClient:
    return ICloudClient.from_config(Config(apple_id="x@y.com", local_folder=str(tmp_path)))


def _no_password_read(monkeypatch):
    """Make any password read fail the test: neither the keyring getter nor _resolve_password
    may be reached on the token-valid path."""

    def _boom(*_a, **_k):
        raise AssertionError("password must NOT be read when the saved session is valid")

    monkeypatch.setattr(ic_module, "get_password_from_keyring", _boom)
    monkeypatch.setattr(ICloudClient, "_resolve_password", lambda self, interactive: _boom())


@pytest.fixture(autouse=True)
def _sandbox(tmp_path, monkeypatch):
    sandbox_home(tmp_path, monkeypatch)
    monkeypatch.delenv("IFOLDER_SYNC_PASSWORD", raising=False)
    monkeypatch.setattr(ic_module, "PyiCloudService", _FakePyiCloud)
    _FakePyiCloud.auth_script = []


def test_token_valid_path_never_reads_password(tmp_path, monkeypatch):
    # The saved trusted session is still good: authenticate() succeeds on the FIRST call, so
    # the Keychain / _resolve_password are never touched.
    _no_password_read(monkeypatch)
    _FakePyiCloud.auth_script = [lambda api: None]  # one success

    client = _client(tmp_path)
    client.connect(interactive=False)

    assert isinstance(client.api, _FakePyiCloud)
    assert client.api._authenticate_calls == 1
    assert client.api._password_raw is None  # never set: no SRP login happened


def test_token_invalid_path_reads_password_once_and_retries(tmp_path, monkeypatch):
    # The saved session is gone: the first authenticate() raises PyiCloudFailedLoginException
    # (pyicloud's "No password set" signal when _password_raw is None), so we resolve the
    # password exactly once, set _password_raw, and authenticate() succeeds on the retry.
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "kc-secret")

    resolve_calls = {"n": 0}
    real_resolve = ICloudClient._resolve_password

    def _counting_resolve(self, interactive):
        resolve_calls["n"] += 1
        return real_resolve(self, interactive)

    monkeypatch.setattr(ICloudClient, "_resolve_password", _counting_resolve)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    def _succeed(api):
        assert api._password_raw == "kc-secret"  # the retry runs WITH the resolved password

    _FakePyiCloud.auth_script = [_fail, _succeed]

    client = _client(tmp_path)
    client.connect(interactive=False)

    assert resolve_calls["n"] == 1
    assert client.api._authenticate_calls == 2
    assert client.api._password_raw == "kc-secret"


def test_token_invalid_no_password_propagates_autherror(tmp_path, monkeypatch):
    # Token paths exhausted AND no password anywhere (non-interactive): _resolve_password's
    # AuthError must propagate so the daemon clean-stops (invariant 9), not be swallowed.
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: None)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    # Only one scripted step: a second authenticate() would mean we wrongly proceeded.
    _FakePyiCloud.auth_script = [_fail]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="No password available"):
        client.connect(interactive=False)
    assert client.api._authenticate_calls == 1


def test_token_invalid_keyring_timeout_propagates_autherror(tmp_path, monkeypatch):
    # The bounded keyring read (this branch's fail-fast) times out: its AuthError must
    # propagate out of connect() unchanged, never retried into a hang.
    import threading

    block = threading.Event()

    def _blocking_read(*_a, **_k):
        block.wait()
        return "never"

    monkeypatch.setattr(ic_module, "get_password_from_keyring", _blocking_read)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    _FakePyiCloud.auth_script = [_fail]

    cfg = Config(apple_id="x@y.com", local_folder=str(tmp_path), keyring_timeout_seconds=0.1)
    client = ICloudClient.from_config(cfg)
    try:
        with pytest.raises(AuthError, match="timed out"):
            client.connect(interactive=False)
    finally:
        block.set()


def test_rejected_password_becomes_autherror(tmp_path, monkeypatch):
    # A REAL Apple rejection on the retry (wrong password) must surface as the operator-facing
    # AuthError, not a raw PyiCloudFailedLoginException.
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "wrong-pw")

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    def _reject(api):
        raise PyiCloudFailedLoginException("Invalid email/password combination.")

    _FakePyiCloud.auth_script = [_fail, _reject]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="rejected by Apple"):
        client.connect(interactive=False)
    assert client.api._authenticate_calls == 2
