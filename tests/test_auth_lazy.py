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
from pyicloud.exceptions import PyiCloudAPIResponseException, PyiCloudFailedLoginException

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


def _reject_401(api) -> None:
    """Mirror pyicloud 2.6.5's wrong-password shape: the SRP-complete 401 is kept as the
    __cause__ of the login exception (base.py wraps with `raise ... from`). The 401 code is
    what distinguishes a real rejection from a transient SRP failure."""
    raise PyiCloudFailedLoginException(
        "Invalid email/password combination."
    ) from PyiCloudAPIResponseException("Invalid email/password combination.", code=401)


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


def test_stale_keyring_password_interactive_prompts_and_recovers(tmp_path, monkeypatch):
    # After an Apple ID password change the Keychain still holds the OLD password. An
    # interactive login must fall back to a prompt when Apple rejects the stored password,
    # retry with the prompted one, and overwrite the stale Keychain item on success —
    # otherwise `ifolder-sync auth` is unrecoverable without manual Keychain surgery.
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "stale-pw")
    stored: list[tuple[str, str]] = []
    monkeypatch.setattr(ic_module, "store_password_in_keyring", lambda u, p: stored.append((u, p)))
    prompts = {"n": 0}

    def _prompt(_msg: str = "") -> str:
        prompts["n"] += 1
        return "new-pw"

    monkeypatch.setattr(ic_module.getpass, "getpass", _prompt)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    def _reject_stale(api):
        assert api._password_raw == "stale-pw"
        _reject_401(api)

    def _succeed_new(api):
        assert api._password_raw == "new-pw"

    _FakePyiCloud.auth_script = [_fail, _reject_stale, _succeed_new]

    client = _client(tmp_path)
    client.connect(interactive=True)

    assert prompts["n"] == 1
    assert client.api._authenticate_calls == 3
    assert stored == [("x@y.com", "new-pw")]


def test_rejected_prompted_password_raises_without_reprompt(tmp_path, monkeypatch):
    # A rejected PROMPT-sourced password must raise, not loop into another prompt: every
    # SRP attempt is a real Apple login and repeated failures can lock the Apple ID.
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: None)
    prompts = {"n": 0}

    def _prompt(_msg: str = "") -> str:
        prompts["n"] += 1
        return "typo-pw"

    monkeypatch.setattr(ic_module.getpass, "getpass", _prompt)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    _FakePyiCloud.auth_script = [_fail, _reject_401]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="rejected by Apple"):
        client.connect(interactive=True)
    assert prompts["n"] == 1


def test_stale_env_password_interactive_raises_without_prompt(tmp_path, monkeypatch):
    # An env-sourced password wins precedence on EVERY run, so prompting (and storing to
    # the Keychain) would not fix the next login — the error must name the variable instead.
    monkeypatch.setenv("IFOLDER_SYNC_PASSWORD", "stale-env")

    def _no_prompt(_msg: str = "") -> str:
        raise AssertionError("must not prompt while IFOLDER_SYNC_PASSWORD is set")

    monkeypatch.setattr(ic_module.getpass, "getpass", _no_prompt)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    _FakePyiCloud.auth_script = [_fail, _reject_401]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="IFOLDER_SYNC_PASSWORD"):
        client.connect(interactive=True)


@pytest.mark.parametrize(
    ("message", "cause_code"),
    [
        # Faithful transient: pyicloud 2.6.5 ALWAYS chains a cause on the signin-init
        # wrap (base.py:594-595) — an Apple-side outage arrives as a 5xx cause.
        ("Failed to initiate srp authentication.", 503),
        # Locked/throttled account: the signin-INIT failure carries a 401 cause too, but
        # it is NOT a wrong password — prompting "your stored password was rejected"
        # would lie and burn another SRP attempt against an already-locked account.
        ("Failed to initiate srp authentication.", 401),
        # Defensive: a cause-less login failure must also never prompt.
        ("Failed to initiate srp authentication.", None),
    ],
)
def test_non_rejection_login_failure_interactive_does_not_prompt(
    tmp_path, monkeypatch, message, cause_code
):
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "kc-pw")

    def _no_prompt(_msg: str = "") -> str:
        raise AssertionError("must not prompt on a non-rejection login failure")

    monkeypatch.setattr(ic_module.getpass, "getpass", _no_prompt)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    def _transient(api):
        if cause_code is None:
            raise PyiCloudFailedLoginException(message)
        raise PyiCloudFailedLoginException(message) from PyiCloudAPIResponseException(
            message, code=cause_code
        )

    _FakePyiCloud.auth_script = [_fail, _transient]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="rejected by Apple"):
        client.connect(interactive=True)


def test_empty_fallback_prompt_aborts_without_srp_attempt(tmp_path, monkeypatch):
    # An empty answer to the fallback prompt aborts cleanly instead of sending an empty
    # password to Apple (which would burn one of the bounded SRP attempts).
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "stale-pw")
    monkeypatch.setattr(ic_module.getpass, "getpass", lambda _msg="": "")

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    _FakePyiCloud.auth_script = [_fail, _reject_401]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="No password entered"):
        client.connect(interactive=True)
    assert client.api._authenticate_calls == 2


def test_stale_keyring_password_noninteractive_never_prompts(tmp_path, monkeypatch):
    # The daemon shape of the stale-password scenario (keyring-sourced + real 401 cause,
    # interactive=False): must stay a clean AuthError — never a prompt under launchd.
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "stale-pw")

    def _no_prompt(_msg: str = "") -> str:
        raise AssertionError("the daemon must never prompt")

    monkeypatch.setattr(ic_module.getpass, "getpass", _no_prompt)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    _FakePyiCloud.auth_script = [_fail, _reject_401]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="rejected by Apple"):
        client.connect(interactive=False)
    assert client.api._authenticate_calls == 2


def test_stale_env_password_noninteractive_names_variable(tmp_path, monkeypatch):
    # Deliberate behavior change over pre-fallback code, pinned on purpose: the env-401
    # message names the variable in BOTH modes (better daemon logs; behavior class —
    # AuthError, no prompt, no hang — unchanged).
    monkeypatch.setenv("IFOLDER_SYNC_PASSWORD", "stale-env")

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    _FakePyiCloud.auth_script = [_fail, _reject_401]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="IFOLDER_SYNC_PASSWORD"):
        client.connect(interactive=False)


def test_stale_then_typoed_prompt_stops_after_one_prompt(tmp_path, monkeypatch):
    # The full anti-lockout bound, end to end: stale keyring 401 -> ONE prompt -> the
    # prompted password is ALSO rejected -> AuthError. Exactly 3 SRP calls, exactly one
    # prompt, and nothing stored in the Keychain on failure.
    monkeypatch.setattr(ic_module, "get_password_from_keyring", lambda *a, **k: "stale-pw")
    stored: list[tuple[str, str]] = []
    monkeypatch.setattr(ic_module, "store_password_in_keyring", lambda u, p: stored.append((u, p)))
    prompts = {"n": 0}

    def _prompt(_msg: str = "") -> str:
        prompts["n"] += 1
        return "typo-pw"

    monkeypatch.setattr(ic_module.getpass, "getpass", _prompt)

    def _fail(api):
        raise PyiCloudFailedLoginException("No password set")

    _FakePyiCloud.auth_script = [_fail, _reject_401, _reject_401]

    client = _client(tmp_path)
    with pytest.raises(AuthError, match="rejected by Apple"):
        client.connect(interactive=True)
    assert prompts["n"] == 1
    assert client.api._authenticate_calls == 3
    assert stored == []
