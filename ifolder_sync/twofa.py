"""Interactive terminal 2FA / 2SA verification for the iCloud login.

Extracted from icloud_client so the prompt / SMS / diagnostics console UX lives apart from
the path-oriented Drive operations. Each function takes the authenticated PyiCloudService
(`api`) and drives the terminal flow.

Keep this flow intact (see the "2FA" section in CLAUDE.md): pyicloud >=2.5 pushes the 2FA
code itself inside authenticate(), so we must NOT push again on entry (that lands a second,
confusing prompt); `[r]esend` uses the public request_2fa_code() with the raw PUT only as a
fallback; only CODE attempts count toward the retry limit; a rejected code must leave the
session discardable by the caller (the poisoned-session handling lives in icloud_client).
"""

from __future__ import annotations

from typing import Optional

from pyicloud import PyiCloudService
from pyicloud.exceptions import PyiCloudAPIResponseException

# Apple's error code for "wrong verification code" (covers device AND SMS).
APPLE_WRONG_CODE = -21669


def handle_2fa(api: PyiCloudService, *, interactive: bool) -> None:
    if api is None:
        raise RuntimeError("Connection not initialized.")
    if not (api.requires_2fa or api.requires_2sa):
        return  # session already trusted (valid cached trust token)
    if not interactive:
        raise RuntimeError(
            "iCloud requires 2FA verification, but the daemon runs "
            "non-interactively. Run `ifolder-sync auth` in a terminal to validate "
            "the code and trust the session; then `start` connects on its own."
        )
    # Precedence matters: on a modern HSA2 account requires_2fa AND requires_2sa
    # are both True, and only the 2FA (idmsa) flow works. The legacy 2SA path
    # (send_verification_code) is only for HSA1 accounts (requires_2fa False).
    if api.requires_2fa:
        _prompt_2fa(api)
    else:
        _prompt_2sa(api)
    if not api.is_trusted_session:
        if not api.trust_session():
            print(
                "Warning: could not trust the session; the daemon may ask for 2FA again next time."
            )


# --- modern 2FA (HSA2 / idmsa) -------------------------------------------
def _auth_headers(api: PyiCloudService) -> dict[str, str]:
    return api._get_auth_headers({"Accept": "application/json"})


def _trigger_device_push(api: PyiCloudService) -> bool:
    """Raw fallback: ask Apple to PUSH a 6-digit code to trusted devices.
    Since ~iOS 26/2026 Apple no longer sends the code automatically on API
    logins. pyicloud >=2.5 owns this push (sent inside authenticate(), and
    re-requestable via the public request_2fa_code()); this raw PUT stays only
    as a fallback for upstreams that lack it. PUT asks, POST validates."""
    headers = _auth_headers(api)
    try:
        api.session.put(
            f"{api.auth_endpoint}/verify/trusteddevice/securitycode",
            headers=headers,
        )
        return True
    except PyiCloudAPIResponseException as exc_put:
        try:
            api.session.get(f"{api.auth_endpoint}/verify/trusteddevice", headers=headers)
            return True
        except PyiCloudAPIResponseException:
            print(f"(Warning: could not trigger the 2FA push: {exc_put})")
            return False


def _resend_push(api: PyiCloudService) -> bool:
    """Re-request the 2FA push. Prefer upstream's request_2fa_code() (it knows
    the active challenge type: trusted-device bridge, sms, security key);
    fall back to the raw PUT for upstreams that lack it."""
    try:
        return bool(api.request_2fa_code())
    except AttributeError:
        return _trigger_device_push(api)
    except Exception as exc:  # noqa: BLE001
        print(f"(Warning: could not re-request the 2FA push: {exc})")
        return False


def _prompt_2fa(api: PyiCloudService) -> None:
    # pyicloud >=2.5 already pushed the code inside authenticate(); pushing
    # again here would land a second, confusing prompt on the user's devices.
    print("\n== Apple two-factor verification (2FA) ==")
    print(
        "A 6-digit code request should appear NOW as a pop-up ('Sign-In Request')\n"
        "on your Apple devices signed into THIS account -- tap 'Allow' to see the\n"
        "6 digits (check Notification Center if it does not pop). It expires in\n"
        "~1 minute. If nothing arrived, use [r]esend or [s]ms."
    )
    _code_loop(api)


def _code_loop(api: PyiCloudService) -> None:
    """Interactive 2FA loop. Accepts the code OR commands: [r]esend push, [s]ms to
    a trusted phone, [d]iagnostics. Only CODE attempts count toward the limit."""
    channel = "device"
    sms_phone_id = None
    attempts, max_attempts = 0, 5
    while attempts < max_attempts:
        choice = input("2FA code | [r]esend push | [s]ms | [d]iag | Enter=cancel: ").strip()
        if not choice:
            raise RuntimeError("2FA cancelled by the user.")
        low = choice.lower()
        if low == "r":
            if _resend_push(api):
                print("Push resent to trusted devices.")
            else:
                print("Could not resend the push; try [s]ms.")
            channel = "device"
            continue
        if low == "s":
            phone_id = _choose_and_send_sms(api)
            if phone_id is not None:
                channel, sms_phone_id = "sms", phone_id
            continue
        if low == "d":
            print_diagnostics(api)
            continue

        code = choice
        if channel == "sms" and sms_phone_id is not None:
            ok = _validate_sms(api, sms_phone_id, code)
        else:
            ok = api.validate_2fa_code(code)
        if ok:
            print("Code accepted.")
            return
        attempts += 1
        if attempts < max_attempts:
            print(
                f"Invalid code (attempt {attempts}/{max_attempts}). "
                "If nothing arrived, try [r]esend or [s]ms."
            )
    raise RuntimeError(
        "2FA code invalid too many times. Run `ifolder-sync auth --fresh` to start over."
    )


# --- SMS to a trusted phone (fallback when the push does not arrive) ------
def _trusted_phone_numbers(api: PyiCloudService) -> list[dict]:
    try:
        resp = api.session.get(api.auth_endpoint, headers=_auth_headers(api))
        data = resp.json()
    except (PyiCloudAPIResponseException, ValueError):
        return []
    return _extract_phone_numbers(data)


def _extract_phone_numbers(data) -> list[dict]:
    """Extract trustedPhoneNumbers from the JSON. Apple has varied the nesting
    (2026 moved it under ...bridgeInitiateData...), so search the key recursively."""
    found: list[dict] = []

    def dig(node):
        if isinstance(node, dict):
            tpn = node.get("trustedPhoneNumbers")
            if isinstance(tpn, list):
                found.extend(tpn)
            for v in node.values():
                dig(v)
        elif isinstance(node, list):
            for v in node:
                dig(v)

    dig(data)
    out, seen = [], set()
    for p in found:
        if not isinstance(p, dict) or "id" not in p or p["id"] in seen:
            continue
        seen.add(p["id"])
        label = p.get("numberWithDialCode") or p.get("obfuscatedNumber") or f"phone #{p['id']}"
        out.append({"id": p["id"], "label": label})
    return out


def _choose_and_send_sms(api: PyiCloudService) -> Optional[int]:
    phones = _trusted_phone_numbers(api)
    if not phones:
        print("No trusted phone found on this account for SMS.")
        return None
    for i, p in enumerate(phones):
        print(f"  [{i}] {p['label']}")
    raw = input("Send SMS to which? [0]: ").strip() or "0"
    try:
        phone = phones[int(raw)]
    except (ValueError, IndexError):
        print("Invalid choice.")
        return None
    if _request_sms(api, phone["id"]):
        print(f"SMS sent to {phone['label']}. Type the code you received.")
        return phone["id"]
    print("Failed to send the SMS.")
    return None


def _request_sms(api: PyiCloudService, phone_id: int) -> bool:
    body = {"phoneNumber": {"id": phone_id}, "mode": "sms"}
    try:
        api.session.put(
            f"{api.auth_endpoint}/verify/phone",
            json=body,
            headers=_auth_headers(api),
        )
        return True
    except PyiCloudAPIResponseException as exc:
        print(f"(Warning sending SMS: {exc})")
        return False


def _validate_sms(api: PyiCloudService, phone_id: int, code: str) -> bool:
    body = {
        "phoneNumber": {"id": phone_id},
        "securityCode": {"code": code},
        "mode": "sms",
    }
    try:
        api.session.post(
            f"{api.auth_endpoint}/verify/phone/securitycode",
            json=body,
            headers=_auth_headers(api),
        )
    except PyiCloudAPIResponseException as exc:
        if str(getattr(exc, "code", "")) == str(APPLE_WRONG_CODE):
            return False
        print(f"(Warning validating SMS: {exc})")
        return False
    api.trust_session()
    return True


# --- diagnostics ----------------------------------------------------------
def print_diagnostics(api: PyiCloudService, include_phones: bool = True) -> None:
    """Print what Apple thinks the auth state is -- turns 'it doesn't work' into
    concrete signals (hsaVersion, 2fa/2sa flags, trusted phones)."""
    if api is None:
        print("(no connection)")
        return
    hsa = api.data.get("dsInfo", {}).get("hsaVersion", "?")
    print("\n-- Authentication diagnostics --")
    print(f"  hsaVersion:         {hsa}")
    print(f"  requires_2fa:       {api.requires_2fa}")
    print(f"  requires_2sa:       {api.requires_2sa}")
    print(f"  is_trusted_session: {api.is_trusted_session}")
    if include_phones:
        phones = _trusted_phone_numbers(api)
        if phones:
            print("  Trusted phones (SMS):")
            for p in phones:
                print(f"    - {p['label']}")
        else:
            print("  Trusted phones (SMS): none/unavailable")
    print("---------------------------------\n")


def _prompt_2sa(api: PyiCloudService) -> None:
    print("\n== Two-step verification (legacy 2SA) ==")
    devices = api.trusted_devices
    if not devices:
        raise RuntimeError("No trusted device available for 2SA.")
    for i, d in enumerate(devices):
        label = d.get("deviceName") or f"SMS to {d.get('phoneNumber', '?')}"
        print(f"  [{i}] {label}")
    idx = int(input("Device [0]: ").strip() or "0")
    device = devices[idx]
    if not api.send_verification_code(device):
        raise RuntimeError("Failed to send the verification code.")
    for attempt in range(3):
        code = input("Code received (empty = cancel): ").strip()
        if not code:
            raise RuntimeError("2SA cancelled by the user.")
        if api.validate_verification_code(device, code):
            print("Code accepted.")
            return
        remaining = 2 - attempt
        if remaining:
            print(f"Invalid code. Try again ({remaining} left).")
    raise RuntimeError("2SA code invalid 3 times.")
