"""Canary: assert the pyicloud API surface ifolder-sync depends on.

Run weekly in CI against the LATEST in-range pyicloud (no credentials needed) so an
upstream release that moves or renames anything we touch fails here before a user
hits it. Every check below maps to a real call site in ifolder_sync/.
"""

from __future__ import annotations

import inspect
import sys

FAILURES: list[str] = []


def check(label: str, fn) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        FAILURES.append(f"{label}: {exc!r}")


def require(cond: bool, msg: str = "assertion failed") -> None:
    if not cond:
        raise AssertionError(msg)


def main() -> int:
    import pyicloud.const as const
    from pyicloud import PyiCloudService
    from pyicloud.exceptions import (  # noqa: F401  (import surface used by retry.py)
        PyiCloudAPIResponseException,
        PyiCloudFailedLoginException,
    )
    from pyicloud.services.drive import DriveNode, DriveService
    from pyicloud.utils import (  # noqa: F401  (import surface used by icloud_client.py)
        get_password_from_keyring,
        password_exists_in_keyring,
        store_password_in_keyring,
    )

    # connect(): constructor kwarg and the 2FA re-request used by [r]esend
    check(
        "PyiCloudService.__init__(cookie_directory=)",
        lambda: inspect.signature(PyiCloudService.__init__).parameters["cookie_directory"],
    )
    check("PyiCloudService.request_2fa_code", lambda: PyiCloudService.request_2fa_code)

    # refresh()/walk(): per-pass cache busting and the etag-cached traversal
    check("DriveService.refresh_root", lambda: DriveService.refresh_root)
    check(
        "DriveNode.get_children(force=)",
        lambda: inspect.signature(DriveNode.get_children).parameters["force"],
    )

    # upload-sets-mtime (invariant 6): the kwarg must still reach the contentws payload
    check(
        "send_file stamps mtime",
        lambda: require("mtime" in inspect.getsource(DriveService._update_contentws)),
    )

    # drive ops by relative path
    for name in ("upload", "mkdir", "open", "move_to_trash"):
        check(f"DriveNode.{name}", lambda n=name: getattr(DriveNode, n))
    for prop in ("size", "date_modified", "type", "name"):
        check(f"DriveNode.{prop} property", lambda p=prop: require(hasattr(DriveNode, p)))

    # _has_poisoned_session / status: session JSON keys
    check(
        "session keys session_token/trust_token",
        lambda: require(
            {"session_token", "trust_token"} <= set(const.HEADER_DATA.values()),
            f"HEADER_DATA values changed: {sorted(const.HEADER_DATA.values())}",
        ),
    )

    import importlib.metadata as im

    version = im.version("pyicloud")
    if FAILURES:
        print(f"CANARY FAILED against pyicloud {version}:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"canary OK against pyicloud {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
