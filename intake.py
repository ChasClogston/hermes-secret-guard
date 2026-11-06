"""The one way a secret comes in. Returns name, fingerprint and length; never the value."""

from __future__ import annotations

import getpass
import os
import sys
from typing import Optional

from . import dialog, keychain, registry


class IntakeError(RuntimeError):
    pass


def _account() -> str:
    return os.environ.get("USER") or getpass.getuser()


def intake(env: str, *, scope: Optional[str] = None, service: Optional[str] = None,
           kc: Optional[str] = None, stdin_test: bool = False, yes: bool = False) -> dict:
    """Take a value for ``env`` and store it.

    Normal path: a native dialog takes the value. ``stdin_test`` reads a value from stdin and is
    allowed ONLY together with a throwaway keychain (``kc``), so the test path can never write a
    real login-keychain entry.
    """
    env = registry.validate_env(env)
    scope = scope or registry.default_scope(env)
    if scope not in registry.SCOPES:
        raise IntakeError(f"scope must be one of {registry.SCOPES}")
    if env in registry.PLATFORM_BOT_ENVS and scope != "default-only":
        raise IntakeError(f"{env} is a messaging bot credential; it must be scope default-only "
                          "(a shared bot token in another profile blocks the multiplex gateway)")
    service = service or registry.service_for(env)
    account = _account()
    if kc is None:
        kc = registry.settings().get("keychain") or None  # dev/test override; unset in production
    if stdin_test and not kc:
        raise IntakeError("--stdin is for test keychains only; pass --keychain <path>")

    replace = False
    if keychain.exists(service, account, kc):
        if stdin_test:
            replace = yes
        else:
            replace = dialog.ask_replace(env)
        if not replace:
            raise IntakeError(f"kept the existing {env}; nothing written")

    if stdin_test:
        value = sys.stdin.readline()
    else:
        value = dialog.ask_value(env)
    if not value or not value.strip():
        raise IntakeError("cancelled or empty; nothing written")

    try:
        result = keychain.write_value(service, account, value, keychain=kc, replace=replace)
        registry.upsert(env, service=service, account=account, scope=scope,
                        fingerprint=result["fingerprint"], length=result["length"], keychain=kc)
        from . import guard
        guard.remember_entered(env, value.strip())  # protected from this turn on, not next restart
    except keychain.KeychainError as exc:
        raise IntakeError(str(exc)) from None
    finally:
        del value
    return {"env": env, "service": service, "scope": scope, "fingerprint": result["fingerprint"],
            "length": result["length"], "replaced": result["replaced"]}


def verify(env: str) -> dict:
    """Compare the keychain item (this plugin's own) and the value Hermes resolved for this profile
    against the registry's fingerprint. Runs only from the `hermes secret` CLI. Never returns a value."""
    entry = registry.load()["secrets"].get(env)
    if not entry:
        return {"env": env, "status": "not registered"}
    got = keychain.stored_fingerprint(entry["service"], entry["account"], entry.get("keychain"))
    if got is None:
        return {"env": env, "status": "missing from keychain"}
    fp, length = got
    if fp != entry.get("fingerprint"):
        return {"env": env, "status": "keychain differs from registry", "fingerprint": fp, "length": length}
    from .guard import _get_secret
    v = _get_secret(env)
    resolved = "not resolved in this profile" if not v else (
        "resolved" if keychain.fingerprint(v) == fp else "RESOLVED VALUE DIFFERS (stale .env line?)")
    del v
    return {"env": env, "status": "ok", "fingerprint": fp, "length": length, "hermes": resolved}
