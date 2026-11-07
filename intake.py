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
    real login-keychain entry. Keychain and registry are changed under one per-item lock; on a
    replace, the verified recovery copy is removed only after the registry has committed.
    """
    env = registry.validate_env(env)
    scope = scope or registry.default_scope(env)
    if scope not in registry.SCOPES:
        raise IntakeError(f"scope must be one of {registry.SCOPES}")
    if env in registry.PLATFORM_BOT_ENVS and scope != "default-only":
        raise IntakeError(f"{env} is a messaging bot credential; it must be scope default-only "
                          "(a shared bot token in another profile blocks the multiplex gateway)")
    service = service or registry.service_for(env)
    try:
        keychain.validate_service(service)
    except keychain.KeychainError as exc:
        raise IntakeError(str(exc)) from None
    account = _account()
    if kc is None:
        kc = registry.settings().get("keychain") or None  # dev/test override; unset in production
    if stdin_test and not kc:
        raise IntakeError("--stdin is for test keychains only; pass --keychain <path>")

    with registry.op_lock(service):
        try:
            if keychain.exists(keychain.staging_name(service), account, kc):
                raise IntakeError(f"an unfinished replace of {env} left a recovery copy; run "
                                  f"`hermes secret recover {env}` first. Nothing was changed.")
            replace = False
            if keychain.exists(service, account, kc):
                replace = yes if stdin_test else dialog.ask_replace(env)
                if not replace:
                    raise IntakeError(f"kept the existing {env}; nothing written")
        except keychain.KeychainError as exc:
            raise IntakeError(str(exc)) from None

        value = sys.stdin.readline() if stdin_test else dialog.ask_value(env)
        if not value or not value.strip():
            raise IntakeError("cancelled or empty; nothing written")

        protected_now = False
        staging_left = False
        try:
            result = keychain.write_value(service, account, value, keychain=kc, replace=replace)
            try:
                registry.upsert(env, service=service, account=account, scope=scope,
                                fingerprint=result["fingerprint"], length=result["length"], keychain=kc)
            except Exception as exc:
                if result["replaced"]:
                    # The recovery copy is still there (cleared only after a commit), so nothing is lost.
                    raise IntakeError(f"{env} was replaced in the keychain but the registry update failed "
                                      f"({type(exc).__name__}). Run `hermes secret recover {env}` to finish; "
                                      "no re-entry needed.") from None
                outcome = keychain.delete(service, account, kc)
                if outcome in ("deleted", "absent"):
                    raise IntakeError(f"couldn't record {env} in the registry ({type(exc).__name__}); "
                                      "the new keychain item was rolled back, nothing changed") from None
                raise IntakeError(f"couldn't record {env} in the registry ({type(exc).__name__}) AND couldn't "
                                  f"roll back the new keychain item {service}. It is stored but unregistered: "
                                  f"run `hermes secret add {env}` again, or delete {service} in Keychain "
                                  "Access.") from None
            if result["replaced"]:
                staging_left = keychain.clear_staging(service, account, kc) == "failed"
            from . import guard
            protected_now = guard.remember_entered(env, value.strip())
        except keychain.KeychainError as exc:
            raise IntakeError(str(exc)) from None
        finally:
            del value
    return {"env": env, "service": service, "scope": scope, "fingerprint": result["fingerprint"],
            "length": result["length"], "replaced": result["replaced"], "protected_now": protected_now,
            "staging_left": staging_left}


def recover(env: str, *, yes: bool = False) -> dict:
    """Finish an interrupted replace from its verified recovery copy, with no re-entry of the value.
    Completing the intended replace means the recovery copy becomes the item and the registry
    records its fingerprint. Never prints or returns a value."""
    entry = registry.load()["secrets"].get(env)
    if not entry:
        raise IntakeError(f"{env} is not registered; nothing to recover")
    svc, acct, kc = entry["service"], entry["account"], entry.get("keychain")
    with registry.op_lock(svc):
        try:
            staging = keychain.staging_name(svc)
            staged = keychain.stored_fingerprint(staging, acct, kc)
            final = keychain.stored_fingerprint(svc, acct, kc)
            if not staged:
                if final and final[0] == entry.get("fingerprint"):
                    return {"env": env, "status": "nothing to recover", "fingerprint": final[0]}
                if final:
                    if not yes:
                        raise IntakeError(f"{env}: the keychain item no longer matches the registry. Re-run with "
                                          "--yes to record the keychain item's fingerprint.")
                    registry.upsert(env, service=svc, account=acct, scope=entry["scope"],
                                    fingerprint=final[0], length=final[1], keychain=kc)
                    return {"env": env, "status": "registry re-synced to keychain", "fingerprint": final[0]}
                raise IntakeError(f"{env}: no keychain item and no recovery copy; add it again")
            if not (final and final[0] == staged[0]):
                if not yes:
                    raise IntakeError(f"{env}: a recovery copy (fp {staged[0]}) is waiting to replace "
                                      f"{'the current item (fp ' + final[0] + ')' if final else 'a missing item'}. "
                                      "Re-run with --yes to finish the replace.")
                keychain.promote_staging(svc, acct, kc)
            registry.upsert(env, service=svc, account=acct, scope=entry["scope"],
                            fingerprint=staged[0], length=staged[1], keychain=kc)
            cleared = keychain.clear_staging(svc, acct, kc)
        except keychain.KeychainError as exc:
            raise IntakeError(str(exc)) from None
    return {"env": env, "status": "replace finished" + ("" if cleared != "failed" else
            "; the recovery copy could not be removed (run recover again)"), "fingerprint": staged[0]}


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
    try:
        pending = keychain.exists(keychain.staging_name(entry["service"]), entry["account"], entry.get("keychain"))
    except keychain.KeychainError:
        return {"env": env, "status": "couldn't check for a recovery copy (keychain locked?)", "fingerprint": fp,
                "length": length}
    if pending:
        return {"env": env, "status": f"unfinished replace: run `hermes secret recover {env}`",
                "fingerprint": fp, "length": length}
    if fp != entry.get("fingerprint"):
        return {"env": env, "status": "keychain differs from registry", "fingerprint": fp, "length": length}
    from .guard import _get_secret
    v = _get_secret(env)
    resolved = "not resolved in this profile" if not v else (
        "resolved" if keychain.fingerprint(v) == fp else "RESOLVED VALUE DIFFERS (stale .env line?)")
    del v
    return {"env": env, "status": "ok", "fingerprint": fp, "length": length, "hermes": resolved}
