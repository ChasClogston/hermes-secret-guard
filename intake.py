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


def _state(env: str, service: str, account: str, kc: Optional[str]) -> dict:
    """Snapshot of everything a decision depends on. Raises KeychainError on unreadable state."""
    entry = registry.load()["secrets"].get(env)
    return {"entry": entry,
            "final": keychain.exists(service, account, kc),
            "stage": keychain.exists(keychain.staging_name(service), account, kc)}


def _plan(env: str, service: str, account: str, kc: Optional[str], scope_arg: Optional[str], st: dict):
    """Decide add vs replace, or refuse, BEFORE any change. Replace is supported only for an item
    already registered to this env var with the same service and keychain, keeping its scope; that
    is the case recovery can always finish (see recover)."""
    entry = st["entry"]
    if st["stage"] or (entry and entry.get("pending")):
        raise IntakeError(f"an unfinished replace of {env} is pending; run `hermes secret recover {env}` "
                          f"(or `hermes secret recover {env} --discard` to cancel it) first. Nothing was changed.")
    if not st["final"]:
        if entry and (entry["service"], entry.get("keychain")) != (service, kc):
            raise IntakeError(f"{env} is registered to {entry['service']}; remove it first to move it. "
                              "Nothing was changed.")
        return "add", scope_arg or (entry or {}).get("scope") or registry.default_scope(env)
    if not entry or (entry["service"], entry["account"], entry.get("keychain")) != (service, account, kc):
        raise IntakeError(f"a keychain item named {service} already exists but is not registered to {env}. "
                          "If it is yours, register it first with `hermes secret import <helper script>`, or "
                          "choose another name with --service. Nothing was changed.")
    if scope_arg and scope_arg != entry["scope"]:
        raise IntakeError(f"{env} is registered with scope {entry['scope']}; to change scope, remove it and add "
                          "it again. Nothing was changed.")
    return "replace", entry["scope"]


def intake(env: str, *, scope: Optional[str] = None, service: Optional[str] = None,
           kc: Optional[str] = None, stdin_test: bool = False, yes: bool = False) -> dict:
    """Take a value for ``env`` and store it.

    Normal path: a native dialog takes the value. ``stdin_test`` reads a value from stdin and is
    allowed ONLY together with a throwaway keychain (``kc``), so the test path can never write a
    real login-keychain entry. The dialog runs before the mutation lock (a person typing never
    blocks other changes); state is re-checked under the lock before anything changes.
    """
    env = registry.validate_env(env)
    if scope is not None and scope not in registry.SCOPES:
        raise IntakeError(f"scope must be one of {registry.SCOPES}")
    entry0 = registry.load()["secrets"].get(env)
    service = service or (entry0 or {}).get("service") or registry.service_for(env)
    try:
        keychain.validate_service(service)
    except keychain.KeychainError as exc:
        raise IntakeError(str(exc)) from None
    account = (entry0 or {}).get("account") or _account()
    if kc is None:
        kc = (entry0 or {}).get("keychain") or registry.settings().get("keychain") or None
    if stdin_test and not kc:
        raise IntakeError("--stdin is for test keychains only; pass --keychain <path>")

    try:
        st0 = _state(env, service, account, kc)
        mode, eff_scope = _plan(env, service, account, kc, scope, st0)
    except keychain.KeychainError as exc:
        raise IntakeError(str(exc)) from None
    if env in registry.PLATFORM_BOT_ENVS and eff_scope != "default-only":
        raise IntakeError(f"{env} is a messaging bot credential; it must be scope default-only "
                          "(a shared bot token in another profile blocks the multiplex gateway)")
    if mode == "replace" and not (yes if stdin_test else dialog.ask_replace(env)):
        raise IntakeError(f"kept the existing {env}; nothing written")

    value = sys.stdin.readline() if stdin_test else dialog.ask_value(env)
    if not value or not value.strip():
        raise IntakeError("cancelled or empty; nothing written")

    protected_now = False
    staging_left = False
    try:
        with registry.mutation_lock():
            st = _state(env, service, account, kc)
            if (st["final"], st["stage"], bool(st["entry"]), (st["entry"] or {}).get("fingerprint")) != \
               (st0["final"], st0["stage"], bool(st0["entry"]), (st0["entry"] or {}).get("fingerprint")):
                raise IntakeError(f"{env} changed while you were entering the value; nothing was written, "
                                  "try again")
            clean = keychain.validate_value(value)
            fp_new, len_new = keychain.fingerprint(clean), len(clean)
            del clean
            if mode == "replace":
                registry.set_pending(env, fp_new, len_new)   # intent first; no keychain change yet
            try:
                result = keychain.write_value(service, account, value, keychain=kc, replace=(mode == "replace"))
            except keychain.KeychainError:
                if mode == "replace":
                    staged = keychain.stored_fingerprint(keychain.staging_name(service), account, kc)
                    if not (staged and staged[0] == fp_new):
                        registry.clear_pending(env)          # no verified copy: nothing to recover
                raise
            try:
                registry.upsert(env, service=service, account=account, scope=eff_scope,
                                fingerprint=result["fingerprint"], length=result["length"], keychain=kc)
            except Exception as exc:
                if mode == "replace":
                    raise IntakeError(f"{env} was replaced in the keychain but the registry update failed "
                                      f"({type(exc).__name__}). Run `hermes secret recover {env}` to finish; "
                                      "no re-entry needed.") from None
                outcome = keychain.delete(service, account, kc)
                if outcome in ("deleted", "absent"):
                    raise IntakeError(f"couldn't record {env} in the registry ({type(exc).__name__}); "
                                      "the new keychain item was rolled back, nothing changed") from None
                raise IntakeError(f"couldn't record {env} in the registry ({type(exc).__name__}) AND couldn't "
                                  f"roll back the new keychain item {service} (outcome unknown). It may be "
                                  f"stored but unregistered: check {service} in Keychain Access.") from None
            if result["replaced"]:
                staging_left = keychain.clear_staging(service, account, kc) == "failed"
        from . import guard
        protected_now = guard.remember_entered(env, value.strip())
    except keychain.KeychainError as exc:
        raise IntakeError(str(exc)) from None
    except registry.RegistryBusy as exc:
        raise IntakeError(str(exc)) from None
    except OSError as exc:  # set_pending failed: it runs before any keychain change
        raise IntakeError(f"couldn't write the registry ({type(exc).__name__}); nothing was changed") from None
    finally:
        del value
    return {"env": env, "service": service, "scope": eff_scope, "fingerprint": result["fingerprint"],
            "length": result["length"], "replaced": result["replaced"], "protected_now": protected_now,
            "staging_left": staging_left}


def recover(env: str, *, yes: bool = False, discard: bool = False) -> dict:
    """Finish (or, with discard, cancel) an interrupted replace. Promotes a recovery copy only if it
    matches the pending record written before the replace began. Never prints or returns a value."""
    try:
        with registry.mutation_lock():
            entry = registry.load()["secrets"].get(env)
            if not entry:
                raise IntakeError(f"{env} is not registered; nothing to recover")
            svc, acct, kc = entry["service"], entry["account"], entry.get("keychain")
            staging = keychain.staging_name(svc)
            pending = entry.get("pending")
            staged = keychain.stored_fingerprint(staging, acct, kc)
            final = keychain.stored_fingerprint(svc, acct, kc)
            if discard:
                if final is None and staged is not None and not yes:
                    raise IntakeError(f"{env}: the recovery copy is the ONLY copy of the key (the main item is "
                                      "missing). Discarding deletes it; re-run with --discard --yes to confirm.")
                if staged is not None and keychain.clear_staging(svc, acct, kc) == "failed":
                    raise IntakeError(f"couldn't delete the recovery copy {staging} (outcome unknown); pending "
                                      "record kept")
                registry.clear_pending(env)
                return {"env": env, "status": "unfinished replace cancelled",
                        "fingerprint": (final or ("-",))[0]}
            if staged is None:
                if pending and final and final[0] == pending["fingerprint"]:
                    registry.upsert(env, service=svc, account=acct, scope=entry["scope"],
                                    fingerprint=final[0], length=final[1], keychain=kc)
                    return {"env": env, "status": "replace finished (registry committed)", "fingerprint": final[0]}
                if pending:
                    registry.clear_pending(env)
                    return {"env": env, "status": "cleared an attempt that never stored a verified copy; "
                                                  "the key was not replaced",
                            "fingerprint": (final or ("-",))[0]}
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
            if final and final[0] == staged[0]:
                registry.upsert(env, service=svc, account=acct, scope=entry["scope"],
                                fingerprint=staged[0], length=staged[1], keychain=kc)
            else:
                if not pending or pending.get("fingerprint") != staged[0]:
                    raise IntakeError(f"{env}: the recovery copy does not match a recorded replace, so it will not "
                                      f"be promoted. Cancel with `hermes secret recover {env} --discard`.")
                if not yes:
                    raise IntakeError(f"{env}: a verified recovery copy (fp {staged[0]}) is waiting to replace "
                                      f"{'the current item (fp ' + final[0] + ')' if final else 'a missing item'}. "
                                      "Re-run with --yes to finish the replace.")
                keychain.promote_staging(svc, acct, kc)
                registry.upsert(env, service=svc, account=acct, scope=entry["scope"],
                                fingerprint=staged[0], length=staged[1], keychain=kc)
            cleared = keychain.clear_staging(svc, acct, kc)
            return {"env": env, "status": "replace finished" + ("" if cleared != "failed" else
                    "; the recovery copy could not be removed (run recover again)"), "fingerprint": staged[0]}
    except (keychain.KeychainError, registry.RegistryBusy, OSError, ValueError) as exc:
        raise IntakeError(str(exc) if not isinstance(exc, OSError) else
                          f"registry update failed ({type(exc).__name__}); state kept, run recover again") from None


def verify(env: str) -> dict:
    """Compare the keychain item and the value Hermes resolved for this profile against the
    registry. Recovery state is checked first, even when the main item is missing. Runs only from
    the `hermes secret` CLI. Never returns a value."""
    entry = registry.load()["secrets"].get(env)
    if not entry:
        return {"env": env, "status": "not registered"}
    svc, acct, kc = entry["service"], entry["account"], entry.get("keychain")
    try:
        pending = bool(entry.get("pending")) or keychain.exists(keychain.staging_name(svc), acct, kc)
        got = keychain.stored_fingerprint(svc, acct, kc)
    except keychain.KeychainError:
        return {"env": env, "status": "couldn't read the keychain (locked or access denied)"}
    if pending:
        return {"env": env, "status": f"unfinished replace: run `hermes secret recover {env}`",
                **({"fingerprint": got[0], "length": got[1]} if got else {})}
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
