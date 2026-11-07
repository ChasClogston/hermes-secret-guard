"""macOS Keychain backend. A port of keychain-intake (Claude-MBP, 2026-09-30).

Rules this module keeps:
  - A value reaches `security` only on stdin (`security -i`), never in argv, so it never shows in ps.
  - Items are created by /usr/bin/security (-T), so headless readers get them without a prompt.
  - Replace is delete-then-add; `add -U` raised a SecurityAgent prompt in testing.
  - Values with whitespace, double quotes, backslashes or non-printables are refused, and an
    over-long value is refused BEFORE any existing entry is touched.
  - Nothing here logs or returns a value except read_value(), whose callers must not print it.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from typing import Optional

SECURITY = "/usr/bin/security"
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_ACCT_RE = re.compile(r"^[A-Za-z0-9._@-]+$")
_MAX_LINE = 4000  # security -i drops input lines near 4,096 bytes (measured 2026-09-30)
_KC_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
_TIMEOUT = 30  # seconds for any one `security` call; a stall becomes a clean failure


def _run(argv, **kw):
    """subprocess.run with a hard timeout; a timeout or launch failure becomes KeychainError."""
    try:
        return subprocess.run(argv, timeout=_TIMEOUT, **kw)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise KeychainError(f"keychain tool did not complete ({type(exc).__name__}); the outcome is unknown. "
                            "Run `hermes secret doctor` to check the item's state.") from None


class KeychainError(RuntimeError):
    """A refusal or failure. Messages never contain the value."""


STAGING_SUFFIX = ".sg-staging"
NOT_FOUND = 44  # `security` exit status for errSecItemNotFound (measured on macOS 2026-11-07)


def staging_name(service: str) -> str:
    return service + STAGING_SUFFIX


def validate_service(service: str) -> str:
    """For user-chosen service names: the staging suffix is reserved for recovery copies."""
    if service.endswith(STAGING_SUFFIX):
        raise KeychainError(f"service names ending in {STAGING_SUFFIX} are reserved for recovery copies")
    return service


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _check_names(service: str, account: str) -> None:
    if not _NAME_RE.match(service or ""):
        raise KeychainError("service name may use only letters, digits, . _ -")
    if not _ACCT_RE.match(account or ""):
        raise KeychainError("account name may use only letters, digits, . _ @ -")


def _kc_args(keychain: Optional[str]) -> list[str]:
    if not keychain:
        return []
    if not _KC_PATH_RE.match(keychain):
        # it is interpolated into the `security -i` command line, so only plain path characters
        raise KeychainError("keychain path must be absolute and use only letters, digits, . _ / -")
    return [keychain]


def validate_value(value: str) -> str:
    """Trim paste whitespace and refuse values `security -i` cannot carry safely."""
    if not isinstance(value, str):
        raise KeychainError("no value")
    value = value.strip()
    if not value:
        raise KeychainError("empty value; nothing written")
    if re.search(r'[\s"\\]', value):
        raise KeychainError("value contains whitespace, a double quote or a backslash; nothing written")
    if any(not ch.isprintable() for ch in value):
        raise KeychainError("value contains non-printable characters; nothing written")
    return value


def exists(service: str, account: str, keychain: Optional[str] = None) -> bool:
    _check_names(service, account)
    r = _run([SECURITY, "find-generic-password", "-s", service, "-a", account, *_kc_args(keychain)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode == 0:
        return True
    if r.returncode == NOT_FOUND:
        return False
    raise KeychainError(f"couldn't check whether {service} exists (security exit {r.returncode}); "
                        "the keychain may be locked")


def read_value(service: str, account: str, keychain: Optional[str] = None) -> Optional[str]:
    """Return the stored value, or None ONLY when the item is verifiably absent (exit 44). Any other
    failure (locked, denied, timeout) raises KeychainError, so "unreadable" is never reported as
    "missing". Callers must never print, log or return the value to a model."""
    _check_names(service, account)
    r = _run([SECURITY, "find-generic-password", "-w", "-s", service, "-a", account, *_kc_args(keychain)],
                       capture_output=True, text=True)
    if r.returncode == NOT_FOUND:
        return None
    if r.returncode != 0:
        raise KeychainError(f"couldn't read {service} (security exit {r.returncode}); the keychain may be "
                            "locked or access was denied")
    return r.stdout.rstrip("\n")


def stored_fingerprint(service: str, account: str, keychain: Optional[str] = None) -> Optional[tuple[str, int]]:
    v = read_value(service, account, keychain)
    if v is None:
        return None
    out = (fingerprint(v), len(v))
    del v
    return out


def write_value(service: str, account: str, value: str, *, keychain: Optional[str] = None,
                replace: bool = False) -> dict:
    """Write a value. Returns {service, account, fingerprint, length, replaced}. Never returns the value."""
    _check_names(service, account)
    kc = _kc_args(keychain)
    value = validate_value(value)
    want, length = fingerprint(value), len(value)
    kcq = f' "{kc[0]}"' if kc else ""
    line = f'add-generic-password -s "{service}" -a "{account}" -T {SECURITY} -w "{value}"{kcq}\n'
    del value
    if len(line) > _MAX_LINE:
        del line
        raise KeychainError(f"value is too long ({length} chars; limit is about 3,900); nothing written")
    replaced = False
    staging = staging_name(service)
    if exists(service, account, keychain):
        if not replace:
            del line
            raise KeychainError(f"{service} already exists; replace not confirmed; nothing written")
        if exists(staging, account, keychain):
            del line
            raise KeychainError(f"an unfinished replace left a recovery copy ({staging}); run "
                                "`hermes secret recover <ENV_VAR>` first. Nothing was changed.")
        # Stage first: write the new value under the reserved recovery name and verify it, so a value
        # `security` cannot store is caught BEFORE the old entry is deleted. The stage is NOT removed
        # here; the caller removes it only after the registry has committed (clear_staging).
        _run([SECURITY, "-i"], input=line.replace(f'-s "{service}"', f'-s "{staging}"', 1), text=True,
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        staged = stored_fingerprint(staging, account, keychain)
        if not staged or staged[0] != want:
            outcome = delete(staging, account, keychain)
            del line
            raise KeychainError(f"the new value could not be stored; the existing {service} is unchanged"
                                + ("" if outcome != "failed" else f" (a partial {staging} may remain)"))
        if delete(service, account, keychain) != "deleted":
            del line
            raise KeychainError(f"couldn't remove the existing {service}; it is unchanged. A verified copy "
                                f"of the new value is in {staging}: run `hermes secret recover <ENV_VAR>`.")
        replaced = True
    _run([SECURITY, "-i"], input=line, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    del line
    got = stored_fingerprint(service, account, keychain)
    if not got or got[0] != want:
        if replaced:
            raise KeychainError(f"WRITE FAILED after the old {service} was removed. The new value is safe in "
                                f"{staging}; run `hermes secret recover <ENV_VAR>` to finish (no re-entry needed).")
        raise KeychainError(f"write failed; {service} was not saved")
    return {"service": service, "account": account, "fingerprint": want, "length": length,
            "replaced": replaced, "staging": staging if replaced else None}


def clear_staging(service: str, account: str, keychain: Optional[str] = None) -> str:
    return delete(staging_name(service), account, keychain)


def promote_staging(service: str, account: str, keychain: Optional[str] = None) -> dict:
    """Finish an interrupted replace: copy the verified recovery copy into the final item. The
    recovery copy is kept; the caller clears it after the registry commits."""
    staging = staging_name(service)
    value = read_value(staging, account, keychain)
    if not value:
        raise KeychainError(f"no recovery copy ({staging}) to restore from")
    fp_, length = fingerprint(value), len(value)
    kc = _kc_args(keychain)
    kcq = f' "{kc[0]}"' if kc else ""
    line = f'add-generic-password -s "{service}" -a "{account}" -T {SECURITY} -w "{value}"{kcq}\n'
    del value
    if exists(service, account, keychain) and delete(service, account, keychain) != "deleted":
        del line
        raise KeychainError(f"couldn't remove the current {service}; recovery copy kept")
    _run([SECURITY, "-i"], input=line, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    del line
    got = stored_fingerprint(service, account, keychain)
    if not got or got[0] != fp_:
        raise KeychainError(f"restore failed; the recovery copy {staging} is kept, try again")
    return {"fingerprint": fp_, "length": length}


def delete(service: str, account: str, keychain: Optional[str] = None) -> str:
    """Returns "deleted", "absent" (verified not found) or "failed" (locked, denied, timed out...)."""
    _check_names(service, account)
    try:
        r = _run([SECURITY, "delete-generic-password", "-s", service, "-a", account, *_kc_args(keychain)],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except KeychainError:
        return "failed"
    if r.returncode == 0:
        return "deleted"
    return "absent" if r.returncode == NOT_FOUND else "failed"
