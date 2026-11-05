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


class KeychainError(RuntimeError):
    """A refusal or failure. Messages never contain the value."""


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
    if not keychain.startswith("/"):
        raise KeychainError("keychain must be an absolute path")
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
    r = subprocess.run([SECURITY, "find-generic-password", "-s", service, "-a", account, *_kc_args(keychain)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def read_value(service: str, account: str, keychain: Optional[str] = None) -> Optional[str]:
    """Return the stored value, or None. Callers must never print, log or return it to a model."""
    _check_names(service, account)
    r = subprocess.run([SECURITY, "find-generic-password", "-w", "-s", service, "-a", account, *_kc_args(keychain)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
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
    if exists(service, account, keychain):
        if not replace:
            del line
            raise KeychainError(f"{service} already exists; replace not confirmed; nothing written")
        r = subprocess.run([SECURITY, "delete-generic-password", "-s", service, "-a", account, *kc],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            del line
            raise KeychainError(f"couldn't remove the existing {service}; nothing written")
        replaced = True
    subprocess.run([SECURITY, "-i"], input=line, text=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    del line
    got = stored_fingerprint(service, account, keychain)
    if not got or got[0] != want:
        if replaced:
            raise KeychainError(f"WRITE FAILED after the old {service} was removed; the entry is now missing. "
                                "Add it again with the same value.")
        raise KeychainError(f"write failed; {service} was not saved")
    return {"service": service, "account": account, "fingerprint": want, "length": length, "replaced": replaced}


def delete(service: str, account: str, keychain: Optional[str] = None) -> bool:
    _check_names(service, account)
    r = subprocess.run([SECURITY, "delete-generic-password", "-s", service, "-a", account, *_kc_args(keychain)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0
