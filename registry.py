"""Registry of guarded secrets: names, env vars, scope. Never holds a value.

Stored at <HERMES_HOME>/secret_guard/registry.json, mode 600.
scope: "all"          every profile resolves it
       "default-only" only the root profile (messaging bot tokens: a shared bot credential in a
                      non-default profile blocks the multiplex gateway; ISSUE-168)
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Optional

SCOPES = ("all", "default-only")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,80}$")
# Bot credentials that must never resolve in more than one profile.
PLATFORM_BOT_ENVS = frozenset({"TELEGRAM_BOT_TOKEN", "DISCORD_BOT_TOKEN", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"})


def _home() -> Path:
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")


def registry_path() -> Path:
    return _home() / "secret_guard" / "registry.json"


def service_for(env: str) -> str:
    return "hermes-" + env.lower().replace("_", "-")


def validate_env(env: str) -> str:
    if not _ENV_RE.match(env or ""):
        raise ValueError("env var name must be UPPER_SNAKE_CASE, e.g. GROQ_API_KEY")
    return env


def default_scope(env: str) -> str:
    return "default-only" if env in PLATFORM_BOT_ENVS else "all"


def load() -> dict:
    p = registry_path()
    if not p.exists():
        return {"version": 1, "secrets": {}}
    data = json.loads(p.read_text())
    data.setdefault("secrets", {})
    return data


def save(data: dict) -> None:
    p = registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(p.parent, 0o700)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".registry.", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def upsert(env: str, *, service: str, account: str, scope: str, fingerprint: str, length: int,
           keychain: Optional[str] = None) -> dict:
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {SCOPES}")
    data = load()
    entry = {"env": env, "service": service, "account": account, "scope": scope,
             "fingerprint": fingerprint, "length": length}
    if keychain:
        entry["keychain"] = keychain
    data["secrets"][env] = entry
    save(data)
    return entry


def remove(env: str) -> bool:
    data = load()
    if env not in data["secrets"]:
        return False
    del data["secrets"][env]
    save(data)
    return True


def settings() -> dict:
    """Optional <HERMES_HOME>/secret_guard/settings.json. Only key today: "keychain", an absolute
    path to a test keychain that every write goes to instead of the login keychain."""
    p = registry_path().parent / "settings.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except Exception:
        return {}
    kc = data.get("keychain")
    if kc is not None and not (isinstance(kc, str) and kc.startswith("/")):
        return {}
    return data
