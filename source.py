"""Keychain secret source: Hermes's own route for getting Secret Guard's keys into each profile.

Hermes calls fetch(cfg, home_path) at startup for every profile that has this plugin enabled AND
`secrets.secret_guard.enabled: true` in its config.yaml (Hermes applies a source only when that key
is explicitly true), and again after plugin discovery. home_path tells us which profile is asking, so scope needs no
config: "all" secrets go to every profile, "default-only" ones (messaging bot tokens) only to the
root profile, which keeps the multiplex gateway's duplicate-credential preflight happy.

Rules this keeps (from agent.secret_sources.base): fetch never raises and never prompts; it
returns the mapping and never writes os.environ; the keychain is read through run_secret_cli
(argv only, minimal env, stdin closed so a prompting helper fails fast).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource, run_secret_cli

SECURITY = "/usr/bin/security"
_NAME_RE = re.compile(r"^[A-Za-z0-9._@-]+$")
_PER_ITEM_TIMEOUT = 10.0


def root_of(home_path: Path) -> Path:
    """The Hermes root for a profile home: <root>/profiles/<name> -> <root>; root -> itself."""
    home_path = Path(home_path)
    return home_path.parent.parent if home_path.parent.name == "profiles" else home_path


def is_root(home_path: Path) -> bool:
    return Path(home_path).parent.name != "profiles"


class KeychainSource(SecretSource):
    name = "secret_guard"
    label = "Secret Guard (macOS Keychain)"
    shape = "mapped"                      # the registry binds each env var to one keychain item
    override_existing_default = True      # the keychain is authoritative over a stale .env line
    remediation_hints = {
        ErrorKind.NOT_CONFIGURED: "No guarded secrets yet: run `hermes secret add <ENV_VAR>`.",
        ErrorKind.BINARY_MISSING: "Secret Guard needs macOS (/usr/bin/security).",
    }

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Resolve guarded secrets from the keychain (Hermes applies a source only when this is true)", "default": False},
            "override_existing": {"description": "Keychain values win over .env/shell values", "default": True},
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        try:
            if not Path(SECURITY).exists():
                return result.fail("macOS security tool not found", ErrorKind.BINARY_MISSING)
            reg = root_of(home_path) / "secret_guard" / "registry.json"
            if not reg.exists():
                return result  # nothing registered yet: not an error
            try:
                secrets = (json.loads(reg.read_text()) or {}).get("secrets") or {}
            except Exception:
                return result.fail("registry.json is unreadable", ErrorKind.INTERNAL)
            root = is_root(home_path)
            for env, e in sorted(secrets.items()):
                if not isinstance(e, dict):
                    continue
                if e.get("scope") == "default-only" and not root:
                    continue  # bot tokens stay with the root profile
                svc, acct, kc = e.get("service", ""), e.get("account", ""), e.get("keychain")
                if not (_NAME_RE.match(svc or "") and _NAME_RE.match(acct or "")):
                    result.warnings.append(f"{env}: bad keychain item name in registry; skipped")
                    continue
                argv = [SECURITY, "find-generic-password", "-w", "-s", svc, "-a", acct]
                if kc:
                    argv.append(str(kc))
                try:
                    proc = run_secret_cli(argv, timeout=_PER_ITEM_TIMEOUT)
                except Exception:
                    result.warnings.append(f"{env}: keychain read failed or timed out")
                    continue
                value = (proc.stdout or "").rstrip("\n")
                if proc.returncode != 0 or not value:
                    result.warnings.append(f"{env}: not in the keychain (run `hermes secret verify {env}`)")
                    continue
                result.secrets[env] = value
            return result
        except Exception as exc:  # fetch must never raise
            return result.fail(f"unexpected error: {type(exc).__name__}", ErrorKind.INTERNAL)
