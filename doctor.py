"""`hermes secret doctor`: read-only health check. Prints names, counts, fingerprints and states only."""

from __future__ import annotations

from pathlib import Path

from . import guard, intake, keychain, migrate, registry
from .source import KeychainSource, is_root

PLUGIN = "secret-guard"


def _profiles(root: Path) -> list[tuple[str, Path]]:
    out = [("default", root)]
    pdir = root / "profiles"
    if pdir.is_dir():
        out += sorted((p.name, p) for p in pdir.iterdir() if (p / "config.yaml").exists())
    return out


def _load_cfg(home: Path) -> dict:
    import yaml
    try:
        return yaml.safe_load((home / "config.yaml").read_text()) or {}
    except Exception:
        return {}


def _plugin_state(home: Path, cfg: dict) -> str:
    installed = (home / "plugins" / PLUGIN).is_dir()
    enabled_list = ((cfg.get("plugins") or {}).get("enabled") or [])
    enabled = PLUGIN in enabled_list if isinstance(enabled_list, list) else False
    if not installed:
        return "not installed"
    return "enabled" if enabled else "installed, not enabled"


def run() -> int:
    bad = 0

    def say(ok, msg):
        nonlocal bad
        bad += ok is False
        print(("  ✓ " if ok else ("  ✗ " if ok is False else "  ! ")) + msg)

    print("Hermes surfaces")
    try:
        from agent.secret_sources.base import SecretSource  # noqa: F401
        say(True, "secret source API present (keys reach profiles through Hermes)")
    except Exception:
        say(False, "agent.secret_sources is missing: this Hermes is too old for Secret Guard")
    try:
        from agent.redact import register_vault_redaction_value  # noqa: F401
        say(True, "exact-value redaction registry present")
    except Exception:
        say(False, "agent.redact.register_vault_redaction_value is gone: a Hermes update moved it. "
                   "The plugin's own transform hooks still scrub tool results, terminal output and replies.")

    secrets = registry.load()["secrets"]
    print("Guarded secrets")
    if not secrets:
        say(None, "none registered (hermes secret add <ENV_VAR>)")
    for env in sorted(secrets):
        r = intake.verify(env)
        msg = f"{env}: {r['status']}" + (f" (fp {r['fingerprint']})" if r.get("fingerprint") else "")
        if r.get("hermes"):
            msg += f"; this profile: {r['hermes']}"
        say(r["status"] == "ok" and "DIFFERS" not in str(r.get("hermes")), msg)
    if registry.settings().get("keychain"):
        say(None, "TEST KEYCHAIN OVERRIDE ACTIVE (secret_guard/settings.json). Never ship this.")

    root = registry._home()
    src = KeychainSource()
    print("Profiles")
    for name, home in _profiles(root):
        cfg = _load_cfg(home)
        state = _plugin_state(home, cfg)
        sg_cfg = ((cfg.get("secrets") or {}).get("secret_guard") or {})
        if state != "enabled":
            say(None, f"{name}: plugin {state}; this profile gets no keys or protection from Secret Guard")
            continue
        if not src.is_enabled(sg_cfg):
            say(False, f"{name}: plugin enabled but its key source is off. Add to {name}'s config.yaml:  "
                       "secrets: {secret_guard: {enabled: true}}")
            continue
        want = {e for e, v in secrets.items() if v.get("scope") != "default-only" or is_root(home)}
        res = src.fetch(sg_cfg, home)
        got = set(res.secrets)
        res.secrets.clear()
        if not res.ok:
            say(False, f"{name}: key source failed ({res.error})")
            continue
        missing = sorted(want - got)
        say(not missing, f"{name}: resolves {len(got)}/{len(want)} guarded secret(s)"
            + (f"; missing {', '.join(missing)}" if missing else ""))
        cmd = ((cfg.get("secrets") or {}).get("command") or {})
        if cmd.get("enabled") and cmd.get("command"):
            path = Path(str(cmd["command"]).split()[0]).expanduser()
            if path.name == "emit-secrets.sh" and path.parent.name == "secret_guard":
                say(None, f"{name}: still wired to the Secret Guard 0.2 helper; remove its secrets.command block")
                continue
            overlap = []
            try:
                overlap = sorted({env for _, env in migrate.parse_existing_helper(path)} & set(secrets))
            except Exception:
                pass
            if overlap:
                say(None, f"{name}: secrets.command also supplies {len(overlap)} guarded var(s) "
                          f"({', '.join(overlap[:4])}{'…' if len(overlap) > 4 else ''}); the first source "
                          "Hermes asks wins. Turn it off once Secret Guard resolves them.")

    print("Guard self-test (synthetic commands, nothing runs)")
    for cmd_, want_ in [("head -1 demo/app.env", True), ("security find-generic-password -s x -w", True),
                        ("printenv", True), ("ls ~/.hermes", False), ("cat README.md", False)]:
        got_ = guard.check_command(cmd_) is not None
        say(got_ == want_, f"{'blocks' if want_ else 'allows'}: {cmd_}")

    print("\n" + ("All checks passed." if not bad else f"{bad} problem(s) found."))
    return 1 if bad else 0
