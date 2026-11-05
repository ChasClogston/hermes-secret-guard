"""`hermes secret doctor`: read-only health check. Prints names, fingerprints and states only."""

from __future__ import annotations

from . import guard, helper, intake, keychain, registry


def run() -> int:
    bad = 0
    def say(ok, msg):
        nonlocal bad
        bad += ok is False
        print(("  ✓ " if ok else ("  ✗ " if ok is False else "  ! ")) + msg)

    print("Hermes hooks")
    try:
        from agent.redact import redact_sensitive_text, register_vault_redaction_value  # noqa: F401
        say(True, "agent.redact vault registry present (value redaction works)")
    except Exception:
        say(False, "agent.redact.register_vault_redaction_value is gone: a Hermes update moved it. "
                   "Value redaction falls back to the plugin's own transform hooks only.")

    print("Guarded secrets")
    secrets = registry.load()["secrets"]
    if not secrets:
        say(None, "none registered (hermes secret add <ENV_VAR>)")
    for env in sorted(secrets):
        r = intake.verify(env)
        say(r["status"] == "ok", f"{env}: {r['status']}" + (f" (fp {r['fingerprint']})" if r.get("fingerprint") else ""))
    if registry.settings().get("keychain"):
        say(None, "TEST KEYCHAIN OVERRIDE ACTIVE (secret_guard/settings.json). Never ship this.")

    print("Helper")
    if not secrets:
        say(None, "no helper needed yet")
    elif helper.is_current():
        say(True, f"{helper.helper_path()} matches the registry")
    else:
        say(False, "helper missing or stale: run `hermes secret helper`")

    print("Profile wiring")
    for name, state in helper.wiring_report():
        say(True if state == "ok" else (False if state.startswith("WRONG") else None), f"{name}: {state}")

    print("Guard self-test (synthetic commands, nothing runs)")
    for cmd, want in [("head -1 demo/app.env", True), ("security find-generic-password -s x -w", True),
                      ("printenv", True), ("ls ~/.hermes", False), ("cat README.md", False)]:
        got = guard.check_command(cmd) is not None
        say(got == want, f"{'blocks' if want else 'allows'}: {cmd}")
    s, n = guard.scrub("canary")  # cheap call path check
    say(True, "scrub path runs")

    print("\n" + ("All checks passed." if not bad else f"{bad} problem(s) found."))
    return 1 if bad else 0
