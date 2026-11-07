"""`hermes secret ...` subcommands. Output is names, fingerprints and lengths only."""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path

from . import doctor, intake as _intake, keychain, migrate, registry


def register_cli(p: argparse.ArgumentParser) -> None:
    subs = p.add_subparsers(dest="secret_action")
    a = subs.add_parser("add", help="Add or replace a secret through a hidden dialog")
    a.add_argument("env", help="Env var name, e.g. GROQ_API_KEY")
    a.add_argument("--scope", choices=registry.SCOPES)
    a.add_argument("--service", help="Keychain service name (default hermes-<env>)")
    a.add_argument("--keychain", help=argparse.SUPPRESS)  # test keychains only
    a.add_argument("--stdin", action="store_true", help=argparse.SUPPRESS)
    a.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
    subs.add_parser("list", help="List guarded secrets (no values)")
    v = subs.add_parser("verify", help="Check a secret against the keychain and what Hermes resolved")
    v.add_argument("env")
    r = subs.add_parser("remove", help="Remove a secret from the keychain and the registry")
    r.add_argument("env")
    r.add_argument("--yes", action="store_true")
    im = subs.add_parser("import", help="Register keys named in an existing keychain helper script")
    im.add_argument("script", help="e.g. ~/.hermes/secrets-provider/keychain-secrets-env.sh")
    subs.add_parser("doctor", help="Read-only health check")
    p.set_defaults(func=secret_command)


def secret_command(args: argparse.Namespace) -> int:
    act = getattr(args, "secret_action", None)
    if act == "add":
        try:
            res = _intake.intake(args.env, scope=args.scope, service=args.service, kc=args.keychain,
                                 stdin_test=args.stdin, yes=args.yes)
        except (_intake.IntakeError, ValueError) as exc:
            print(f"secret-guard: {exc}")
            return 1
        print(f"Saved {res['env']} ({res['service']}, scope {res['scope']})"
              + (", replacing the old entry" if res["replaced"] else ""))
        print(f"fingerprint {res['fingerprint']}  length {res['length']}")
        print("Profiles pick it up at their next start.")
        return 0
    if act == "list":
        secrets = registry.load()["secrets"]
        if not secrets:
            print("No guarded secrets yet. Add one with: hermes secret add <ENV_VAR>")
            return 0
        for env, e in sorted(secrets.items()):
            print(f"{env:32} {e['scope']:13} fp {e['fingerprint']}  len {e['length']:>4}  {e['service']}")
        return 0
    if act == "verify":
        res = _intake.verify(args.env)
        print(" ".join(f"{k}={v}" for k, v in res.items()))
        return 0 if res.get("status") == "ok" else 1
    if act == "remove":
        entry = registry.load()["secrets"].get(args.env)
        if not entry:
            print(f"{args.env} is not registered")
            return 1
        if not args.yes:
            print(f"This deletes {args.env} ({entry['service']}) from the keychain. Re-run with --yes to confirm.")
            return 1
        keychain.delete(entry["service"], entry["account"], entry.get("keychain"))
        registry.remove(args.env)
        print(f"Removed {args.env}")
        return 0
    if act == "import":
        pairs = migrate.parse_existing_helper(Path(os.path.expanduser(args.script)))
        acct = os.environ.get("USER") or getpass.getuser()
        kc = registry.settings().get("keychain")
        n = 0
        for service, env in pairs:
            got = keychain.stored_fingerprint(service, acct, kc)
            if not got:
                print(f"skip {env}: {service} not in keychain")
                continue
            registry.upsert(env, service=service, account=acct, scope=registry.default_scope(env),
                            fingerprint=got[0], length=got[1], keychain=kc)
            print(f"registered {env:30} scope {registry.default_scope(env):13} fp {got[0]}")
            n += 1
        print(f"{n} imported. Run `hermes secret doctor` to see which profiles still get them from "
              "the old helper; turn that helper off once every profile resolves them from Secret Guard.")
        return 0
    if act == "doctor":
        return doctor.run()
    print("usage: hermes secret {add,list,verify,remove,import,doctor} ...")
    return 1
