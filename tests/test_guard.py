"""Self-contained block/allow matrix for Secret Guard.

Creates a throwaway HERMES_HOME and a throwaway keychain, stores a random canary through the
plugin's own write path, runs every check, then removes the keychain. Never touches ~/.hermes or
the login keychain.

    PYTHONPATH=~/.hermes/hermes-agent ~/.hermes/hermes-agent/venv/bin/python tests/test_guard.py
"""
import os, secrets, subprocess, sys, tempfile
from pathlib import Path

ROOT = tempfile.mkdtemp(prefix="secret-guard-test-")
TMP = os.path.join(ROOT, "profiles", "work")   # run as a NON-default profile on purpose
os.makedirs(TMP)
os.environ["HERMES_HOME"] = TMP            # before any Hermes import
KC = os.path.join(TMP, "test.keychain-db")
subprocess.run(["/usr/bin/security", "create-keychain", "-p", "throwaway", KC], check=True)
subprocess.run(["/usr/bin/security", "set-keychain-settings", KC], check=True)

# Load the plugin by path: Hermes installs it as "secret-guard", which is not an importable name.
import importlib.util
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("secret_guard", os.path.join(_root, "__init__.py"),
                                               submodule_search_locations=[_root])
_pkg = importlib.util.module_from_spec(_spec); sys.modules["secret_guard"] = _pkg; _spec.loader.exec_module(_pkg)
from secret_guard import guard, keychain, registry

ACCT = os.environ.get("USER", "test")
CANARY = secrets.token_hex(20)              # prefix-less: core regexes alone would miss it
res = keychain.write_value("hermes-sg-test-key", ACCT, CANARY, keychain=KC)
registry.upsert("SG_TEST_KEY", service="hermes-sg-test-key", account=ACCT, scope="all",
                fingerprint=res["fingerprint"], length=res["length"], keychain=KC)
BOT = "123456789:AA" + secrets.token_hex(17)
res_b = keychain.write_value("hermes-telegram-bot-token", ACCT, BOT, keychain=KC)
registry.upsert("TELEGRAM_BOT_TOKEN", service="hermes-telegram-bot-token", account=ACCT, scope="default-only",
                fingerprint=res_b["fingerprint"], length=res_b["length"], keychain=KC)
os.environ["SG_TEST_KEY"] = CANARY   # what Hermes resolves through the keychain source

fails = 0
def check(label, got, want):
    global fails
    ok = got == want
    fails += not ok
    print(("PASS " if ok else "FAIL ") + label + ("" if ok else f"  (got {got!r})"))

B = lambda c: guard.check_command(c, cwd="/tmp") is not None
H = "~/.hermes"
try:
    print("== registry is per root, not per profile")
    check("registry lives at the root", str(registry.registry_path()).startswith(os.path.realpath(ROOT) + "/secret_guard") or str(registry.registry_path()).startswith(ROOT + "/secret_guard"), True)

    print("== keychain secret source")
    from secret_guard.source import KeychainSource, root_of, is_root
    from agent.secret_sources.base import SecretSource
    src = KeychainSource()
    check("is a Hermes SecretSource", isinstance(src, SecretSource), True)
    check("name/shape", (src.name, src.shape), ("secret_guard", "mapped"))
    check("off unless explicitly enabled (Hermes convention)", src.is_enabled({}), False)
    check("on with enabled: true", src.is_enabled({"enabled": True}), True)
    check("root_of(profile) is the root", root_of(Path(TMP)) == Path(ROOT), True)
    check("profile is not root", is_root(Path(TMP)), False)
    r_prof = src.fetch({}, Path(TMP))
    r_root = src.fetch({}, Path(ROOT))
    check("fetch ok in a profile", r_prof.ok, True)
    check("profile gets the 'all' secret", r_prof.secrets.get("SG_TEST_KEY") == CANARY, True)
    check("profile does NOT get the default-only bot token", "TELEGRAM_BOT_TOKEN" in r_prof.secrets, False)
    check("root gets both", sorted(r_root.secrets) == ["SG_TEST_KEY", "TELEGRAM_BOT_TOKEN"], True)
    empty = src.fetch({}, Path(tempfile.mkdtemp()))
    check("no registry -> ok, nothing", (empty.ok, empty.secrets), (True, {}))
    r_prof.secrets.clear(); r_root.secrets.clear()

    print("== keychain write path")
    check("fingerprint round-trips", keychain.stored_fingerprint("hermes-sg-test-key", ACCT, KC)[0], res["fingerprint"])
    for bad in ["has space", 'quo"te', "back\\slash", "x" * 3950]:
        try:
            keychain.write_value("hermes-sg-bad", ACCT, bad, keychain=KC); got = "written"
        except keychain.KeychainError:
            got = "refused"
        check(f"refuses {bad[:12]!r}", got, "refused")
    try:
        keychain.write_value("hermes-sg-test-key", ACCT, "another-value-123", keychain=KC); got = "written"
    except keychain.KeychainError:
        got = "refused"
    check("refuses silent replace", got, "refused")

    print("== layer 1: block")
    BLOCK = [
        f"cat {H}/.env",
        "head -5 /Users/x/.hermes/profiles/a/.env",
        "grep KEY .env",
        f"tail {H}/config.yaml",
        f"cat {H}/auth.json",
        "less id_rsa",
        "base64 server.pem",
        f"python3 -c \"print(open('/Users/x/.hermes/.env').read())\"",
        "perl -ne 'print' ~/.openclaw/openclaw.json",
        "cd /tmp && cat my-secret.txt",
        "security find-generic-password -s hermes-groq-api-key -w",
        "security find-generic-password -ws foo",
        "security dump-keychain",
        f"source {H}/secrets-provider/keychain-secrets-env.sh",
        f"bash {H}/secrets-provider/keychain-secrets-env-noplatform.sh",
        f"{H}/secret_guard/emit-secrets.sh --root",
        f"sh {H}/secret_guard/emit-secrets.sh",
        "printenv",
        "env",
        "openclaw mcp show perplexity",
        "echo hi | cat - .env.local",
        f"x=$(cat {H}/.env)",
        "sudo cat /etc/ssl/private/site.pem",
        f"cp {H}/.env /tmp/x",
    ]
    for c in BLOCK:
        check("block  " + c, B(c), True)
    print("== layer 1: allow")
    for c in [f"ls {H}", "cat README.md", "cat tokenizer.py", "security find-generic-password -s x",
              "env FOO=1 python3 run.py", "printenv HOME", "cat ~/project/config.yaml",
              f"tail -20 {H}/logs/gateway.log", "echo token", "git status", "python3 -c 'print(1+1)'",
              "openclaw mcp doctor", "cat notes.txt", "sh ~/scripts/build.sh"]:
        check("allow  " + c, B(c), False)
    print("== layer 1: file tools")
    check("block  read_file .env", guard.on_pre_tool_call("read_file", {"path": H + "/.env"}) is not None, True)
    check("allow  read_file notes.md", guard.on_pre_tool_call("read_file", {"path": "~/notes.md"}), None)
    check("allow  web_search", guard.on_pre_tool_call("web_search", {"query": "cat .env"}), None)
    r = guard.on_pre_tool_call("terminal", {"command": f"cat {H}/.env"}) or {}
    check("block  returns action=block + message", r.get("action") == "block" and bool(r.get("message")), True)

    print("== layer 2: value redaction")
    out, hits = guard.scrub(f"a {CANARY} b {CANARY}")
    check("scrub removes value", CANARY not in out and hits == 2, True)
    check("scrub labels env", "[secret:SG_TEST_KEY redacted]" in out, True)
    check("transform: None when clean", guard.on_transform_tool_result(result="clean"), None)
    check("transform: rewrites when dirty", CANARY not in (guard.on_transform_terminal_output(output=CANARY) or CANARY), True)
    guard.register_values()
    from agent.redact import redact_sensitive_text
    check("core redactor scrubs registered value", CANARY not in redact_sensitive_text("v " + CANARY), True)
    orig = guard.scrub
    guard.scrub = lambda t: (_ for _ in ()).throw(RuntimeError("boom"))
    check("transform withholds on internal error", guard.on_transform_tool_result(result=CANARY), guard.WITHHELD)
    guard.scrub = orig

    del os.environ["SG_TEST_KEY"]
    check("unresolved secret is not scrubbed from memory it never had", "SG_TEST_KEY" in guard._load_values(), False)
    os.environ["SG_TEST_KEY"] = CANARY
    os.environ["SG_TEST_KEY"] = "a-different-value-xyz"
    check("resolved value with wrong fingerprint is ignored", "SG_TEST_KEY" in guard._load_values(), False)
    os.environ["SG_TEST_KEY"] = CANARY

    del os.environ["SG_TEST_KEY"]
    guard.remember_entered("SG_TEST_KEY", CANARY)
    check("value entered this session is scrubbed before any restart", guard.scrub("x " + CANARY)[1], 1)
    guard._entered.clear()
    os.environ["SG_TEST_KEY"] = CANARY

    print("== layer 3: inbound")
    blk = guard.on_pre_llm_call(user_message=f"my key {CANARY}") or {}
    check("block  pasted registered value", blk.get("action"), "block")
    check("block  message never holds the value", CANARY not in blk.get("message", ""), True)
    check("block  sk- key", (guard.on_pre_llm_call(user_message="sk-proj-" + "a1B2" * 8) or {}).get("action"), "block")
    check("block  telegram token", (guard.on_pre_llm_call(user_message="123456789:AA" + "x" * 33) or {}).get("action"), "block")
    check("block  multimodal parts", (guard.on_pre_llm_call(user_message=[{"type": "text", "text": "ghp_" + "A" * 36}]) or {}).get("action"), "block")
    m_cli = (guard.on_pre_llm_call(user_message=CANARY, platform="cli") or {}).get("message", "")
    m_tg = (guard.on_pre_llm_call(user_message=CANARY, platform="telegram") or {}).get("message", "")
    check("cli wording: never left this machine", "never left this machine" in m_cli, True)
    check("telegram wording: rotate it", "Telegram" in m_tg and "rotate" in m_tg, True)
    check("allow  ordinary message", guard.on_pre_llm_call(user_message="add my Groq key please"), None)
    check("allow  mentions sk- prefix", guard.on_pre_llm_call(user_message="OpenAI keys start with sk-"), None)
    print("== review fixes: gate covers every tool by argument name")
    blk = lambda tool, args: (guard.on_pre_tool_call(tool, args) or {}).get("action") == "block"
    check("block  unknown tool with a command arg", blk("custom_executor", {"command": f"cat {H}/.env"}), True)
    check("block  process_manage", blk("process_manage", {"command": "printenv"}), True)
    check("block  cronjob_manage scheduling a .env read", blk("cronjob_manage", {"command": f"cat {H}/.env"}), True)
    check("block  execute_code opening .env", blk("execute_code", {"code": "print(open('.env').read())"}), True)
    check("block  execute_code keychain print", blk("execute_code", {"code": "subprocess.run(['security','find-generic-password','-s','x','-w'])"}), True)
    check("block  browser_exec reading a token file", blk("browser_exec", {"js": "fs.readFileSync('/srv/app/api-token.txt')"}), True)
    check("block  vision tool on a key file", blk("vision_analyze", {"image_path": "/tmp/id_rsa"}), True)
    check("block  list of paths", blk("some_tool", {"paths": ["a.txt", f"{H}/.env"]}), True)
    check("allow  execute_code arithmetic", blk("execute_code", {"code": "print(1+1)"}), False)
    check("allow  query text mentioning .env", blk("web_search", {"query": "cat .env best practice"}), False)
    check("block  *secret*.log no longer exempt", guard.is_secret_path("production-secrets.log"), True)
    check("allow  README.md", guard.is_secret_path("README.md"), False)
    _orig = guard.check_tool_args
    guard.check_tool_args = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    r = guard.on_pre_tool_call("terminal", {"command": "ls " + CANARY}) or {}
    check("internal error fails closed", r.get("action"), "block")
    check("fail-closed message never echoes args", CANARY not in r.get("message", ""), True)
    guard.check_tool_args = _orig

    print("== review fixes: inbound shapes")
    check("block  single part dict", (guard.on_pre_llm_call(user_message={"type": "text", "text": CANARY}) or {}).get("action"), "block")
    check("block  tuple of parts", (guard.on_pre_llm_call(user_message=({"type": "text", "text": "x"}, CANARY)) or {}).get("action"), "block")

    print("== review fixes: entered values are per profile")
    del os.environ["SG_TEST_KEY"]
    _s = guard._scope
    guard._scope = lambda: "/profile/A"
    guard.remember_entered("SG_TEST_KEY", CANARY)
    in_a = "SG_TEST_KEY" in guard._load_values()
    guard._scope = lambda: "/profile/B"
    in_b = "SG_TEST_KEY" in guard._load_values()
    check("entered value visible in its own profile", in_a, True)
    check("entered value NOT visible in another profile", in_b, False)
    guard._scope = _s; guard._entered.clear()
    os.environ["SG_TEST_KEY"] = CANARY

    print("== known limits, asserted so the README stays honest")
    import base64
    b64 = base64.b64encode(CANARY.encode()).decode()
    check("LIMIT: base64 of a key is NOT scrubbed (documented)", guard.scrub("x " + b64)[1], 0)
    check("LIMIT: a key split in two is NOT scrubbed (documented)", guard.scrub(CANARY[:20])[1] + guard.scrub(CANARY[20:])[1], 0)
    from agent.redact import register_vault_redaction_value, redact_sensitive_text as _rst
    guard.register_values()
    for i in range(70):
        register_vault_redaction_value(f"browser-vault-filler-{i:03d}-{secrets.token_hex(6)}")
    check("64-cap: core registry evicted our key (documented)", CANARY in _rst("v " + CANARY), True)
    check("64-cap: plugin's own transform still scrubs it", CANARY not in (guard.on_transform_tool_result(result="v " + CANARY) or CANARY), True)
    guard.register_values()
    check("64-cap: next turn's re-registration restores core coverage", CANARY not in _rst("v " + CANARY), True)

    print("== review fixes: keychain safety")
    try:
        keychain.write_value("hermes-sg-x", ACCT, "abcdefgh12345", keychain='/tmp/bad"path.keychain-db'); got = "accepted"
    except keychain.KeychainError:
        got = "refused"
    check("keychain path with a quote refused", got, "refused")
    r2 = keychain.write_value("hermes-sg-test-key", ACCT, CANARY + "-v2", keychain=KC, replace=True)
    check("staged replace stores the new value", keychain.stored_fingerprint("hermes-sg-test-key", ACCT, KC)[0], r2["fingerprint"])
    check("staged replace cleans up the staging item", keychain.exists("hermes-sg-test-key.sg-staging", ACCT, KC), False)
    _sf = keychain.stored_fingerprint
    keychain.stored_fingerprint = lambda svc, a, k=None: None if svc.endswith(".sg-staging") else _sf(svc, a, k)
    try:
        keychain.write_value("hermes-sg-test-key", ACCT, "would-be-v3-value", keychain=KC, replace=True); got = "written"
    except keychain.KeychainError:
        got = "refused"
    keychain.stored_fingerprint = _sf
    check("failed staging leaves the existing entry untouched", (got, keychain.stored_fingerprint("hermes-sg-test-key", ACCT, KC)[0]), ("refused", r2["fingerprint"]))
    _sr = subprocess.run
    def _stall(*a, **k): raise subprocess.TimeoutExpired(a[0] if a else "security", 30)
    keychain.subprocess.run = _stall
    try:
        keychain.write_value("hermes-sg-y", ACCT, "abcdefgh12345", keychain=KC); got = "no error"
    except keychain.KeychainError:
        got = "clean KeychainError"
    keychain.subprocess.run = _sr
    check("stalled security call becomes a clean error", got, "clean KeychainError")

    print("== review fixes: registry and intake")
    import io, threading
    from secret_guard import intake
    _up = registry.upsert
    registry.upsert = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
    _stdin = sys.stdin; sys.stdin = io.StringIO("fresh-value-abcdef123\n")
    try:
        intake.intake("SG_ROLLBACK_KEY", kc=KC, stdin_test=True); got = "ok"
    except intake.IntakeError:
        got = "IntakeError"
    sys.stdin = _stdin; registry.upsert = _up
    check("registry failure -> clean error", got, "IntakeError")
    check("registry failure -> new keychain item rolled back", keychain.exists("hermes-sg-rollback-key", ACCT, KC), False)
    def _many(n):
        for i in range(10):
            registry.upsert(f"SG_RACE_{n}_{i}", service="hermes-x", account=ACCT, scope="all", fingerprint="0"*16, length=1)
    ts = [threading.Thread(target=_many, args=(n,)) for n in range(8)]
    [x.start() for x in ts]; [x.join() for x in ts]
    check("80 concurrent upserts all kept", len([k for k in registry.load()["secrets"] if k.startswith("SG_RACE_")]), 80)
    for k in [k for k in registry.load()["secrets"] if k.startswith("SG_RACE_")]:
        registry.remove(k)
    regp = registry.registry_path(); good = regp.read_text(); regp.write_text("{not json")
    bad = src.fetch({}, Path(TMP))
    check("malformed registry: fetch fails cleanly, never raises", (bad.ok, bool(bad.error)), (False, True))
    regp.write_text(good)
finally:
    subprocess.run(["/usr/bin/security", "delete-keychain", KC], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

print(f"\n{'ALL PASS' if not fails else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
