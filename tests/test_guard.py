"""Self-contained block/allow matrix for Secret Guard.

Creates a throwaway HERMES_HOME and a throwaway keychain, stores a random canary through the
plugin's own write path, runs every check, then removes the keychain. Never touches ~/.hermes or
the login keychain.

    PYTHONPATH=~/.hermes/hermes-agent ~/.hermes/hermes-agent/venv/bin/python tests/test_guard.py
"""
import os, secrets, subprocess, sys, tempfile

TMP = tempfile.mkdtemp(prefix="secret-guard-test-")
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
os.environ["SG_TEST_KEY"] = CANARY   # what Hermes's secrets.command would have resolved

fails = 0
def check(label, got, want):
    global fails
    ok = got == want
    fails += not ok
    print(("PASS " if ok else "FAIL ") + label + ("" if ok else f"  (got {got!r})"))

B = lambda c: guard.check_command(c, cwd="/tmp") is not None
H = "~/.hermes"
try:
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

    print("== layer 3: inbound")
    blk = guard.on_pre_llm_call(user_message=f"my key {CANARY}") or {}
    check("block  pasted registered value", blk.get("action"), "block")
    check("block  message never holds the value", CANARY not in blk.get("message", ""), True)
    check("block  sk- key", (guard.on_pre_llm_call(user_message="sk-proj-" + "a1B2" * 8) or {}).get("action"), "block")
    check("block  telegram token", (guard.on_pre_llm_call(user_message="123456789:AA" + "x" * 33) or {}).get("action"), "block")
    check("block  multimodal parts", (guard.on_pre_llm_call(user_message=[{"type": "text", "text": "ghp_" + "A" * 36}]) or {}).get("action"), "block")
    check("allow  ordinary message", guard.on_pre_llm_call(user_message="add my Groq key please"), None)
    check("allow  mentions sk- prefix", guard.on_pre_llm_call(user_message="OpenAI keys start with sk-"), None)
finally:
    subprocess.run(["/usr/bin/security", "delete-keychain", KC], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

print(f"\n{'ALL PASS' if not fails else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
