"""1.3 pattern layer and hold-and-release: synthetic data only.

Every key-shaped string here is built at run time from random bytes, so no realistic token is
committed to the repository. No keychain, no ~/.hermes: HERMES_HOME is a throwaway folder and the
"stored key" case replaces guard._load_values for the duration of one test.

    PYTHONPATH=~/.hermes/hermes-agent ~/.hermes/hermes-agent/venv/bin/python tests/test_patterns.py
"""
import base64, hashlib, json, os, secrets, string, sys, tempfile, unittest
from pathlib import Path

os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="secret-guard-patterns-")

import importlib.util
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("secret_guard", os.path.join(_root, "__init__.py"),
                                               submodule_search_locations=[_root])
_pkg = importlib.util.module_from_spec(_spec); sys.modules["secret_guard"] = _pkg; _spec.loader.exec_module(_pkg)
from secret_guard import detectors, guard

ALNUM = string.ascii_letters + string.digits


def rnd(n, alphabet=ALNUM):
    s = "".join(secrets.choice(alphabet) for _ in range(n))
    # make sure both letters and digits appear (the assigned-value rule requires it)
    return s if any(c.isdigit() for c in s) and any(c.isalpha() for c in s) else rnd(n, alphabet)


def hexs(n):
    return secrets.token_hex(n // 2)


with open(detectors._WORDLIST_PATH) as _f:
    WORDS = _f.read().split()


def mnemonic(n_words):
    ent_bits = n_words * 11 * 32 // 33
    ent = secrets.token_bytes(ent_bits // 8)
    cs_len = ent_bits // 32
    bits = (int.from_bytes(ent, "big") << cs_len) | (hashlib.sha256(ent).digest()[0] >> (8 - cs_len))
    return [WORDS[(bits >> (11 * (n_words - 1 - i))) & 2047] for i in range(n_words)]


def b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def keys():
    """One generated example per prefixed format."""
    return {
        "anthropic": "sk-" + "ant-api03-" + rnd(40, ALNUM + "_-"),
        "openai": "sk-" + "proj-" + rnd(40),
        "openrouter": "sk-" + "or-v1-" + hexs(64),
        "github": "gh" + "p_" + rnd(36),
        "github_pat": "github" + "_pat_" + rnd(60, ALNUM + "_"),
        "slack": "xox" + "b-" + rnd(30, ALNUM + "-"),
        "aws": "AK" + "IA" + rnd(16, string.ascii_uppercase + string.digits),
        "aws_temp": "AS" + "IA" + rnd(16, string.ascii_uppercase + string.digits),
        "google": "AI" + "za" + rnd(35, ALNUM + "_-"),
        "gitlab": "gl" + "pat-" + rnd(24),
        "hf": "hf" + "_" + rnd(34),
        "xai": "xa" + "i-" + rnd(40),
        "groq": "gs" + "k_" + rnd(40),
        "perplexity": "pp" + "lx-" + rnd(40),
        "telegram": "123456789" + ":AA" + rnd(33, ALNUM + "_-"),
        "stripe": "sk" + "_live_" + rnd(30),
        "stripe_webhook": "wh" + "sec_" + rnd(32),
        "google_oauth": "GOC" + "SPX-" + rnd(28, ALNUM + "_-"),
        "google_access": "ya" + "29." + rnd(60, ALNUM + "_-"),
        "npm": "np" + "m_" + rnd(36),
        "digitalocean": "do" + "p_v1_" + hexs(64),
        "shopify": "sh" + "pat_" + hexs(32),
        "sendgrid": "S" + "G." + rnd(22, ALNUM + "_-") + "." + rnd(43, ALNUM + "_-"),
        "square": "sq0" + "atp-" + rnd(22, ALNUM + "_-"),
        "grafana": "gl" + "sa_" + rnd(32) + "_" + hexs(8),
        "pypi": "py" + "pi-AgEIcHlwaS5vcmc" + rnd(60, ALNUM + "_-"),
    }


class Detection(unittest.TestCase):
    def assertCaught(self, secret, context="value: {}", label=None):
        text = context.format(secret)
        out, n = detectors.redact(text)
        self.assertGreaterEqual(n, 1, f"missed: {context}")
        self.assertNotIn(secret, out, f"left in output: {context}")
        if label:
            self.assertIn(f"possible {label} redacted", out)

    def assertClean(self, text):
        self.assertEqual(detectors.detect(text), [], f"false alarm on: {text[:80]!r}")

    def test_every_prefixed_format(self):
        for name, k in keys().items():
            with self.subTest(name):
                self.assertCaught(k, "here it is {} thanks")

    def test_original_formats_still_present(self):
        self.assertGreaterEqual(len(detectors.KEY_FORMATS), 13)
        self.assertIs(guard.KEY_FORMATS, detectors.KEY_FORMATS)

    def test_private_key_blocks(self):
        body = "\n".join(rnd(64, ALNUM + "+/") for _ in range(6))
        for kind in ("", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "):
            with self.subTest(kind):
                block = f"-----BEGIN {kind}PRIVATE KEY-----\n{body}\n-----END {kind}PRIVATE KEY-----"
                out, _ = detectors.redact("cat id\n" + block + "\ndone")
                self.assertNotIn(body.splitlines()[2], out)
                self.assertTrue(out.endswith("\ndone"))
        # truncated output with no END line: redacted to the end, never left half-shown
        out, _ = detectors.redact("-----BEGIN PRIVATE KEY-----\n" + body)
        self.assertNotIn(body.splitlines()[-1], out)
        self.assertClean("-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----")
        self.assertClean("-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----")

    def test_jwt(self):
        tok = b64u({"alg": "HS256", "typ": "JWT"}) + "." + b64u({"sub": rnd(12), "iat": 1}) + "." + rnd(43, ALNUM + "_-")
        self.assertCaught(tok, "Authorization: {}", "JWT")
        fake = b64u({"hello": "world"}) + "." + b64u({"sub": "x" * 12}) + "." + rnd(43)
        self.assertClean("not a token " + fake)

    def test_seed_phrases(self):
        for n in (12, 15, 18, 21, 24):
            with self.subTest(n):
                words = mnemonic(n)
                self.assertCaught(" ".join(words), "my wallet words: {} ok", "seed phrase")
        words = mnemonic(12)
        numbered = " ".join(f"{i + 1}. {w}" for i, w in enumerate(words))
        self.assertCaught(numbered, "{}")
        self.assertCaught("\n".join(words), "{}")
        self.assertCaught(", ".join(words).upper(), "{}")

    def test_seed_phrase_checksum_matters(self):
        misses = 0
        for _ in range(200):
            words = [secrets.choice(WORDS) for _ in range(12)]
            idx = [detectors._wordlist()[w] for w in words]
            if not detectors.bip39_valid(idx):
                misses += 1
                self.assertClean(" ".join(words))
        self.assertGreater(misses, 150)   # about 15 in 16 random runs fail the checksum

    def test_assigned_values(self):
        v = rnd(32)
        for ctx in ('api_key = "{}"', "OPENAI_API_KEY={}", '"client_secret": "{}"', "x-api-key: {}",
                    "db_password: {}", "Authorization: Bearer {}", "access_token => '{}'",
                    "PRIVATE_KEY=" + "{}"):
            with self.subTest(ctx):
                self.assertCaught(v, ctx)
        self.assertCaught(hexs(64), "private_key = {}")       # long hex is fine next to a key name

    def test_assigned_values_that_are_not_secrets(self):
        v = rnd(32)
        for text in (f'"next_page_token": "{v}"', f"page_token={v}", "max_tokens = 4096",
                     f"token_count: {v}", "password: hunter2", "api_key = /Users/me/.config/key.txt",
                     "api_key = your-api-key-goes-here-1234", "OPENAI_API_KEY=sk-...",
                     "api_key: ${OPENAI_API_KEY}", "secret = " + "x" * 30, f"token_type: {v}",
                     "secret_key = abcdefabcdef1234",            # hex, too short
                     "token = 0000000000000000000000000000"):
            with self.subTest(text):
                self.assertClean(text)

    def test_false_alarm_corpus(self):
        sha = hexs(40)
        corpus = [
            f"commit {sha}\nAuthor: Someone <a@b.c>\n\n    Fix the thing",
            f"{hexs(64)}  bip39_english.txt",
            "7f3e2a10-9c4d-4b8e-a1f2-3c5d6e7f8a9b request id",
            "integrity sha512-" + base64.b64encode(secrets.token_bytes(64)).decode(),
            "data:image/png;base64," + base64.b64encode(secrets.token_bytes(300)).decode(),
            "https://example.com/search?q=" + rnd(40) + "&page=2",
            "The quick brown fox jumps over the lazy dog near the river bank today.",
            "Please add my Groq key, then check the weather for Little Rock this afternoon.",
            "OpenAI keys start with sk- and GitHub tokens start with ghp_",
            "session " + rnd(32) + " started",            # random id with no key-like name
            "eth tx 0x" + hexs(64),                         # transaction hash, no key-like name
        ]
        for text in corpus:
            with self.subTest(text[:30]):
                self.assertClean(text)

    def test_placeholder_keys_left_in_output_but_stop_chat(self):
        # Seen in real history: a doc example "sk-" plus a run of one letter, in a bundled skill.
        for ph in ("sk-" + "x" * 20, "sk-" + "abcd" * 6, "gh" + "p_" + "A" * 36,
                   "sk-" + "proj-your-key-goes-here-" + "1" * 8):
            with self.subTest(ph):
                self.assertClean(f'headers:\n  Authorization: "{ph}"')
                self.assertTrue(detectors.detect(ph, inbound=True))     # chat still stops it

    def test_signed_links_are_hidden(self):
        # Policy (Charles, 2026-11-22): a signed-link token grants access to that file, so it is
        # redacted like any other credential; the agent cannot open such links.
        jwt = b64u({"alg": "HS256", "typ": "JWT"}) + "." + b64u({"sub": rnd(12)}) + "." + rnd(43, ALNUM + "_-")
        v = rnd(36)
        for text, secret in ((f"https://cdn.example.net/a/{rnd(20)}.png?jwt={jwt}", jwt),
                             (f"https://firebasestorage.googleapis.com/v0/b/x/o/f.webp?alt=media&token={v}", v),
                             (f"https://www.youtube.com/redirect?event=x&redir_token={v}&q=y", v),
                             (f"not a link at all &token={jwt}", jwt)):        # R4: no URL needed
            with self.subTest(text[:40]):
                out, n = detectors.redact(text)
                self.assertGreaterEqual(n, 1)
                self.assertNotIn(secret, out)

    def test_r3_prefixed_names_are_not_excluded_by_substring(self):
        v = rnd(32)
        for ctx in ("admin_password={}", "account_api_key={}", "account_secret: {}",
                    "tenant_client_secret={}", "minio_secret_key={}", "countdown_token={}",
                    "typesense_api_key={}", "maxmind_license_secret={}"):
            with self.subTest(ctx):
                self.assertCaught(v, ctx)
                self.assertTrue(detectors.detect(ctx.format(v), inbound=True))
        for text in (f"next_page_token={v}", f'"nextPageToken": "{v}"', f"pageToken={v}",
                     f"sync-token: {v}", f"continuation_token={v}", f"cursor_token={v}"):
            with self.subTest(text):
                self.assertClean(text)

    def test_r4_random_key_containing_a_word_is_still_a_key(self):
        body = rnd(12) + "your" + rnd(20)
        self.assertCaught("gh" + "p_" + body, "token: {} ok")
        self.assertCaught("sk-" + "proj-" + rnd(10) + "example" + rnd(20), "{}")

    def test_url_parameters_that_still_count(self):
        v = rnd(36)
        jwt = b64u({"alg": "RS256"}) + "." + b64u({"sub": rnd(12)}) + "." + rnd(43, ALNUM + "_-")
        for text, secret in ((f"https://api.example.com/v1?api_key={v}", v),
                             (f"https://x.example.com/cb#x&access_token={v}", v),
                             (f"https://x.example.com/cb?client_secret={v}", v),
                             (f"https://x.example.com/cb?id_token={jwt}", jwt),
                             (f"curl -H 'Authorization: Bearer {jwt}' https://x", jwt),
                             (f"token={v}", v)):                   # not in a web address
            with self.subTest(text[:40]):
                out, n = detectors.redact(text)
                self.assertGreaterEqual(n, 1)
                self.assertNotIn(secret, out)

    def test_wordlist_integrity_is_checked(self):
        self.assertEqual(len(detectors._wordlist()), 2048)
        self.assertEqual(hashlib.sha256(Path(detectors._WORDLIST_PATH).read_bytes()).hexdigest(),
                         detectors._WORDLIST_SHA256)


class OutputRedaction(unittest.TestCase):
    def test_tool_output_redacted(self):
        k = keys()["github"]
        out = guard.on_transform_tool_result(result=f"GITHUB_TOKEN={k}\nok")
        self.assertIsNotNone(out)
        self.assertNotIn(k, out)
        self.assertTrue(out.endswith("\nok"))

    def test_terminal_and_reply_redacted(self):
        words = " ".join(mnemonic(24))
        self.assertNotIn(words, guard.on_transform_terminal_output(output="seed: " + words))
        k = keys()["anthropic"]
        self.assertNotIn(k, guard.on_transform_llm_output(response_text="Your key is " + k))

    def test_clean_output_untouched(self):
        self.assertIsNone(guard.on_transform_tool_result(result=f"commit {hexs(40)}\nall good"))

    def test_detector_failure_withholds(self):
        real = detectors.detect
        detectors.detect = lambda t: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            self.assertEqual(guard.on_transform_tool_result(result="anything"), guard.WITHHELD)
        finally:
            detectors.detect = real


class HoldAndRelease(unittest.TestCase):
    S = {"session_id": "s1", "sender_id": "u1", "platform": "desktop"}

    def setUp(self):
        guard._held.clear()

    def stop(self, text, **kw):
        a = {**self.S, **kw}
        r = guard.on_pre_llm_call(user_message=text, **a) or {}
        self.assertEqual(r.get("action"), "block", text[:40])
        key = guard._hold_key(a["session_id"], a["sender_id"], a["platform"])
        return r["message"], guard._held[key]["code"]

    def send(self, text, **kw):
        return guard.on_pre_llm_call(user_message=text, **{**self.S, **kw})

    def test_message_offers_both_options(self):
        msg, code = self.stop("deploy with " + keys()["stripe"])
        self.assertIn(f"proceed {code}", msg)
        self.assertIn(f"proceed {code} as-is", msg)
        self.assertIn("API key", msg)

    def test_release_redacted(self):
        k = keys()["stripe"]
        _, code = self.stop(f"deploy the site with {k} please")
        r = self.send(f"proceed {code}")
        self.assertIn("context", r)
        self.assertNotIn(k, r["context"])
        self.assertIn("deploy the site with", r["context"])
        self.assertIn("[secret:possible API key redacted]", r["context"])

    def test_release_as_is(self):
        k = keys()["openai"]
        _, code = self.stop(f"is {k} a valid format?")
        r = self.send(f"Proceed {code.lower()} as-is.")
        self.assertIn(k, r["context"])
        self.assertIn("unchanged", r["context"])

    def test_single_use(self):
        _, code = self.stop("x " + keys()["groq"])
        self.assertIn("context", self.send(f"proceed {code}"))
        self.assertIsNone(self.send(f"proceed {code}"))      # nothing held: ordinary text

    def test_wrong_code_keeps_it_held(self):
        _, code = self.stop("x " + keys()["groq"])
        wrong = "ZZZZ" if code != "ZZZZ" else "YYYY"
        r = self.send(f"proceed {wrong}")
        self.assertEqual(r["action"], "block")
        self.assertIn("context", self.send(f"proceed {code}"))

    def test_expiry(self):
        _, code = self.stop("x " + keys()["groq"])
        next(iter(guard._held.values()))["expires"] = 0
        self.assertIsNone(self.send(f"proceed {code}"))

    def test_other_conversation_or_sender_cannot_release(self):
        _, code = self.stop("x " + keys()["groq"])
        self.assertIsNone(self.send(f"proceed {code}", session_id="s2"))
        self.assertIsNone(self.send(f"proceed {code}", sender_id="u2"))
        self.assertIn("context", self.send(f"proceed {code}"))

    def test_command_must_be_the_whole_message(self):
        _, code = self.stop("x " + keys()["groq"])
        self.assertIsNone(self.send(f"ok so proceed {code} now and also check the weather"))
        self.assertEqual(len(guard._held), 1)

    def test_newer_stop_replaces_older(self):
        _, first = self.stop("x " + keys()["groq"])
        _, second = self.stop("y " + keys()["xai"])
        if first != second:
            self.assertEqual(self.send(f"proceed {first}")["action"], "block")
        self.assertIn("y ", self.send(f"proceed {second}")["context"])

    def test_stored_key_cannot_go_as_is(self):
        stored = rnd(40)
        real = guard._load_values
        guard._load_values = lambda: {"SG_FAKE": stored}
        try:
            msg, code = self.stop(f"use {stored} for this")
            self.assertNotIn("as-is", msg)
            r = self.send(f"proceed {code} as-is")
            self.assertEqual(r["action"], "block")
            r = self.send(f"proceed {code}")
            self.assertNotIn(stored, r["context"])
            self.assertIn("[secret:SG_FAKE redacted]", r["context"])
        finally:
            guard._load_values = real

    def test_attachment_note(self):
        _, code = self.stop([{"type": "text", "text": "see " + keys()["groq"]},
                             {"type": "image_url", "image_url": {"url": "data:..."}}])
        self.assertIn("attachment", self.send(f"proceed {code}")["context"])

    def test_placeholder_paste_releases_redacted(self):
        ph = "sk-" + "x" * 24
        _, code = self.stop(f"is {ph} the right shape?")
        r = self.send(f"proceed {code}")
        self.assertIn("context", r)
        self.assertNotIn(ph, r["context"])

    def test_too_long_to_hold_is_not_retained(self):          # R6: refused at insertion
        r = self.send("x " + keys()["groq"] + " " + "word " * 2000)
        self.assertEqual(r["action"], "block")
        self.assertIn("too long to hold", r["message"])
        self.assertNotIn("proceed", r["message"])
        self.assertEqual(guard._held, {})

    def test_original_formats_count(self):
        self.assertEqual(len(detectors.KEY_FORMATS), 25)   # README states this number

    def test_remote_platform_wording(self):
        msg, _ = self.stop("x " + keys()["groq"], platform="telegram")
        self.assertIn("If it is a real key", msg)
        self.assertIn("rotate", msg)

    def test_ordinary_messages_pass(self):
        self.assertIsNone(self.send("proceed with the plan"))
        self.assertIsNone(self.send("what's the weather"))


class ReviewRegressions(unittest.TestCase):
    """One or more tests per finding of Astra's PR #8 review (R1, R2, R5, R6)."""

    def setUp(self):
        guard._held.clear()
        self._real_load = guard._load_values

    def tearDown(self):
        guard._load_values = self._real_load
        guard._held.clear()

    def call(self, text, **kw):
        a = {"session_id": "s1", "sender_id": "u1", "platform": "telegram", **kw}
        return guard.on_pre_llm_call(user_message=text, **a) or {}

    def code_in(self, msg):
        import re as _re
        m = _re.search(r"proceed ([A-Z0-9]{4})", msg)
        return m.group(1) if m else None

    # R1: identity -------------------------------------------------------------------------
    def test_r1_missing_sender_off_this_machine_is_not_held(self):
        for plat in ("telegram", "discord", "api", "cron", ""):
            with self.subTest(plat):
                r = self.call("x " + keys()["groq"], sender_id="", platform=plat)
                self.assertEqual(r["action"], "block")
                self.assertIsNone(self.code_in(r["message"]))
                self.assertIn("cannot tell who sent it", r["message"])
        self.assertEqual(guard._held, {})

    def test_r1_missing_session_is_not_held(self):
        r = self.call("x " + keys()["groq"], session_id="", platform="desktop")
        self.assertIsNone(self.code_in(r["message"]))
        self.assertEqual(guard._held, {})

    def test_r1_local_surface_without_sender_can_release(self):
        r = self.call("x " + keys()["groq"], sender_id="", platform="desktop")
        code = self.code_in(r["message"])
        self.assertIsNotNone(code)
        self.assertIn("context", self.call(f"proceed {code}", sender_id="", platform="desktop"))

    def test_r1_group_chat_other_member_cannot_release(self):
        code = self.code_in(self.call("x " + keys()["groq"], sender_id="alice")["message"])
        self.assertEqual(self.call(f"proceed {code}", sender_id="bob"), {})   # ordinary text for bob
        self.assertEqual(self.call(f"proceed {code}", sender_id=""), {})      # unknown sender
        self.assertIn("context", self.call(f"proceed {code}", sender_id="alice"))

    def test_r1_other_platform_or_profile_cannot_release(self):
        code = self.code_in(self.call("x " + keys()["groq"])["message"])
        self.assertEqual(self.call(f"proceed {code}", platform="discord"), {})
        real_scope = guard._scope
        guard._scope = lambda: "/other/profile"
        try:
            self.assertEqual(self.call(f"proceed {code}"), {})
        finally:
            guard._scope = real_scope
        self.assertIn("context", self.call(f"proceed {code}"))

    def test_r1_non_string_ids_are_not_trusted(self):
        r = self.call("x " + keys()["groq"], session_id=123, sender_id=None)
        self.assertIsNone(self.code_in(r["message"]))

    # R2: as-is re-checks stored values now ---------------------------------------------------
    def test_r2_key_registered_after_the_stop_refuses_as_is(self):
        k = keys()["openai"]
        code = self.code_in(self.call(f"is {k} valid?")["message"])
        guard._load_values = lambda: {"SG_LATE": k}
        r = self.call(f"proceed {code} as-is")
        self.assertEqual(r["action"], "block")
        self.assertIn("stored keys", r["message"])
        r = self.call(f"proceed {code}")
        self.assertNotIn(k, r["context"])

    def test_r2_encoded_stored_value_refuses_as_is(self):
        stored = rnd(40)
        enc = base64.b64encode(stored.encode()).decode()
        guard._load_values = lambda: {"SG_ENC": stored}
        msg = self.call(f"api_key={enc}")["message"]
        code = self.code_in(msg)
        self.assertIsNotNone(code)
        r = self.call(f"proceed {code} as-is")
        self.assertEqual(r["action"], "block")
        r = self.call(f"proceed {code}")
        self.assertNotIn(enc, r["context"])

    def test_r2_check_failure_fails_closed(self):
        code = self.code_in(self.call("x " + keys()["groq"])["message"])
        def boom():
            raise RuntimeError("keychain unavailable")
        guard._load_values = boom
        r = self.call(f"proceed {code} as-is")
        self.assertEqual(r["action"], "block")
        self.assertNotIn("context", r)
        self.assertEqual(guard._held, {})

    # R5: the rendered payload is what is measured ------------------------------------------
    def test_r5_redaction_expansion_is_measured_after_rendering(self):
        text = " ".join(f"pwd={rnd(20)}" for _ in range(210))      # about 5,300 characters
        self.assertLess(len(text), guard._spill_limit() - guard._WRAPPER_ROOM)
        code = self.code_in(self.call(text)["message"])
        self.assertIsNotNone(code)
        r = self.call(f"proceed {code}")
        self.assertEqual(r["action"], "block")
        self.assertIn("more than Hermes passes to the model intact", r["message"])
        self.assertEqual(guard._held, {})

    def test_r5_lower_configured_limit_is_honoured(self):
        real = guard._spill_limit
        guard._spill_limit = lambda: 1_000
        try:
            r = self.call("x " + keys()["groq"] + " " + "word " * 200)
            self.assertIn("too long to hold", r["message"])
            code = self.code_in(self.call("x " + keys()["groq"] + " " + "word " * 100)["message"])
            r = self.call(f"proceed {code} as-is")
            self.assertIn("context", r)
            self.assertLessEqual(len(r["context"]), 1_000)
        finally:
            guard._spill_limit = real

    # R6: retention -----------------------------------------------------------------------------
    def test_r6_idle_process_drops_the_hold(self):
        import time as _t
        old = guard.HOLD_SECONDS
        guard.HOLD_SECONDS = 0.3
        try:
            self.call("x " + keys()["groq"])
            self.assertEqual(len(guard._held), 1)
            _t.sleep(0.8)                                   # no other call happens
            self.assertEqual(guard._held, {})
        finally:
            guard.HOLD_SECONDS = old

    def test_r6_ordinary_turn_purges_expired(self):
        self.call("x " + keys()["groq"])
        next(iter(guard._held.values()))["expires"] = 0
        self.call("what's the weather")
        self.assertEqual(guard._held, {})

    def test_r6_global_cap(self):
        for i in range(guard.MAX_HELD + 5):
            self.call("x " + keys()["groq"], session_id=f"s{i}")
        self.assertEqual(len(guard._held), guard.MAX_HELD)

    def test_r6_closing_the_conversation_drops_the_hold(self):
        self.call("x " + keys()["groq"], session_id="sA")
        self.call("x " + keys()["groq"], session_id="sB")
        guard.on_session_closed(session_id="sA")
        self.assertEqual([k[2] for k in guard._held], ["sB"])

    # R8: wording at the decision point --------------------------------------------------------
    def test_r8_stop_message_discloses_what_as_is_does(self):
        msg = self.call("x " + keys()["groq"])["message"]
        self.assertNotIn("not stored", msg)
        self.assertIn("model provider", msg)
        self.assertIn("history", msg)

    def test_released_text_is_framed_as_user_words_not_approval(self):
        code = self.code_in(self.call("x " + keys()["groq"])["message"])
        self.assertIn("not approval of anything it asks for", self.call(f"proceed {code}")["context"])


class RecheckRegressions(unittest.TestCase):
    """Astra's recheck of 64d4af3: F1 (bounded expiry workers), F2 (assigned placeholders),
    F3 (signed-link coverage), and the R1 automated-turn hardening."""

    HIGH = "Ab3Cd4Ef5Gh6Jk7Lm8Np9Qr0St1Uv2Wx3"

    def setUp(self):
        guard._held.clear()

    def tearDown(self):
        guard._held.clear()
        guard._purge()

    def sweepers(self):
        import threading as _th
        return [t for t in _th.enumerate() if t.name == "secret-guard-hold-sweeper" and t.is_alive()]

    def call(self, text, **kw):
        a = {"session_id": "s1", "sender_id": "u1", "platform": "telegram", **kw}
        return guard.on_pre_llm_call(user_message=text, **a) or {}

    # F1 ------------------------------------------------------------------------------------------
    def test_f1_replacing_one_hold_64_times_uses_one_worker(self):
        for _ in range(64):
            self.call("x " + keys()["groq"])
        self.assertEqual(len(guard._held), 1)
        self.assertLessEqual(len(self.sweepers()), 1)

    def test_f1_many_conversations_releases_and_closes_stay_bounded(self):
        for i in range(40):
            self.call("x " + keys()["groq"], session_id=f"s{i}")
        self.assertEqual(len(guard._held), guard.MAX_HELD)
        for k in list(guard._held):
            guard.on_session_closed(session_id=k[2])
        self.assertEqual(guard._held, {})
        self.assertLessEqual(len(self.sweepers()), 1)

    def test_f1_worker_exits_when_nothing_is_held(self):
        import time as _t
        self.call("x " + keys()["groq"])
        guard.on_session_closed(session_id="s1")
        deadline = _t.monotonic() + 2
        while self.sweepers() and _t.monotonic() < deadline:
            _t.sleep(0.05)
        self.assertEqual(self.sweepers(), [])

    def test_f1_old_expiry_never_removes_a_newer_hold(self):
        import time as _t
        old = guard.HOLD_SECONDS
        try:
            guard.HOLD_SECONDS = 0.3
            self.call("x " + keys()["groq"])
            guard.HOLD_SECONDS = 30
            self.call("y " + keys()["xai"])            # same person and conversation: replaces
            _t.sleep(0.7)
            self.assertEqual(len(guard._held), 1)
            self.assertTrue(next(iter(guard._held.values()))["text"].startswith("y "))
        finally:
            guard.HOLD_SECONDS = old

    def test_f1_idle_expiry_still_works(self):
        import time as _t
        old = guard.HOLD_SECONDS
        guard.HOLD_SECONDS = 0.3
        try:
            self.call("x " + keys()["groq"])
            _t.sleep(0.8)
            self.assertEqual(guard._held, {})
        finally:
            guard.HOLD_SECONDS = old

    # F2 ------------------------------------------------------------------------------------------
    def test_f2_values_starting_with_a_placeholder_word_are_still_secrets(self):
        for pre in ("your", "dummy", "example", "changeme", "placeholder", "my", "redacted"):
            v = pre + self.HIGH
            with self.subTest(pre):
                out, n = detectors.redact(f"api_key={v}")
                self.assertEqual(n, 1)
                self.assertNotIn(v, out)
                self.assertTrue(detectors.detect(f"api_key={v}", inbound=True))

    def test_f2_documented_examples_left_in_output_but_stop_chat(self):
        # Every example here has letters and digits: a value with letters only is not matched in
        # either direction (README, honest limits), so it cannot show the inbound difference.
        for text in ("api_key = your-api-key-goes-here-1234", "client_secret: changeme_secret_value_2026",
                     "password=" + "x" * 20 + "1234", "secret_key = example-secret-key-for-docs-01"):
            with self.subTest(text):
                self.assertEqual(detectors.detect(text), [])
                self.assertTrue(detectors.detect(text, inbound=True))

    def test_f2_masked_preview_is_not_a_value_anywhere(self):
        text = "OPENAI_API_KEY=sk-proj-Ab3...Wx3z"
        self.assertEqual(detectors.detect(text), [])
        self.assertEqual(detectors.detect(text, inbound=True), [])

    # F3 ------------------------------------------------------------------------------------------
    def test_f3_signature_fields_in_links_are_redacted(self):
        v = rnd(40, ALNUM + "-_")
        hx = hexs(64)
        enc = "Ab3Cd4%2BEf5Gh6%2FJk7Lm8Np9%3D%3D"
        for text, secret in ((f"https://example.invalid/file?sig={v}", v),
                             (f"https://example.invalid/file?Signature={v}&Expires=1", v),
                             (f"https://bucket.s3.example.invalid/k?X-Amz-Signature={hx}", hx),
                             (f"https://storage.example.invalid/o?X-Goog-Signature={hx}&x=1", hx),
                             (f"https://example.invalid/f?a=1&sig={enc}", enc),
                             (f"https://example.invalid/f?X-Amz-Security-Token={enc}{v}", enc + v),
                             (f"https://maps.example.invalid/api?key={v}", v)):
            with self.subTest(text[:48]):
                out, n = detectors.redact(text)
                self.assertGreaterEqual(n, 1)
                self.assertNotIn(secret, out)
                self.assertTrue(detectors.detect(text, inbound=True))

    def test_f3_ordinary_links_and_bare_signatures_unchanged(self):
        for text in ("https://example.invalid/search?q=weather+little+rock&page=2&id=12345",
                     "https://example.invalid/a?ref=homepage_banner_2026&utm_source=newsletter",
                     "https://example.invalid/docs/signature-verification?lang=en",
                     "the signature=" + hexs(64) + " in this log line is a checksum"):
            with self.subTest(text[:40]):
                self.assertEqual(detectors.detect(text), [])

    # R1 hardening ------------------------------------------------------------------------------------
    def test_r1_automated_turn_with_a_sender_is_never_held(self):
        for plat in ("cron", ""):
            with self.subTest(plat):
                r = self.call("x " + keys()["groq"], platform=plat, sender_id="scheduler")
                self.assertNotIn("proceed", r["message"])
        self.assertEqual(guard._held, {})


class HermesBoundary(unittest.TestCase):
    """The real Hermes collector, with a stub agent, passes our ids through and applies our result.
    Skipped where Hermes is not importable (CI); run locally against the installed hermes-agent."""

    @classmethod
    def setUpClass(cls):
        try:
            from agent import turn_context
            import hermes_cli.lifecycle as lifecycle
        except Exception as e:                                  # pragma: no cover
            raise unittest.SkipTest(f"Hermes not importable: {type(e).__name__}")
        cls.tc, cls.lc = turn_context, lifecycle

    def setUp(self):
        guard._held.clear()
        self._real = self.lc._plugin_hooks
        self.seen = []

        def hooks(name, **kw):
            if name != "pre_llm_call":
                return []
            self.seen.append({k: kw.get(k) for k in ("session_id", "sender_id", "platform")})
            r = guard.on_pre_llm_call(**kw)
            return [r] if r is not None else []
        self.lc._plugin_hooks = hooks

    def tearDown(self):
        self.lc._plugin_hooks = self._real
        guard._held.clear()

    def agent(self, sender):
        class A:
            pass
        a = A()
        a.session_id, a.model, a.platform, a._user_id, a._parent_session_id = "sess-1", "m", "telegram", sender, None
        return a

    def collect(self, a, text):
        blocks = []
        ctx = self.tc._collect_pre_llm_call_context(
            a, effective_task_id="t", turn_id="u", original_user_message=text,
            messages=[{"role": "user", "content": text}], conversation_history=[], blocks=blocks)
        return ctx, blocks

    def test_collector_passes_identity_and_applies_block_then_context(self):
        _, blocks = self.collect(self.agent("alice"), "x " + keys()["groq"])
        self.assertEqual(self.seen[-1], {"session_id": "sess-1", "sender_id": "alice", "platform": "telegram"})
        self.assertEqual(len(blocks), 1)
        code = HoldAndReleaseCodes.code(blocks[0])
        ctx, blocks = self.collect(self.agent("bob"), f"proceed {code}")
        self.assertEqual((ctx, blocks), ("", []))                 # bob: nothing released
        ctx, blocks = self.collect(self.agent("alice"), f"proceed {code}")
        self.assertEqual(blocks, [])
        self.assertIn("Secret Guard: the user approved", ctx)
        api = self.tc.compose_user_api_content(f"proceed {code}", "", ctx)
        self.assertTrue(api.startswith(f"proceed {code}") and "approved" in api)

    def test_collector_with_missing_sender_gives_no_code(self):
        _, blocks = self.collect(self.agent(None), "x " + keys()["groq"])
        self.assertIsNone(HoldAndReleaseCodes.code(blocks[0]))


class HoldAndReleaseCodes:
    @staticmethod
    def code(msg):
        import re as _re
        m = _re.search(r"proceed ([A-Z0-9]{4})", msg)
        return m.group(1) if m else None


if __name__ == "__main__":
    unittest.main(verbosity=1)
