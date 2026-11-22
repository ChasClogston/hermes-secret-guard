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
        r = guard.on_pre_llm_call(user_message=text, **{**self.S, **kw}) or {}
        self.assertEqual(r.get("action"), "block", text[:40])
        return r["message"], guard._held[(kw.get("session_id", "s1"), kw.get("sender_id", "u1"))]["code"]

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
        guard._held[("s1", "u1")]["expires"] = 0
        self.assertIsNone(self.send(f"proceed {code}"))

    def test_other_conversation_or_sender_cannot_release(self):
        _, code = self.stop("x " + keys()["groq"])
        self.assertIsNone(self.send(f"proceed {code}", session_id="s2"))
        self.assertIsNone(self.send(f"proceed {code}", sender_id="u2"))
        self.assertIn("context", self.send(f"proceed {code}"))

    def test_command_must_be_the_whole_message(self):
        _, code = self.stop("x " + keys()["groq"])
        self.assertIsNone(self.send(f"ok so proceed {code} now and also check the weather"))
        self.assertIn(("s1", "u1"), guard._held)

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

    def test_too_long_to_release(self):
        _, code = self.stop("x " + keys()["groq"] + " " + "word " * 2000)
        r = self.send(f"proceed {code}")
        self.assertEqual(r["action"], "block")
        self.assertIn("too long", r["message"])
        self.assertNotIn(("s1", "u1"), guard._held)

    def test_original_formats_count(self):
        self.assertEqual(len(detectors.KEY_FORMATS), 25)   # README states this number

    def test_remote_platform_wording(self):
        msg, _ = self.stop("x " + keys()["groq"], platform="telegram")
        self.assertIn("If it is a real key", msg)
        self.assertIn("rotate", msg)

    def test_ordinary_messages_pass(self):
        self.assertIsNone(self.send("proceed with the plan"))
        self.assertIsNone(self.send("what's the weather"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
