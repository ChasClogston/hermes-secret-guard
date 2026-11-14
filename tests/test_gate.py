"""Gate and redaction matrix for the 1.1 coverage work. Runs anywhere Python runs: no Hermes, no
keychain, no network. Synthetic files and one synthetic value in a temporary folder.

    python tests/test_gate.py

Each row states the expected result. Rows marked KNOWN LIMIT document what layer 1 cannot see;
layer 2 (value redaction) is the control there.
"""
import base64, importlib.util, json, os, shutil, sys, tempfile, unittest, urllib.parse
from unittest import mock

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("secret_guard_gate", os.path.join(_root, "__init__.py"),
                                               submodule_search_locations=[_root])
_pkg = importlib.util.module_from_spec(_spec); sys.modules["secret_guard_gate"] = _pkg; _spec.loader.exec_module(_pkg)
from secret_guard_gate import guard

VALUE = "drill-synthetic-value-0123456789abcdef"
GUARDED = {"secrets": {"DRILL_FAKE_KEY": {}, "OPENAI_API_KEY": {}}}


def T(command):
    return ("terminal", {"command": command})


class GateMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = os.getcwd()
        cls.base = os.path.realpath(tempfile.mkdtemp(prefix="sg-gate-"))
        w = cls.w = os.path.join(cls.base, "work")
        for d in ("sub", "clean/src", "hidden_only", "nested/a/b/c/d/e/f/g", "nprod", "tokdir",
                  "proj/node_modules/pkg", "proj/src"):
            os.makedirs(os.path.join(w, d))
        cls.deep = os.path.join(cls.base, "deep", *"abcdefghijklmn")   # beyond the scan depth
        os.makedirs(cls.deep)
        files = {".env": "DRILL_FAKE_KEY=" + VALUE + "\n", "notes.txt": "hello\n", "sub/prod.env": "X=1\n",
                 "clean/src/app.py": "print(1)\n", "clean/tokenizer.json": "{}\n", "clean/readme.md": "x\n",
                 "clean/.env.example": "KEY=changeme\n", "clean/src/credential_files.cpython-314.pyc": "x",
                 "hidden_only/.env": "X=1\n", "hidden_only/a.txt": "x\n", "nested/a/b/c/d/e/f/g/x.txt": "x\n",
                 "nprod/prod.env": "X=1\n", "tokdir/access-token.txt": "x\n",
                 "proj/node_modules/pkg/prod.env": "X=1\n", "proj/src/a.py": "x\n"}
        for rel, text in files.items():
            with open(os.path.join(w, rel), "w") as fh:
                fh.write(text)
        os.chdir(w)
        cls.patch = mock.patch.object(guard.registry, "load", return_value=GUARDED)
        cls.patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop(); os.chdir(cls.old); shutil.rmtree(cls.base, ignore_errors=True)

    def verdict(self, tool, args):
        return "blocked" if guard.check_tool_args(tool, args) else "allowed"

    def run_rows(self, rows):
        bad = [(label, want, got) for label, (tool, args), want in rows
               for got in [self.verdict(tool, args)] if got != want]
        self.assertEqual(bad, [], "\n".join(f"{l}: want {w}, got {g}" for l, w, g in bad))

    def test_named_secret_files_stay_blocked(self):
        w = self.w
        self.run_rows([
            ("read_file .env", ("read_file", {"path": ".env"}), "blocked"),
            ("read_file sub/prod.env", ("read_file", {"path": w + "/sub/prod.env"}), "blocked"),
            ("search_files path=.env", ("search_files", {"pattern": ".", "path": w + "/.env"}), "blocked"),
            ("cat < .env", T("cat < .env"), "blocked"),
            ("F=.env; cat $F", T("F=.env; cat $F"), "blocked"),
            ("while read < .env", T("while read l; do echo $l; done < .env"), "blocked"),
            ("mv then cat", T("mv .env x.txt; cat x.txt"), "blocked"),
            ("ln -s then cat", T("ln -s .env l.txt; cat l.txt"), "blocked"),
            ("git diff --no-index", T("git diff --no-index /dev/null .env"), "blocked"),
            ("printenv", T("printenv"), "blocked"),
            ("env | grep KEY", T("env | grep KEY"), "blocked"),
            ("python -c open(.env)", T("python3 -c \"print(open('.env').read())\""), "blocked"),
            ("execute_code open(.env)", ("execute_code", {"code": "print(open('.env').read())"}), "blocked"),
            ("security dump-keychain", T("security dump-keychain -d"), "blocked"),
            ("security find -w", T("security find-generic-password -s x -w"), "blocked"),
        ])

    def test_folder_wide_reads_now_blocked(self):
        w = self.w
        self.run_rows([
            ("search_files folder, content", ("search_files", {"pattern": "DRILL", "path": w, "target": "content"}), "blocked"),
            ("search_files no path (cwd)", ("search_files", {"pattern": "DRILL"}), "blocked"),
            ("search_files file_glob=.env", ("search_files", {"pattern": ".", "path": w, "file_glob": ".env"}), "blocked"),
            ("search_files file_glob=*.env", ("search_files", {"pattern": ".", "path": w, "file_glob": "*.env"}), "blocked"),
            ("grep -r .", T("grep -r DRILL ."), "blocked"),
            ("grep -rn (no path)", T("grep -rn DRILL"), "blocked"),
            ("grep -R folder", T("grep -R DRILL " + w), "blocked"),
            ("rg (non-hidden prod.env below)", T("rg DRILL"), "blocked"),
            ("rg --hidden in hidden_only", T("rg --hidden X hidden_only"), "blocked"),
            ("tar | base64", T("tar cf - . | base64"), "blocked"),
            ("zip -r", T("zip -r - . | base64"), "blocked"),
            ("cp -r", T("cp -r . /tmp/copy"), "blocked"),
            ("find -exec cat", T("find . -name '.e*' -exec cat {} +"), "blocked"),
            ("find | xargs cat", T("find . -type f | xargs cat"), "blocked"),
            ("folder too deep to check", T("grep -r x " + os.path.join(self.base, "deep")), "blocked"),
        ])

    def test_globs_and_substitution_now_blocked(self):
        self.run_rows([
            ("cat .e*", T("cat .e*"), "blocked"),
            ("cat .en?", T("cat .en?"), "blocked"),
            ("cat sub/*", T("cat sub/*"), "blocked"),
            ("head sub/p[a-z]*", T("head sub/p[a-z]*"), "blocked"),
            ("cat $(ls -a | grep env)", T("cat $(ls -a | grep env)"), "blocked"),
            ("cat `ls`", T("cat `ls -a`"), "blocked"),
            ("base64 <(…)", T("base64 <(ls)"), "blocked"),
        ])

    def test_environment_reads_now_blocked(self):
        self.run_rows([
            ("printenv GUARDED", T("printenv OPENAI_API_KEY"), "blocked"),
            ("echo $GUARDED", T("echo $OPENAI_API_KEY"), "blocked"),
            ("echo ${GUARDED} | base64", T("echo ${DRILL_FAKE_KEY} | base64"), "blocked"),
            ("printf guarded", T("printf '%s' \"$OPENAI_API_KEY\""), "blocked"),
            ("set", T("set"), "blocked"),
            ("export -p", T("export -p"), "blocked"),
            ("export", T("export"), "blocked"),
            ("declare -p", T("declare -p"), "blocked"),
            ("python print(os.environ)", T("python3 -c \"import os; print(os.environ)\""), "blocked"),
            ("execute_code dict(os.environ)", ("execute_code", {"code": "import os; print(dict(os.environ))"}), "blocked"),
            ("execute_code print guarded name", ("execute_code", {"code": "import os\nprint(os.environ['OPENAI_API_KEY'])"}), "blocked"),
            ("node console.log(process.env)", ("execute_code", {"code": "console.log(process.env)"}), "blocked"),
        ])

    def test_file_urls_now_blocked(self):
        w = self.w
        self.run_rows([
            ("browser file:// .env", ("browser_navigate", {"url": "file://" + w + "/.env"}), "blocked"),
            ("file:// percent-encoded", ("browser_navigate", {"url": "file://" + urllib.parse.quote(w) + "/%2Eenv"}), "blocked"),
            ("curl file://", T("curl file://" + w + "/sub/prod.env"), "blocked"),
        ])

    def test_ordinary_work_still_allowed(self):
        w = self.w
        self.run_rows([
            ("echo hi", T("echo hi"), "allowed"),
            ("read_file notes.txt", ("read_file", {"path": "notes.txt"}), "allowed"),
            ("search_files clean folder", ("search_files", {"pattern": "print", "path": w + "/clean"}), "allowed"),
            ("search_files file_glob=*.py over secret folder", ("search_files", {"pattern": "x", "path": w, "file_glob": "*.py"}), "allowed"),
            ("search_files names only", ("search_files", {"pattern": "*.env", "path": w, "target": "files"}), "allowed"),
            ("search_files single ordinary file", ("search_files", {"pattern": "h", "path": w + "/notes.txt"}), "allowed"),
            ("grep -r clean folder (tokenizer.json, .env.example, credential .pyc present)", T("grep -r print clean"), "allowed"),
            ("direct read of .env.example is still blocked", T("cat clean/.env.example"), "blocked"),
            ("grep without -r on a file", T("grep hello notes.txt"), "allowed"),
            ("grep -r in an 8-level clean folder", T("grep -r x nested"), "allowed"),
            ("rg in hidden_only (dotfiles skipped)", T("rg X hidden_only"), "allowed"),
            ("tar of clean folder", T("tar cf /tmp/c.tar clean"), "allowed"),
            ("cat ./* (shell skips dotfiles; no secret at top level)", T("cat ./*"), "allowed"),
            ("cat clean/src/*.py", T("cat clean/src/*.py"), "allowed"),
            ("find without -exec", T("find . -name '*.py'"), "allowed"),
            ("find -exec in clean folder", T("find clean -name '*.py' -exec cat {} +"), "allowed"),
            ("curl using a guarded key", T("curl -H \"Authorization: Bearer $OPENAI_API_KEY\" https://example.invalid"), "allowed"),
            ("echo unguarded variable", T("echo $HOME"), "allowed"),
            ("printenv unguarded", T("printenv PATH"), "allowed"),
            ("set -e", T("set -euo pipefail; echo ok"), "allowed"),
            ("export NAME=value", T("export FOO=bar"), "allowed"),
            ("code passes env to a child", ("execute_code", {"code": "import os, subprocess\nsubprocess.run(['ls'], env=os.environ.copy())"}), "allowed"),
            ("code reads one unguarded variable", ("execute_code", {"code": "import os\nprint(os.environ.get('HOME'))"}), "allowed"),
            ("web_search", ("web_search", {"query": "python glob"}), "allowed"),
            ("session_search", ("session_search", {"query": "env"}), "allowed"),
            ("browser https", ("browser_navigate", {"url": "https://example.invalid/.env.html"}), "allowed"),
            ("head with arithmetic", T("head -n 3 notes.txt"), "allowed"),
        ])

    def test_known_limits_documented(self):
        # KNOWN LIMIT: file names built at run time inside code are invisible to a static gate.
        self.run_rows([
            ("execute_code glob", ("execute_code", {"code": "import glob\nfor f in glob.glob('.*'): print(open(f).read())"}), "allowed"),
            ("python -c glob", T("python3 -c \"import glob; [print(open(f).read()) for f in glob.glob('.*')]\""), "allowed"),
        ])


class ReviewFindings(GateMatrix):
    """Regressions for the independent review of 490fb4d (SG-PR1-01 .. 07). Expected results are
    the reviewer's: none was changed to bless a bypass."""

    def test_named_secret_files_stay_blocked(self): pass
    def test_folder_wide_reads_now_blocked(self): pass
    def test_globs_and_substitution_now_blocked(self): pass
    def test_environment_reads_now_blocked(self): pass
    def test_file_urls_now_blocked(self): pass
    def test_ordinary_work_still_allowed(self): pass
    def test_known_limits_documented(self): pass

    def test_02_recursive_search_options(self):
        self.run_rows([
            ("grep -r in hidden_only (control)", T("grep -r X hidden_only"), "blocked"),
            ("rg -uun (clustered)", T("rg -uun X hidden_only"), "blocked"),
            ("rg -uu", T("rg -uu X hidden_only"), "blocked"),
            ("rg -u alone does not search dotfiles", T("rg -u X hidden_only"), "allowed"),
            ("rg --hidden -g '*' PATTERN (cwd)", T("rg --hidden -g \"*\" DRILL"), "blocked"),
            ("rg -g value attached", T("rg -g'*' DRILL hidden_only"), "blocked"),
            ("rg --glob=… unhides", T("rg --glob=.env X hidden_only"), "blocked"),
            ("grep -r -e A -e B (cwd)", T("grep -r -e DRILL -e OTHER"), "blocked"),
            ("grep -r --regexp=A (cwd)", T("grep -r --regexp=DRILL"), "blocked"),
            ("grep -re PATTERN (cluster, cwd)", T("grep -re DRILL"), "blocked"),
            ("grep -r PATTERN n* (folder glob)", T("grep -r X n*"), "blocked"),
            ("grep -r PATTERN equal to a file name", T("grep -r notes.txt"), "blocked"),
            ("grep -r -- PATTERN . ", T("grep -r -- X ."), "blocked"),
            ("grep --directories=recurse", T("grep --directories=recurse X ."), "blocked"),
            ("rg unknown option: working folder checked too", T("rg --frobnicate val notes.txt"), "blocked"),
            ("grep -r with access-token.txt in folder", T("grep -r x tokdir"), "blocked"),
            ("grep -r reads node_modules", T("grep -r X proj"), "blocked"),
            ("tar reads node_modules", T("tar cf /tmp/p.tar proj"), "blocked"),
            # controls that must keep working
            ("rg skips node_modules by default", T("rg X proj"), "allowed"),
            ("rg --no-ignore reads node_modules", T("rg --no-ignore X proj"), "blocked"),
            ("grep -rePATTERN clean (attached value)", T("grep -rePATTERN clean"), "allowed"),
            ("grep -r -e A -e B clean", T("grep -r -e a -e b clean"), "allowed"),
            ("grep -r -- PATTERN clean", T("grep -r -- x clean"), "allowed"),
            ("grep -rn -A 3 PATTERN clean", T("grep -rn -A 3 x clean"), "allowed"),
            ("rg -e PATTERN hidden_only (dotfiles skipped)", T("rg -e X hidden_only"), "allowed"),
            ("rg PATTERN one-file", T("rg hello notes.txt"), "allowed"),
            ("rg -t py -m 5 PATTERN clean", T("rg -t py -m 5 x clean"), "allowed"),
            ("grep -r PATTERN cl* (clean folder glob)", T("grep -r x cl*"), "allowed"),
        ])

    def test_03_search_globs_are_path_aware(self):
        w = self.w
        S = lambda **a: ("search_files", {"pattern": "X", "path": w, **a})
        self.run_rows([
            ("file_glob **/*.env", S(file_glob="**/*.env"), "blocked"),
            ("file_glob sub/*.env", S(file_glob="sub/*.env"), "blocked"),
            ("file_glob sub/**", S(file_glob="sub/**"), "blocked"),
            ("file_glob /sub/prod.env", S(file_glob="/sub/prod.env"), "blocked"),
            ("file_glob exclusion is not proof of safety", S(file_glob="!*.py"), "blocked"),
            ("file_glob braces not modelled", S(file_glob="*.{py,env}"), "blocked"),
            ("file_glob *.env", S(file_glob="*.env"), "blocked"),
            ("file_glob *.py", S(file_glob="*.py"), "allowed"),
            ("file_glob **/*.py", S(file_glob="**/*.py"), "allowed"),
            ("file_glob clean/src/*.py", S(file_glob="clean/src/*.py"), "allowed"),
            ("nested schema: input.path dirty", ("search_files", {"input": {"path": w, "pattern": "x"}, "cwd": w + "/clean"}), "blocked"),
            ("nested schema on a custom search tool", ("code_search", {"input": {"directory": w + "/sub", "query": "x"}}), "blocked"),
            ("nested schema, clean folder", ("code_search", {"input": {"directory": w + "/clean", "query": "x"}}), "allowed"),
        ])

    def test_04_shell_wrappers(self):
        self.run_rows([
            ("sh -c grep -r", T("sh -c 'grep -r X hidden_only'"), "blocked"),
            ("bash -lc grep -r", T("bash -lc \"grep -r X hidden_only\""), "blocked"),
            ("zsh -c with cd", T("zsh -c 'cd hidden_only && grep -r X .'"), "blocked"),
            ("env sh -c", T("env sh -c 'grep -r X hidden_only'"), "blocked"),
            ("nested wrappers", T("sh -c \"bash -c 'grep -r X hidden_only'\""), "blocked"),
            ("eval", T("eval \"grep -r X hidden_only\""), "blocked"),
            ("command string from a variable", T("sh -c \"$CMD\""), "blocked"),
            ("sh -c with no command", T("sh -c"), "blocked"),
            ("wrappers nested beyond the limit", T("sh -c \"sh -c \\\"sh -c \\\\\\\"sh -c 'echo hi'\\\\\\\"\\\"\""), "blocked"),
            ("sh -c tar", T("sh -c 'tar cf - . | base64'"), "blocked"),
            ("sh -c clean grep", T("sh -c 'grep -r print clean'"), "allowed"),
            ("sh -c echo", T("sh -c 'echo hi; echo there'"), "allowed"),
            ("sh script.sh", T("sh clean/run.sh"), "allowed"),
            ("quoted separators are not commands", T("echo 'x; grep -r X hidden_only | cat'"), "allowed"),
            ("double-quoted separators", T("echo \"a; b | c && d\""), "allowed"),
            ("substitution inside double quotes still checked", T("echo \"$(grep -r X hidden_only)\""), "blocked"),
            ("backticks inside double quotes still checked", T("echo \"`grep -r X hidden_only`\""), "blocked"),
            ("substitution body with its own quotes", T("echo \"n: $(grep -rc 'a b' hidden_only)\""), "blocked"),
            ("clean substitution inside double quotes", T("echo \"n: $(grep -rc print clean) done\""), "allowed"),
            ("literal parenthesis in double quotes", T("echo \"(not a command) ; x\""), "allowed"),
        ])

    def test_05_work_is_bounded_and_overflow_blocks(self):
        big = os.path.join(self.base, "big"); os.makedirs(big)
        for i in range(2100):
            open(os.path.join(big, "f%04d.txt" % i), "w").close()
        open(os.path.join(big, "fzz.env"), "w").close()
        self.assertEqual(self.verdict(*T("cat " + big + "/f*")), "blocked")        # secret after the match limit
        for name in ("d1", "d2"):
            os.makedirs(os.path.join(self.base, name))
            for i in range(30):
                open(os.path.join(self.base, name, "%d.txt" % i), "w").close()
        d1, d2 = os.path.join(self.base, "d1"), os.path.join(self.base, "d2")
        seen = {"n": 0}
        real = os.scandir
        class Counting:
            def __init__(self, path): self.it = real(path)
            def __enter__(self): return self
            def __exit__(self, *a): self.it.close()
            def __iter__(self): return self
            def __next__(self):
                e = next(self.it); seen["n"] += 1; return e
        with mock.patch.object(guard, "SCAN_MAX_ENTRIES", 50):
            self.assertEqual(self.verdict(*T("grep -r x " + d1)), "allowed")
            self.assertEqual(self.verdict(*T("grep -r x " + d1 + " " + d2)), "blocked")   # shared budget
            with mock.patch.object(guard.os, "scandir", Counting):
                self.assertEqual(self.verdict(*T("grep -r x " + big)), "blocked")
            self.assertLessEqual(seen["n"], 51)                                    # stopped at the limit
        with mock.patch.object(guard, "SCAN_MAX_SECONDS", -1.0), mock.patch.object(guard, "SCAN_MAX_ENTRIES", 10**9):
            self.assertEqual(self.verdict(*T("grep -r x " + big)), "blocked")      # time budget
        os.symlink(big, os.path.join(d1, "loop")); os.symlink(d1, os.path.join(d1, "self"))
        self.assertEqual(self.verdict(*T("grep -r x " + d1)), "allowed")           # symlinked folders not followed

    def test_06_scan_errors_block(self):
        real = os.scandir
        def deny(path):
            raise PermissionError(13, "denied")
        with mock.patch.object(guard.os, "scandir", deny):
            reason = guard.check_tool_args("terminal", {"command": "grep -r needle clean"})
            self.assertTrue(reason and "could not be checked" in reason, reason)
            self.assertEqual(self.verdict("search_files", {"pattern": "x", "path": self.w + "/clean"}), "blocked")
            self.assertEqual(self.verdict(*T("cat clean/src/*.py")), "blocked")
        def flaky(path):
            if path.endswith("src"):
                raise OSError(5, "I/O error")
            return real(path)
        with mock.patch.object(guard.os, "scandir", flaky):
            self.assertEqual(self.verdict(*T("grep -r x clean")), "blocked")
        self.assertEqual(self.verdict(*T("grep -r x clean")), "allowed")
        self.assertNotIn(VALUE, guard.check_tool_args("terminal", {"command": "grep -r x ."}) or "")


class EncodedForms(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(guard, "_load_values", return_value={"DRILL_FAKE_KEY": VALUE})
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def redacted(self, text):
        out = guard.on_transform_tool_result(result="output: " + text + " end")
        return out is not None and text not in out and VALUE not in out and "DRILL_FAKE_KEY redacted" in out

    def test_forms_redacted(self):
        raw = VALUE.encode()
        b64 = base64.b64encode(raw).decode()
        cases = {
            "verbatim": VALUE,
            "inside JSON": json.dumps({"k": VALUE}),
            "base64": b64,
            "base64 url-safe": base64.urlsafe_b64encode(b"\xfb\xff" + raw).decode(),
            "base64 of NAME=value line": base64.b64encode(b"DRILL_FAKE_KEY=" + raw + b"\n").decode(),
            "base64 at offset 1": base64.b64encode(b"x" + raw + b"yz").decode(),
            "base64 at offset 2": base64.b64encode(b"xy" + raw + b"z").decode(),
            "base64 of a tar-like stream": base64.b64encode(os.urandom(512) + raw + os.urandom(512)).decode(),
            "base64 wrapped at 64 columns": "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) if len(b64) > 64 else b64[:20] + "\n" + b64[20:],
            "hex": raw.hex(),
            "hex upper": raw.hex().upper(),
            "hex wrapped": raw.hex()[:30] + "\n" + raw.hex()[30:],
        }
        failed = [name for name, text in cases.items() if not self.redacted(text)]
        self.assertEqual(failed, [])

    def test_percent_encoding_redacted(self):
        value = "drill/synthetic+value=0123456789abcdef"
        with mock.patch.object(guard, "_load_values", return_value={"DRILL_FAKE_KEY": value}):
            for text in (urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value),
                         urllib.parse.quote(value, safe="").lower().replace("drill", "drill")):
                out = guard.on_transform_terminal_output(output="x " + text + " y")
                self.assertTrue(out is not None and "redacted" in out and text not in out, text)

    def test_deliberate_obfuscation_not_claimed(self):
        # KNOWN LIMIT: these pass through and the README says so.
        for text in (VALUE[::-1], " ".join(VALUE), VALUE.upper(), VALUE[:19]):
            self.assertIsNone(guard.on_transform_tool_result(result="output: " + text))

    def test_ordinary_text_untouched(self):
        for text in ("hello world", base64.b64encode(b"nothing secret here at all").decode(), "deadbeef" * 8):
            self.assertIsNone(guard.on_transform_tool_result(result=text))

    def _no_copy_left(self, value, text, hook=None):
        hook = hook or (lambda t: guard.on_transform_tool_result(result=t))
        with mock.patch.object(guard, "_load_values", return_value={"DRILL_FAKE_KEY": value}):
            out = hook(text)
            self.assertIsNotNone(out)
            flat = "".join(out.split())
            left = [f for f in guard.encoded_forms(value) if f in flat]
            self.assertEqual(left, [], "an encoded copy survived")
            self.assertNotIn(value, out)
            return out

    def test_01_mixed_wrapped_and_unwrapped(self):
        value = "synthetic-review-value-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        raw = value.encode()
        wrap = lambda t, n: "\n".join(t[i:i + n] for i in range(0, len(t), n))
        hooks = [lambda t: guard.on_transform_tool_result(result=t), lambda t: guard.on_transform_terminal_output(output=t),
                 lambda t: guard.on_transform_llm_output(response_text=t)]
        for enc in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(b"\xfb\xff\xfe" + raw).decode().rstrip("="),
                    raw.hex(), raw.hex().upper()):
            for n in (16, 60, 76):
                w = wrap(enc, n)
                for text in (enc + "\n---\n" + w, w + "\n---\n" + enc, enc + " " + enc + "\n" + w + "\n" + w,
                             "a " + w + " b " + enc + " c " + wrap(enc, 7)):
                    for hook in hooks:
                        out = self._no_copy_left(value, text, hook)
                        self.assertGreaterEqual(out.count("redacted (encoded)"), 2)

    def test_07_short_values_all_alignments(self):
        for value in ("AbCdEfGh", "AbCdEfGhI", "AbCdEfGhIj", "AbCdEfGhIjKlMnOp", "pässwörd", "ключ-ключ"):
            raw = value.encode("utf-8")
            self.assertGreaterEqual(len(raw), 8)
            for off in (0, 1, 2):
                for tail in (0, 1, 2):
                    stream = b"\x01" * off + raw + b"\x02" * tail
                    for enc in (base64.b64encode(stream).decode(), base64.urlsafe_b64encode(stream).decode()):
                        self._no_copy_left(value, "x " + enc + " y")
            self._no_copy_left(value, base64.b64encode(raw).decode()[:6] + "\n" + base64.b64encode(raw).decode()[6:])
            self._no_copy_left(value, raw.hex())

    def test_07_no_false_positives_on_random_text(self):
        import random
        rnd = random.Random(7)
        with mock.patch.object(guard, "_load_values", return_value={"A": "AbCdEfGh", "B": VALUE}):
            for _ in range(400):
                blob = base64.b64encode(bytes(rnd.getrandbits(8) for _ in range(rnd.randint(30, 300)))).decode()
                self.assertIsNone(guard.on_transform_tool_result(result=blob + " " + blob[::-1].lower()))

    def test_llm_output_hook(self):
        out = guard.on_transform_llm_output(response_text="here: " + base64.b64encode(VALUE.encode()).decode())
        self.assertTrue(out and "redacted (encoded)" in out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
