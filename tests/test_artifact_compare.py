"""Artifact comparison tests (contract artifact-compare-v1). Synthetic byte files and dummy helpers only.

    python tests/test_artifact_compare.py

Every "secret" here is made up in this file and every helper is a throwaway script that prints them.
No keychain, no real helper and no real credential is touched. Nothing here imports sqlite3.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import artifact_compare as ac  # noqa: E402
import history_scan as hs  # noqa: E402

CANARY = "neighbour-canary-text-4471"


def fake(i, n=48):
    """A made-up key body with upper, lower and digits."""
    raw = hashlib.sha256(b"c%d" % i).hexdigest() * 4
    return "".join(c.upper() if j % 3 == 0 else c for j, c in enumerate(raw))[:n - 2] + "Zq"


K1 = "sk-" + fake(1)                       # an sk- shaped value
K2 = "plain-token-" + fake(2, 30)          # no listed shape at all
K3 = "ghp_" + fake(3, 36)
OLD = "sk-" + fake(4)                      # in the files, not printed by the helper


class Home(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="sg-cmp-"))
        self.home = os.path.join(self.base, "home"); os.makedirs(self.home)
        self.db, self.wal = os.path.join(self.home, "state.db"), os.path.join(self.home, "state.db-wal")
        self.marker = os.path.join(self.base, "helper-ran")

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def put(self, db=None, wal=None):
        for path, data in ((self.db, db), (self.wal, wal)):
            if data is not None:
                with open(path, "wb") as fh:
                    fh.write(data)

    def helper(self, pairs=(), body=None, mode=0o700, name="helper.sh"):
        """A throwaway helper that leaves a marker when it runs and prints the given NAME=VALUE lines."""
        path = os.path.join(self.base, name)
        lines = ["#!/bin/sh", ": > %s" % shlex.quote(self.marker)]
        lines += [body] if body is not None else ["printf '%%s\\n' %s" % shlex.quote("%s=%s" % p) for p in pairs]
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(path, mode)
        return path

    def run_compare(self, values):
        fd = os.open(self.home, hs._DIR)
        try:
            return ac.compare(fd, values)
        finally:
            os.close(fd)

    def standard(self):
        self.put(db=b"\x00" * 100 + b'key "' + K1.encode() + b'" x' + K2.encode() + b"y role" + K1.encode() + b"\x00 old " + OLD.encode() + b" end",
                 wal=b"w " + K2.encode() + b" " + K2.encode() + b"\n")
        return {K1.encode(): ["OPENAI_API_KEY", "VOICE_KEY"], K2.encode(): ["OTHER_TOKEN"], K3.encode(): ["GITHUB_TOKEN"],
                b"short": ["SHORT"], b"some-long-value-under-a-bad-name": [None]}

    def by_names(self, res):
        return {tuple(s["names"]): (s["occurrences"]["state.db"], s["occurrences"]["state.db-wal"]) for s in res["secrets"]}


class Helper(Home):
    def test_output_is_parsed_like_the_dotenv_reader(self):
        path = self.helper(body="printf '%s\\n' 'A_KEY=value-one-0123456789' 'B_KEY=value-one-0123456789' 'C_KEY=\"quoted value 0123456789\"' "
                                "'D_KEY=' 'no equals sign here' '=nameless' 'lower=some-lowercase-named-value' 'E_KEY=has=equals=inside-0123' "
                                "\"F_KEY='single quoted 0123456789'\"; printf 'G_KEY=crlf-value-0123456789\\r\\n'")
        values, label = ac.run_helper(path)
        self.assertIsNone(label)
        self.assertEqual(values, {b"value-one-0123456789": ["A_KEY", "B_KEY"], b"quoted value 0123456789": ["C_KEY"],
                                  b"some-lowercase-named-value": [None], b"has=equals=inside-0123": ["E_KEY"],
                                  b"single quoted 0123456789": ["F_KEY"], b"crlf-value-0123456789": ["G_KEY"]})

    def test_helpers_that_are_refused_without_being_run(self):
        good = self.helper([("A_KEY", "value-one-0123456789")])
        cases = [("helper.sh", "helper_path_not_absolute"), (os.path.join(self.base, "missing"), "helper_unavailable"),
                 (self.base, "helper_not_a_regular_file"), (self.helper([], mode=0o720, name="g.sh"), "helper_writable_by_others"),
                 (self.helper([], mode=0o702, name="o.sh"), "helper_writable_by_others")]
        for path, want in cases:
            self.assertEqual(ac.run_helper(path), ({}, want), path)
        self.assertFalse(os.path.exists(self.marker))
        with mock.patch.object(os, "geteuid", lambda: os.stat(good).st_uid + 1):
            self.assertEqual(ac.run_helper(good), ({}, "helper_not_owned_by_you"))
        self.assertFalse(os.path.exists(self.marker))
        self.assertEqual(ac.run_helper(good)[1], None); self.assertTrue(os.path.exists(self.marker))

    def test_helpers_that_fail_time_out_or_print_too_much(self):
        text = CANARY + K1
        self.assertEqual(ac.run_helper(self.helper(body="echo %s >&2; printf 'A_KEY=%s\\n'; exit 3" % (text, K1))), ({}, "helper_failed"))
        self.assertEqual(ac.run_helper(self.helper(body="echo nothing useful")), ({}, "helper_printed_no_usable_value"))
        self.assertEqual(ac.run_helper(self.helper(body="exit 0")), ({}, "helper_printed_no_usable_value"))
        with mock.patch.object(ac, "HELPER_MAX_OUTPUT", 200):
            self.assertEqual(ac.run_helper(self.helper(body="printf 'A_KEY=%%s\\n' %s" % ("x" * 400))), ({}, "helper_output_too_large"))
        t0 = time.monotonic()
        with mock.patch.object(ac, "HELPER_TIMEOUT_S", 0.5):
            self.assertEqual(ac.run_helper(self.helper(body="printf 'A_KEY=%s\\n'; sleep 30" % K1)), ({}, "helper_timed_out"))
        self.assertLess(time.monotonic() - t0, 10)
        with mock.patch.object(ac, "MAX_VALUES", 3):
            values, label = ac.run_helper(self.helper([("K%d_KEY" % i, "value-number-%d-0123456789" % i) for i in range(6)]))
        self.assertEqual((len(values), label), (3, "value_limit_reached"))

    def test_the_helper_is_run_directly_with_no_shell_and_no_input(self):
        tricky = self.helper([("A_KEY", "value-one-0123456789")], name="has space; touch INJECTED.sh")
        real, seen = subprocess.Popen, []

        def popen(argv, **kw):
            seen.append((argv, kw.get("shell", False), kw.get("stdin"), kw.get("stderr")))
            return real(argv, **kw)
        with mock.patch.object(subprocess, "Popen", popen):
            values, label = ac.run_helper(tricky)
        self.assertEqual((values, label), ({b"value-one-0123456789": ["A_KEY"]}, None))
        self.assertEqual(seen, [([tricky], False, subprocess.DEVNULL, subprocess.DEVNULL)])
        self.assertFalse(os.path.exists(os.path.join(self.base, "INJECTED.sh")))


class Compare(Home):
    def test_counts_by_secret_and_classes_by_match(self):
        res = self.run_compare(self.standard())
        self.assertEqual(self.by_names(res), {("OPENAI_API_KEY", "VOICE_KEY"): (2, 0), ("OTHER_TOKEN",): (1, 2), ("GITHUB_TOKEN",): (0, 0),
                                              (): (0, 0)})                           # the value under a name that is not printed
        self.assertEqual(res["not_compared"], [{"names": ["SHORT"], "reason": "shorter_than_16_bytes"}])
        self.assertEqual((res["values_from_helper"], res["values_compared"], res["names_not_printed"]), (5, 4, 1))
        m = res["matches"]
        self.assertEqual((m["equals_a_current_secret"], m["no_current_secret"]),
                         ({"distinct": 1, "names": ["OPENAI_API_KEY", "VOICE_KEY"]}, {"distinct": 1, "names": []}))    # K1 twice is one string; OLD is the other
        self.assertEqual((m["contains_a_current_secret"]["distinct"], m["inside_a_current_secret"]["distinct"]), (0, 0))
        self.assertEqual((res["finished"], res["run"]), (True, []))

    def test_contains_and_inside_classes(self):
        longer = (K1 + "extraTAIL9").encode()                                  # the match runs on past the value
        self.put(db=b" " + longer + b" and " + K3.encode()[:30] + b" ")        # 30 bytes of K3 are not a gh match at all
        res = self.run_compare({K1.encode(): ["OPENAI_API_KEY"], K3.encode(): ["GITHUB_TOKEN"]})
        self.assertEqual(res["matches"]["contains_a_current_secret"], {"distinct": 1, "names": ["OPENAI_API_KEY"]})
        self.assertEqual(self.by_names(res)[("OPENAI_API_KEY",)], (1, 0))        # the value itself is there, inside the longer run
        self.put(db=b" " + K1.encode() + b" ")
        res = self.run_compare({(K1 + "-and-more-after-it").encode() + b"!": ["WRAPPED_KEY"]})   # the stored value is longer than the match
        self.assertEqual(res["matches"]["inside_a_current_secret"], {"distinct": 1, "names": ["WRAPPED_KEY"]})
        self.assertEqual(self.by_names(res)[("WRAPPED_KEY",)], (0, 0))

    def test_overlapping_and_boundary_length_values(self):
        self.put(db=b"x" + b"a" * 20 + b"x" + b"B" * 15 + b"x" + b"c" * 4096 + b"x" + b"d" * 4097)
        res = self.run_compare({b"a" * 16: ["SIXTEEN_A"], b"B" * 15: ["FIFTEEN_B"], b"c" * 4096: ["MAX_C"], b"d" * 4097: ["OVER_D"]})
        self.assertEqual(self.by_names(res), {("SIXTEEN_A",): (5, 0), ("MAX_C",): (1, 0)})       # five overlapping starts in twenty
        self.assertEqual(res["not_compared"], [{"names": ["OVER_D"], "reason": "longer_than_4096_bytes"},
                                               {"names": ["FIFTEEN_B"], "reason": "shorter_than_16_bytes"}])

    def test_results_do_not_depend_on_where_chunks_fall(self):
        vals = {("value-%03d-" % i + fake(i, 20 + i % 40)).encode(): ["V%d_KEY" % i] for i in range(30)}
        vals[b"L" * 700] = ["LONG_KEY"]
        keys, parts = list(vals), []
        for i in range(600):
            parts.append(b"\x00" * (1 + (i * 41) % 700)); parts.append(keys[i % len(keys)])
            if i % 7 == 0:
                parts.append(b" sk-" + fake(1000 + i).encode() + b" ")
        self.put(db=b"".join(parts))
        seen = set()
        for chunk, overlap in ((1024 * 1024, 1024), (4096, 1024), (1500, 1024), (1025, 1024), (2048, 300), (701, 300)):
            with mock.patch.object(hs, "CHUNK", chunk), mock.patch.object(hs, "OVERLAP", overlap):
                res = self.run_compare(vals)
            self.assertTrue(res["finished"], chunk)
            seen.add(json.dumps([res["secrets"], res["matches"]], sort_keys=True))
        self.assertEqual(len(seen), 1)
        got = self.by_names(res)
        for i in range(30):
            self.assertEqual(got[("V%d_KEY" % i,)], (20 if i < 11 else 19, 0), i)       # 600 placements over 31 values
        self.assertEqual(got[("LONG_KEY",)], (19, 0))
        self.assertEqual(res["matches"]["no_current_secret"]["distinct"], 86)

    def test_no_value_and_no_file_byte_reaches_any_output(self):
        vals = self.standard()
        self.put(db=CANARY.encode() + open(self.db, "rb").read() + CANARY.encode())
        res = self.run_compare(vals)
        allowed = set(re.findall(r"[A-Za-z_]+", ac.render(ac._new_result()) + json.dumps(ac._new_result()) + " ".join(ac.MATCH_CLASSES + ac.STATUS + ac.RUN_LABELS)
                                 + " FOUND found names occurrences reason distinct at least shorter_than_ bytes _bytes longer_than_ true false yes no name not printed"
                                 + " OPENAI_API_KEY VOICE_KEY OTHER_TOKEN GITHUB_TOKEN SHORT"))
        for out in (ac.render(res), json.dumps(res)):
            for secret in (K1, K2, K3, OLD, fake(1), fake(2, 30), fake(4), CANARY, "some-long-value", self.base, K1[:12], K2[-10:]):
                self.assertNotIn(secret, out)
            self.assertEqual(sorted(set(re.findall(r"[A-Za-z_]+", out)) - allowed), [])
            self.assertIsNone(re.search(r"[0-9a-f]{12,}", out))
        self.assertIn("FOUND  [OPENAI_API_KEY, VOICE_KEY]  state.db 2  state.db-wal 0", ac.render(res))

    def test_only_the_two_files_are_opened_and_nothing_is_written(self):
        vals = self.standard()
        with open(self.db + "-shm", "wb") as fh:
            fh.write(K1.encode())
        before = sorted((n, os.stat(os.path.join(self.home, n)).st_mtime_ns) for n in os.listdir(self.home))
        real, names = os.open, []

        def opening(path, flags, *a, **k):
            names.append((path, flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
            return real(path, flags, *a, **k)
        fd = real(self.home, hs._DIR)
        with mock.patch.object(os, "open", opening), mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no program may be started")):
            res = ac.compare(fd, vals)
        os.close(fd)
        self.assertEqual(names, [("state.db", 0), ("state.db-wal", 0)])
        self.assertEqual(sorted((n, os.stat(os.path.join(self.home, n)).st_mtime_ns) for n in os.listdir(self.home)), before)
        self.assertTrue(res["finished"]); self.assertNotIn("sqlite3", sys.modules)
        r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import artifact_compare; "
                            "print(sorted(m for m in sys.modules if m.split('.')[0] in ('sqlite3', '_sqlite3', 'socket', 'ssl', 'urllib', 'http')))" % REPO],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "[]")                                    # the tool loads no database or network module


class Status(Home):
    def acting(self, at_read, action):
        real, n = os.read, {"n": 0}

        def reading(fd, size):
            data = real(fd, size); n["n"] += 1
            if n["n"] == at_read:
                action()
            return data
        return mock.patch.object(os, "read", reading)

    def test_missing_database_symlink_and_changes(self):
        vals = {K1.encode(): ["OPENAI_API_KEY"]}
        res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"]), (False, ["database_absent"]))
        self.put(db=b"harmless " * 400)
        res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["files"]["state.db-wal"]["status"]), (True, "absent"))

        def create():
            with open(self.wal, "wb") as fh:
                fh.write(K1.encode())
        with self.acting(1, create):
            res = self.run_compare(vals)                                           # a log that appears is never a finished run
        self.assertEqual((res["finished"], res["run"], res["files"]["state.db-wal"]["change_observed"]), (False, ["source_change_observed"], True))
        os.remove(self.wal)

        def grow():
            with open(self.db, "ab") as fh:
                fh.write(b"more")
        with self.acting(1, grow):
            res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"]), (False, ["source_change_observed"]))
        target = os.path.join(self.base, "elsewhere")
        with open(target, "wb") as fh:
            fh.write(K1.encode())
        os.symlink(target, self.wal)
        res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["files"]["state.db-wal"]["status"], self.by_names(res)), (False, "symlink_not_followed", {("OPENAI_API_KEY",): (0, 0)}))

    def test_limits_late_deadline_and_errors(self):
        self.put(db=b"".join(b" sk-" + fake(i).encode() + b" " for i in range(40)) + K1.encode())
        vals = {K1.encode(): ["OPENAI_API_KEY"]}
        with mock.patch.object(ac, "MAX_DISTINCT", 10):
            res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"], res["distinct_counts_are_lower_bounds"]), (False, ["distinct_limit_reached"], True))
        self.assertEqual(self.by_names(res), {("OPENAI_API_KEY",): (2, 0)})            # part 1 stays exact: fake(1) is K1's body
        self.assertIn("at least ", ac.render(res))
        with mock.patch.object(ac, "TIME_BUDGET_S", -1.0):
            res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"]), (False, ["time_budget_reached"]))
        real_clock, real_fstat, state = time.monotonic, os.fstat, {"n": 0, "jump": 0.0}

        def fstat(fd):
            state["n"] += 1
            if state["n"] == 2:                                                     # the end check on the one file
                state["jump"] = 100000.0
            return real_fstat(fd)
        before = len(os.listdir("/dev/fd"))
        with mock.patch.object(os, "fstat", fstat), mock.patch("time.monotonic", lambda: real_clock() + state["jump"]):
            res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"], res["files"]["state.db"]["traversal_finished"]), (False, ["time_budget_reached"], True))
        self.assertEqual(len(os.listdir("/dev/fd")), before)
        for exc, label in ((OSError(5, CANARY + K1), None), (RuntimeError(CANARY + K1), "internal_error"), (KeyboardInterrupt(), "cancelled")):
            def reading(fd, size, exc=exc):
                raise exc
            with mock.patch.object(os, "read", reading):
                res = self.run_compare(vals)
            self.assertFalse(res["finished"])
            self.assertEqual(res["run"] if label else res["files"]["state.db"]["status"], [label] if label else "read_error")
            self.assertNotIn(CANARY, ac.render(res) + json.dumps(res)); self.assertNotIn(K1, ac.render(res) + json.dumps(res))
            self.assertEqual(len(os.listdir("/dev/fd")), before)


class Invocation(Home):
    def cli(self, *args, cmd=None):
        import pty
        master, slave = pty.openpty()
        p = subprocess.Popen(cmd or [sys.executable, os.path.join(REPO, "artifact_compare.py"), *args], stdin=slave, stdout=slave,
                             stderr=subprocess.PIPE, close_fds=True)
        os.close(slave); chunks = []
        while True:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        err = p.stderr.read().decode(); p.stderr.close(); os.close(master)
        return p.wait(timeout=60), b"".join(chunks).decode().replace("\r\n", "\n"), err

    def test_end_to_end_at_a_terminal_with_a_dummy_helper(self):
        self.standard()
        helper = self.helper([("OPENAI_API_KEY", K1), ("VOICE_KEY", K1), ("OTHER_TOKEN", K2), ("GITHUB_TOKEN", K3), ("SHORT", "abc")])
        code, out, err = self.cli("--home", self.home, "--secrets-command", helper)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("FOUND  [OPENAI_API_KEY, VOICE_KEY]  state.db 2  state.db-wal 0", out)
        self.assertIn("FOUND  [OTHER_TOKEN]  state.db 1  state.db-wal 2", out)
        self.assertIn("equals_a_current_secret      1  [OPENAI_API_KEY, VOICE_KEY]", out)
        self.assertIn("Comparison finished.", out)
        for secret in (K1, K2, K3, OLD):
            self.assertNotIn(secret, out)
        code, out, err = self.cli("--home", self.home, "--secrets-command", helper, "--json")
        self.assertEqual(json.loads(out)["matches"]["no_current_secret"]["distinct"], 1)

    def test_the_helper_is_not_run_unless_everything_else_is_in_order(self):
        self.standard()
        helper = self.helper([("OPENAI_API_KEY", K1)])
        r = subprocess.run([sys.executable, os.path.join(REPO, "artifact_compare.py"), "--home", self.home, "--secrets-command", helper],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stdout), (2, "")); self.assertIn("run this yourself at a terminal", r.stderr)   # not a terminal
        code, out, err = self.cli("--home", os.path.join(self.base, "missing"), "--secrets-command", helper)
        self.assertEqual(code, 1); self.assertIn("run notes: home_unavailable", out)                                     # no home
        code, out, err = self.cli("--home", self.home)
        self.assertEqual(code, 2)                                                                                        # no helper named
        wrapper = "import sqlite3, sys; sys.path.insert(0, %r); import artifact_compare as c; sys.exit(c.main(['--home', %r, '--secrets-command', %r]))" % (REPO, self.home, helper)
        code, out, err = self.cli(cmd=[sys.executable, "-c", wrapper])
        self.assertEqual(code, 1); self.assertIn("run notes: refused_sqlite_loaded_in_process", out)                     # sqlite3 loaded
        self.assertFalse(os.path.exists(self.marker))
        bad = self.helper([("OPENAI_API_KEY", K1)], mode=0o722, name="bad.sh")
        code, out, err = self.cli("--home", self.home, "--secrets-command", bad)
        self.assertEqual(code, 1); self.assertIn("run notes: helper_writable_by_others", out)
        self.assertIn("state.db: status not_reached, 0 of 0 byte(s) read", out)                                          # and then nothing is read
        self.assertFalse(os.path.exists(self.marker))
        code, out, err = self.cli("--home", self.home, "--secrets-command", helper)
        self.assertEqual(code, 0); self.assertTrue(os.path.exists(self.marker))

    def test_a_failed_helper_reads_nothing_and_a_moved_home_is_not_finished(self):
        self.standard()
        failing = self.helper(body="echo %s >&2; exit 2" % (CANARY + K1), name="fail.sh")
        code, out, err = self.cli("--home", self.home, "--secrets-command", failing)
        self.assertEqual((code, err), (1, "")); self.assertIn("run notes: helper_failed", out)
        self.assertIn("state.db: status not_reached, 0 of 0 byte(s) read", out); self.assertNotIn(CANARY, out)
        helper = self.helper([("OPENAI_API_KEY", K1)])
        os.makedirs(self.home + ".other")
        wrapper = ("import os, sys; sys.path.insert(0, %r); import artifact_compare as c\n"
                   "real, home, n = os.read, %r, {'n': 0}\n"
                   "def reading(fd, size):\n"
                   "    data = real(fd, size); n['n'] += 1\n"
                   "    if n['n'] == 1:\n"
                   "        os.rename(home, home + '.moved'); os.rename(home + '.other', home)\n"
                   "    return data\n"
                   "os.read = reading\n"
                   "sys.exit(c.main(['--home', home, '--secrets-command', %r, '--json']))\n" % (REPO, self.home, helper))
        code, out, err = self.cli(cmd=[sys.executable, "-c", wrapper])
        data = json.loads(out)
        self.assertEqual((code, data["finished"], data["run"]), (1, False, ["home_path_changed_during_run"]))
        self.assertEqual(data["secrets"][0]["occurrences"]["state.db"], 2)             # the folder opened at the start

    def test_documented_limits_and_labels_are_the_code(self):
        doc = ac.__doc__
        for word in ac.MATCH_CLASSES + ("shorter than 16 bytes", "longer than\n      4,096 bytes", "30 second", "1 MiB", "2,000\n  values",
                                        "900 second", "THIS TOOL HANDLES LIVE CREDENTIALS", "never through a shell", "Read the helper before naming it",
                                        "A count of zero does not show", "no_current_secret does not show a match is harmless"):
            self.assertIn(word, doc)
        self.assertEqual((ac.MIN_VALUE_BYTES, ac.MAX_VALUE_BYTES, ac.HELPER_TIMEOUT_S, ac.HELPER_MAX_OUTPUT, ac.MAX_VALUES, ac.TIME_BUDGET_S),
                         (16, 4096, 30.0, 1024 * 1024, 2000, 900.0))


if __name__ == "__main__":
    unittest.main(verbosity=1)
