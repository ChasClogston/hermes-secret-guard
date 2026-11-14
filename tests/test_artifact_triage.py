"""Artifact triage tests (contract artifact-triage-v1). Synthetic byte files only.

    python tests/test_artifact_triage.py

The scanner and the triage read bytes, so a state.db that is not a database places them exactly.
Nothing here imports sqlite3; the triage declines to run in a process that has.
"""
import hashlib
import json
import os
import re
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
import artifact_triage as at  # noqa: E402
import history_scan as hs  # noqa: E402

CANARY = "neighbour-canary-text-4471"


def uuid(i):
    h = hashlib.sha256(b"u%d" % i).hexdigest()
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:32])


def mixed(i, n=48):
    """Synthetic key body with upper, lower and digits. Not a credential."""
    raw = hashlib.sha256(b"m%d" % i).hexdigest() * 4
    return "".join(c.upper() if j % 3 == 0 else c for j, c in enumerate(raw))[:n - 2] + "Zq"


class Home(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="sg-tri-"))
        self.home = os.path.join(self.base, "home"); os.makedirs(self.home)
        self.db, self.wal = os.path.join(self.home, "state.db"), os.path.join(self.home, "state.db-wal")

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def put(self, db=None, wal=None):
        for path, data in ((self.db, db), (self.wal, wal)):
            if data is not None:
                with open(path, "wb") as fh:
                    fh.write(data)

    def run_triage(self):
        fd = os.open(self.home, hs._DIR)
        try:
            return at.triage(fd)
        finally:
            os.close(fd)

    def groups(self, res):
        return {(g["shape"], g["before"], g["word"], g["body"], g["length"]): (g["occurrences"], g["distinct"]) for g in res["groups"]}


SK, PROJ, ANT, GH = "openai-style sk-", "openai-style sk-proj-", "anthropic-style sk-ant-", "github token ghp_/gho_/ghu_/ghs_/ghr_"


class Classify(Home):
    def test_labels_for_each_kind_of_match(self):
        u = uuid(1).encode()
        cases = [
            (b"sk-" + u, b"\x00ta", (SK, "letter", "task", "uuid_layout", 36)),
            (b"sk-" + u, b"multita", (SK, "letter", "task", "uuid_layout", 36)),
            (b"sk-" + u, b"TA", (SK, "letter", "task", "uuid_layout", 36)),
            (b"sk-" + u, b"fla", (SK, "letter", "flask", "uuid_layout", 36)),
            (b"sk-" + u, b"de", (SK, "letter", "desk", "uuid_layout", 36)),
            (b"sk-" + u, b" a", (SK, "letter", "ask", "uuid_layout", 36)),
            (b"sk-" + u, b" ", (SK, "other_printable", "none", "uuid_layout", 36)),
            (b"sk-" + u, b"", (SK, "start_of_file", "none", "uuid_layout", 36)),
            (b"sk-" + u, b"x9", (SK, "digit", "none", "uuid_layout", 36)),
            (b"sk-" + u, b"a_", (SK, "hyphen_or_underscore", "none", "uuid_layout", 36)),
            (b"sk-" + u, b"\xff", (SK, "not_printable", "none", "uuid_layout", 36)),
            (b"sk-management-system-for-everything-ok", b"my-ta", (SK, "letter", "task", "lowercase_and_hyphens", 35)),
            (b"sk-" + b"1" * 40, b'"', (SK, "other_printable", "none", "digits_and_hyphens", 40)),
            (b"sk-" + b"abcdef0123" * 4, b'"', (SK, "other_printable", "none", "hex_and_hyphens", 40)),
            (b"sk-" + mixed(1).encode(), b'"', (SK, "other_printable", "none", "mixed_alphanumeric", 48)),
            (b"sk-proj-" + mixed(2).encode(), b"\x05", (PROJ, "not_printable", "none", "mixed_alphanumeric", 48)),
            (b"sk-ant-api03-" + mixed(3).encode(), b"r", (ANT, "letter", "none", "mixed_alphanumeric", 54)),
            (b"ghp_" + mixed(4, 36).encode(), b"user", (GH, "letter", "not_applicable", "mixed_alphanumeric", 36)),
            (b"AKIA" + b"QWERTYUIOPASDFGH", b" ", ("aws access key id AKIA", "other_printable", "not_applicable", "other", 16)),
            (b"zz-" + b"a" * 40, b" ", ("unrecognised", "other_printable", "not_applicable", "lowercase_and_hyphens", 43)),
        ]
        for token, left, want in cases:
            self.assertEqual(at.classify(token, left), want, (token[:10], left))
        for labels in (c[2] for c in cases):
            self.assertIn(labels[0], at.SHAPES); self.assertIn(labels[1], at.BEFORE)
            self.assertIn(labels[2], at.WORD_LABELS); self.assertIn(labels[3], at.BODY)


class EndToEnd(Home):
    def planted(self):
        u1, u2, k = uuid(1).encode(), uuid(2).encode(), b"sk-" + mixed(1).encode()
        return (b"\x00" * 300 + b"id ta" + b"sk-" + u1 + b"\x00" + b"again ta" + b"sk-" + u1 + b" " + b"ta" + b"sk-" + u2 + b'"'
                + b"\x01" * 50 + b'key="' + k + b'" and role' + k + b"\x00"
                + b"desk-" + b"lamp-and-chair-and-a-very-long-slug-name" + b" " + b"\x07" * 700)

    def test_groups_are_exact_and_agree_with_the_scanner(self):
        self.put(db=self.planted(), wal=b"wal ta" + b"sk-" + uuid(3).encode() + b"\n")
        res = self.run_triage()
        self.assertEqual(self.groups(res), {
            (SK, "letter", "task", "uuid_layout", 36): (4, 3),                       # three ids, one repeated, across both files
            (SK, "other_printable", "none", "mixed_alphanumeric", 48): (1, 1),       # the same key after a quote ...
            (SK, "letter", "none", "mixed_alphanumeric", 48): (1, 1),                # ... and glued to "role": two groups, each distinct 1
            (SK, "letter", "desk", "lowercase_and_hyphens", 40): (1, 1),
        })
        self.assertEqual((res["finished"], res["run"]), (True, []))
        self.assertEqual((res["files"]["state.db"]["matches"], res["files"]["state.db-wal"]["matches"]), (6, 1))
        r = subprocess.run([sys.executable, "-c", "import sys, json; sys.path.insert(0, %r); import history_scan as h; "
                            "print(json.dumps(h.scan_artifacts(%r)))" % (REPO, self.home)], capture_output=True, text=True)
        scan = json.loads(r.stdout)["artifacts"]
        self.assertEqual((scan["state.db"]["occurrences"]["provider-key-prefix"], scan["state.db-wal"]["occurrences"]["provider-key-prefix"]), (6, 1))

    def test_labels_do_not_depend_on_where_chunks_fall(self):
        """Many planted matches with their left context landing on every kind of seam."""
        parts = []
        for i in range(400):
            parts.append(b"\x00" * (3 + (i * 37) % 900))
            parts.append((b"ta", b" ", b"role", b"fla", b"x_")[i % 5] + b"sk-" + (uuid(i).encode() if i % 2 else mixed(i).encode()) + b"\x00")
        data = b"".join(parts)
        self.put(db=data)
        seen = set()
        for chunk, overlap in ((1024 * 1024, 1024), (4096, 1024), (1500, 1024), (1025, 1024), (2048, 300), (1333, 400)):
            with mock.patch.object(hs, "CHUNK", chunk), mock.patch.object(hs, "OVERLAP", overlap):
                res = self.run_triage()
            self.assertTrue(res["finished"])
            seen.add(json.dumps(res["groups"], sort_keys=True))
        self.assertEqual(len(seen), 1)
        g = self.groups(res)
        self.assertEqual(sum(v[0] for v in g.values()), 400)
        self.assertEqual(g[(SK, "letter", "task", "mixed_alphanumeric", 48)], (40, 40))
        self.assertEqual(g[(SK, "letter", "flask", "uuid_layout", 36)], (40, 40))

    def test_output_holds_only_fixed_labels_and_numbers(self):
        self.put(db=CANARY.encode() + self.planted() + CANARY.encode(), wal=b"x")
        res = self.run_triage()
        text, data = at.render(res), json.dumps(res)
        fixed = at.render(at._new_result()) + json.dumps(at._new_result()) + " ".join(at.SHAPES + at.BEFORE + at.WORD_LABELS + at.BODY + at.STATUS + at.RUN_LABELS)
        fixed += " shape before word body length occurrences distinct at least yes no finished true false"
        vocab = set(re.findall(r"[A-Za-z_]+", fixed))
        for out in (text, data):
            self.assertEqual(sorted(set(re.findall(r"[A-Za-z_]+", out)) - vocab), [])
            for secret in (CANARY, uuid(1), uuid(2), mixed(1), "lamp", self.base):
                self.assertNotIn(secret, out)
            self.assertIsNone(re.search(r"[0-9a-f]{12,}", out))                     # no digest, no hex run

    def test_only_the_two_files_are_opened_and_nothing_is_written(self):
        self.put(db=self.planted(), wal=b"w")
        with open(self.db + "-shm", "wb") as fh:
            fh.write(b"ta" + b"sk-" + uuid(9).encode())
        os.makedirs(os.path.join(self.home, "sessions"))
        before = sorted((n, os.stat(os.path.join(self.home, n)).st_mtime_ns) for n in os.listdir(self.home))
        real, names = os.open, []

        def opening(path, flags, *a, **k):
            names.append((path, flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
            return real(path, flags, *a, **k)
        fd = real(self.home, hs._DIR)
        with mock.patch.object(os, "open", opening):
            res = at.triage(fd)
        os.close(fd)
        self.assertEqual(names, [("state.db", 0), ("state.db-wal", 0)])
        self.assertEqual(sorted((n, os.stat(os.path.join(self.home, n)).st_mtime_ns) for n in os.listdir(self.home)), before)
        self.assertNotIn("sqlite3", sys.modules); self.assertTrue(res["finished"])


class Status(Home):
    def test_missing_database_symlink_and_absent_log(self):
        res = self.run_triage()
        self.assertEqual((res["finished"], res["run"], res["files"]["state.db"]["status"]), (False, ["database_absent"], "absent"))
        self.put(db=b"nothing here")
        res = self.run_triage()
        self.assertEqual((res["finished"], res["groups"], res["files"]["state.db-wal"]["status"]), (True, [], "absent"))
        target = os.path.join(self.base, "elsewhere")
        with open(target, "wb") as fh:
            fh.write(b"ta" + b"sk-" + uuid(1).encode())
        os.symlink(target, self.wal)
        res = self.run_triage()
        self.assertEqual((res["finished"], res["files"]["state.db-wal"]["status"], res["groups"]), (False, "symlink_not_followed", []))

    def test_a_change_during_the_read_is_not_a_finished_triage(self):
        self.put(db=b"\x00" * 5000 + b"ta" + b"sk-" + uuid(1).encode() + b" ")
        real, n = os.read, {"n": 0}

        def reading(fd, size):
            data = real(fd, size); n["n"] += 1
            if n["n"] == 1:
                with open(self.db, "ab") as fh:
                    fh.write(b"more")
            return data
        with mock.patch.object(os, "read", reading):
            res = self.run_triage()
        self.assertEqual((res["finished"], res["run"], res["files"]["state.db"]["change_observed"]), (False, ["source_change_observed"], True))

    def test_limits_and_late_deadline(self):
        self.put(db=b"".join(b" " + b"sk-" + mixed(i, 40 + i % 30).encode() + b" " for i in range(90)))
        with mock.patch.object(at, "MAX_GROUPS", 5):
            res = self.run_triage()
        self.assertEqual((res["finished"], res["run"], len(res["groups"])), (False, ["group_limit_reached"], 5))
        with mock.patch.object(at, "MAX_DISTINCT", 10):
            res = self.run_triage()
        self.assertEqual((res["finished"], res["run"], res["distinct_counts_are_lower_bounds"]), (False, ["distinct_limit_reached"], True))
        self.assertEqual(sum(g["occurrences"] for g in res["groups"]), 90)             # occurrences stay exact
        self.assertIn("distinct at least ", at.render(res))
        with mock.patch.object(at, "TIME_BUDGET_S", -1.0):
            res = self.run_triage()
        self.assertEqual((res["finished"], res["run"]), (False, ["time_budget_reached"]))
        real_clock, real_fstat, state = time.monotonic, os.fstat, {"n": 0, "jump": 0.0}

        def fstat(fd):                                                              # the end check is the second fstat on the one file
            state["n"] += 1
            if state["n"] == 2:
                state["jump"] = 100000.0
            return real_fstat(fd)
        before = len(os.listdir("/dev/fd"))
        with mock.patch.object(os, "fstat", fstat), mock.patch("time.monotonic", lambda: real_clock() + state["jump"]):
            res = self.run_triage()
        self.assertEqual((res["finished"], res["run"], res["files"]["state.db"]["traversal_finished"]), (False, ["time_budget_reached"], True))
        self.assertEqual(len(os.listdir("/dev/fd")), before)

    def test_errors_carry_no_text_and_leak_no_descriptor(self):
        self.put(db=b"ta" + b"sk-" + uuid(1).encode() + b" ", wal=b"w")
        real, before = os.read, len(os.listdir("/dev/fd"))
        for exc, label in ((OSError(5, CANARY), None), (RuntimeError(CANARY), "internal_error"), (KeyboardInterrupt(), "cancelled")):
            def reading(fd, size, exc=exc):
                raise exc
            with mock.patch.object(os, "read", reading):
                res = self.run_triage()
            self.assertFalse(res["finished"])
            if label:
                self.assertEqual(res["run"], [label])
            else:
                self.assertEqual(res["files"]["state.db"]["status"], "read_error")
            self.assertNotIn(CANARY, at.render(res) + json.dumps(res))
            self.assertEqual(len(os.listdir("/dev/fd")), before)


class Invocation(Home):
    def cli(self, *args):
        import pty
        master, slave = pty.openpty()
        p = subprocess.Popen([sys.executable, os.path.join(REPO, "artifact_triage.py"), *args], stdin=slave, stdout=slave,
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

    def test_needs_a_terminal_and_a_home(self):
        r = subprocess.run([sys.executable, os.path.join(REPO, "artifact_triage.py"), "--home", self.home], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stdout), (2, "")); self.assertIn("run this yourself at a terminal", r.stderr)
        code, out, err = self.cli()
        self.assertEqual(code, 2)

    def test_runs_at_a_terminal_and_fails_closed_on_a_missing_home(self):
        self.put(db=b"x ta" + b"sk-" + uuid(1).encode() + b" ")
        code, out, err = self.cli("--home", self.home)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("shape [openai-style sk-]  before letter  word task  body uuid_layout  length 36  occurrences 1  distinct 1", out)
        self.assertIn("Triage finished.", out)
        code, out, err = self.cli("--home", self.home, "--json")
        self.assertEqual(json.loads(out)["groups"][0]["word"], "task")
        code, out, err = self.cli("--home", os.path.join(self.base, "missing"))
        self.assertEqual(code, 1); self.assertIn("run notes: home_unavailable", out); self.assertIn("NOT FINISHED", out)

    def test_declines_when_sqlite_is_loaded(self):
        self.put(db=b"x")
        r = subprocess.run([sys.executable, "-c", "import sqlite3, os, sys, json; sys.path.insert(0, %r); import artifact_triage as t, history_scan as h; "
                            "fd = os.open(%r, h._DIR); print(json.dumps(t.triage(fd)))" % (REPO, self.home)], capture_output=True, text=True)
        res = json.loads(r.stdout)
        self.assertEqual((res["run"], res["finished"], res["files"]["state.db"]["bytes_read"]), (["refused_sqlite_loaded_in_process"], False, 0))

    def test_documented_labels_are_the_code_labels(self):
        doc = at.__doc__
        for word in at.BEFORE + at.BODY + at.WORDS:
            self.assertIn(word, doc)
        self.assertIn('contract "artifact-triage-v1"', doc); self.assertIn("never prints a matched byte", doc)
        self.assertEqual(len(at.SHAPE_PREFIXES), 8)                                   # the seven listed shapes, with sk-proj- named apart from sk-


if __name__ == "__main__":
    unittest.main(verbosity=1)
