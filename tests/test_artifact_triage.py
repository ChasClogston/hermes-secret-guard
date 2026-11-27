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
            (b"sk-" + u, b"\x00ta", (SK, "letter", "listed_word", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b"multita", (SK, "letter", "listed_word", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b"TA", (SK, "letter", "listed_word", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b"fla", (SK, "letter", "listed_word", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b"de", (SK, "letter", "listed_word", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b" a", (SK, "letter", "listed_word", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b" ", (SK, "other_printable", "none", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b"", (SK, "start_of_file", "none", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b"x9", (SK, "digit", "none", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b"a_", (SK, "hyphen_or_underscore", "none", "uuid_layout", "32_to_39")),
            (b"sk-" + u, b"\xff", (SK, "not_printable", "none", "uuid_layout", "32_to_39")),
            (b"sk-management-system-for-everything-ok", b"my-ta", (SK, "letter", "listed_word", "lowercase_and_hyphens", "32_to_39")),
            (b"sk-" + b"1" * 40, b'"', (SK, "other_printable", "none", "digits_and_hyphens", "40_to_63")),
            (b"sk-" + b"abcdef0123" * 4, b'"', (SK, "other_printable", "none", "hex_and_hyphens", "40_to_63")),
            (b"sk-" + mixed(1).encode(), b'"', (SK, "other_printable", "none", "mixed_alphanumeric", "40_to_63")),
            (b"sk-proj-" + mixed(2).encode(), b"\x05", (PROJ, "not_printable", "none", "mixed_alphanumeric", "40_to_63")),
            (b"sk-ant-api03-" + mixed(3).encode(), b"r", (ANT, "letter", "none", "mixed_alphanumeric", "40_to_63")),
            (b"ghp_" + mixed(4, 36).encode(), b"user", (GH, "letter", "not_applicable", "mixed_alphanumeric", "32_to_39")),
            (b"AKIA" + b"QWERTYUIOPASDFGH", b" ", ("aws access key id AKIA", "other_printable", "not_applicable", "other", "under_32")),
            (b"zz-" + b"a" * 40, b" ", ("unrecognised", "other_printable", "not_applicable", "lowercase_and_hyphens", "40_to_63")),
        ]
        for token, left, want in cases:
            self.assertEqual(at.classify(token, left), want, (token[:10], left))
        for labels in (c[2] for c in cases):
            self.assertIn(labels[0], at.SHAPES); self.assertIn(labels[1], at.BEFORE)
            self.assertIn(labels[2], at.WORD_LABELS); self.assertIn(labels[3], at.BODY); self.assertIn(labels[4], at.LENGTHS)
        for n, want in ((16, "under_32"), (31, "under_32"), (32, "32_to_39"), (39, "32_to_39"), (40, "40_to_63"), (63, "40_to_63"),
                        (64, "64_to_127"), (127, "64_to_127"), (128, "128_or_more"), (200, "128_or_more")):
            self.assertEqual(at.classify(b"sk-" + b"a" * n, b" ")[4], want, n)
        for w in at.WORDS:                                                           # which word it was is never a label
            self.assertEqual(at.classify(b"sk-" + b"a" * 40, w[:-2].encode())[2], "listed_word", w)
            self.assertNotIn(w, at.WORD_LABELS)


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
            (SK, "letter", "listed_word", "uuid_layout", "32_to_39"): (4, 3),                       # three ids, one repeated, across both files
            (SK, "other_printable", "none", "mixed_alphanumeric", "40_to_63"): (1, 1),       # the same key after a quote ...
            (SK, "letter", "none", "mixed_alphanumeric", "40_to_63"): (1, 1),                # ... and glued to "role": two groups, each distinct 1
            (SK, "letter", "listed_word", "lowercase_and_hyphens", "40_to_63"): (1, 1),
        })
        self.assertEqual((res["finished"], res["run"]), (True, []))
        self.assertEqual((res["files"]["state.db"]["matches"], res["files"]["state.db-wal"]["matches"]), (6, 1))
        r = subprocess.run([sys.executable, "-c", "import sys, json; sys.path.insert(0, %r); import history_scan as h; "
                            "print(json.dumps(h.scan_artifacts(%r)))" % (REPO, self.home)], capture_output=True, text=True)
        scan = json.loads(r.stdout)["artifacts"]
        self.assertEqual((scan["state.db"]["occurrences"]["provider-key-prefix"], scan["state.db-wal"]["occurrences"]["provider-key-prefix"]), (6, 1))

    def test_expected_totals_for_every_shape_written_out_by_hand(self):
        """Expected counts come from the listed shape rules worked by hand, not from the scanner's pattern:
        every prefix at its shortest and longest length, one past the longest, nested and run-on pairs."""
        A = b"a"
        cases = [  # (bytes, how many matches, expected shape of the first)
            (b"sk-" + A * 32, 1, SK), (b"sk-" + A * 200, 1, SK), (b"sk-" + A * 31, 0, None), (b"sk-" + A * 201, 0, None),
            (b"sk-proj-" + A * 32, 1, PROJ), (b"sk-proj-" + A * 200, 1, PROJ), (b"sk-proj-" + A * 201, 0, None),
            (b"sk-ant-" + A * 32, 1, ANT), (b"sk-ant-" + A * 200, 1, ANT), (b"sk-ant-" + A * 201, 0, None),
            (b"ghp_" + A * 36, 1, GH), (b"gho_" + A * 255, 1, GH), (b"ghu_" + A * 35, 0, None), (b"ghs_" + A * 256, 0, None), (b"ghr_" + A * 40, 1, GH),
            (b"github_pat_" + A * 60, 1, "github fine-grained github_pat_"), (b"github_pat_" + A * 255, 1, "github fine-grained github_pat_"),
            (b"github_pat_" + A * 59, 0, None), (b"github_pat_" + A * 256, 0, None),
            (b"xoxb-" + A * 20, 1, "slack token xox?-"), (b"xoxp-" + A * 200, 1, "slack token xox?-"), (b"xoxa-" + A * 19, 0, None),
            (b"xoxr-" + A * 201, 0, None), (b"xoxs-" + A * 50, 1, "slack token xox?-"),
            (b"AKIA" + b"Q" * 16, 1, "aws access key id AKIA"), (b"AKIA" + b"Q" * 15, 0, None), (b"AKIA" + b"Q" * 17, 0, None),
            (b"AIza" + A * 35, 1, "google api key AIza"), (b"AIza" + A * 34, 0, None), (b"AIza" + A * 36, 0, None),
            (b"sk-" + b"B" * 150 + b"ghp_" + A * 36, 1, SK),                        # a gh shape nested in one sk- run: one match
            (b"sk-" + A * 40 + b"sk-" + A * 40, 1, SK),                             # run-on sk- pair: one run of key characters, one match
            (b"ghp_" + A * 36 + b"ghp_" + A * 36, 1, GH),                           # run-on gh pair: the first is hidden by the second's underscore
            (b"sk-" + A * 40 + b" " + b"sk-" + A * 40, 2, SK),
        ]
        total = 0
        for i, (data, want, shape) in enumerate(cases):
            self.put(db=b"\x00" + data + b"\x00")
            res = self.run_triage()
            self.assertEqual(res["files"]["state.db"]["matches"], want, (i, data[:14], len(data)))
            self.assertEqual(sum(g["occurrences"] for g in res["groups"]), want, i)
            if want:
                self.assertEqual(res["groups"][0]["shape"], shape, i)
            total += want
        self.put(db=b"\x00".join(c[0] for c in cases) + b"\x00")                   # all together, at several chunk settings
        for chunk, overlap in ((1024 * 1024, 1024), (1500, 1024), (1025, 1024), (2048, 300)):
            with mock.patch.object(hs, "CHUNK", chunk), mock.patch.object(hs, "OVERLAP", overlap):
                self.assertEqual(self.run_triage()["files"]["state.db"]["matches"], total, chunk)

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
        self.assertEqual(g[(SK, "letter", "listed_word", "mixed_alphanumeric", "40_to_63")], (80, 80))    # after "ta" and after "fla"
        self.assertEqual(g[(SK, "letter", "listed_word", "uuid_layout", "32_to_39")], (80, 80))
        self.assertEqual(g[(SK, "letter", "none", "uuid_layout", "32_to_39")], (40, 40))                   # after "role"

    def test_output_holds_only_fixed_labels_and_numbers(self):
        self.put(db=CANARY.encode() + self.planted() + CANARY.encode(), wal=b"x")
        res = self.run_triage()
        text, data = at.render(res), json.dumps(res)
        fixed = at.render(at._new_result()) + json.dumps(at._new_result()) + " ".join(at.SHAPES + at.BEFORE + at.WORD_LABELS + at.BODY + at.LENGTHS + at.STATUS + at.RUN_LABELS)
        fixed += " shape before word body length occurrences distinct at least yes no finished true false"
        vocab = set(re.findall(r"[A-Za-z_]+", fixed))
        for out in (text, data):
            self.assertEqual(sorted(set(re.findall(r"[A-Za-z_]+", out)) - vocab), [])
            for secret in (CANARY, uuid(1), uuid(2), mixed(1), "lamp", self.base, "task", "desk"):
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

    def acting(self, at_read, action):
        """Patch os.read so that `action` runs right after the n-th read of the run."""
        real, n = os.read, {"n": 0}

        def reading(fd, size):
            data = real(fd, size); n["n"] += 1
            if n["n"] == at_read:
                action()
            return data
        return mock.patch.object(os, "read", reading)

    def test_a_log_that_appears_during_the_read_is_never_a_finished_triage(self):
        """T1. The log was absent when first looked at and exists at the end. It was never opened, so the
        result would silently leave out a file that is there."""
        self.put(db=b"harmless " * 400)

        def create():
            with open(self.wal, "wb") as fh:
                fh.write(b"x ta" + b"sk-" + uuid(1).encode() + b" ")
        with self.acting(1, create):
            res = self.run_triage()
        wal = res["files"]["state.db-wal"]
        self.assertEqual((res["finished"], res["run"]), (False, ["source_change_observed"]))
        self.assertEqual((wal["status"], wal["bytes_read"], wal["change_observed"]), ("absent", 0, True))
        os.remove(self.wal)
        res = self.run_triage()                                                     # an absent log that stays absent is normal
        self.assertEqual((res["finished"], res["run"], res["files"]["state.db-wal"]["change_observed"]), (True, [], False))

    def test_entry_changes_between_the_first_look_and_the_open(self):
        """T1. Each entry is looked at before it is opened. If it is gone, replaced or newly there by the
        time it is opened, the run is not finished."""
        payload = b"x ta" + b"sk-" + uuid(1).encode() + b" "
        real, n = hs._entry_identity, {"n": 0}

        def looking(action):
            def look(fd, name):
                out = real(fd, name); n["n"] += 1
                if n["n"] == 2:                                                     # both first looks are done; nothing is open yet
                    action()
                return out
            return mock.patch.object(hs, "_entry_identity", look)

        def replace_db():
            with open(self.db + ".new", "wb") as fh:
                fh.write(payload)
            os.replace(self.db + ".new", self.db)
        for action, db_status, wal_status in ((lambda: os.remove(self.db), "absent", "scanned"), (replace_db, "scanned", "scanned"),
                                              (lambda: os.remove(self.wal), "scanned", "absent")):
            n["n"] = 0
            self.put(db=payload, wal=b"w")
            with looking(action):
                res = self.run_triage()
            self.assertFalse(res["finished"], db_status)
            self.assertIn("source_change_observed", res["run"])
            self.assertEqual((res["files"]["state.db"]["status"], res["files"]["state.db-wal"]["status"]), (db_status, wal_status))
        n["n"] = 0
        self.put(db=payload)
        if os.path.exists(self.wal):
            os.remove(self.wal)

        def create_wal():
            with open(self.wal, "wb") as fh:
                fh.write(b"w")
        with looking(create_wal):                                                   # absent at the first look, there at the open
            res = self.run_triage()
        wal = res["files"]["state.db-wal"]
        self.assertEqual((res["finished"], wal["status"], wal["change_observed"]), (False, "scanned", True))

    def test_a_file_swapped_for_the_open_and_swapped_back_is_still_seen(self):
        """The entry names the same file at the first look and at the end, and a different file was opened
        in between. Only the comparison of the first look with the opened file can see that."""
        self.put(db=b"original " * 50)
        real_look, looks = hs._entry_identity, {"n": 0}

        def look(fd, name):
            out = real_look(fd, name); looks["n"] += 1
            if looks["n"] == 2:
                os.rename(self.db, self.db + ".keep")
                with open(self.db, "wb") as fh:
                    fh.write(b"x ta" + b"sk-" + uuid(1).encode() + b" ")
            return out
        with mock.patch.object(hs, "_entry_identity", look), self.acting(1, lambda: os.replace(self.db + ".keep", self.db)):
            res = self.run_triage()
        db = res["files"]["state.db"]
        self.assertEqual((res["finished"], res["run"], db["change_observed"], db["matches"]), (False, ["source_change_observed"], True, 1))

    def test_the_first_file_changing_while_the_second_is_read(self):
        self.put(db=b"d" * 3000, wal=b"w" * 3000)

        def touch_db():                                                             # read 1 is the whole db, read 2 the log
            with open(self.db, "ab") as fh:
                fh.write(b"more")
        with self.acting(2, touch_db):
            res = self.run_triage()
        self.assertEqual((res["finished"], res["run"]), (False, ["source_change_observed"]))
        self.assertEqual((res["files"]["state.db"]["change_observed"], res["files"]["state.db-wal"]["change_observed"]), (True, False))

    def test_an_end_check_that_cannot_be_made_is_not_a_pass(self):
        self.put(db=b"d" * 100)
        real, n = hs._entry_identity, {"n": 0}

        def look(fd, name):
            n["n"] += 1
            if n["n"] == 4:                                                         # the end look at the absent log
                raise RuntimeError(CANARY)
            return real(fd, name)
        before = len(os.listdir("/dev/fd"))
        with mock.patch.object(hs, "_entry_identity", look):
            res = self.run_triage()
        self.assertEqual((res["finished"], res["files"]["state.db-wal"]["change_observed"]), (False, True))
        self.assertNotIn(CANARY, at.render(res) + json.dumps(res)); self.assertEqual(len(os.listdir("/dev/fd")), before)

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
        lefts = (b" ", b"a", b"7", b"_", b"\x01", b"ta")                               # six "before"/"word" kinds, five length ranges
        self.put(db=b"".join(b"\x00" + lefts[i % 6] + b"sk-" + mixed(i, (33, 45, 70, 130, 36)[i % 5]).encode() + b" " for i in range(90)))
        with mock.patch.object(at, "MAX_GROUPS", 5):
            res = self.run_triage()
        self.assertEqual((res["finished"], res["run"], len(res["groups"])), (False, ["group_limit_reached"], 5))
        self.assertIn("groups left out are not shown at all", at.render(res))
        self.assertLess(sum(g["occurrences"] for g in res["groups"]), 90)             # the shown groups keep their own counts only
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
        self.assertIn("shape [openai-style sk-]  before letter  word listed_word  body uuid_layout  length 32_to_39  occurrences 1  distinct 1", out)
        self.assertIn("Triage finished.", out)
        code, out, err = self.cli("--home", self.home, "--json")
        self.assertEqual(json.loads(out)["groups"][0]["word"], "listed_word")
        code, out, err = self.cli("--home", os.path.join(self.base, "missing"))
        self.assertEqual(code, 1); self.assertIn("run notes: home_unavailable", out); self.assertIn("NOT FINISHED", out)

    def swapped(self, mode):
        """Run the command with the home path changed during the first read. T2."""
        other = self.home + ".other"; os.makedirs(other)
        with open(os.path.join(other, "state.db"), "wb") as fh:
            fh.write(b"a different harmless database")
        wrapper = ("import os, sys; sys.path.insert(0, %r); import artifact_triage as t\n"
                   "real, home, n = os.read, %r, {'n': 0}\n"
                   "def reading(fd, size):\n"
                   "    data = real(fd, size); n['n'] += 1\n"
                   "    if n['n'] == 1:\n"
                   "        os.rename(home, home + '.moved')\n"
                   "        if %r == 'replace':\n"
                   "            os.rename(home + '.other', home)\n"
                   "        if %r == 'restore':\n"
                   "            os.rename(home + '.moved', home)\n"
                   "    return data\n"
                   "os.read = reading\n"
                   "before = len(os.listdir('/dev/fd'))\n"
                   "code = t.main(['--home', home, '--json'])\n"
                   "sys.stderr.write('fds %%d' %% (len(os.listdir('/dev/fd')) - before))\n"
                   "sys.exit(code)\n" % (REPO, self.home, mode, mode))
        import pty
        master, slave = pty.openpty()
        p = subprocess.Popen([sys.executable, "-c", wrapper], stdin=slave, stdout=slave, stderr=subprocess.PIPE, close_fds=True)
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
        return p.wait(timeout=60), json.loads(b"".join(chunks).decode()), err

    def test_command_is_not_finished_when_the_home_path_changes(self):
        """T2. The reads stay in the folder opened at the start, and the result says the path moved."""
        payload = b"x ta" + b"sk-" + uuid(1).encode() + b" "
        for mode in ("replace", "missing"):                                         # another folder at the path; nothing at the path
            shutil.rmtree(self.base); os.makedirs(self.home)
            self.put(db=payload)
            code, data, err = self.swapped(mode)
            self.assertEqual((code, err), (1, "fds 0"), mode)
            self.assertEqual((data["finished"], data["run"]), (False, ["home_path_changed_during_run"]), mode)
            self.assertEqual(data["files"]["state.db"]["matches"], 1)               # the opened folder, not the swapped-in one
        shutil.rmtree(self.base); os.makedirs(self.home)
        self.put(db=payload)
        code, data, err = self.swapped("restore")                                   # moved and put back: not seen, and said so in the text
        self.assertEqual((code, data["finished"], data["run"], err), (0, True, [], "fds 0"))
        self.assertIn("a path re-pointed and restored\n  in between is not seen", at.__doc__)
        code, out, err = self.cli("--home", self.home)
        self.assertEqual(code, 0); self.assertNotIn("no longer points", out)

    def test_declines_when_sqlite_is_loaded(self):
        self.put(db=b"x")
        r = subprocess.run([sys.executable, "-c", "import sqlite3, os, sys, json; sys.path.insert(0, %r); import artifact_triage as t, history_scan as h; "
                            "fd = os.open(%r, h._DIR); print(json.dumps(t.triage(fd)))" % (REPO, self.home)], capture_output=True, text=True)
        res = json.loads(r.stdout)
        self.assertEqual((res["run"], res["finished"], res["files"]["state.db"]["bytes_read"]), (["refused_sqlite_loaded_in_process"], False, 0))

    def test_documented_labels_are_the_code_labels(self):
        doc = at.__doc__
        for word in at.BEFORE + at.BODY + at.WORDS + at.LENGTHS + at.WORD_LABELS:
            self.assertIn(word, doc)
        self.assertIn('contract "artifact-triage-v1"', doc); self.assertIn("No raw excerpt is printed", doc)
        for phrase in ("structural classifications only", "confirms a credential or clears one", "do not add up",
                       "WHAT THE OUTPUT STILL DISCLOSES", "groups left out are not represented at all"):
            self.assertIn(phrase, doc)
        self.assertNotIn("strong hint", doc)
        self.assertEqual(len(at.SHAPE_PREFIXES), 8)                                   # the seven listed shapes, with sk-proj- named apart from sk-


if __name__ == "__main__":
    unittest.main(verbosity=1)
