"""Database-artifact byte scan tests (contract artifact-bytes-v1). Synthetic databases only.

    python tests/test_artifact_scan.py

The test process builds fixtures with sqlite3. The scanner never loads sqlite3 and refuses to run
in a process that has, so every scan here runs in its own process, as the contract requires.
"""
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BODY = "Zq7Lm2Xc9Vb4Nn6Hh8Jj1Kk3Pp5Rr0TtWwYy"
NEIGHBOUR = "neighbour-canary-text-4471"
TITLE = "session-title-canary-9917"
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def key(i):
    """A distinct synthetic key in the ghp_ shape. Not a credential."""
    return "ghp_" + hashlib.sha256(b"k%d" % i).hexdigest()[:36]


RUNNER = r'''
import json, os, sys
opts = json.loads(os.environ.get("SG_TEST_OPTS", "{}"))
trace = []
if opts.get("audit"):
    def hook(event, args):
        if event in ("open", "import", "subprocess.Popen", "os.system", "socket.connect", "socket.bind", "mmap.__new__",
                     "sqlite3.connect", "os.remove", "os.rename", "os.truncate", "os.mkdir", "fcntl.flock", "fcntl.lockf", "fcntl.fcntl"):
            trace.append([event, [repr(a)[:300] for a in args[:3]]])
    sys.addaudithook(hook)                     # installed before the scanner module is executed
sys.path.insert(0, opts["repo"])
if opts.get("control") == "sqlite":            # positive control: a prohibited action must be visible
    import sqlite3
    c = sqlite3.connect(os.path.join(opts["home"], "state.db")); c.execute("select count(*) from messages").fetchall(); c.close()
if opts.get("control") == "write":
    open(os.path.join(opts["home"], "scanner-made-file"), "w").close()
import history_scan as hs
for k, v in opts.get("patch", {}).items():
    setattr(hs, k, v)
act = opts.get("action")
if act:
    real, state = os.read, {"n": 0}
    home = opts["home"]
    def acting(fd, n):
        data = real(fd, n)
        state["n"] += 1
        if state["n"] == act.get("at", 1):
            p = os.path.join(home, act["file"])
            kind = act["do"]
            if kind == "append":
                with open(p, "ab") as fh: fh.write(b"x" * 100)
            elif kind == "truncate":
                os.truncate(p, 10)
            elif kind == "rewrite":            # same size, new modification time
                st = os.stat(p); os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
            elif kind == "replace":
                with open(p + ".new", "wb") as fh: fh.write(open(p, "rb").read())
                os.replace(p + ".new", p)
            elif kind == "delete":
                os.remove(p)
            elif kind == "create":
                with open(p, "wb") as fh: fh.write(b"new log")
            elif kind == "interrupt":
                raise KeyboardInterrupt()
            elif kind == "crash":
                raise RuntimeError(act.get("text", "boom"))
            elif kind == "ioerror":
                raise OSError(5, act.get("text", "boom"))
        return data
    os.read = acting
res = hs.scan_artifacts(opts["home"], text_cancelled=bool(opts.get("text_cancelled")))
print(json.dumps({"res": res, "text": hs.render_artifacts(res), "trace": trace,
                  "mods": sorted(m for m in sys.modules if m.split(".")[0] in ("sqlite3", "_sqlite3", "socket", "subprocess", "mmap", "fcntl"))}))
'''


def run_scan(home, **opts):
    opts.update(home=home, repo=REPO)
    r = subprocess.run([sys.executable, "-c", RUNNER], capture_output=True, text=True, timeout=120,
                       env={**os.environ, "SG_TEST_OPTS": json.dumps(opts), "PYTHONDONTWRITEBYTECODE": "1"})
    if not r.stdout.strip():
        raise AssertionError("scanner process printed nothing; stderr: " + r.stderr[-800:])
    out = json.loads(r.stdout)
    out["stderr"] = r.stderr
    return out


def physical(path, pattern):
    """What a whole-file regex pass finds: the reference for the chunked scanner."""
    if not os.path.exists(path):
        return []
    with open(path, "rb") as fh:
        return [m.group(0) for m in re.finditer(pattern, fh.read())]


GH = re.compile(rb"(?<![A-Za-z0-9_-])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_-])")
SCHEMA = ("CREATE TABLE sessions (id TEXT PRIMARY KEY, display_name TEXT, system_prompt TEXT);"
          "CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, tool_calls TEXT, reasoning TEXT);")


class DB(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="sg-art-"))
        self.home = os.path.join(self.base, "home"); os.makedirs(self.home)
        self.db = os.path.join(self.home, "state.db")
        self.wal = self.db + "-wal"

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def connect(self, page_size=4096, encoding="UTF-8", wal=True, autocheckpoint=0):
        c = sqlite3.connect(self.db, isolation_level=None)
        c.execute("PRAGMA page_size=%d" % page_size); c.execute("PRAGMA encoding='%s'" % encoding)
        if wal:
            c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA wal_autocheckpoint=%d" % autocheckpoint)
        c.execute("PRAGMA secure_delete=OFF")
        c.executescript(SCHEMA)
        return c

    def plain_db(self, tokens=(), checkpoint=True):
        c = self.connect()
        for i, t in enumerate(tokens):
            c.execute("INSERT INTO messages(session_id, role, content) VALUES (?,?,?)", ("s", "user", "%s %s %s" % (NEIGHBOUR, t, NEIGHBOUR)))
        if checkpoint:
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        c.close()

    def arts(self, out):
        return out["res"]["artifacts"]["state.db"], out["res"]["artifacts"]["state.db-wal"]


class Oracle(DB):
    """The scanner must equal a whole-file regex pass (physical bytes). What it misses against the
    logical contents is listed by mechanism, and is never claimed as coverage."""

    def compare(self, out):
        db, wal = self.arts(out)
        for a, path in ((db, self.db), (wal, self.wal)):
            found = physical(path, GH)
            self.assertEqual(a["occurrences"]["provider-key-prefix"], len(found), path)
            self.assertEqual(a["distinct_candidates"]["provider-key-prefix"], len(set(found)), path)
        both = set(physical(self.db, GH)) | set(physical(self.wal, GH))
        self.assertEqual(out["res"]["combined_distinct_candidates"]["provider-key-prefix"], len(both))
        return both

    def logical(self):
        c = sqlite3.connect("file:%s?mode=ro" % self.db, uri=True)
        rows = [r[0] for r in c.execute("SELECT content FROM messages")]
        c.close()
        return {m.encode() for r in rows for m in re.findall(r"ghp_[A-Za-z0-9]{36}", r or "")}

    def test_short_rows_are_found_for_several_page_sizes(self):
        for page in (1024, 4096, 16384):
            shutil.rmtree(self.home); os.makedirs(self.home)
            c = self.connect(page_size=page)
            keys = [key(i) for i in range(40)]
            for k in keys:
                c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','user',?)", ("my key is %s ok" % k,))
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()
            out = run_scan(self.home)
            phys = self.compare(out)
            self.assertEqual(phys, {k.encode() for k in keys}, page)          # short local values: all physically whole
            self.assertTrue(out["res"]["scope_finished"], out["res"]["run"])

    def test_overflow_fragmentation_misses_values_that_are_logically_there(self):
        """A long value spills across overflow pages. A key that lands on a page seam is logically
        present and physically split. The miss is shown, counted, and not given a rate."""
        c = self.connect(page_size=1024)
        keys = [key(i) for i in range(400)]
        for i, k in enumerate(keys):                                            # slide each key across the seams
            c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','assistant',?)", ("a" * (600 + i * 7) + " " + k + " " + "b" * 3000,))
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()
        out = run_scan(self.home)
        phys = self.compare(out)
        logical = self.logical()
        self.assertEqual(len(logical), 400)
        missed = logical - phys
        self.assertTrue(missed, "expected at least one logically present key to be physically split")
        self.assertTrue(phys <= logical)
        self.assertEqual(len(missed) + len(phys & logical), 400)

    def test_utf16_text_is_not_matched_at_all(self):
        c = self.connect(encoding="UTF-16le")
        for i in range(20):
            c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','user',?)", ("key %s" % key(i),))
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()
        out = run_scan(self.home)
        self.assertEqual(self.compare(out), set())
        self.assertEqual(len(self.logical()), 20)                                # all there, none seen: stated exclusion

    def test_field_edge_bytes_can_hide_or_create_a_match(self):
        """A stored value sits between its neighbours' bytes. A message that is exactly a key comes right
        after the role text, so the detector's left boundary hides it. Two columns can also form a key."""
        c = self.connect()
        bare, spaced = key(1), key(2)
        accidental = "ghp_" + "A1b2C3d4E5" + "f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','user',?)", (bare,))            # the whole message is the key
        c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','user',?)", (" " + spaced + " ",))
        c.execute("INSERT INTO messages(session_id, role, content, tool_calls, reasoning) VALUES ('s',':',?,?,' ')",
                  (accidental[:14], accidental[14:]))                                                           # neither column is a key
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()
        out = run_scan(self.home)
        phys = self.compare(out)
        logical = self.logical()
        self.assertEqual(logical, {bare.encode(), spaced.encode()})
        self.assertIn(spaced.encode(), phys)
        self.assertNotIn(bare.encode(), phys)                    # logically present, physically hidden by the neighbour
        self.assertIn(accidental.encode(), phys)                 # physically matched, logically not a value at all

    def test_deleted_rows_can_still_match(self):
        c = self.connect()
        keys = [key(i) for i in range(30)]
        for k in keys:
            c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','user',?)", ("key %s end" % k,))
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        c.execute("DELETE FROM messages")
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()
        out = run_scan(self.home)
        phys = self.compare(out)
        self.assertEqual(self.logical(), set())                                   # logically gone
        self.assertTrue(phys, "expected deleted content to remain physically matchable in this fixture")

    def test_log_only_content_then_stale_frames(self):
        c = self.connect(autocheckpoint=0)
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        k = key(7)
        c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','user',?)", ("key %s end" % k,))
        out = run_scan(self.home)                                                # committed, not checkpointed: in the log only
        db, wal = self.arts(out)
        self.compare(out)
        self.assertEqual((db["occurrences"]["provider-key-prefix"], wal["occurrences"]["provider-key-prefix"]), (0, 1))
        c.execute("PRAGMA wal_checkpoint(PASSIVE)")                              # now in the database; the frame stays in the log
        out = run_scan(self.home)
        db, wal = self.arts(out)
        self.compare(out)
        self.assertEqual((db["occurrences"]["provider-key-prefix"], wal["occurrences"]["provider-key-prefix"]), (1, 1))
        self.assertEqual(out["res"]["combined_distinct_candidates"]["provider-key-prefix"], 1)     # one byte string, two places
        c.close()

    def test_fts_configurations_are_not_relied_on(self):
        for name, ddl in (("ordinary", "CREATE VIRTUAL TABLE f USING fts5(content)"),
                          ("external", "CREATE VIRTUAL TABLE f USING fts5(content, content='messages', content_rowid='id')"),
                          ("contentless", "CREATE VIRTUAL TABLE f USING fts5(content, content='')"),
                          ("trigram", "CREATE VIRTUAL TABLE f USING fts5(content, tokenize='trigram')")):
            shutil.rmtree(self.home); os.makedirs(self.home)
            c = self.connect()
            c.execute(ddl)
            k = key(3)
            c.execute("INSERT INTO messages(id, session_id, role, content) VALUES (1,'s','user',?)", ("key %s end" % k,))
            c.execute("INSERT INTO f(rowid, content) VALUES (1, ?)", ("key %s end" % k,))
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()
            out = run_scan(self.home)
            self.compare(out)                                                    # equal to the bytes, whatever the index stores
            self.assertEqual(out["res"]["combined_distinct_candidates"]["provider-key-prefix"], 1, name)


class Status(DB):
    def test_missing_database_is_not_a_finished_scan(self):
        out = run_scan(self.home)
        db, wal = self.arts(out)
        self.assertEqual((db["status"], wal["status"], out["res"]["scope_finished"]), ("absent", "absent", False))
        self.assertIn("database_absent", out["res"]["run"])
        self.assertFalse(db["traversal_finished"])

    def test_normal_log_absence_is_distinct_and_does_not_block(self):
        self.plain_db([key(1)])
        self.assertFalse(os.path.exists(self.wal) and os.path.getsize(self.wal))
        if os.path.exists(self.wal):
            os.remove(self.wal)
        out = run_scan(self.home)
        db, wal = self.arts(out)
        self.assertEqual((db["status"], db["traversal_finished"], wal["status"], wal["traversal_finished"]), ("scanned", True, "absent", False))
        self.assertEqual((out["res"]["scope_finished"], out["res"]["run"]), (True, []))
        self.assertFalse(out["res"]["snapshot_established"]); self.assertFalse(db["snapshot_established"])

    def test_log_without_a_database_is_never_a_pair(self):
        with open(self.wal, "wb") as fh:
            fh.write(("orphan %s " % key(5)).encode())
        out = run_scan(self.home)
        db, wal = self.arts(out)
        self.assertEqual((db["status"], wal["status"], wal["occurrences"]["provider-key-prefix"]), ("absent", "scanned", 1))
        self.assertFalse(out["res"]["scope_finished"])
        self.assertIn("not a verified pair", out["text"])

    def test_symlink_special_and_directory_entries(self):
        outside = os.path.join(self.base, "outside.db")
        with open(outside, "wb") as fh:
            fh.write(key(9).encode())
        cases = {"symlink_not_followed": lambda p: os.symlink(outside, p), "not_a_regular_file": lambda p: os.mkfifo(p)}
        for want, make in cases.items():
            for name in ("state.db", "state.db-wal"):
                shutil.rmtree(self.home); os.makedirs(self.home)
                if name != "state.db":
                    self.plain_db([key(1)])
                    if os.path.exists(self.wal):
                        os.remove(self.wal)
                make(os.path.join(self.home, name))
                out = run_scan(self.home)
                a = out["res"]["artifacts"][name]
                self.assertEqual((a["status"], a["bytes_read"], out["res"]["scope_finished"]), (want, 0, False), (want, name))
                self.assertEqual(out["res"]["combined_distinct_candidates"]["provider-key-prefix"], 0 if name == "state.db" else 1)
        shutil.rmtree(self.home); os.makedirs(os.path.join(self.home, "state.db"))
        out = run_scan(self.home)
        self.assertEqual((self.arts(out)[0]["status"], out["res"]["scope_finished"]), ("not_a_regular_file", False))

    @unittest.skipIf(IS_ROOT, "root ignores file modes")
    def test_unreadable_artifact(self):
        self.plain_db([key(1)])
        os.chmod(self.db, 0)
        out = run_scan(self.home)
        os.chmod(self.db, 0o600)
        self.assertEqual((self.arts(out)[0]["status"], out["res"]["scope_finished"]), ("unreadable", False))

    def test_shm_is_never_opened_and_no_file_is_created(self):
        c = self.connect(); c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','u',?)", (key(1),))
        before = sorted(os.listdir(self.home))
        self.assertIn("state.db-shm", before)
        out = run_scan(self.home, audit=True)
        opened = " ".join(a for ev, args in out["trace"] if ev == "open" for a in args)
        self.assertNotIn("-shm", opened)
        self.assertEqual(sorted(os.listdir(self.home)), before)
        c.close()

    def test_refuses_in_a_process_that_loaded_sqlite(self):
        self.plain_db([key(1)])
        out = run_scan(self.home, control="sqlite")
        self.assertEqual((out["res"]["run"], out["res"]["scope_finished"]), (["refused_sqlite_loaded_in_process"], False))
        self.assertEqual(self.arts(out)[0]["bytes_read"], 0)

    def test_skipped_when_the_text_scope_was_cancelled(self):
        self.plain_db([key(1)])
        out = run_scan(self.home, text_cancelled=True)
        self.assertEqual((out["res"]["run"], self.arts(out)[0]["status"]), (["skipped_text_scope_cancelled"], "not_reached"))


class Change(DB):
    def build(self):
        c = self.connect()
        for i in range(200):
            c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','u',?)", ("x" * 500 + key(i),))
        c.execute("PRAGMA wal_checkpoint(PASSIVE)")
        c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','u',?)", ("tail " + key(999),))
        c.close()
        if not os.path.exists(self.wal) or not os.path.getsize(self.wal):
            with open(self.wal, "wb") as fh:
                fh.write(b"w" * 9000)

    def test_every_observed_change_ends_not_finished(self):
        cases = [("state.db", "append", "grew"), ("state.db", "truncate", "shrank"), ("state.db", "rewrite", "modified"),
                 ("state.db", "replace", "replaced"), ("state.db", "delete", "disappeared"),
                 ("state.db-wal", "append", "grew"), ("state.db-wal", "truncate", "shrank"), ("state.db-wal", "rewrite", "modified"),
                 ("state.db-wal", "replace", "replaced"), ("state.db-wal", "delete", "disappeared")]
        for name, do, want in cases:
            shutil.rmtree(self.home); os.makedirs(self.home); self.build()
            out = run_scan(self.home, action={"file": name, "do": do, "at": 1}, patch={"CHUNK": 4096})
            a = out["res"]["artifacts"][name]
            self.assertIn(want, a["changes"], (name, do, a))
            self.assertTrue(a["source_change_observed"])
            self.assertEqual((out["res"]["scope_finished"], "source_change_observed" in out["res"]["run"]), (False, True), (name, do))
            self.assertIn("NOT FINISHED", out["text"])

    def test_a_log_that_appears_during_the_read(self):
        self.plain_db([key(1)])
        if os.path.exists(self.wal):
            os.remove(self.wal)
        out = run_scan(self.home, action={"file": "state.db-wal", "do": "create", "at": 1})
        wal = self.arts(out)[1]
        self.assertEqual((wal["status"], wal["changes"], out["res"]["scope_finished"]), ("absent", ["appeared"], False))

    def test_growth_is_not_chased(self):
        self.build()
        size = os.path.getsize(self.db)
        out = run_scan(self.home, action={"file": "state.db", "do": "append", "at": 1}, patch={"CHUNK": 4096})
        db = self.arts(out)[0]
        self.assertEqual((db["extent_bytes"], db["bytes_read"]), (size, size))    # the size at open, and no further

    def test_no_change_is_reported_without_claiming_stability(self):
        self.build()
        out = run_scan(self.home)
        self.assertTrue(out["res"]["scope_finished"])
        self.assertIn("Seeing no change does not show they were stable", out["text"])
        self.assertIn("snapshot established no", out["text"])


class Bounds(DB):
    def big(self):
        with open(self.db, "wb") as fh:
            fh.write(b"p" * 5000 + (" %s " % key(1)).encode() + b"q" * 5000)
        with open(self.wal, "wb") as fh:
            fh.write(b"r" * 3000 + (" %s " % key(2)).encode() + b"s" * 3000)
        return os.path.getsize(self.db), os.path.getsize(self.wal)

    def test_exact_byte_accounting_under_every_cap(self):
        d, w = self.big()
        for total in (1, 4000, d - 1, d, d + 1, d + w - 1, d + w):
            for chunk in (512, 4096):
                out = run_scan(self.home, patch={"ART_MAX_TOTAL_BYTES": total, "CHUNK": chunk, "OVERLAP": 64})
                db, wal = self.arts(out)
                read = db["bytes_read"] + wal["bytes_read"]
                self.assertEqual(read, min(total, d + w), (total, chunk))
                if total >= d + w:
                    self.assertTrue(out["res"]["scope_finished"])
                else:
                    self.assertEqual((out["res"]["scope_finished"], "total_byte_limit_reached" in out["res"]["run"]), (False, True), total)
        out = run_scan(self.home, patch={"ART_MAX_TOTAL_BYTES": d - 1})
        self.assertEqual(self.arts(out)[1]["status"], "not_reached")              # the log was starved, and says so

    def test_per_file_cap(self):
        d, w = self.big()
        out = run_scan(self.home, patch={"ART_MAX_FILE_BYTES": 4000, "CHUNK": 1000, "OVERLAP": 64})
        db, wal = self.arts(out)
        self.assertEqual((db["bytes_read"], db["traversal_finished"], wal["bytes_read"], wal["traversal_finished"]), (4000, False, 4000, False))
        self.assertEqual((out["res"]["scope_finished"], out["res"]["run"]), (False, ["truncated_at_size_cap"]))

    def test_time_budget_and_distinct_memory(self):
        d, w = self.big()
        out = run_scan(self.home, patch={"ART_TIME_BUDGET_S": -1.0})
        self.assertEqual((out["res"]["scope_finished"], out["res"]["run"]), (False, ["time_budget_reached"]))
        with open(self.db, "wb") as fh:
            fh.write(("\n".join(key(i) for i in range(60)) + "\n").encode())
        with open(self.wal, "wb") as fh:
            fh.write(("\n".join(key(i) for i in range(40, 100)) + "\n").encode())
        out = run_scan(self.home, patch={"ART_MAX_DISTINCT": 70})
        db, wal = self.arts(out)
        self.assertEqual((db["occurrences"]["provider-key-prefix"], wal["occurrences"]["provider-key-prefix"]), (60, 60))   # occurrences stay exact
        self.assertEqual(out["res"]["combined_distinct_candidates"]["provider-key-prefix"], 70)                             # one map for both
        self.assertEqual((out["res"]["scope_finished"], out["res"]["run"]), (False, ["distinct_limit_reached"]))
        out = run_scan(self.home)
        db, wal = self.arts(out)
        self.assertEqual((db["distinct_candidates"]["provider-key-prefix"], wal["distinct_candidates"]["provider-key-prefix"],
                          out["res"]["combined_distinct_candidates"]["provider-key-prefix"]), (60, 60, 100))


class NoLeak(DB):
    def vocabulary(self):
        r = subprocess.run([sys.executable, "-c", "import sys, json; sys.path.insert(0, %r); import history_scan as h; "
                            "r = {'artifacts': {n: h._new_artifact() for n in h.ARTIFACTS}, 'contract': h.ARTIFACT_CONTRACT, 'run': [], "
                            "'combined_distinct_candidates': {c: 0 for c in h.CATEGORIES if c != 'private-key-header'}, 'scope_finished': False, 'snapshot_established': False}; "
                            "print(h.render_artifacts(r) + json.dumps(r) + ' '.join(h.ARTIFACT_STATUS + h.ARTIFACT_CHANGES + h.ARTIFACT_RUN_LABELS))" % REPO],
                           capture_output=True, text=True)
        return set(re.findall(r"[A-Za-z_]+", r.stdout + " yes no true false finished partial inconclusive result")) | {"db", "wal", "state"}

    def test_output_is_counters_and_fixed_labels_on_every_path(self):
        c = self.connect()
        c.execute("INSERT INTO sessions(id, display_name, system_prompt) VALUES ('s', ?, ?)", (TITLE, "prompt " + NEIGHBOUR))
        for i in range(30):
            c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','u',?)", ("%s %s %s" % (NEIGHBOUR, key(i), NEIGHBOUR),))
        c.close()
        vocab = self.vocabulary()
        runs = [{}, {"action": {"file": "state.db", "do": "interrupt", "at": 1}}, {"action": {"file": "state.db", "do": "crash", "at": 1, "text": NEIGHBOUR + key(1)}},
                {"action": {"file": "state.db", "do": "ioerror", "at": 1, "text": NEIGHBOUR}}, {"action": {"file": "state.db-wal", "do": "delete", "at": 1}},
                {"patch": {"ART_MAX_TOTAL_BYTES": 100}}]
        for opts in runs:
            out = run_scan(self.home, **opts)
            text = out["text"] + json.dumps(out["res"])
            for secret in [NEIGHBOUR, TITLE, self.base, "ghp_"] + [key(i) for i in range(30)]:
                self.assertNotIn(secret, text, opts)
            self.assertEqual(sorted(set(re.findall(r"[A-Za-z_]+", text)) - vocab), [], opts)
            self.assertEqual(out["stderr"], "", opts)
            if opts:
                self.assertFalse(out["res"]["scope_finished"], opts)
        out = run_scan(self.home, action={"file": "state.db", "do": "ioerror", "at": 1})
        self.assertEqual(self.arts(out)[0]["status"], "read_error")


class Evidence(DB):
    """Layers of evidence for: no SQLite connection, no lock protocol, no write by the scanner. Each has a
    positive control, because an empty trace proves little. None of this is a sandbox."""

    def test_audit_layer_with_positive_controls(self):
        c = self.connect(); c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','u',?)", (key(1),))
        out = run_scan(self.home, audit=True)
        events = out["trace"]
        opens = [args for ev, args in events if ev == "open"]
        self.assertEqual([m for m in out["mods"] if "sqlite" in m], [])
        self.assertEqual([e for e, _a in events if e in ("sqlite3.connect", "subprocess.Popen", "os.system", "socket.connect", "os.remove", "os.rename", "os.truncate", "os.mkdir")], [])
        self.assertTrue(any("state.db" in a[0] for a in opens), "the hook must see the scanner's own artifact opens")
        for args in opens:
            if "state.db" in args[0]:
                flags = int(args[2]) if args[2].lstrip("-").isdigit() else 0
                self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND), 0, args)
        control = run_scan(self.home, audit=True, control="sqlite")
        self.assertTrue([e for e, _a in control["trace"] if e == "sqlite3.connect"], "control: a SQLite connection must be seen")
        control = run_scan(self.home, audit=True, control="write")
        self.assertTrue(any("scanner-made-file" in a[0] for ev, a in control["trace"] if ev == "open"), "control: a created file must be seen")
        os.remove(os.path.join(self.home, "scanner-made-file"))
        c.close()

    @unittest.skipUnless(shutil.which("strace"), "no operating-system tracer on this platform: this layer of evidence is absent here")
    def test_operating_system_trace_with_positive_control(self):
        c = self.connect(); c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','u',?)", (key(1),))
        self.addCleanup(c.close)                                  # kept open: the log and the -shm file exist while traced
        self.assertTrue(os.path.exists(self.db + "-shm"))

        def traced(**opts):
            opts.update(home=self.home, repo=REPO)
            log = os.path.join(self.base, "trace-%d.log" % time.monotonic_ns())
            subprocess.run(["strace", "-f", "-qq", "-o", log, "-e", "trace=open,openat,flock,fcntl,mmap,write,pwrite64,ftruncate,rename,renameat,renameat2,unlink,unlinkat,execve,clone,fork,vfork,socket,connect",
                            sys.executable, "-c", RUNNER], capture_output=True, text=True, timeout=120,
                           env={**os.environ, "SG_TEST_OPTS": json.dumps(opts), "PYTHONDONTWRITEBYTECODE": "1"})
            with open(log) as fh:
                return fh.read().splitlines()

        def facts(lines):
            fds, f = {}, {"opens": [], "write_opens": [], "shm": 0, "locks": 0, "maps": 0, "writes": 0, "children": 0, "sockets": 0, "sqlite_lib": 0}
            for ln in lines:
                body = re.sub(r"^\d+\s+", "", ln)
                m = re.match(r'open(?:at)?\((?:[^,]+, )?"([^"]*)", ([A-Z_|0-9]+)[^)]*\)\s+= (\d+)', body)
                if m:
                    path, flags, fd = m.group(1), m.group(2), m.group(3)
                    if "sqlite" in path.lower():
                        f["sqlite_lib"] += 1
                    if os.path.basename(path).startswith("state.db"):
                        f["opens"].append(os.path.basename(path)); fds[fd] = path
                        if re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND", flags):
                            f["write_opens"].append(path)
                        if path.endswith("-shm"):
                            f["shm"] += 1
                    continue
                m = re.match(r"(flock|fcntl|mmap|write|pwrite64|ftruncate)\((.*)", body)
                if m:
                    call, rest = m.group(1), m.group(2)
                    if call == "mmap":
                        fd = re.search(r", (\d+), ", rest.rsplit(")", 1)[0] + " ")
                        if fd and fd.group(1) in fds:
                            f["maps"] += 1
                    else:
                        fd = rest.split(",", 1)[0].strip()
                        if fd in fds:
                            if call in ("flock",) or (call == "fcntl" and re.search(r"F_(OFD_)?SETLKW?|F_GETLK", rest)):
                                f["locks"] += 1
                            if call in ("write", "pwrite64", "ftruncate"):
                                f["writes"] += 1
                if re.match(r"(execve|clone|fork|vfork)\(", body) and "= 0" not in body[:0]:
                    f["children"] += 1
                if re.match(r"(socket|connect)\(", body):
                    f["sockets"] += 1
            return f
        scan = facts(traced())
        self.assertEqual(sorted(set(scan["opens"])), ["state.db", "state.db-wal"])       # the tracer sees the scanner's opens
        self.assertEqual((scan["write_opens"], scan["shm"], scan["locks"], scan["maps"], scan["writes"], scan["sockets"], scan["sqlite_lib"]),
                         ([], 0, 0, 0, 0, 0, 0))
        self.assertEqual(scan["children"], 1)                                             # the traced interpreter itself, and nothing else
        control = facts(traced(control="sqlite"))                                         # positive control: SQLite on the same files
        self.assertTrue(control["locks"] > 0 and control["sqlite_lib"] > 0, control)
        self.assertTrue(control["write_opens"] or control["shm"], control)

    def test_writer_is_measured_against_a_baseline(self):
        """A concurrent synthetic writer, with and without the scanner. Numbers are reported, not asserted
        equal: this is a measurement, and it is not proof of non-interference."""
        c = self.connect(autocheckpoint=0)
        for i in range(300):
            c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','u',?)", ("x" * 2000 + key(i),))

        def burst():
            errors, busy, t0 = 0, 0, time.monotonic()
            for i in range(120):
                try:
                    c.execute("INSERT INTO messages(session_id, role, content) VALUES ('s','u',?)", ("y" * 800,))
                    if i % 20 == 19:
                        busy += c.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()[0]
                except sqlite3.Error:
                    errors += 1
            return errors, busy, time.monotonic() - t0
        base = burst()
        scanners = [subprocess.Popen([sys.executable, "-c", RUNNER], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env={**os.environ, "SG_TEST_OPTS": json.dumps({"home": self.home, "repo": REPO}), "PYTHONDONTWRITEBYTECODE": "1"})
                    for _ in range(3)]
        with_scan = burst()
        results = [json.loads(p.communicate(timeout=120)[0]) for p in scanners]
        self.assertEqual((base[0], base[1], with_scan[0], with_scan[1]), (0, 0, 0, 0))   # no writer error, no blocked checkpoint
        self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok")       # a check of the fixture, not a claim by the scanner
        sys.stderr.write("\n[measurement] writer burst: %.3fs alone, %.3fs with 3 scanners; scans finished: %s\n"
                         % (base[2], with_scan[2], [r["res"]["scope_finished"] for r in results]))
        c.close()


class Invocation(DB):
    def cli(self, *args):
        import pty
        cmd = [sys.executable, os.path.join(REPO, "history_scan.py"), *args]
        master, slave = pty.openpty()
        p = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=subprocess.PIPE, close_fds=True)
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

    def test_default_run_opens_no_database_content(self):
        self.plain_db([key(1)])
        code, out, err = self.cli("--home", self.home)
        self.assertEqual((code, err), (0, ""))
        self.assertNotIn("artifact", out.lower())
        self.assertIn("NOT SCANNED: the session database (state.db) [present_not_scanned]", out)
        code, out, err = self.cli("--home", self.home, "--json")
        data = json.loads(out)
        self.assertNotIn("artifact_scope", data); self.assertIn("kinds", data)       # text-v1 output is unchanged

    def test_the_switch_adds_the_artifact_scope_after_text_with_separate_status(self):
        self.plain_db([key(1)])
        os.makedirs(os.path.join(self.home, "logs"))
        with open(os.path.join(self.home, "logs", "agent.log"), "w") as fh:
            fh.write("log %s\n" % key(2))
        code, out, err = self.cli("--home", self.home, "--database-artifacts")
        self.assertEqual((code, err), (0, ""))
        self.assertLess(out.index("Text scope finished."), out.index("Database-artifact byte scan"))
        self.assertIn("Artifact scope finished.", out); self.assertIn("Both scopes finished.", out)
        code, out, err = self.cli("--home", self.home, "--database-artifacts", "--json")
        data = json.loads(out)
        self.assertEqual((data["complete"], data["text_scope"]["complete"], data["artifact_scope"]["scope_finished"]), (True, True, True))
        self.assertEqual(data["text_scope"]["distinct_candidates"]["provider-key-prefix"], 1)      # text counts stay separate
        self.assertEqual(data["artifact_scope"]["combined_distinct_candidates"]["provider-key-prefix"], 1)
        os.remove(self.db)
        code, out, err = self.cli("--home", self.home, "--database-artifacts")
        self.assertEqual(code, 1)
        self.assertIn("Text scope finished.", out); self.assertIn("Artifact scope NOT FINISHED", out); self.assertIn("NOT both finished", out)

    def test_documented_limits_are_the_code_limits(self):
        r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import history_scan as h; "
                            "print(h.ART_MAX_FILE_BYTES, h.ART_MAX_TOTAL_BYTES, h.ART_MAX_DISTINCT, h.ART_TIME_BUDGET_S, h.TIME_BUDGET_S); print(h.__doc__)" % REPO],
                           capture_output=True, text=True)
        first, doc = r.stdout.split("\n", 1)
        self.assertEqual(first.split(), [str(4 * 1024 ** 3), str(6 * 1024 ** 3), "200000", "600.0", "120.0"])
        for phrase in ("4 GiB per file, 6 GiB for both", "200,000 distinct candidates for both together", "720 seconds at most",
                       "NOT a read of the conversations", "state.db-shm is never read", "refuses to run in a process that has loaded sqlite3",
                       "a log reset and regrown to the same size can go unseen"):
            self.assertIn(phrase, doc)


if __name__ == "__main__":
    unittest.main(verbosity=1)
