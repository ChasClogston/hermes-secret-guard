"""Artifact comparison tests (contract artifact-compare-v2). Synthetic byte files and a dummy fetch program only.

    python tests/test_artifact_compare.py

Every "value" here is made up in this file. The program the tool would run on a Mac, /usr/bin/security, is
never run: the tests point the tool at a throwaway script that prints made-up values from a temp folder.
No keychain and no real credential is touched. Nothing here imports sqlite3.
"""
import hashlib
import pwd
import json
import os
import re
import select
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
    raw = hashlib.sha256(b"c%d" % i).hexdigest() * 4
    return "".join(c.upper() if j % 3 == 0 else c for j, c in enumerate(raw))[:n - 2] + "Zq"


K1 = "sk-" + fake(1)
K2 = "plain-token-" + fake(2, 30)
K3 = "ghp_" + fake(3, 36)
OLD = "sk-" + fake(4)                      # in the files, never supplied


def fds():
    return len(os.listdir("/dev/fd"))


def text_of(path):
    with open(path) as fh:
        return fh.read()


class Home(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="sg-cmp-"))
        self.home = os.path.join(self.base, "home"); os.makedirs(self.home)
        self.db, self.wal = os.path.join(self.home, "state.db"), os.path.join(self.home, "state.db-wal")
        self.store = os.path.join(self.base, "bin", "store"); os.makedirs(self.store)
        self.marker = os.path.join(self.base, "fetch-ran")
        self.tool = self.script("dummy-security", [
            "echo run >> %s" % shlex.quote(self.marker),
            '[ "$1" = find-generic-password ] && [ "$2" = -w ] && [ "$3" = -s ] && [ "$5" = -a ] && [ $# -eq 6 ] || exit 64',
            'f=%s/"$4"' % shlex.quote(self.store),
            '[ -f "$f" ] || { echo "%s no such item" >&2; exit 44; }' % CANARY,
            'cat "$f"; echo'])
        real = ac.check_tool
        self.patches = [mock.patch.object(ac, "SECURITY_BIN", self.tool), mock.patch.object(ac, "TOOL_OWNER_UID", os.geteuid()),
                        mock.patch.object(ac, "check_tool", lambda path, uid, stop="/": real(path, uid, stop=self.base))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.base, ignore_errors=True)

    def script(self, name, lines, mode=0o700):
        path = os.path.join(self.base, "bin", name)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n" + "\n".join(lines) + "\n")
        os.chmod(path, mode)
        return path

    def item(self, name, value):
        with open(os.path.join(self.store, name), "wb") as fh:
            fh.write(value if isinstance(value, bytes) else value.encode())

    def put(self, db=None, wal=None):
        for path, data in ((self.db, db), (self.wal, wal)):
            if data is not None:
                with open(path, "wb") as fh:
                    fh.write(data)

    def run_compare(self, values):
        fd = os.open(self.home, hs._DIR)
        try:
            return ac.compare(fd, values)
        finally:
            os.close(fd)

    def standard(self):
        self.put(db=b"\x00" * 100 + b'key "' + K1.encode() + b'" x' + K2.encode() + b"y role" + K1.encode() + b"\x00 old " + OLD.encode() + b" end",
                 wal=b"w " + K2.encode() + b" " + K2.encode() + b"\n")
        return {K1.encode(): ["openai-item", "voice-item"], K2.encode(): ["other-item"], K3.encode(): ["github-item"]}

    def by_names(self, res):
        return {tuple(s["names"]): (s["occurrences"]["state.db"], s["occurrences"]["state.db-wal"]) for s in res["supplied"]}

    def ran(self):
        return os.path.exists(self.marker) and len(text_of(self.marker).split())


class ToolTrust(unittest.TestCase):
    """check_tool on its own, on folders this test builds. `stop` limits how far up it looks, for the test only."""

    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="sg-tool-"))
        self.dir = os.path.join(self.base, "a", "b"); os.makedirs(self.dir)
        self.tool = os.path.join(self.dir, "tool")
        with open(self.tool, "w") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(self.tool, 0o755)
        self.uid = os.geteuid()

    def tearDown(self):
        os.chmod(self.dir, 0o755); os.chmod(os.path.dirname(self.dir), 0o755)
        shutil.rmtree(self.base, ignore_errors=True)

    def check(self, path=None, uid=None):
        return ac.check_tool(path or self.tool, self.uid if uid is None else uid, stop=self.base)

    def test_a_sound_tool_and_each_refusal(self):
        ident, label = self.check()
        st = os.stat(self.tool)
        self.assertEqual((ident, label), ((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns), None))
        self.assertEqual(self.check("tool"), (None, "tool_path_not_absolute"))
        self.assertEqual(self.check(self.dir + "/../b/tool"), (None, "tool_path_not_absolute"))       # not in plain form
        self.assertEqual(self.check(self.tool + "-missing"), (None, "tool_unavailable"))
        self.assertEqual(self.check(self.dir), (None, "tool_not_a_regular_file"))
        self.assertEqual(self.check(uid=self.uid + 1), (None, "tool_owner_not_allowed"))
        link = os.path.join(self.dir, "link"); os.symlink(self.tool, link)
        self.assertEqual(self.check(link), (None, "tool_is_a_link"))
        for mode in (0o775, 0o757):
            os.chmod(self.tool, mode)
            self.assertEqual(self.check(), (None, "tool_writable_by_others"), oct(mode))
        os.chmod(self.tool, 0o755)

    def test_every_folder_above_the_tool_is_checked(self):
        for folder in (self.dir, os.path.dirname(self.dir), self.base):
            for mode in (0o775, 0o757, 0o1777):                                      # a sticky shared folder is refused too
                os.chmod(folder, mode)
                self.assertEqual(self.check(), (None, "tool_folder_writable_by_others"), (folder, oct(mode)))
            os.chmod(folder, 0o755)
        self.assertEqual(self.check()[1], None)
        moved = os.path.join(self.base, "a", "real-b"); os.rename(self.dir, moved); os.symlink(moved, self.dir)
        self.assertEqual(self.check(), (None, "tool_is_a_link"))                     # a linked folder in the chain
        os.remove(self.dir); os.rename(moved, self.dir)
        real = os.lstat

        def lstat(path, *a, **k):
            st = real(path, *a, **k)
            if path == os.path.dirname(self.dir):                                   # pretend this folder belongs to someone else
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid + 1, st.st_gid, st.st_size, 0, 0, 0))
            return st
        with mock.patch.object(os, "lstat", lstat):
            self.assertEqual(self.check(), (None, "tool_folder_owner_not_allowed"))

    @unittest.skipUnless(sys.platform == "darwin", "the real program path exists only on macOS")
    def test_the_real_program_path_passes_the_check_on_a_mac(self):
        ident, label = ac.check_tool("/usr/bin/security", 0)                         # looked at, never run
        self.assertEqual(label, None); self.assertEqual(len(ident), 4)


class Fetch(Home):
    ENV = {"PATH": "/usr/bin:/bin", "HOME": "/", "USER": "u", "LANG": "C"}
    G = "g" * 16                                                                       # not hexadecimal

    def one(self, lines, name="t.sh"):
        before = fds()
        out = ac.fetch_one([self.script(name, lines)], self.ENV)
        self.assertEqual(fds(), before)
        with self.assertRaises(ChildProcessError):                                  # nothing left to reap
            os.waitpid(-1, os.WNOHANG)
        return out

    def test_value_newline_status_and_discarded_errors(self):
        self.assertEqual(self.one(["printf '%s\\n' " + shlex.quote(K1)]), (K1.encode(), "fetched"))
        self.assertEqual(self.one(["printf '%s' " + shlex.quote(K1)]), (K1.encode(), "fetched"))
        self.assertEqual(self.one(["printf '%s\\n\\n' " + shlex.quote(K1)]), ((K1 + "\n").encode(), "fetched"))      # only one newline is taken off
        self.assertEqual(self.one(["echo %s%s >&2" % (CANARY, K1), "printf '%s\\n' " + shlex.quote(K1), "exit 44"]), (None, "item_unavailable"))
        self.assertEqual(self.one(["printf '%s\\n' short"]), (b"short", "value_too_short"))     # bytes come back so names can be checked against them
        self.assertEqual(self.one(["printf '%s\\n' " + "g" * 15])[1], "value_too_short")
        self.assertEqual(self.one(["printf '%s\\n' " + "g" * 16])[1], "fetched")
        self.assertEqual(self.one(["printf '%s\\n' " + "g" * 4096])[1], "fetched")
        self.assertEqual(self.one(["printf '%s\\n' " + "g" * 4097])[1], "value_too_long")
        self.assertEqual(ac.fetch_one([os.path.join(self.base, "missing")], self.ENV), (None, "fetch_failed"))

    def test_output_that_may_be_a_hexadecimal_rendering_is_refused(self):
        """R2. The system program prints a value with a non-printing byte as hexadecimal digits, unmarked.
        An even run of hexadecimal digits is therefore refused, never decoded, and never compared."""
        secret = b"\x00made-up\xffbinary value 01"                                    # what would be stored
        for shown, status in ((secret.hex(), "value_format_ambiguous"),               # the program's rendering of it
                              ("0123456789abcdef0123", "value_format_ambiguous"),     # a genuine printable hexadecimal key: also refused
                              ("0123456789ABCDEF0123", "value_format_ambiguous"),
                              ("deadbeef" * 8, "value_format_ambiguous"),
                              ("0123456789abcdef012", "fetched"),                     # odd length cannot be that rendering
                              ("0123456789abcdefg0", "fetched"),                      # one character that is not hexadecimal
                              ("sk-0123456789abcdef0123", "fetched")):
            self.assertEqual(self.one(["printf '%s\\n' " + shown]), (shown.encode(), status), shown)
        self.item("bin-item", secret.hex()); self.item("plain-item", K1)
        self.put(db=b"x " + secret + b" y " + secret.hex().encode() + b" z")
        for names in (["bin-item"], ["plain-item", "bin-item"]):
            values, statuses, label = ac.fetch_items(names, "me")
            self.assertEqual((values, label, statuses[-1]), ({}, "an_item_could_not_be_used", "value_format_ambiguous"))
    def test_the_output_limit_is_enforced_while_reading(self):
        """C2. The program is stopped as soon as one byte past the limit arrives, while it is still running."""
        fill = "head -c %d /dev/zero | tr '\\000' g"
        self.assertEqual(self.one([fill % 8192]), (b"g" * 8192, "value_too_long"))      # exactly at the limit: read whole, then judged by length
        for lines, label in (([fill % 8193, "sleep 30"], "cap+1 then still running"), ([fill % 100000], "finite oversize"),
                             (["while :; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done"], "never stops")):
            t0 = time.monotonic()
            self.assertEqual(self.one(lines), (None, "fetch_output_too_large"), label)
            self.assertLess(time.monotonic() - t0, 5, label)
        real, real_select, watched, got = os.read, select.select, set(), []

        def selecting(r, w, x, t):
            watched.update(r); return real_select(r, w, x, t)

        def reading(fd, size):
            data = real(fd, size)
            if fd in watched:
                got.append((size, len(data)))
            return data
        with mock.patch.object(os, "read", reading), mock.patch.object(select, "select", selecting):
            self.one(["while :; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done"], name="u.sh")
        self.assertLessEqual(max(size for size, _n in got), ac.FETCH_MAX_OUTPUT + 1)    # never asks for more than one byte past the limit
        self.assertEqual(sum(n for _size, n in got), ac.FETCH_MAX_OUTPUT + 1)           # and takes in exactly that much before stopping

    def test_timeout_a_held_pipe_and_cancellation(self):
        with mock.patch.object(ac, "FETCH_TIMEOUT_S", 0.6):
            t0 = time.monotonic()
            self.assertEqual(self.one(["printf '%s\\n' " + shlex.quote(K1), "sleep 30"]), (None, "fetch_timed_out"))
            beat = os.path.join(self.base, "beat")
            # the program exits at once but leaves a child that holds the pipe open and keeps writing a heartbeat
            self.assertEqual(self.one(["( while :; do date +%%s%%N > %s; sleep 0.05; done ) &" % shlex.quote(beat),
                                       "sleep 0.2", "printf '%s\\n' " + shlex.quote(K1)], name="h.sh"), (None, "fetch_timed_out"))
            self.assertLess(time.monotonic() - t0, 8)
        self.assertTrue(os.path.exists(beat))                                          # it did run
        time.sleep(0.3); first = text_of(beat); time.sleep(0.5)
        self.assertEqual(text_of(beat), first)                                         # and it was stopped with the program
        real, n = select.select, {"n": 0}

        def selecting(*a):
            n["n"] += 1
            if n["n"] == 1:
                raise KeyboardInterrupt()
            return real(*a)
        before = fds()
        with mock.patch.object(select, "select", selecting), self.assertRaises(KeyboardInterrupt):
            ac.fetch_one([self.script("k.sh", ["printf '%s\\n' " + shlex.quote(K1), "sleep 30"])], self.ENV)
        self.assertEqual(fds(), before)
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)

    def test_exact_command_no_shell_small_environment(self):
        self.item("openai-item", K1)
        real, seen = subprocess.Popen, []

        def popen(argv, **kw):
            seen.append((list(argv), kw.get("shell", False), kw.get("stdin"), kw.get("stderr"), kw.get("cwd"), dict(kw.get("env") or {})))
            return real(argv, **kw)
        me = pwd.getpwuid(os.geteuid())
        with mock.patch.object(subprocess, "Popen", popen), mock.patch.dict(os.environ, {"SECRET_IN_ENV": CANARY, "HOME": "/somewhere", "USER": "other"}):
            values, statuses, label = ac.fetch_items(["openai-item"], "someone")
        self.assertEqual((values, statuses, label), ({K1.encode(): ["openai-item"]}, ["fetched"], None))
        self.assertEqual(seen, [([self.tool, "find-generic-password", "-w", "-s", "openai-item", "-a", "someone"], False, subprocess.DEVNULL,
                                 subprocess.DEVNULL, "/", {"PATH": "/usr/bin:/bin", "HOME": me.pw_dir, "USER": me.pw_name, "LANG": "C"})])   # from the account record, not the environment
        with mock.patch.object(pwd, "getpwuid", side_effect=KeyError("no record")):
            self.assertEqual(ac.fetch_items(["openai-item"], "someone"), ({}, ["not_fetched"], "user_record_unavailable"))

class Items(Home):
    def test_names_must_be_plain_and_unique(self):
        self.item("openai-item", K1)
        self.assertEqual(ac.fetch_items([], "me"), ({}, [], "no_item_named"))
        self.assertEqual(ac.fetch_items(["i%d" % i for i in range(9)], "me"), ({}, [], "too_many_items"))
        for bad in ("-w", "has space", "a/b", "../x", "", "x" * 65, "n\u00e9", "a;b", "$(id)"):
            self.assertEqual(ac.fetch_items(["openai-item", bad], "me"), ({}, [], "item_name_not_allowed"), bad)
            self.assertEqual(ac.fetch_items(["i%d" % i for i in range(8)] + [bad], "me"), ({}, [], "item_name_not_allowed"), bad)   # checked before the count
        self.assertEqual(ac.fetch_items(["openai-item", "openai-item"], "me"), ({}, [], "item_named_twice"))               # C3
        for bad in ("", "-a", "two words"):
            self.assertEqual(ac.fetch_items(["openai-item"], bad), ({}, [], "account_name_not_allowed"), bad)
        with mock.patch.object(ac, "disable_core_dumps", lambda: False):
            self.assertEqual(ac.fetch_items(["openai-item"], "me"), ({}, ["not_fetched"], "core_dump_limit_not_set"))
        self.assertFalse(self.ran())                                                                                       # nothing was run for any of these
    def test_all_or_nothing(self):
        self.item("openai-item", K1); self.item("short-item", "xyz"); self.item("long-item", "L" * 5000)
        for names, statuses in ((["openai-item", "absent-item"], ["fetched", "item_unavailable"]),
                                (["short-item", "openai-item"], ["value_too_short", "fetched"]),
                                (["long-item"], ["value_too_long"])):
            self.assertEqual(ac.fetch_items(names, "me"), ({}, statuses, "an_item_could_not_be_used"))    # by position, never by name
        self.item("voice-item", K1); self.item("other-item", K2)
        values, statuses, label = ac.fetch_items(["openai-item", "other-item", "voice-item"], "me")
        self.assertEqual((values, statuses, label), ({K1.encode(): ["openai-item", "voice-item"], K2.encode(): ["other-item"]}, ["fetched"] * 3, None))
    def test_a_typed_name_and_a_fetched_value_must_not_overlap(self):
        """R1 / C1. If a typed name carries anything that was fetched, or the reverse, the run stops, and what
        comes back names nothing: no name, and every item reset to not_fetched."""
        gone = ({}, "a_name_and_a_value_overlap")
        self.item("g" * 20, "g" * 16)                                                  # the value lies inside the name
        self.assertEqual(ac.fetch_items(["g" * 20], "me"), ({}, ["not_fetched"], "a_name_and_a_value_overlap"))
        self.item("openai-item", "prefix-openai-item-suffix-0123456789")               # the name lies inside the value
        self.assertEqual(ac.fetch_items(["openai-item"], "me")[::2], gone)
        self.item("first-item", K1); self.item("second-item", "zz-first-item-zz-0123456789")   # another item's name inside a value
        self.assertEqual(ac.fetch_items(["first-item", "second-item"], "me"), ({}, ["not_fetched"] * 2, "a_name_and_a_value_overlap"))
        self.item("xyz", "xyz")                                                        # a value too short to compare is still checked against names
        self.assertEqual(ac.fetch_items(["xyz"], "me"), ({}, ["not_fetched"], "a_name_and_a_value_overlap"))
        self.item("0123456789abcdef", "0123456789abcdef")                              # and so is one refused as ambiguous
        self.assertEqual(ac.fetch_items(["0123456789abcdef"], "me"), ({}, ["not_fetched"], "a_name_and_a_value_overlap"))
        self.assertEqual(ac.fetch_items(["first-item", "absent-item", "xyz"], "me"), ({}, ["not_fetched"] * 3, "a_name_and_a_value_overlap"))   # one failed item does not hide another's overlap
    def test_the_program_is_looked_at_before_and_after_every_run(self):
        """C4. Two looks at the path, and the result is discarded if the file changed in between."""
        self.item("openai-item", K1)
        real = ac.fetch_one

        def swapping(argv, env):
            out = real(argv, env)
            with open(self.tool + ".new", "w") as fh:
                fh.write("#!/bin/sh\necho replaced-value-0123456789\n")
            os.chmod(self.tool + ".new", 0o700); os.replace(self.tool + ".new", self.tool)
            return out
        with mock.patch.object(ac, "fetch_one", swapping):
            self.assertEqual(ac.fetch_items(["openai-item"], "me"), ({}, ["not_fetched"], "tool_changed_during_run"))
        os.chmod(self.tool, 0o770)
        self.assertEqual(ac.fetch_items(["openai-item"], "me")[2], "tool_writable_by_others")
        os.chmod(self.tool, 0o700); os.chmod(os.path.dirname(self.tool), 0o777)
        self.assertEqual(ac.fetch_items(["openai-item"], "me")[2], "tool_folder_writable_by_others")
        os.chmod(os.path.dirname(self.tool), 0o755)

    def test_core_dumps_are_off_here_and_in_what_is_started(self):
        code = ("import sys, resource, subprocess; sys.path.insert(0, %r); import artifact_compare as c; "
                "print(c.disable_core_dumps(), resource.getrlimit(resource.RLIMIT_CORE), "
                "subprocess.run(['/bin/sh', '-c', 'ulimit -c'], capture_output=True, text=True).stdout.strip())" % REPO)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "True (0, 0) 0")


class Compare(Home):
    def test_counts_by_item_and_classes_by_match(self):
        res = self.run_compare(self.standard())
        self.assertEqual(self.by_names(res), {("openai-item", "voice-item"): (2, 0), ("other-item",): (1, 2), ("github-item",): (0, 0)})
        m = res["matches"]
        self.assertEqual((m["equals_a_supplied_value"], m["no_supplied_value"]),
                         ({"distinct": 1, "names": ["openai-item", "voice-item"]}, {"distinct": 1, "names": []}))
        self.assertEqual((m["contains_a_supplied_value"]["distinct"], m["inside_a_supplied_value"]["distinct"]), (0, 0))
        self.assertEqual((res["finished"], res["run"], res["values_compared"]), (True, [], 3))

    def test_nothing_is_read_unless_every_value_is_usable(self):
        self.standard()
        real, n = os.read, {"n": 0}

        def reading(fd, size):
            n["n"] += 1; return real(fd, size)
        with mock.patch.object(os, "read", reading):
            for values in ({}, {b"short": ["x-item"]}, {K1.encode(): ["a-item"], b"L" * 5000: ["b-item"]}):
                res = self.run_compare(values)
                self.assertEqual((res["finished"], res["run"], res["files"]["state.db"]["status"]), (False, ["an_item_could_not_be_used"], "not_reached"))
        self.assertEqual(n["n"], 0)

    def test_class_precedence_when_a_match_relates_to_several_values(self):
        inner = K1[3:25].encode()                                                   # 22 bytes that lie inside K1
        longer = (K1 + "extraTAIL9").encode()
        self.put(db=b" " + K1.encode() + b" and " + longer + b" ")
        res = self.run_compare({K1.encode(): ["whole-item"], inner: ["inner-item"], (K1 + "extraTAIL9-and-more!").encode(): ["outer-item"]})
        m = res["matches"]
        self.assertEqual(m["equals_a_supplied_value"], {"distinct": 1, "names": ["whole-item"]})          # equal wins; inner-item and outer-item are not listed for it
        self.assertEqual(m["contains_a_supplied_value"], {"distinct": 1, "names": ["inner-item", "whole-item"]})   # the longer match: contains wins over inside
        self.assertEqual(m["inside_a_supplied_value"], {"distinct": 0, "names": []})
        self.put(db=b" " + K1.encode() + b" ")
        res = self.run_compare({(K1 + "-and-more-after-it!").encode(): ["wrapped-item"]})
        self.assertEqual(res["matches"]["inside_a_supplied_value"], {"distinct": 1, "names": ["wrapped-item"]})
        self.assertEqual(self.by_names(res)[("wrapped-item",)], (0, 0))
        self.assertIn("each in the first class that fits", ac.render(res))

    def test_overlapping_occurrences_and_boundary_lengths(self):
        self.put(db=b"x" + b"a" * 20 + b"x" + b"c" * 4096 + b"x")
        res = self.run_compare({b"a" * 16: ["sixteen-item"], b"c" * 4096: ["max-item"]})
        self.assertEqual(self.by_names(res), {("sixteen-item",): (5, 0), ("max-item",): (1, 0)})

    def test_results_do_not_depend_on_where_chunks_fall(self):
        vals = {("value-%03d-" % i + fake(i, 20 + i % 40)).encode(): ["v%d-item" % i] for i in range(30)}
        vals[b"L" * 700] = ["long-item"]
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
            seen.add(json.dumps([res["supplied"], res["matches"]], sort_keys=True))
        self.assertEqual(len(seen), 1)
        got = self.by_names(res)
        for i in range(30):
            self.assertEqual(got[("v%d-item" % i,)], (20 if i < 11 else 19, 0), i)
        self.assertEqual((got[("long-item",)], res["matches"]["no_supplied_value"]["distinct"]), ((19, 0), 86))

    def test_no_value_and_no_file_byte_reaches_any_output(self):
        vals = self.standard()
        with open(self.db, "rb") as fh:
            data = fh.read()
        self.put(db=CANARY.encode() + data + CANARY.encode())
        res = self.run_compare(vals)
        res["items"] = ["fetched"] * 4
        allowed = set(re.findall(r"[A-Za-z_]+", ac.render(ac._new_result()) + json.dumps(ac._new_result())
                                 + " ".join(ac.MATCH_CLASSES + ac.STATUS + ac.RUN_LABELS + ac.ITEM_STATUS)
                                 + " FOUND found not names occurrences distinct at least true false yes no item openai voice other github"
                                 + " every named was compared against both files in full"))
        for out in (ac.render(res), json.dumps(res)):
            for secret in (K1, K2, K3, OLD, fake(1), fake(2, 30), fake(4), CANARY, self.base, K1[:12], K2[-10:]):
                self.assertNotIn(secret, out)
            self.assertEqual(sorted(set(re.findall(r"[A-Za-z_]+", out)) - allowed), [])
            self.assertIsNone(re.search(r"[0-9a-f]{12,}", out))
        text = ac.render(res)
        self.assertIn("FOUND      [openai-item, voice-item]  state.db 2  state.db-wal 0", text)
        self.assertIn("not found  [github-item]  state.db 0  state.db-wal 0", text)
        self.assertIn("Nothing ties them to this home or to what Hermes uses", text)
        self.assertNotIn("current", text)

    def test_only_the_two_files_are_opened_and_nothing_is_started_or_written(self):
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
        self.assertEqual(r.stdout.strip(), "[]")


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
        vals = {K1.encode(): ["openai-item"]}
        res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"]), (False, ["database_absent"]))
        self.put(db=b"harmless " * 400)
        res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["files"]["state.db-wal"]["status"]), (True, "absent"))

        def create():
            with open(self.wal, "wb") as fh:
                fh.write(K1.encode())
        with self.acting(1, create):
            res = self.run_compare(vals)
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
        self.assertEqual((res["finished"], res["files"]["state.db-wal"]["status"], self.by_names(res)), (False, "symlink_not_followed", {("openai-item",): (0, 0)}))

    def test_limits_late_deadline_and_errors(self):
        self.put(db=b"".join(b" sk-" + fake(i).encode() + b" " for i in range(40)) + K1.encode())
        vals = {K1.encode(): ["openai-item"]}
        with mock.patch.object(ac, "MAX_DISTINCT", 10):
            res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"], res["distinct_counts_are_lower_bounds"]), (False, ["distinct_limit_reached"], True))
        self.assertEqual(self.by_names(res), {("openai-item",): (2, 0)})               # part 1 stays exact
        self.assertIn("at least ", ac.render(res))
        with mock.patch.object(ac, "TIME_BUDGET_S", -1.0):
            res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"]), (False, ["time_budget_reached"]))
        real_clock, real_fstat, state = time.monotonic, os.fstat, {"n": 0, "jump": 0.0}

        def fstat(fd):
            state["n"] += 1
            if state["n"] == 2:
                state["jump"] = 100000.0
            return real_fstat(fd)
        before = fds()
        with mock.patch.object(os, "fstat", fstat), mock.patch("time.monotonic", lambda: real_clock() + state["jump"]):
            res = self.run_compare(vals)
        self.assertEqual((res["finished"], res["run"], res["files"]["state.db"]["traversal_finished"]), (False, ["time_budget_reached"], True))
        self.assertEqual(fds(), before)
        for exc, label in ((OSError(5, CANARY + K1), None), (RuntimeError(CANARY + K1), "internal_error"), (KeyboardInterrupt(), "cancelled")):
            def reading(fd, size, exc=exc):
                raise exc
            with mock.patch.object(os, "read", reading):
                res = self.run_compare(vals)
            self.assertFalse(res["finished"])
            self.assertEqual(res["run"] if label else res["files"]["state.db"]["status"], [label] if label else "read_error")
            self.assertNotIn(CANARY, ac.render(res) + json.dumps(res)); self.assertNotIn(K1, ac.render(res) + json.dumps(res))
            self.assertEqual(fds(), before)


class Invocation(Home):
    def cli(self, *args, pre="", plain=False):
        """Run the command at a pseudo-terminal, pointed at the dummy fetch program unless `plain`."""
        import pty
        setup = "" if plain else ("real = c.check_tool\nc.SECURITY_BIN = %r\nc.TOOL_OWNER_UID = %d\n"
                                  "c.check_tool = lambda path, uid, stop='/': real(path, uid, stop=%r)\n" % (self.tool, os.geteuid(), self.base))
        code = "%simport os, sys; sys.path.insert(0, %r); import artifact_compare as c\n%ssys.exit(c.main(%r))\n" % (pre, REPO, setup, list(args))
        master, slave = pty.openpty()
        p = subprocess.Popen([sys.executable, "-c", code], stdin=slave, stdout=slave, stderr=subprocess.PIPE, close_fds=True)
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

    def test_end_to_end_at_a_terminal_with_the_dummy_program(self):
        self.standard()
        self.item("openai-item", K1); self.item("voice-item", K1); self.item("other-item", K2); self.item("github-item", K3)
        args = ["--home", self.home, "--keychain-account", "me"] + [x for n in ("openai-item", "voice-item", "other-item", "github-item") for x in ("--keychain-service", n)]
        code, out, err = self.cli(*args)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("item 1: fetched", out); self.assertIn("item 4: fetched", out)
        self.assertIn("FOUND      [openai-item, voice-item]  state.db 2  state.db-wal 0", out)
        self.assertIn("FOUND      [other-item]  state.db 1  state.db-wal 2", out)
        self.assertIn("not found  [github-item]  state.db 0  state.db-wal 0", out)
        self.assertIn("equals_a_supplied_value      1  [openai-item, voice-item]", out)
        self.assertIn("Comparison finished: every named item was compared against both files in full.", out)
        for secret in (K1, K2, K3, OLD):
            self.assertNotIn(secret, out)
        code, out, err = self.cli(*args, "--json")
        data = json.loads(out)
        self.assertEqual((data["matches"]["no_supplied_value"]["distinct"], data["finished"], self.ran()), (1, True, 8))    # four fetches per run

    def test_nothing_is_fetched_unless_everything_else_is_in_order(self):
        self.standard(); self.item("openai-item", K1)
        base = ["--home", self.home, "--keychain-service", "openai-item", "--keychain-account", "me"]
        r = subprocess.run([sys.executable, os.path.join(REPO, "artifact_compare.py"), *base], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stdout), (2, "")); self.assertIn("run this yourself at a terminal", r.stderr)      # not a terminal
        code, out, err = self.cli("--home", os.path.join(self.base, "missing"), *base[2:])
        self.assertEqual(code, 1); self.assertIn("run notes: home_unavailable", out)                                         # no home
        code, out, err = self.cli(*base, pre="import sqlite3\n")
        self.assertEqual(code, 1); self.assertIn("run notes: refused_sqlite_loaded_in_process", out)                         # sqlite3 loaded
        code, out, err = self.cli("--home", self.home)
        self.assertEqual(code, 1); self.assertIn("run notes: no_item_named", out)                                            # nothing named
        self.assertFalse(self.ran())
        code, out, err = self.cli(*base)
        self.assertEqual((code, self.ran()), (0, 1))

    def test_an_item_that_cannot_be_used_means_nothing_is_read(self):
        self.standard(); self.item("openai-item", K1)
        code, out, err = self.cli("--home", self.home, "--keychain-account", "me", "--keychain-service", "openai-item", "--keychain-service", "absent-item")
        self.assertEqual((code, err), (1, ""))
        self.assertIn("item 1: fetched", out); self.assertIn("item 2: item_unavailable", out)
        self.assertIn("run notes: an_item_could_not_be_used", out); self.assertIn("Nothing was read from the home.", out)
        self.assertIn("state.db: status not_reached, 0 of 0 byte(s) read", out)
        for text in (CANARY, K1, "openai-item", "absent-item"):                             # a run that stops early prints no name
            self.assertNotIn(text, out)

    def test_no_refusal_ever_repeats_what_was_typed_or_fetched(self):
        """R1. Every way of stopping early, as text and as JSON, on both output streams. A made-up value is used
        as a name, alone and beside other items, and its whole, its start and its end must appear nowhere."""
        self.standard()
        secret = "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh"                                               # 26 characters, allowed as a name
        self.item(secret, secret); self.item("openai-item", K1); self.item("xyz", "xyz")
        nine = [x for i in range(8) for x in ("--keychain-service", "i%d" % i)]
        cases = [
            (["--keychain-service", secret], "a_name_and_a_value_overlap"),
            (["--keychain-service", "openai-item", "--keychain-service", secret], "a_name_and_a_value_overlap"),
            (["--keychain-service", secret, "--keychain-service", "absent-item"], "a_name_and_a_value_overlap"),
            (["--keychain-service", "xyz"], "a_name_and_a_value_overlap"),
            (nine + ["--keychain-service", secret + "!bad"], "item_name_not_allowed"),      # too many and not allowed: neither is echoed
            (nine + ["--keychain-service", secret], "too_many_items"),
            (["--keychain-service", secret, "--keychain-service", secret], "item_named_twice"),
            (["--keychain-service", secret, "--keychain-account", "bad account " + secret], "account_name_not_allowed"),
            (["--keychain-service", "openai-item", "--keychain-service", "absent-" + secret], "an_item_could_not_be_used"),
        ]
        for extra, label in cases:
            for fmt in ([], ["--json"]):
                args = ["--home", self.home] + (["--keychain-account", "me"] if "--keychain-account" not in extra else []) + extra + fmt
                code, out, err = self.cli(*args)
                self.assertEqual(code, 1, (label, fmt))
                self.assertIn(label, out, (label, fmt))
                for text in (secret, secret[:10], secret[-10:], "openai-item", "absent-", K1, CANARY, "bad account"):
                    self.assertNotIn(text, out + err, (label, fmt, text))
                self.assertIn("0 of 0 byte(s) read" if not fmt else '"bytes_read": 0', out)
        for bad in (["--no-such-option-" + secret], ["--keychain-service"], ["--home", self.home, "stray-" + secret], ["--keychain-serv", secret]):
            code, out, err = self.cli(*bad, plain=True)                                     # a command line that cannot be parsed
            self.assertEqual((code, out), (2, ""), bad)
            self.assertEqual(err, "artifact_compare: the command line was not understood; nothing was run. See --help.\n")
        ran = self.ran()
        code, out, err = self.cli("--home", self.home, "--keychain-account", "me", "--keychain-serv", "openai-item")   # a shortened option is not accepted
        self.assertEqual((code, out, self.ran()), (2, "", ran))
    def test_what_the_program_prints_is_only_ever_a_value(self):
        """C1. Text shaped like NAME=VALUE from the fetch program is a value and nothing else. No name can come from it."""
        payload = "EVIL_NAME=" + fake(7, 30)
        self.item("openai-item", payload)
        self.put(db=b"x " + payload.encode() + b" y")
        code, out, err = self.cli("--home", self.home, "--keychain-account", "me", "--keychain-service", "openai-item", "--json")
        data = json.loads(out)
        self.assertEqual((code, data["supplied"]), (0, [{"names": ["openai-item"], "occurrences": {"state.db": 1, "state.db-wal": 0}}]))
        self.assertNotIn("EVIL_NAME", out); self.assertNotIn(fake(7, 30), out)

    def test_a_moved_home_is_not_finished(self):
        self.standard(); self.item("openai-item", K1)
        os.makedirs(self.home + ".other")
        pre = ("import os, stat\nreal_read, n = os.read, {'n': 0}\n"
               "def reading(fd, size):\n"
               "    data = real_read(fd, size)\n"
               "    if stat.S_ISREG(os.fstat(fd).st_mode):\n"                     # the first read of a database file, not of a fetch pipe
               "        n['n'] += 1\n"
               "        if n['n'] == 1:\n"
               "            os.rename(%r, %r); os.rename(%r, %r)\n"
               "    return data\n"
               "os.read = reading\n" % (self.home, self.home + ".moved", self.home + ".other", self.home))
        code, out, err = self.cli("--home", self.home, "--keychain-account", "me", "--keychain-service", "openai-item", "--json", pre=pre)
        data = json.loads(out)
        self.assertEqual((code, data["finished"], data["run"]), (1, False, ["home_path_changed_during_run"]))
        self.assertEqual(data["supplied"][0]["occurrences"]["state.db"], 2)

    def test_documented_limits_and_labels_are_the_code(self):
        doc = ac.__doc__
        for word in ac.MATCH_CLASSES + ("/usr/bin/security find-generic-password -w -s NAME -a ACCOUNT", "at most 8", "8,192 bytes", "10 second",
                                        "16 to 4,096 bytes", "900 second", "THIS TOOL HANDLES LIVE CREDENTIALS", "It runs no program you supply",
                                        "value_format_ambiguous", "never decodes hexadecimal", "Item names must not be secret", "it prints no name at all",
                                        "not at access-control lists", "searches its default list of\n      keychains", "not from the environment",
                                        "not a lock", "Core dumps are turned off", "never \"current secret\"", "ALL OR NOTHING",
                                        "the first class that fits", "A count of zero does not show", "no_supplied_value does not show a match is harmless"):
            self.assertIn(word, doc)
        self.assertEqual((ac.SECURITY_BIN if False else "/usr/bin/security", ac.MAX_ITEMS, ac.MIN_VALUE_BYTES, ac.MAX_VALUE_BYTES, ac.FETCH_MAX_OUTPUT,
                          ac.FETCH_TIMEOUT_S, ac.TIME_BUDGET_S), ("/usr/bin/security", 8, 16, 4096, 8192, 10.0, 900.0))
        r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import artifact_compare as c; print(c.SECURITY_BIN, c.TOOL_OWNER_UID)" % REPO],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "/usr/bin/security 0")                    # the unpatched program path and owner


if __name__ == "__main__":
    unittest.main(verbosity=1)
