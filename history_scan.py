"""Summary-only scan of one Hermes home's text records for secret-shaped text. Read-only.

    python3 history_scan.py --home /path/to/one/hermes/home

Run it yourself, at a terminal. It prints counters and fixed labels and nothing else: no source
text, file name, path, offset, digest or error message taken from input. It writes no file.

COVERAGE CONTRACT "text-v1" (Hermes 0.23, source commit 3b4215785882)
  transcripts   <home>/sessions/*.jsonl and *.json      (direct entries only)
  logs          <home>/logs/*.log and *.log.N           (direct entries only)

NOT COVERED, and said so on every run
  - the session database (state.db), where Hermes keeps most conversation history
  - every other file and folder in the home, and every subfolder of the two above
  - binary formats, archives, compressed files
  - secrets in any encoded or transformed form
  - assignments to secret-looking names, and generic high-entropy strings
  - values registered with Secret Guard (that would need the keychain; this tool has no access)

OPTIONAL SECOND SCOPE, off unless you ask: --database-artifacts   (contract "artifact-bytes-v2")
  After the text scope, also read two files of the home as plain bytes: state.db and state.db-wal.
  This is NOT a read of the conversations. It looks for contiguous secret-shaped byte strings in
  two database files, with no SQLite involved: no connection, no lock protocol, and no write to
  the database or its side files by this tool. state.db-shm is never read.
    - A match is physical neighbouring bytes, not a stored value. A value split across cells,
      overflow pages or log frames is not put back together. UTF-16 text is not matched.
      Neighbouring bytes can hide, shorten or lengthen a match, or form an accidental one.
    - Matches can come from deleted, superseded or uncommitted content. They are not row counts.
    - The two files are never read as a coordinated snapshot, and are never presented as a pair.
      Any change seen while reading makes the artifact scope not finished. Seeing no change does
      not show the files were stable: a log reset and regrown to the same size can go unseen.
    - Each file is read up to its size when opened; a growing log is not chased.
    - Zero matches does not show the database holds no secrets. Nothing here speaks to the
      database's health.
    - Detection differs from the text scope in one way. A provider-key shape is matched wherever
      its prefix starts, with no rule about the byte before it, because inside a database record
      a stored value sits directly against the bytes of its neighbouring fields. The byte after
      a match must still not be a key character. Matches never overlap: the leftmost wins, then
      the search resumes after it. This is not a complete fix. A following key character, a
      value longer than the shape allows, or a split across pages still hides or shortens a
      match, and accidental matches inside binary data are more likely than in text. The
      bot-token shape has no distinctive prefix and keeps its left-hand rule here.
    - Run it as its own process. It declines to run when the standard sqlite3 module is already
      loaded in its process. That is a rejection check, not proof that no SQLite connection
      exists: another SQLite binding or a natively loaded library would not be noticed. It must
      never be imported into a running Hermes.
    - Both scopes read through one opened handle on the home folder, so they read the same
      folder even if the path is re-pointed mid-run. If the path no longer names that folder at
      the end, the run says so and is not finished.
    - Linux system-call traces back the "no write, no lock" statements in the tests. No such
      trace has been taken on macOS.
  Fixed limits: 4 GiB per file, 6 GiB for both, 200,000 distinct candidates for both together.
  Two separate cooperative time budgets: 120 seconds for text, 600 seconds for this scope. They
  are checked between bounded steps and cannot interrupt a stalled system call, so they are not
  a hard limit on wall-clock time.

So a finished run is a finished scan of that text scope. It is not a scan of the home's whole
history, and zero findings does not show the history holds no secrets.

What a count means
  - Every full match of a listed shape is counted as a candidate. Nothing is left out for looking
    like a placeholder. A match whose last 24 characters hold fewer than 8 different characters
    is also counted under "low-variety", as an annotation only.
  - A candidate is a shape, not a confirmed secret: look-alikes are counted, and keys of another
    length or alphabet are missed.
  - Files are chosen by name and read as bytes. A binary file with a covered name is scanned
    like any other; nothing is decoded or unpacked.

Limits to know
  - Symlinks. The home you name is followed if it is a link, because you chose it. Nothing
    below it is: a linked folder or file is counted and not opened.
  - Limits are exact. A read is never larger than the per-file and total byte limits still
    allow, and there is no look-ahead read. A token cut by a limit can be counted in shortened
    form or missed; a run stopped by a limit is reported as not finished and its counts are partial.
  - Memory. At most 200,000 distinct candidates per category are remembered. Past that the
    distinct count is a floor, the run says so, and it is reported as not finished.
  - Same-user limit. The terminal check is friction, not proof that a person started the run.
    Any process running as you can start this script or imitate a terminal.
  - Scope means the directory entries named above. A hard
    link shares its content with a file elsewhere; such files are scanned and counted as
    hard-linked. A folder renamed after it was opened is still read through the open handle.
  - The time limit is cooperative: it is checked while listing, before and after each open,
    between bounded reads and before the scope is called finished. It cannot interrupt a call
    the operating system has stalled.
  - A file that changes while it is read is counted as changed. No point-in-time snapshot of a
    live history is claimed.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import time

CONTRACT = "text-v1"
BASELINE = "Hermes 0.23, source commit 3b4215785882"
# kind -> (folder, pattern for direct entries)
COVERAGE = (("transcripts", "sessions", re.compile(r"^[^/\x00]{1,255}\.(?:jsonl|json)$")),
            ("logs", "logs", re.compile(r"^[^/\x00]{1,255}\.log(?:\.[0-9]{1,3})?$")))
DATABASE = "state.db"

MAX_ENTRIES = 20_000                # directory entries listed per covered folder
MAX_FILES = 5_000                   # files opened per run
MAX_FILE_BYTES = 64 * 1024 * 1024   # bytes read per file; the rest is not scanned
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
TIME_BUDGET_S = 120.0               # cooperative
CHUNK = 1024 * 1024
OVERLAP = 1024                      # longer than any token a detector can match
MAX_DISTINCT = 200_000              # distinct candidates remembered per category (about 32 bytes of digest each)
LOW_VARIETY_CHARS = 8               # fewer distinct characters in a token's last 24: annotated, and still counted

_L, _R = rb"(?<![A-Za-z0-9_-])", rb"(?![A-Za-z0-9_-])"
# Shapes chosen by the author from the public look of these keys. They are not vendor guarantees:
# a key of a different length or alphabet is missed, and a look-alike string is counted.
PROVIDER_SHAPES = (
    ("anthropic-style sk-ant-", rb"sk-ant-[A-Za-z0-9_-]{32,200}"),
    ("openai-style sk- / sk-proj-", rb"sk-(?:proj-)?[A-Za-z0-9_-]{32,200}"),
    ("github token ghp_/gho_/ghu_/ghs_/ghr_", rb"gh[pousr]_[A-Za-z0-9]{36,255}"),
    ("github fine-grained github_pat_", rb"github_pat_[A-Za-z0-9_]{60,255}"),
    ("slack token xoxb-/xoxp-/xoxa-/xoxr-/xoxs-", rb"xox[abprs]-[A-Za-z0-9-]{20,200}"),
    ("aws access key id AKIA", rb"AKIA[0-9A-Z]{16}"),
    ("google api key AIza", rb"AIza[0-9A-Za-z_-]{35}"),
)
# category -> (compiled pattern, whether distinct candidates are counted)
DETECTORS = (
    # A header only: every key of one type has the same header, so distinct is not meaningful here.
    ("private-key-header", re.compile(rb"-----BEGIN (?:[A-Z0-9]{1,12} ){0,3}PRIVATE KEY-----"), False),
    ("provider-key-prefix", re.compile(_L + rb"(?:" + rb"|".join(p for _n, p in PROVIDER_SHAPES) + rb")" + _R), True),
    ("bot-token-shape", re.compile(rb"(?<![0-9A-Za-z])[0-9]{8,10}:[A-Za-z0-9_-]{35}" + _R), True),
)
# Artifact scope only. The provider-key shape drops the left-hand rule (see the header); the right-hand rule,
# the private-key header and the bot-token shape are the same as in the text scope.
ARTIFACT_DETECTORS = (
    DETECTORS[0],
    ("provider-key-prefix", re.compile(rb"(?:" + rb"|".join(p for _n, p in PROVIDER_SHAPES) + rb")" + _R), True),
    DETECTORS[2],
)
CATEGORIES = tuple(c for c, _p, _d in DETECTORS)
KINDS = tuple(k for k, _f, _p in COVERAGE)

# Every label this tool can print about a file or a run. Nothing else is ever printed about input.
FILE_LABELS = ("symlink_not_followed", "not_a_regular_file", "unreadable", "repeated_file", "read_error",
               "truncated_at_size_cap", "changed_during_scan", "hard_linked", "not_covered_entry")
ARTIFACT_CONTRACT = "artifact-bytes-v2"
ARTIFACTS = ("state.db", "state.db-wal")        # read in this order; state.db-shm is never read
ART_MAX_FILE_BYTES = 4 * 1024 ** 3
ART_MAX_TOTAL_BYTES = 6 * 1024 ** 3
ART_MAX_DISTINCT = 200_000                      # one map for both artifacts and all categories
ART_TIME_BUDGET_S = 600.0                       # cooperative; its own allowance, so text cannot starve it
ARTIFACT_STATUS = ("scanned", "absent", "symlink_not_followed", "not_a_regular_file", "unreadable", "read_error",
                   "not_reached")
ARTIFACT_CHANGES = ("grew", "shrank", "modified", "replaced", "disappeared", "appeared")
ARTIFACT_RUN_LABELS = ("refused_sqlite_loaded_in_process", "home_unavailable", "database_absent",
                       "truncated_at_size_cap", "total_byte_limit_reached", "time_budget_reached",
                       "distinct_limit_reached", "source_change_observed", "cancelled", "internal_error",
                       "skipped_text_scope_cancelled")
AGGREGATE_LABELS = ("home_path_changed_during_run",)
RUN_LABELS = ("home_unavailable", "location_absent", "location_is_a_symlink", "location_unavailable",
              "entry_limit_reached", "file_limit_reached", "total_byte_limit_reached", "time_budget_reached",
              "distinct_limit_reached",
              "cancelled", "internal_error")
_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_FILE = os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)


class _Stop(Exception):
    def __init__(self, label):
        self.label = label


def _new_result() -> dict:
    return {"contract": CONTRACT, "baseline": BASELINE,
            "kinds": {k: {"files_inspected": 0, "bytes_read": 0, "low_variety_also_counted": 0,
                          "occurrences": {c: 0 for c in CATEGORIES}, "files": {l: 0 for l in FILE_LABELS}} for k in KINDS},
            "distinct_candidates": {c: 0 for c, _p, d in DETECTORS if d},
            "session_database": "not_scanned", "run": [], "complete": False}


def _tick(budget: dict) -> None:
    """The cooperative deadline. Called between bounded steps; it cannot interrupt a stalled system call."""
    if time.monotonic() > budget["deadline"]:
        raise _Stop("time_budget_reached")


def _scan_bytes(fd: int, kind: dict, seen: dict, key: bytes, budget: dict, size_hint: int) -> bool:
    """Read one open regular file in bounded chunks and count matches. Returns True if the per-file cap
    cut the read short. Holds at most one chunk plus the overlap; lines are never assembled.

    Every byte read is counted against the per-file and the total limit before it is asked for: a read
    is never larger than what both limits still allow, and there is no look-ahead read. When a limit
    stops a file part-way, what was read is still matched to its end, so a token cut by the limit can
    be counted in shortened form or missed. Counts from a run that is not finished are partial."""
    carry, lead, read = b"", 0, 0
    while True:
        _tick(budget)
        allowed = min(CHUNK, MAX_FILE_BYTES - read, MAX_TOTAL_BYTES - budget["total"])
        chunk = os.read(fd, allowed) if allowed > 0 else b""
        read += len(chunk); budget["total"] += len(chunk); kind["bytes_read"] += len(chunk)
        final = not chunk
        buf = carry + chunk
        cutoff = len(buf) if final else max(0, len(buf) - OVERLAP)
        for category, pattern, distinct in DETECTORS:
            for m in pattern.finditer(buf):
                if m.start() < lead:
                    continue                       # began before the last cutoff: already counted
                if m.start() >= cutoff:
                    break
                token = m.group(0)
                kind["occurrences"][category] += 1          # every full match is a candidate
                if distinct:
                    if len(set(token[-24:])) < LOW_VARIETY_CHARS:
                        kind["low_variety_also_counted"] += 1   # an annotation, not an exclusion
                    digest = hmac.new(key, token, hashlib.sha256).digest()
                    if digest not in seen[category]:
                        if len(seen[category]) >= MAX_DISTINCT:
                            budget["distinct_overflow"] = True
                        else:
                            seen[category].add(digest)
        if final:
            more = max(size_hint, os.fstat(fd).st_size) > read       # is there content this run did not read?
            if more and read >= MAX_FILE_BYTES:
                return True
            if more and budget["total"] >= MAX_TOTAL_BYTES:
                raise _Stop("total_byte_limit_reached")
            return False
        lead = 1 if cutoff > 0 else 0              # keep one byte of left context for the boundary check
        carry = buf[cutoff - lead:]


def scan(home: str, home_fd=None) -> dict:
    """Scan one home. Never raises: whatever happens, the result says complete or not, with fixed labels.
    Given an open directory descriptor, it reads through that and leaves it open for the caller."""
    res = _new_result()
    seen = {c: set() for c in res["distinct_candidates"]}
    key = os.urandom(32)                       # lives for this call only; no digest leaves this function
    budget = {"deadline": time.monotonic() + TIME_BUDGET_S, "total": 0, "files": 0, "distinct_overflow": False}
    identities, fds = set(), []

    def note(label):
        if label not in res["run"]:
            res["run"].append(label)

    try:
        if home_fd is None:
            try:
                home_fd = os.open(home, _DIR)      # the home is the operator's explicit choice: a link is followed
                fds.append(home_fd)
            except OSError:
                note("home_unavailable")
                return res
        try:
            os.stat(DATABASE, dir_fd=home_fd, follow_symlinks=False)
            res["session_database"] = "present_not_scanned"
        except OSError:
            res["session_database"] = "not_found_not_scanned"
        for kind_name, folder, pattern in COVERAGE:
            kind = res["kinds"][kind_name]
            _tick(budget)
            try:
                dfd = os.open(folder, _DIR | _NOFOLLOW, dir_fd=home_fd)
            except FileNotFoundError:
                note("location_absent"); continue
            except OSError as exc:
                note("location_is_a_symlink" if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK) else "location_unavailable")
                continue
            fds.append(dfd)
            names = []
            try:
                with os.scandir(dfd) as it:
                    for entry in it:
                        _tick(budget)
                        if len(names) >= MAX_ENTRIES:
                            note("entry_limit_reached"); break
                        names.append(entry.name)
            except OSError:
                note("location_unavailable"); continue
            _tick(budget)
            for name in sorted(names):
                _tick(budget)
                if not pattern.match(name):
                    kind["files"]["not_covered_entry"] += 1
                    continue
                if budget["files"] >= MAX_FILES:
                    raise _Stop("file_limit_reached")
                budget["files"] += 1
                try:
                    fd = os.open(name, _FILE, dir_fd=dfd)
                except OSError as exc:
                    kind["files"]["symlink_not_followed" if exc.errno in (errno.ELOOP, errno.EMLINK)
                                  else "not_a_regular_file" if exc.errno in (errno.ENXIO, errno.EISDIR, errno.ENOTDIR)
                                  else "unreadable"] += 1
                    continue
                try:
                    _tick(budget)                  # the open may have been slow
                    before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode):
                        kind["files"]["not_a_regular_file"] += 1
                        continue
                    ident = (before.st_dev, before.st_ino)
                    if ident in identities:
                        kind["files"]["repeated_file"] += 1
                        continue
                    identities.add(ident)
                    if before.st_nlink > 1:
                        kind["files"]["hard_linked"] += 1
                    kind["files_inspected"] += 1
                    try:
                        if _scan_bytes(fd, kind, seen, key, budget, before.st_size):
                            kind["files"]["truncated_at_size_cap"] += 1
                    except OSError:
                        kind["files"]["read_error"] += 1
                        continue
                    after = os.fstat(fd)
                    if (after.st_size, after.st_mtime_ns, after.st_ino) != (before.st_size, before.st_mtime_ns, before.st_ino):
                        kind["files"]["changed_during_scan"] += 1
                    _tick(budget)
                finally:
                    os.close(fd)
        _tick(budget)                              # last check before the scope is called finished
        res["complete"] = True
    except _Stop as stop:
        note(stop.label)
    except KeyboardInterrupt:
        note("cancelled")
    except BaseException:                          # never let input-derived exception text escape
        note("internal_error")
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass
    for c in seen:
        res["distinct_candidates"][c] = len(seen[c])
    if budget["distinct_overflow"]:
        note("distinct_limit_reached")             # occurrences stay exact; the distinct count is a floor
    blocking = ("unreadable", "read_error", "truncated_at_size_cap", "changed_during_scan")
    if res["run"] and set(res["run"]) - {"location_absent"}:
        res["complete"] = False
    if any(res["kinds"][k]["files"][l] for k in KINDS for l in blocking):
        res["complete"] = False
    return res


def _entry_identity(home_fd: int, name: str):
    """(dev, ino) of a directory entry without following a link, 'absent', or 'unreadable'."""
    try:
        st = os.stat(name, dir_fd=home_fd, follow_symlinks=False)
        return (st.st_dev, st.st_ino)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unreadable"


def _new_artifact() -> dict:
    return {"status": "not_reached", "traversal_finished": False, "source_change_observed": False,
            "snapshot_established": False, "bytes_read": 0, "extent_bytes": 0, "changes": [],
            "occurrences": {c: 0 for c in CATEGORIES}, "low_variety_also_counted": 0,
            "distinct_candidates": {c: 0 for c, _p, d in DETECTORS if d}}


def scan_artifacts(home: str, text_cancelled: bool = False, home_fd=None) -> dict:
    """Contract artifact-bytes-v1: read state.db and state.db-wal of one home as plain bytes.

    Never raises. Imports and uses no SQLite. Given an open directory descriptor, it reads through that
    and leaves it open for the caller. Both files are opened first and checked again after
    both have been read, so the change check spans the whole read. Extent is each file's size at
    open. One digest map with a membership flag per artifact holds the distinct candidates."""
    res = {"contract": ARTIFACT_CONTRACT, "artifacts": {name: _new_artifact() for name in ARTIFACTS},
           "combined_distinct_candidates": {c: 0 for c, _p, d in DETECTORS if d},
           "snapshot_established": False, "run": [], "scope_finished": False}
    art = res["artifacts"]

    def note(label):
        if label not in res["run"]:
            res["run"].append(label)

    if text_cancelled:
        note("skipped_text_scope_cancelled")
        return res
    if "sqlite3" in sys.modules or "_sqlite3" in sys.modules:
        note("refused_sqlite_loaded_in_process")      # closing our descriptor could cancel that library's locks
        return res
    key = os.urandom(32)
    seen = {c: {} for c in res["combined_distinct_candidates"]}      # category -> {digest: membership flags}
    state = {"total": 0, "distinct": 0, "overflow": False}
    deadline = time.monotonic() + ART_TIME_BUDGET_S
    opened, owns_home = {}, home_fd is None

    def tick():
        if time.monotonic() > deadline:
            raise _Stop("time_budget_reached")

    try:
        if home_fd is None:
            try:
                home_fd = os.open(home, _DIR)
            except OSError:
                note("home_unavailable")
                return res
        # --- open both first, so the change check covers the whole read
        for name in ARTIFACTS:
            a = art[name]
            ident = _entry_identity(home_fd, name)
            if ident == "absent":
                a["status"] = "absent"
                opened[name] = (None, None, ident)
                continue
            if ident == "unreadable":
                a["status"] = "unreadable"
                opened[name] = (None, None, ident)
                continue
            try:
                fd = os.open(name, _FILE, dir_fd=home_fd)
            except OSError as exc:
                a["status"] = ("symlink_not_followed" if exc.errno in (errno.ELOOP, errno.EMLINK)
                               else "not_a_regular_file" if exc.errno in (errno.ENXIO, errno.EISDIR, errno.ENOTDIR)
                               else "absent" if exc.errno == errno.ENOENT else "unreadable")
                opened[name] = (None, None, ident)
                continue
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                a["status"] = "not_a_regular_file"
                opened[name] = (None, None, ident)
                continue
            a["extent_bytes"] = st.st_size
            opened[name] = (fd, st, ident)
        # --- read each, in the fixed order, to its extent at open
        for flag, name in enumerate(ARTIFACTS):
            fd, st, _ident = opened[name]
            a = art[name]
            if fd is None:
                continue
            tick()
            extent, carry, base, read = st.st_size, b"", 0, 0       # base: offset in the file of carry[0]
            resume = {c: 0 for c in CATEGORIES}                     # per category: file offset where the search resumes
            try:
                while True:
                    tick()
                    allowed = min(CHUNK, extent - read, ART_MAX_FILE_BYTES - read, ART_MAX_TOTAL_BYTES - state["total"])
                    chunk = os.read(fd, allowed) if allowed > 0 else b""
                    read += len(chunk); state["total"] += len(chunk); a["bytes_read"] += len(chunk)
                    final = not chunk
                    buf = carry + chunk
                    cutoff = len(buf) if final else max(0, len(buf) - OVERLAP)
                    for category, pattern, distinct in ARTIFACT_DETECTORS:
                        # Search from where the last counted match ended, so matches never overlap and the
                        # result is the same as one pass over the whole file, wherever the chunks fall.
                        for m in pattern.finditer(buf, max(0, resume[category] - base)):
                            if m.start() >= cutoff:
                                break              # starts in the overlap: the next buffer sees it whole
                            resume[category] = base + m.end()
                            token = m.group(0)
                            a["occurrences"][category] += 1
                            if distinct:
                                if len(set(token[-24:])) < LOW_VARIETY_CHARS:
                                    a["low_variety_also_counted"] += 1
                                digest = hmac.new(key, token, hashlib.sha256).digest()
                                flags = seen[category].get(digest)
                                if flags is None:
                                    if state["distinct"] >= ART_MAX_DISTINCT:
                                        state["overflow"] = True
                                        continue
                                    state["distinct"] += 1
                                    flags = 0
                                seen[category][digest] = flags | (1 << flag)
                    if final:
                        break
                    lead = 1 if cutoff > 0 else 0              # one byte of left context for the bot-token rule
                    for category in resume:
                        resume[category] = max(resume[category], base + cutoff)
                    base += cutoff - lead
                    carry = buf[cutoff - lead:]
            except OSError:
                a["status"] = "read_error"
                continue
            a["status"] = "scanned"
            if read >= extent:
                a["traversal_finished"] = True
            elif read >= ART_MAX_FILE_BYTES:
                note("truncated_at_size_cap")
            elif state["total"] >= ART_MAX_TOTAL_BYTES:
                raise _Stop("total_byte_limit_reached")
            # read < extent with allowance left: the file shrank under us; the end check records it
        tick()
    except _Stop as stop:
        note(stop.label)
    except KeyboardInterrupt:
        note("cancelled")
    except BaseException:
        note("internal_error")
    finally:
        # --- end checks on both, whatever happened: entry identity and open descriptor, start against end
        try:
            for name in ARTIFACTS:
                if name not in opened or home_fd is None:
                    continue
                fd, st, ident0 = opened[name]
                a = art[name]
                ident1 = _entry_identity(home_fd, name)
                if ident0 == "absent" and ident1 != "absent":
                    a["changes"].append("appeared")
                elif ident0 != "absent" and ident1 == "absent":
                    a["changes"].append("disappeared")
                elif ident0 != ident1:
                    a["changes"].append("replaced")
                if fd is not None:
                    try:
                        end = os.fstat(fd)
                        if end.st_size > st.st_size:
                            a["changes"].append("grew")
                        elif end.st_size < st.st_size:
                            a["changes"].append("shrank")
                        elif end.st_mtime_ns != st.st_mtime_ns:
                            a["changes"].append("modified")
                        if isinstance(ident0, tuple) and ident0 != (st.st_dev, st.st_ino) and "replaced" not in a["changes"]:
                            a["changes"].append("replaced")
                    except OSError:
                        a["changes"].append("modified")
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                a["source_change_observed"] = bool(a["changes"])
            if home_fd is not None and owns_home:
                os.close(home_fd)
        except BaseException:
            note("internal_error")
    for name_flag, name in enumerate(ARTIFACTS):
        for c in seen:
            art[name]["distinct_candidates"][c] = sum(1 for f in seen[c].values() if f & (1 << name_flag))
    for c in seen:
        res["combined_distinct_candidates"][c] = len(seen[c])
    if state["overflow"]:
        note("distinct_limit_reached")             # distinct counts, per file and combined, are lower bounds
    if any(art[n]["source_change_observed"] for n in ARTIFACTS):
        note("source_change_observed")
    db, wal = art["state.db"], art["state.db-wal"]
    if db["status"] == "absent" and "home_unavailable" not in res["run"]:
        note("database_absent")                    # a missing database is not a successful database scan
    ok_db = db["status"] == "scanned" and db["traversal_finished"]
    ok_wal = wal["status"] == "absent" or (wal["status"] == "scanned" and wal["traversal_finished"])
    res["scope_finished"] = bool(ok_db and ok_wal and not res["run"])
    return res


def _home_moved(home: str, pinned) -> bool:
    """True when the named path no longer resolves to the directory opened at the start. A check at one
    moment: a path re-pointed and restored in between is not seen."""
    if pinned is None:
        return False
    try:
        a, b = os.fstat(pinned), os.stat(home)
        return (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino)
    except OSError:
        return True


def render_artifacts(res: dict) -> str:
    out = ["", "Database-artifact byte scan: contract %s (asked for with --database-artifacts)" % res["contract"],
           "  NOT a read of the conversations. Contiguous byte matches in two files, read without SQLite.",
           "  Values split across pages or log frames are not put back together. UTF-16 text is not matched.",
           "  Matches can come from deleted, superseded or uncommitted content. state.db-shm is never read.",
           "  A provider-key shape is matched wherever its prefix starts; the byte after it must not be a key character.",
           "  Neighbouring bytes can still hide, shorten or create a match. This is not a complete search."]
    for name in ARTIFACTS:
        a = res["artifacts"][name]
        out.append("%s: status %s, %d of %d byte(s) read, traversal finished %s, change observed %s, snapshot established no"
                   % (name, a["status"], a["bytes_read"], a["extent_bytes"], "yes" if a["traversal_finished"] else "no",
                      "yes (" + ", ".join(a["changes"]) + ")" if a["changes"] else "no"))
        for c in CATEGORIES:
            distinct = a["distinct_candidates"].get(c)
            out.append("    %-22s occurrences %d, %s" % (c, a["occurrences"][c], "distinct %d" % distinct if distinct is not None
                                                          else "distinct not counted (header only)"))
        out.append("    of those, low-variety (also counted) %d" % a["low_variety_also_counted"])
    out.append("different matched byte strings across both files (not a verified pair, not rows, not confirmed secrets):")
    for c, n in res["combined_distinct_candidates"].items():
        out.append("    %-22s %d" % (c, n))
    out.append("artifact run notes: " + (", ".join(res["run"]) if res["run"] else "none"))
    out.append("Artifact scope " + ("finished." if res["scope_finished"] else "NOT FINISHED: this is a partial or inconclusive result."))
    out.append("The two files were not read as a coordinated snapshot. Seeing no change does not show they were stable.")
    out.append("Zero matches does not show the database holds no secrets. Nothing here speaks to the database's health.")
    return "\n".join(out)


def render(res: dict) -> str:
    out = ["Secret Guard history scan: summary only",
           "coverage contract %s (%s)" % (res["contract"], res["baseline"]),
           "  transcripts: sessions/*.jsonl, sessions/*.json   logs: logs/*.log, logs/*.log.N   (direct entries only)",
           "  Files are chosen by name and read as bytes. The home you name is followed if it is a link; nothing below it is.",
           "NOT SCANNED: the session database (state.db) [%s], every other file and subfolder," % res["session_database"],
           "  encoded or transformed values, name assignments, registered values.", ""]
    totals = {c: 0 for c in CATEGORIES}
    for k in KINDS:
        d = res["kinds"][k]
        out.append("%s: %d file(s) inspected, %d byte(s) read" % (k, d["files_inspected"], d["bytes_read"]))
        for c in CATEGORIES:
            totals[c] += d["occurrences"][c]
            out.append("    occurrences %-22s %d" % (c, d["occurrences"][c]))
        out.append("    of those, low-variety (also counted) %d" % d["low_variety_also_counted"])
        flagged = ["%s %d" % (l, n) for l, n in d["files"].items() if n]
        out.append("    file notes: " + (", ".join(flagged) if flagged else "none"))
    out += ["", "totals"]
    for c in CATEGORIES:
        distinct = res["distinct_candidates"].get(c)
        out.append("    %-22s occurrences %d, %s" % (c, totals[c], "distinct candidates %d" % distinct if distinct is not None
                                                      else "distinct not counted (header only)"))
    out.append("run notes: " + (", ".join(res["run"]) if res["run"] else "none"))
    out.append("")
    out.append("Text scope " + ("finished." if res["complete"] else "NOT FINISHED: this is a partial result, not a clean one."))
    out.append("Counts are candidates by shape, not confirmed secrets. Counts from a run that is not finished are partial.")
    out.append("This is not a scan of the home's whole history. Zero findings does not show it holds no secrets.")
    out.append("No point-in-time snapshot is claimed: files can change while they are read.")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="history_scan", description="Summary-only scan of one Hermes home's text records.")
    ap.add_argument("--home", required=True, help="the one Hermes home to scan (no default)")
    ap.add_argument("--json", action="store_true", help="print the same counters as JSON")
    ap.add_argument("--database-artifacts", action="store_true",
                    help="after the text scope, also read state.db and state.db-wal as plain bytes (not a read of the conversations)")
    args = ap.parse_args(argv)
    try:
        attached = sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        attached = False
    if not attached:
        sys.stderr.write("history_scan: run this yourself at a terminal; it does not run unattended or into a pipe.\n")
        return 2
    pinned = None
    try:
        try:
            pinned = os.open(args.home, _DIR)       # one handle for the whole run; both scopes read through it
        except OSError:
            pinned = None                           # each scope then reports home_unavailable itself
        res = scan(args.home, home_fd=pinned)
        finished = res["complete"]
        text = render(res)
        if args.database_artifacts:                 # only on request: the default run opens no database content
            art = scan_artifacts(args.home, text_cancelled="cancelled" in res["run"], home_fd=pinned)
            moved = _home_moved(args.home, pinned)
            res = {"text_scope": res, "artifact_scope": art, "run": ["home_path_changed_during_run"] if moved else [],
                   "complete": bool(finished and art["scope_finished"] and not moved)}
            finished = res["complete"]
            text += "\n" + render_artifacts(art) + "\n"
            if moved:
                text += ("\nThe path you named no longer points at the folder that was read. "
                         "Both scopes read the folder that was opened at the start.")
            text += "\nBoth scopes " + ("finished." if finished else "NOT both finished.")
        print(json.dumps(res, indent=2, sort_keys=True) if args.json else text)
        return 0 if finished else 1
    except KeyboardInterrupt:
        sys.stderr.write("history_scan: cancelled; no result.\n")
        return 1
    except BaseException:
        sys.stderr.write("history_scan: internal error; no result.\n")
        return 1
    finally:
        if pinned is not None:
            try:
                os.close(pinned)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
