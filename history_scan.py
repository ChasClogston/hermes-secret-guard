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

So a finished run is a finished scan of that text scope. It is not a scan of the home's whole
history, and zero findings does not show the history holds no secrets.

Limits to know
  - Same-user limit. The terminal check is friction, not proof that a person started the run.
    Any process running as you can start this script or imitate a terminal.
  - Scope means the directory entries named above, opened without following symlinks. A hard
    link shares its content with a file elsewhere; such files are scanned and counted as
    hard-linked. A folder renamed after it was opened is still read through the open handle.
  - The time limit is cooperative: it is checked between bounded reads and cannot interrupt a
    read the operating system has stalled.
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
MIN_DISTINCT_CHARS = 8              # fewer distinct characters in a token's last 24: placeholder-like, not counted

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
CATEGORIES = tuple(c for c, _p, _d in DETECTORS)
KINDS = tuple(k for k, _f, _p in COVERAGE)

# Every label this tool can print about a file or a run. Nothing else is ever printed about input.
FILE_LABELS = ("symlink_not_followed", "not_a_regular_file", "unreadable", "repeated_file", "read_error",
               "truncated_at_size_cap", "changed_during_scan", "hard_linked", "not_covered_entry")
RUN_LABELS = ("home_unavailable", "location_absent", "location_is_a_symlink", "location_unavailable",
              "entry_limit_reached", "file_limit_reached", "total_byte_limit_reached", "time_budget_reached",
              "cancelled", "internal_error")
_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_FILE = os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)


class _Stop(Exception):
    def __init__(self, label):
        self.label = label


def _new_result() -> dict:
    return {"contract": CONTRACT, "baseline": BASELINE,
            "kinds": {k: {"files_inspected": 0, "bytes_read": 0, "placeholder_like_not_counted": 0,
                          "occurrences": {c: 0 for c in CATEGORIES}, "files": {l: 0 for l in FILE_LABELS}} for k in KINDS},
            "distinct_candidates": {c: 0 for c, _p, d in DETECTORS if d},
            "session_database": "not_scanned", "run": [], "complete": False}


def _scan_bytes(fd: int, kind: dict, seen: dict, key: bytes, budget: dict) -> bool:
    """Read one open regular file in bounded chunks and count matches. Returns True if the size cap
    cut the read short. Holds at most one chunk plus the overlap; lines are never assembled."""
    carry, lead, read, truncated = b"", 0, 0, False
    while True:
        if time.monotonic() > budget["deadline"]:
            raise _Stop("time_budget_reached")
        if budget["total"] >= MAX_TOTAL_BYTES:
            raise _Stop("total_byte_limit_reached")
        if read >= MAX_FILE_BYTES:
            truncated = bool(os.read(fd, 1))
            chunk = b""
        else:
            chunk = os.read(fd, min(CHUNK, MAX_FILE_BYTES - read))
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
                if distinct and len(set(token[-24:])) < MIN_DISTINCT_CHARS:
                    kind["placeholder_like_not_counted"] += 1
                    continue
                kind["occurrences"][category] += 1
                if distinct:
                    seen[category].add(hmac.new(key, token, hashlib.sha256).digest())
        if final:
            return truncated
        lead = 1 if cutoff > 0 else 0              # keep one byte of left context for the boundary check
        carry = buf[cutoff - lead:]


def scan(home: str) -> dict:
    """Scan one home. Never raises: whatever happens, the result says complete or not, with fixed labels."""
    res = _new_result()
    seen = {c: set() for c in res["distinct_candidates"]}
    key = os.urandom(32)                       # lives for this call only; no digest leaves this function
    budget = {"deadline": time.monotonic() + TIME_BUDGET_S, "total": 0, "files": 0}
    identities, fds = set(), []

    def note(label):
        if label not in res["run"]:
            res["run"].append(label)

    try:
        try:
            home_fd = os.open(home, _DIR)          # the home is the operator's explicit choice: a link is followed
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
                        if len(names) >= MAX_ENTRIES:
                            note("entry_limit_reached"); break
                        names.append(entry.name)
            except OSError:
                note("location_unavailable"); continue
            for name in sorted(names):
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
                        if _scan_bytes(fd, kind, seen, key, budget):
                            kind["files"]["truncated_at_size_cap"] += 1
                    except OSError:
                        kind["files"]["read_error"] += 1
                        continue
                    after = os.fstat(fd)
                    if (after.st_size, after.st_mtime_ns, after.st_ino) != (before.st_size, before.st_mtime_ns, before.st_ino):
                        kind["files"]["changed_during_scan"] += 1
                finally:
                    os.close(fd)
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
    blocking = ("unreadable", "read_error", "truncated_at_size_cap", "changed_during_scan")
    if res["run"] and set(res["run"]) - {"location_absent"}:
        res["complete"] = False
    if any(res["kinds"][k]["files"][l] for k in KINDS for l in blocking):
        res["complete"] = False
    return res


def render(res: dict) -> str:
    out = ["Secret Guard history scan: summary only",
           "coverage contract %s (%s)" % (res["contract"], res["baseline"]),
           "  transcripts: sessions/*.jsonl, sessions/*.json   logs: logs/*.log, logs/*.log.N   (direct entries only)",
           "NOT SCANNED: the session database (state.db) [%s], every other file and subfolder," % res["session_database"],
           "  encoded or transformed values, name assignments, registered values.", ""]
    totals = {c: 0 for c in CATEGORIES}
    for k in KINDS:
        d = res["kinds"][k]
        out.append("%s: %d file(s) inspected, %d byte(s) read" % (k, d["files_inspected"], d["bytes_read"]))
        for c in CATEGORIES:
            totals[c] += d["occurrences"][c]
            out.append("    occurrences %-22s %d" % (c, d["occurrences"][c]))
        out.append("    placeholder-like, not counted       %d" % d["placeholder_like_not_counted"])
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
    out.append("This is not a scan of the home's whole history. Zero findings does not show it holds no secrets.")
    out.append("No point-in-time snapshot is claimed: files can change while they are read.")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="history_scan", description="Summary-only scan of one Hermes home's text records.")
    ap.add_argument("--home", required=True, help="the one Hermes home to scan (no default)")
    ap.add_argument("--json", action="store_true", help="print the same counters as JSON")
    args = ap.parse_args(argv)
    try:
        attached = sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        attached = False
    if not attached:
        sys.stderr.write("history_scan: run this yourself at a terminal; it does not run unattended or into a pipe.\n")
        return 2
    try:
        res = scan(args.home)
        print(json.dumps(res, indent=2, sort_keys=True) if args.json else render(res))
        return 0 if res["complete"] else 1
    except KeyboardInterrupt:
        sys.stderr.write("history_scan: cancelled; no result.\n")
        return 1
    except BaseException:
        sys.stderr.write("history_scan: internal error; no result.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
