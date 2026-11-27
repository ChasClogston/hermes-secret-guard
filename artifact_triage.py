#!/usr/bin/env python3
"""One-off triage of database-artifact matches. Read-only. Prints labels and numbers, nothing else.

    python3 artifact_triage.py --home /path/to/one/hermes/home

Run it yourself, at a terminal. It answers one question about a home whose artifact scan
(history_scan.py --database-artifacts, contract "artifact-bytes-v2") reported provider-key-shaped
matches: what kind of match is each one? It does not say what any match is.

WHAT IT READS
  state.db and state.db-wal of the one home you name, as plain bytes, through one opened handle on
  the home. No SQLite: no connection, no lock protocol, no write. state.db-shm is never read.
  It finds the same matches as the artifact scope: the same provider-key pattern, leftmost and
  non-overlapping, independent of where the read chunks fall. Only that category is triaged.

WHAT IT PRINTS (contract "artifact-triage-v1")
  For every group of matches that share all of the following, one line with two counts
  (occurrences, and distinct byte strings within this run):
    shape        which of the seven listed shapes the match starts with
    before       the class of the one byte before the match:
                 start_of_file, letter, digit, hyphen_or_underscore, other_printable, not_printable
    word         listed_word when the bytes just before the match, joined to the "sk" of the
                 prefix, end in one of a fixed list of English words (flask, task, desk, disk,
                 risk, mask, ask), otherwise none. Only for the shapes that begin "sk-"; other
                 shapes say not_applicable. Which word it was is not printed.
    body         the class of the characters after the prefix:
                 uuid_layout (8-4-4-4-12 hexadecimal), hex_and_hyphens, lowercase_and_hyphens,
                 digits_and_hyphens, mixed_alphanumeric, other
    length       a range for the number of characters after the prefix:
                 under_32, 32_to_39, 40_to_63, 64_to_127, 128_or_more
  No raw excerpt is printed: no matched byte, no neighbouring byte, no offset, no page number, no
  digest, no file name other than the two fixed ones, no error message taken from input. It
  writes no file.

WHAT THE OUTPUT STILL DISCLOSES
  Labels are metadata about the matches, and metadata is information. A group with one member
  tells a reader that a string of that shape, body class and length range exists in the home,
  and, with listed_word, that the bytes before it spell one of seven fixed words. The per-file
  totals and the group counts show how the matches are distributed between the two files and
  across kinds. Read the output with that in mind before sharing it.

HOW TO READ THE COUNTS
  - The labels are structural classifications only. No label and no combination of labels
    confirms a credential or clears one. A match after the word "task" with a uuid_layout body
    is shaped like an ordinary identifier, and it may still be a credential; hex_and_hyphens
    describes real keys as well as identifiers.
  - Nothing here should be used to ignore a candidate automatically or to change what the
    scanner detects.
  - Distinct counts are per group and do not add up: the same byte string seen in two different
    contexts is counted once in each of two groups.
  - Every limit of the artifact scope applies: physical neighbouring bytes, not stored values;
    deleted or superseded content can match; values split across pages are not put back together;
    the two files are not a snapshot. Nothing here speaks to the database's health.
  - Zero groups does not show the database holds no secrets.

LIMITS
  Same fixed byte limits as the artifact scope (4 GiB per file, 6 GiB for both) and a 600 second
  cooperative time budget that cannot interrupt a stalled system call. At most 500 groups and
  200,000 distinct strings are remembered. Past the group limit, the groups shown keep their own
  counts and the groups left out are not represented at all; past the distinct limit, distinct
  counts are lower bounds. Either way the run says so and is not finished.
  Each of the two entries is looked at before it is opened and again at the end, whether or not
  it existed or could be opened. A file that appears, disappears, is replaced, grows, shrinks or
  is modified in between makes the run not finished, and so does a check that cannot be made. An
  absent log that stays absent is normal. Seeing no change does not show the files were stable.
  The home is opened once and read through that handle. If the path you named no longer points
  at that folder at the end, the run says so and is not finished; a path re-pointed and restored
  in between is not seen. If the home cannot be opened, nothing is read.
  It declines to run when the standard sqlite3 module is already loaded in its process; that is a
  rejection check, not proof that no SQLite connection exists. The terminal check is friction,
  not proof that a person started the run. No system-call trace of this tool exists on macOS.
"""
import argparse
import errno
import hashlib
import hmac
import json
import os
import stat
import sys
import time

import history_scan as hs

CONTRACT = "artifact-triage-v1"
SHAPE_PREFIXES = (                      # checked in this order; the first that fits names the shape
    ("anthropic-style sk-ant-", (b"sk-ant-",)),
    ("openai-style sk-proj-", (b"sk-proj-",)),
    ("openai-style sk-", (b"sk-",)),
    ("github fine-grained github_pat_", (b"github_pat_",)),
    ("github token ghp_/gho_/ghu_/ghs_/ghr_", (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_")),
    ("slack token xox?-", (b"xoxa-", b"xoxb-", b"xoxp-", b"xoxr-", b"xoxs-")),
    ("aws access key id AKIA", (b"AKIA",)),
    ("google api key AIza", (b"AIza",)),
)
SHAPES = tuple(n for n, _p in SHAPE_PREFIXES) + ("unrecognised",)
BEFORE = ("start_of_file", "letter", "digit", "hyphen_or_underscore", "other_printable", "not_printable")
WORDS = ("flask", "task", "desk", "disk", "risk", "mask", "ask")      # longest first; each ends in "sk"
WORD_LABELS = ("listed_word", "none", "not_applicable")
LENGTHS = ("under_32", "32_to_39", "40_to_63", "64_to_127", "128_or_more")
BODY = ("uuid_layout", "hex_and_hyphens", "lowercase_and_hyphens", "digits_and_hyphens", "mixed_alphanumeric", "other")
STATUS = hs.ARTIFACT_STATUS
RUN_LABELS = ("refused_sqlite_loaded_in_process", "home_unavailable", "home_path_changed_during_run", "database_absent", "source_change_observed",
              "truncated_at_size_cap", "total_byte_limit_reached", "time_budget_reached", "group_limit_reached",
              "distinct_limit_reached", "cancelled", "internal_error")
MAX_GROUPS = 500
MAX_DISTINCT = 200_000
TIME_BUDGET_S = 600.0
CONTEXT = 8                             # bytes of left context kept for the "before" and "word" labels
_HEX = frozenset(b"0123456789abcdefABCDEF")
_LOWER = frozenset(b"abcdefghijklmnopqrstuvwxyz")
_DIGIT = frozenset(b"0123456789")
_LETTER = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_ALNUM = _LETTER | _DIGIT
_PATTERN = hs.ARTIFACT_DETECTORS[1][1]
assert hs.ARTIFACT_DETECTORS[1][0] == "provider-key-prefix"


def classify(token: bytes, left: bytes):
    """Labels for one match. `left` is up to CONTEXT bytes that come directly before it."""
    shape, prefix = "unrecognised", b""
    for name, prefixes in SHAPE_PREFIXES:
        hit = next((p for p in prefixes if token.startswith(p)), None)
        if hit is not None:
            shape, prefix = name, hit
            break
    if not left:
        before = "start_of_file"
    else:
        b = left[-1]
        before = ("letter" if b in _LETTER else "digit" if b in _DIGIT else "hyphen_or_underscore" if b in b"-_"
                  else "other_printable" if 0x20 <= b < 0x7F else "not_printable")
    word = "not_applicable"
    if prefix.startswith(b"sk-"):
        word = "none"
        joined = (left + b"sk").lower()
        if any(joined.endswith(w.encode()) for w in WORDS):
            word = "listed_word"
    body = token[len(prefix):]
    chars = frozenset(body)
    parts = body.split(b"-")
    if [len(p) for p in parts] == [8, 4, 4, 4, 12] and chars <= _HEX | frozenset(b"-"):
        kind = "uuid_layout"
    elif chars <= _DIGIT | frozenset(b"-"):
        kind = "digits_and_hyphens"
    elif chars <= _HEX | frozenset(b"-"):
        kind = "hex_and_hyphens"
    elif chars <= _LOWER | frozenset(b"-"):
        kind = "lowercase_and_hyphens"
    elif chars <= _ALNUM | frozenset(b"-_") and chars & _DIGIT and (chars & _LETTER):
        kind = "mixed_alphanumeric"
    else:
        kind = "other"
    n = len(body)
    return shape, before, word, kind, ("under_32" if n < 32 else "32_to_39" if n < 40 else "40_to_63" if n < 64
                                       else "64_to_127" if n < 128 else "128_or_more")


def _new_file() -> dict:
    return {"status": "not_reached", "traversal_finished": False, "bytes_read": 0, "extent_bytes": 0,
            "change_observed": False, "matches": 0}


def _new_result() -> dict:
    return {"contract": CONTRACT, "scans_contract": hs.ARTIFACT_CONTRACT, "files": {n: _new_file() for n in hs.ARTIFACTS},
            "groups": [], "distinct_counts_are_lower_bounds": False, "run": [], "finished": False}


def triage(home_fd: int) -> dict:
    """Read both artifacts through an open home descriptor. Never raises; leaves the descriptor open."""
    res = _new_result()

    def note(label):
        if label not in res["run"]:
            res["run"].append(label)

    if "sqlite3" in sys.modules or "_sqlite3" in sys.modules:
        note("refused_sqlite_loaded_in_process")
        return res
    key = os.urandom(32)
    groups, digests, fds, opened, initial = {}, {}, [], {}, {}
    state = {"total": 0, "distinct": 0, "overflow": False}
    deadline = time.monotonic() + TIME_BUDGET_S

    def tick():
        if time.monotonic() > deadline:
            raise hs._Stop("time_budget_reached")

    def record(labels, token):
        g = groups.get(labels)
        if g is None:
            if len(groups) >= MAX_GROUPS:
                note("group_limit_reached")
                return
            g = groups[labels] = [0, 0]
        g[0] += 1
        d = hmac.new(key, token, hashlib.sha256).digest()
        seen = digests.get(d)
        if seen is None:
            if state["distinct"] >= MAX_DISTINCT:
                state["overflow"] = True
                return
            state["distinct"] += 1
            seen = digests[d] = set()
        if labels not in seen:
            seen.add(labels)
            g[1] += 1

    try:
        for name in hs.ARTIFACTS:                  # look at both entries first, before either is opened
            initial[name] = hs._entry_identity(home_fd, name)
        for name in hs.ARTIFACTS:
            tick()
            f = res["files"][name]
            if initial[name] == "unreadable":
                f["status"] = "unreadable"
                continue
            try:
                fd = os.open(name, hs._FILE, dir_fd=home_fd)
            except OSError as exc:
                f["status"] = ("symlink_not_followed" if exc.errno in (errno.ELOOP, errno.EMLINK)
                               else "not_a_regular_file" if exc.errno in (errno.ENXIO, errno.EISDIR, errno.ENOTDIR)
                               else "absent" if exc.errno == errno.ENOENT else "unreadable")
                continue
            fds.append(fd)
            try:
                st = os.fstat(fd)
            except OSError:
                f["status"] = "unreadable"
                continue
            if not stat.S_ISREG(st.st_mode):
                f["status"] = "not_a_regular_file"
                continue
            if initial[name] != (st.st_dev, st.st_ino):
                f["change_observed"] = True        # the entry was absent or a different file when first looked at
            f["extent_bytes"] = st.st_size
            opened[name] = (fd, st)
        for name in hs.ARTIFACTS:
            if name not in opened:
                continue
            fd, st = opened[name]
            f = res["files"][name]
            extent, carry, base, read, resume = st.st_size, b"", 0, 0, 0
            try:
                while True:
                    tick()
                    allowed = min(hs.CHUNK, extent - read, hs.ART_MAX_FILE_BYTES - read, hs.ART_MAX_TOTAL_BYTES - state["total"])
                    chunk = os.read(fd, allowed) if allowed > 0 else b""
                    read += len(chunk); state["total"] += len(chunk); f["bytes_read"] += len(chunk)
                    final = not chunk
                    buf = carry + chunk
                    cutoff = len(buf) if final else max(0, len(buf) - hs.OVERLAP)
                    for m in _PATTERN.finditer(buf, max(0, resume - base)):
                        if m.start() >= cutoff:
                            break
                        resume = base + m.end()
                        f["matches"] += 1
                        record(classify(m.group(0), buf[max(0, m.start() - CONTEXT):m.start()]), m.group(0))
                    if final:
                        break
                    keep = min(cutoff, CONTEXT)                # left context for a match that starts at the cutoff
                    resume = max(resume, base + cutoff)
                    base += cutoff - keep
                    carry = buf[cutoff - keep:]
            except OSError:
                f["status"] = "read_error"
                continue
            f["status"] = "scanned"
            if read >= extent:
                f["traversal_finished"] = True
            elif read >= hs.ART_MAX_FILE_BYTES:
                note("truncated_at_size_cap")
            elif state["total"] >= hs.ART_MAX_TOTAL_BYTES:
                raise hs._Stop("total_byte_limit_reached")
        tick()
    except hs._Stop as stop:
        note(stop.label)
    except KeyboardInterrupt:
        note("cancelled")
    except BaseException:
        note("internal_error")
    finally:
        # End checks for every entry that was looked at, opened or not: an entry that appeared,
        # disappeared or was replaced, and an open file that grew, shrank or was modified.
        for name in hs.ARTIFACTS:
            if name not in initial:
                continue
            try:
                if hs._entry_identity(home_fd, name) != initial[name]:
                    res["files"][name]["change_observed"] = True
                if name in opened:
                    fd, st = opened[name]
                    end = os.fstat(fd)
                    if (end.st_size, end.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
                        res["files"][name]["change_observed"] = True
            except KeyboardInterrupt:
                note("cancelled")
            except BaseException:
                res["files"][name]["change_observed"] = True       # a check that cannot be made is not a pass
        for fd in fds:
            try:
                os.close(fd)
            except BaseException:
                pass
    try:
        res["groups"] = [{"shape": k[0], "before": k[1], "word": k[2], "body": k[3], "length": k[4],
                          "occurrences": v[0], "distinct": v[1]} for k, v in sorted(groups.items())]
    except BaseException:
        note("internal_error")
    if state["overflow"]:
        note("distinct_limit_reached")
        res["distinct_counts_are_lower_bounds"] = True
    if any(f["change_observed"] for f in res["files"].values()):
        note("source_change_observed")
    db, wal = res["files"]["state.db"], res["files"]["state.db-wal"]
    if db["status"] == "absent":
        note("database_absent")
    if time.monotonic() > deadline:
        note("time_budget_reached")
    ok_db = db["status"] == "scanned" and db["traversal_finished"]
    ok_wal = wal["status"] == "absent" or (wal["status"] == "scanned" and wal["traversal_finished"])
    res["finished"] = bool(ok_db and ok_wal and not res["run"])
    return res


def render(res: dict) -> str:
    out = ["Secret Guard artifact triage: labels and counts only (contract %s, for matches of %s)" % (res["contract"], res["scans_contract"]),
           "  NOT a read of the conversations. No raw excerpt is printed: no matched byte, neighbour, offset or digest.",
           "  The labels are structural classifications only. No label or combination confirms a credential or clears one.",
           "  They are still information about the matches. Distinct counts are per group and do not add up."]
    for name in hs.ARTIFACTS:
        f = res["files"][name]
        out.append("%s: status %s, %d of %d byte(s) read, traversal finished %s, change observed %s, provider-key matches %d"
                   % (name, f["status"], f["bytes_read"], f["extent_bytes"], "yes" if f["traversal_finished"] else "no",
                      "yes" if f["change_observed"] else "no", f["matches"]))
    low = res["distinct_counts_are_lower_bounds"]
    out.append("groups across both files: %d" % len(res["groups"]))
    for g in res["groups"]:
        out.append("    shape [%s]  before %s  word %s  body %s  length %s  occurrences %d  distinct %s%d"
                   % (g["shape"], g["before"], g["word"], g["body"], g["length"], g["occurrences"], "at least " if low else "", g["distinct"]))
    if low:
        out.append("The distinct limit was reached. Occurrences are exact; every distinct figure is a lower bound.")
    if "group_limit_reached" in res["run"]:
        out.append("The group limit was reached. The groups above keep their own counts; groups left out are not shown at all.")
    out.append("run notes: " + (", ".join(res["run"]) if res["run"] else "none"))
    out.append("Triage " + ("finished." if res["finished"] else "NOT FINISHED: this is a partial or inconclusive result."))
    if "home_path_changed_during_run" in res["run"]:
        out.append("The path you named no longer points at the folder that was read. The counts describe the folder opened at the start.")
    out.append("Zero groups does not show the database holds no secrets. The two files were not read as a snapshot.")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="artifact_triage", description="Labels-and-counts triage of database-artifact matches.")
    ap.add_argument("--home", required=True, help="the one Hermes home to read (no default)")
    ap.add_argument("--json", action="store_true", help="print the same labels and counts as JSON")
    args = ap.parse_args(argv)
    try:
        attached = sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        attached = False
    if not attached:
        sys.stderr.write("artifact_triage: run this yourself at a terminal; it does not run unattended or into a pipe.\n")
        return 2
    pinned = None
    try:
        try:
            pinned = os.open(args.home, hs._DIR)
        except OSError:
            res = _new_result()
            res["run"].append("home_unavailable")
        else:
            res = triage(pinned)
            if hs._home_moved(args.home, pinned):          # also true when the comparison cannot be made
                res["run"].append("home_path_changed_during_run")
                res["finished"] = False
        print(json.dumps(res, indent=2, sort_keys=True) if args.json else render(res))
        return 0 if res["finished"] else 1
    except KeyboardInterrupt:
        sys.stderr.write("artifact_triage: cancelled; no result.\n")
        return 1
    except BaseException:
        sys.stderr.write("artifact_triage: internal error; no result.\n")
        return 1
    finally:
        if pinned is not None:
            try:
                os.close(pinned)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
