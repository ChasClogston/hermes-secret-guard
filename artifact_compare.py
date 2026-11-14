#!/usr/bin/env python3
"""One-off comparison of two database files with the secrets a Hermes home is configured to use.
Read-only. Prints secret names and counts. Never prints a secret value or any byte of the files.

    python3 artifact_compare.py --home /path/to/one/hermes/home --secrets-command /path/to/helper

Run it yourself, at a terminal. It answers one question: is the value of any secret that this
home's own helper hands to Hermes present, byte for byte, in state.db or state.db-wal?

THIS TOOL HANDLES LIVE CREDENTIALS
  It runs the helper you name, the same program Hermes runs at start-up (secrets.command), and
  holds every value the helper prints in this process's memory for the length of the run. That is
  a larger exposure than the scanner or the triage, which never touch a credential. Nothing here
  reduces it to zero. What the tool does about it:
    - The helper path has no default. It must be an absolute path to a regular file owned by you
      and writable by nobody else. It is run directly, never through a shell, with a 30 second
      limit and a 1 MiB limit on its output. Its error output is discarded unread.
    - Values are never printed, logged, written to a file, put in an error message, passed to
      another program or sent anywhere. No digest of a value is printed either.
    - It writes no file and opens no network connection.
  It cannot protect against another program running as you that inspects this process, and it
  cannot know whether the helper itself is safe to run. Read the helper before naming it.

WHAT IT READS
  state.db and state.db-wal of the one home you name, as plain bytes, through one opened handle
  on the home. No SQLite: no connection, no lock protocol, no write. state.db-shm is never read.

WHAT IT PRINTS (contract "artifact-compare-v1")
  Part 1, by secret. For each value the helper printed, under the name or names the helper gave
  it: how many times those exact bytes occur in each of the two files. A name is printed only if
  it is capitals, digits and underscores; any other name is counted and not printed.
    - A value shorter than 16 bytes is not searched for: short values occur by accident, and a
      count for one would say more about the value than about the database. A value longer than
      4,096 bytes is not searched for either. Both are listed by name as not_compared.
    - Several names with the same value are one line. Occurrences may overlap.
  Part 2, by match. The provider-key-shaped matches of the artifact scope ("artifact-bytes-v2",
  same pattern, leftmost and non-overlapping), counted as distinct byte strings in four classes:
    equals_a_current_secret       the match is exactly a value from the helper
    contains_a_current_secret     a value from the helper lies inside the match
    inside_a_current_secret       the match lies inside a value from the helper
    no_current_secret             none of the above
  The first three classes also print the names involved.

WHAT THE OUTPUT DISCLOSES, AND WHAT IT DOES NOT SHOW
  - A name with a count above zero says that this credential's current value is in the home's
    conversation database. That is the purpose, and it is sensitive: read the output before
    sharing it.
  - A count of zero does not show the credential was never in the database. It shows these exact
    bytes were not found as one contiguous run. A value split across pages, stored in another
    encoding, or stored with an escape inside it is not found. An earlier value of the same
    credential, since rotated, is not compared at all.
  - no_current_secret does not show a match is harmless. It may be a revoked key, a key of another
    home or machine, a key this helper does not print, or an example from documentation.
  - Matches can come from deleted or superseded content. The two files are not a snapshot.
    Nothing here speaks to the database's health.

LIMITS
  Same fixed byte limits as the artifact scope (4 GiB per file, 6 GiB for both), at most 2,000
  values, at most 200,000 distinct matches, and a 900 second cooperative time budget that cannot
  interrupt a stalled system call. Each of the two entries is looked at before it is opened and
  again at the end; a file that appears, disappears, is replaced or changes makes the run not
  finished, as does a check that cannot be made, a home path that no longer points at the opened
  folder, a helper that fails, times out, prints too much or prints nothing usable, any limit, or
  any error. If the home cannot be opened or the helper is refused, nothing is read. It declines
  to run when the standard sqlite3 module is already loaded in its process; that is a rejection
  check, not proof that no SQLite connection exists. The terminal check is friction, not proof
  that a person started the run. No system-call trace of this tool exists on macOS.
"""
import argparse
import errno
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import time

import history_scan as hs

CONTRACT = "artifact-compare-v1"
MIN_VALUE_BYTES = 16
MAX_VALUE_BYTES = 4096
MAX_VALUES = 2000
MAX_DISTINCT = 200_000
HELPER_TIMEOUT_S = 30.0
HELPER_MAX_OUTPUT = 1024 * 1024
TIME_BUDGET_S = 900.0
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
MATCH_CLASSES = ("equals_a_current_secret", "contains_a_current_secret", "inside_a_current_secret", "no_current_secret")
STATUS = hs.ARTIFACT_STATUS
HELPER_LABELS = ("helper_path_not_absolute", "helper_not_a_regular_file", "helper_not_owned_by_you", "helper_writable_by_others",
                 "helper_unavailable", "helper_failed", "helper_timed_out", "helper_output_too_large", "helper_printed_no_usable_value",
                 "value_limit_reached")
RUN_LABELS = HELPER_LABELS + ("refused_sqlite_loaded_in_process", "home_unavailable", "home_path_changed_during_run", "database_absent",
                              "source_change_observed", "truncated_at_size_cap", "total_byte_limit_reached", "time_budget_reached",
                              "distinct_limit_reached", "cancelled", "internal_error")
_PATTERN = hs.ARTIFACT_DETECTORS[1][1]
assert hs.ARTIFACT_DETECTORS[1][0] == "provider-key-prefix"


def check_helper(path: str):
    """A fixed label if the helper must not be run, else None. Looks at the file; does not run it."""
    if not os.path.isabs(path):
        return "helper_path_not_absolute"
    try:
        st = os.stat(path)
    except OSError:
        return "helper_unavailable"
    if not stat.S_ISREG(st.st_mode):
        return "helper_not_a_regular_file"
    if st.st_uid != os.geteuid():
        return "helper_not_owned_by_you"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "helper_writable_by_others"
    return None


def run_helper(path: str):
    """Run the helper once and return (values, label). `values` maps a value (bytes) to the list of names the
    helper gave it; names that are not capitals, digits and underscores are kept as None. Never raises, and
    nothing the helper printed appears in a label."""
    label = check_helper(path)
    if label:
        return {}, label
    try:
        proc = subprocess.Popen([path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                close_fds=True, start_new_session=True, cwd="/")
    except OSError:
        return {}, "helper_unavailable"
    try:
        out, _ = proc.communicate(timeout=HELPER_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            pass
        try:
            proc.communicate(timeout=5)
        except BaseException:
            pass
        return {}, "helper_timed_out"
    except BaseException:
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            pass
        return {}, "helper_failed"
    if proc.returncode != 0:
        return {}, "helper_failed"
    if len(out) > HELPER_MAX_OUTPUT:
        return {}, "helper_output_too_large"
    values, label = {}, None
    for line in out.split(b"\n"):
        name, sep, value = line.partition(b"=")
        if not sep or not name:
            continue
        value = value.rstrip(b"\r")
        if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in (b'"', b"'"):
            value = value[1:-1]                      # the one quoting form the dotenv reader also strips
        if not value:
            continue
        try:
            shown = name.decode("ascii")
        except UnicodeDecodeError:
            shown = None
        if shown is not None and not NAME_RE.match(shown):
            shown = None
        if value not in values:
            if len(values) >= MAX_VALUES:
                label = "value_limit_reached"
                break
            values[value] = []
        if shown not in values[value]:
            values[value].append(shown)
    if not values:
        return {}, "helper_printed_no_usable_value"
    return values, label


def _new_file() -> dict:
    return {"status": "not_reached", "traversal_finished": False, "bytes_read": 0, "extent_bytes": 0, "change_observed": False}


def _new_result() -> dict:
    return {"contract": CONTRACT, "scans_contract": hs.ARTIFACT_CONTRACT, "files": {n: _new_file() for n in hs.ARTIFACTS},
            "values_from_helper": 0, "values_compared": 0, "secrets": [], "not_compared": [], "names_not_printed": 0,
            "matches": {c: {"distinct": 0, "names": []} for c in MATCH_CLASSES},
            "distinct_counts_are_lower_bounds": False, "run": [], "finished": False}


def _names(names):
    return sorted(n for n in names if n is not None)


def compare(home_fd: int, values: dict) -> dict:
    """Search both artifacts, through an open home descriptor, for the given values. Never raises; leaves the
    descriptor open. `values` is the mapping run_helper returns."""
    res = _new_result()

    def note(label):
        if label not in res["run"]:
            res["run"].append(label)

    if "sqlite3" in sys.modules or "_sqlite3" in sys.modules:
        note("refused_sqlite_loaded_in_process")
        return res
    res["values_from_helper"] = len(values)
    res["names_not_printed"] = sum(1 for names in values.values() for n in names if n is None)
    wanted = [v for v in values if MIN_VALUE_BYTES <= len(v) <= MAX_VALUE_BYTES]
    res["values_compared"] = len(wanted)
    res["not_compared"] = sorted(({"names": _names(values[v]), "reason": "shorter_than_16_bytes" if len(v) < MIN_VALUE_BYTES else "longer_than_4096_bytes"}
                                  for v in values if v not in wanted), key=lambda d: (d["reason"], d["names"]))
    counts = {v: {n: 0 for n in hs.ARTIFACTS} for v in wanted}
    keep = max([len(v) for v in wanted] + [1]) - 1          # bytes carried so a value across a seam is seen whole
    key = os.urandom(32)
    tokens = {}                                             # digest -> class index; the token itself is not kept
    involved = {c: set() for c in MATCH_CLASSES}
    state = {"total": 0, "overflow": False}
    fds, opened, initial = [], {}, {}
    deadline = time.monotonic() + TIME_BUDGET_S

    def tick():
        if time.monotonic() > deadline:
            raise hs._Stop("time_budget_reached")

    def classify(token):
        if token in values:
            return 0, values[token]
        names, inside = [], []
        for v in wanted:
            if v in token:
                names += values[v]
            elif token in v:
                inside += values[v]
        if names:
            return 1, names
        if inside:
            return 2, inside
        return 3, []

    try:
        for name in hs.ARTIFACTS:
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
                f["change_observed"] = True
            f["extent_bytes"] = st.st_size
            opened[name] = (fd, st)
        for name in hs.ARTIFACTS:
            if name not in opened:
                continue
            fd, st = opened[name]
            f = res["files"][name]
            extent, read = st.st_size, 0
            vcarry = b""                                     # for the value search: starts exactly at the last cutoff
            pcarry, pbase, resume = b"", 0, 0                # for the pattern search, as in the artifact scope
            try:
                while True:
                    tick()
                    allowed = min(hs.CHUNK, extent - read, hs.ART_MAX_FILE_BYTES - read, hs.ART_MAX_TOTAL_BYTES - state["total"])
                    chunk = os.read(fd, allowed) if allowed > 0 else b""
                    read += len(chunk); state["total"] += len(chunk); f["bytes_read"] += len(chunk)
                    final = not chunk
                    # --- part 1: exact values. An occurrence is counted in the buffer where it starts before the cutoff.
                    buf = vcarry + chunk
                    cutoff = len(buf) if final else max(0, len(buf) - keep)
                    for v in wanted:
                        pos = buf.find(v)
                        while pos != -1 and pos < cutoff:
                            counts[v][name] += 1
                            pos = buf.find(v, pos + 1)
                    vcarry = buf[cutoff:]
                    tick()
                    # --- part 2: provider-key-shaped matches, leftmost and non-overlapping
                    buf = pcarry + chunk
                    cutoff = len(buf) if final else max(0, len(buf) - hs.OVERLAP)
                    for m in _PATTERN.finditer(buf, max(0, resume - pbase)):
                        if m.start() >= cutoff:
                            break
                        resume = pbase + m.end()
                        token = m.group(0)
                        digest = hmac.new(key, token, hashlib.sha256).digest()
                        if digest not in tokens:
                            if len(tokens) >= MAX_DISTINCT:
                                state["overflow"] = True
                                continue
                            cls, names = classify(token)
                            tokens[digest] = cls
                            involved[MATCH_CLASSES[cls]].update(n for n in names if n is not None)
                    if final:
                        break
                    resume = max(resume, pbase + cutoff)
                    pbase += cutoff
                    pcarry = buf[cutoff:]
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
                res["files"][name]["change_observed"] = True
        for fd in fds:
            try:
                os.close(fd)
            except BaseException:
                pass
    try:
        res["secrets"] = sorted(({"names": _names(values[v]), "occurrences": dict(counts[v])} for v in wanted),
                                key=lambda d: (-sum(d["occurrences"].values()), d["names"]))
        for i, c in enumerate(MATCH_CLASSES):
            res["matches"][c] = {"distinct": sum(1 for x in tokens.values() if x == i), "names": sorted(involved[c])}
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
    out = ["Secret Guard artifact comparison: secret names and counts only (contract %s)" % res["contract"],
           "  NOT a read of the conversations. No secret value, no byte of either file, no offset and no digest is printed.",
           "  A name with a count above zero says that credential's current value is in this home's database. Treat this output as sensitive."]
    for name in hs.ARTIFACTS:
        f = res["files"][name]
        out.append("%s: status %s, %d of %d byte(s) read, traversal finished %s, change observed %s"
                   % (name, f["status"], f["bytes_read"], f["extent_bytes"], "yes" if f["traversal_finished"] else "no",
                      "yes" if f["change_observed"] else "no"))
    out.append("values from the helper: %d; compared: %d; names not printed (not capitals, digits and underscores): %d"
               % (res["values_from_helper"], res["values_compared"], res["names_not_printed"]))
    found = [s for s in res["secrets"] if sum(s["occurrences"].values())]
    out.append("Part 1. Current values found as exact bytes: %d of %d compared" % (len(found), res["values_compared"]))
    for s in found:
        out.append("    FOUND  [%s]  state.db %d  state.db-wal %d" % (", ".join(s["names"]) or "name not printed",
                                                                        s["occurrences"]["state.db"], s["occurrences"]["state.db-wal"]))
    out.append("    not found as exact bytes: %d value(s)" % (res["values_compared"] - len(found)))
    for d in res["not_compared"]:
        out.append("    not_compared  [%s]  %s" % (", ".join(d["names"]) or "name not printed", d["reason"]))
    low = res["distinct_counts_are_lower_bounds"]
    out.append("Part 2. Provider-key-shaped matches (%s), distinct byte strings by class:" % res["scans_contract"])
    for c in MATCH_CLASSES:
        m = res["matches"][c]
        out.append("    %-28s %s%d%s" % (c, "at least " if low else "", m["distinct"], "  [%s]" % ", ".join(m["names"]) if m["names"] else ""))
    out.append("run notes: " + (", ".join(res["run"]) if res["run"] else "none"))
    out.append("Comparison " + ("finished." if res["finished"] else "NOT FINISHED: this is a partial or inconclusive result."))
    if "home_path_changed_during_run" in res["run"]:
        out.append("The path you named no longer points at the folder that was read. The counts describe the folder opened at the start.")
    out.append("Zero does not show a credential was never in the database: only that these exact bytes were not found in one run.")
    out.append("no_current_secret does not show a match is harmless. The two files were not read as a snapshot.")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="artifact_compare", description="Names-and-counts comparison of database artifacts with a home's current secrets.")
    ap.add_argument("--home", required=True, help="the one Hermes home to read (no default)")
    ap.add_argument("--secrets-command", required=True, help="absolute path of the helper that prints NAME=VALUE lines (no default)")
    ap.add_argument("--json", action="store_true", help="print the same names and counts as JSON")
    args = ap.parse_args(argv)
    try:
        attached = sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        attached = False
    if not attached:
        sys.stderr.write("artifact_compare: run this yourself at a terminal; it does not run unattended or into a pipe.\n")
        return 2
    pinned = None
    try:
        res = None
        if "sqlite3" in sys.modules or "_sqlite3" in sys.modules:
            res = _new_result(); res["run"].append("refused_sqlite_loaded_in_process")
        if res is None:
            try:
                pinned = os.open(args.home, hs._DIR)
            except OSError:
                res = _new_result(); res["run"].append("home_unavailable")
        if res is None:                                  # the home is open and usable: only now is the helper run
            values, label = run_helper(args.secrets_command)
            if label and not values:
                res = _new_result(); res["run"].append(label)
            else:
                res = compare(pinned, values)
                if label:
                    res["run"].append(label); res["finished"] = False
                if hs._home_moved(args.home, pinned):
                    res["run"].append("home_path_changed_during_run"); res["finished"] = False
            values = None
        print(json.dumps(res, indent=2, sort_keys=True) if args.json else render(res))
        return 0 if res["finished"] else 1
    except KeyboardInterrupt:
        sys.stderr.write("artifact_compare: cancelled; no result.\n")
        return 1
    except BaseException:
        sys.stderr.write("artifact_compare: internal error; no result.\n")
        return 1
    finally:
        if pinned is not None:
            try:
                os.close(pinned)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
