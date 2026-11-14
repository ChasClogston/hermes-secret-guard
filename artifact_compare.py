#!/usr/bin/env python3
"""One-off comparison of two database files with a few Keychain items that you name.
Read-only. Prints the item names you typed and counts. Never prints a value or any byte of the files.

    python3 artifact_compare.py --home /path/to/one/hermes/home \\
        --keychain-service NAME [--keychain-service NAME ...]

Run it yourself, at a terminal, on macOS. It answers one question: do the bytes that this Mac's
Keychain returns right now, for each item you name, occur in state.db or state.db-wal of that home?

THIS TOOL HANDLES LIVE CREDENTIALS
  For each item you name (at most 8) it runs the system program /usr/bin/security once, as
      /usr/bin/security find-generic-password -w -s NAME -a ACCOUNT
  and holds what that prints in this process's memory until the comparison ends. That is a larger
  exposure than the scanner or the triage, which touch no credential. Nothing here reduces it to
  zero. What the tool does about it:
    - It runs no program you supply. The one program is a fixed absolute path. Before each run the
      tool checks that the file is a regular file, not a link, owned by root and not writable by
      group or others, and that every folder above it is owned by root and not writable by group
      or others. It checks the file again after the run and discards the result if the file's
      identity, size or modification time changed. This relies on the system's files being
      trustworthy. It looks at owner and permission bits only, not at access-control lists, and
      it is two looks at a path, not a lock: it does not bind the run to the file that was
      checked, a change made and undone between the looks is not seen, and nothing here guards
      against root or against another program running as you.
    - Output from the program is read a piece at a time with a hard limit of 8,192 bytes and a
      10 second limit per item. Past either, the program's process group is killed, the program
      itself is reaped and its pipe closed, and nothing is read from the home. Something the
      program started that left its process group would not be stopped. Error output is
      discarded unread.
    - The program gets a small fixed environment: PATH; HOME and USER taken from the account
      record of the user running the tool, not from the environment; LANG. No input, and "/" as
      its working folder. No keychain file is named, so the program searches its default list of
      keychains. An item name and account identify the query, not one unique item.
    - Core dumps are turned off for this process and its children before any value is fetched. If
      that cannot be confirmed, the tool stops.
    - Values are never printed, logged, written to a file, put in an error message or sent
      anywhere. No digest of a value is printed. The tool writes no file.
  It cannot zero memory, and it cannot protect a value from another program running as you that
  inspects this process. What /usr/bin/security itself reads, writes or contacts is that program's
  business; "no write" and "no network" below describe this tool's own reader only.

WHAT IT READS
  state.db and state.db-wal of the one home you name, as plain bytes, through one opened handle
  on the home. No SQLite: no connection, no lock protocol, no write. state.db-shm is never read.

WHAT THE VALUES ARE, AND ARE NOT
  They are what this Mac's Keychain returns now, to you, for the item names you typed. Nothing
  ties them to the home you named or to what Hermes is using: --home only chooses which two files
  are read. A value Hermes holds from another source, an override, or an earlier value since
  rotated is not compared. The output therefore says "supplied value", never "current secret".

WHAT IT PRINTS (contract "artifact-compare-v2")
  The only names ever printed are item names you typed on the command line, and they are printed
  only when the whole run was allowed to proceed. Item names must not be secret: the tool treats
  what you type as safe to show. Each must be letters, digits, dot, underscore or hyphen, at most
  64 characters, and must not be typed twice. If a name you typed contains anything that was
  fetched, or something fetched contains a name, the tool stops before reading the home.
  Whenever the tool stops early, for that or any other reason, it prints no name at all: items
  are then referred to by their position on the command line (item 1, item 2), and a command
  line it cannot parse gets one fixed message.
  Part 1, by item. For each value: how many times those exact bytes occur in each of the two
  files. Items that return the same value are one line. Occurrences may overlap.
  Part 2, by match. The provider-key-shaped matches of the artifact scope ("artifact-bytes-v2",
  same pattern, leftmost and non-overlapping), counted as distinct byte strings in four classes:
    equals_a_supplied_value       the match is exactly a supplied value
    contains_a_supplied_value     a supplied value lies inside the match
    inside_a_supplied_value       the match lies inside a supplied value
    no_supplied_value             none of the above
  Each match is put in the first class that fits, in that order, and only the item names for that
  class are listed. A match that equals one value and also contains another is listed as equal,
  with only the names of the value it equals. A substring relation is not proof that two things are the same
  credential.

ALL OR NOTHING
  Every item you name must be fetched and must be 16 to 4,096 bytes long. If one is missing,
  unreadable, shorter or longer, the tool says which, by its position, and reads nothing from
  the home.

VALUES THAT CANNOT BE COMPARED
  When a stored value contains a non-printing byte, the system program prints it as hexadecimal
  digits instead, with nothing to say it has done so. The tool cannot tell that apart from a
  value that really is hexadecimal text. So any item whose output is an even number of
  hexadecimal digits and nothing else is refused as value_format_ambiguous, and nothing is read
  from the home. This also refuses genuine keys made only of hexadecimal digits; they cannot be
  checked with this tool. The tool never decodes hexadecimal on its own. "Finished" therefore means: every named item was compared against both files in
  full. It does not mean every credential of the home was compared.

WHAT THE OUTPUT DISCLOSES, AND WHAT IT DOES NOT SHOW
  - A count above zero says the bytes the Keychain returned for that item are in this home's
    database. That is the purpose, and it is sensitive: read the output before sharing it.
  - A count of zero does not show the credential was never in the database. It shows these exact
    bytes were not found as one contiguous run. A value split across pages, stored in another
    encoding or with an escape inside it is not found.
  - no_supplied_value does not show a match is harmless. It may be a revoked key, a key held
    somewhere else, an item you did not name, or an example from documentation.
  - Matches can come from deleted or superseded content. The two files are not a snapshot.
    Nothing here speaks to the database's health.

LIMITS
  Same fixed byte limits as the artifact scope (4 GiB per file, 6 GiB for both), at most 200,000
  distinct matches, and a 900 second cooperative time budget that cannot interrupt a stalled
  system call. Each of the two entries is looked at before it is opened and again at the end; a
  file that appears, disappears, is replaced or changes makes the run not finished, as does a
  check that cannot be made, a home path that no longer points at the opened folder, any limit or
  any error. If the home cannot be opened, no item is fetched. It declines to run when the
  standard sqlite3 module is already loaded in its process; that is a rejection check, not proof
  that no SQLite connection exists. The terminal check is friction, not proof that a person
  started the run. No system-call trace of this tool exists on macOS.
"""
import argparse
import errno
import hashlib
import hmac
import json
import os
import re
import resource
import select
import signal
import stat
import subprocess
import sys
import time

import history_scan as hs

CONTRACT = "artifact-compare-v2"
SECURITY_BIN = "/usr/bin/security"
TOOL_OWNER_UID = 0
MAX_ITEMS = 8
MIN_VALUE_BYTES = 16
MAX_VALUE_BYTES = 4096
FETCH_MAX_OUTPUT = 8192
FETCH_TIMEOUT_S = 10.0
MAX_DISTINCT = 200_000
TIME_BUDGET_S = 900.0
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MATCH_CLASSES = ("equals_a_supplied_value", "contains_a_supplied_value", "inside_a_supplied_value", "no_supplied_value")
STATUS = hs.ARTIFACT_STATUS
ITEM_STATUS = ("fetched", "not_fetched", "item_unavailable", "fetch_timed_out", "fetch_output_too_large", "fetch_failed",
               "value_too_short", "value_too_long", "value_format_ambiguous")
_HEX = frozenset(b"0123456789abcdefABCDEF")
SETUP_LABELS = ("no_item_named", "too_many_items", "item_name_not_allowed", "item_named_twice", "account_name_not_allowed",
                "user_record_unavailable", "core_dump_limit_not_set", "tool_path_not_absolute", "tool_unavailable", "tool_is_a_link", "tool_not_a_regular_file",
                "tool_owner_not_allowed", "tool_writable_by_others", "tool_folder_owner_not_allowed", "tool_folder_writable_by_others",
                "tool_changed_during_run", "an_item_could_not_be_used", "a_name_and_a_value_overlap")
RUN_LABELS = SETUP_LABELS + ("refused_sqlite_loaded_in_process", "home_unavailable", "home_path_changed_during_run", "database_absent",
                             "source_change_observed", "truncated_at_size_cap", "total_byte_limit_reached", "time_budget_reached",
                             "distinct_limit_reached", "cancelled", "internal_error")
_PATTERN = hs.ARTIFACT_DETECTORS[1][1]
assert hs.ARTIFACT_DETECTORS[1][0] == "provider-key-prefix"


def disable_core_dumps() -> bool:
    """Turn core dumps off for this process and its children. True only if the limit reads back as zero."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
    except (ValueError, OSError):
        return False


def check_tool(path: str, owner_uid: int, stop: str = "/"):
    """Look at the program and every folder above it up to `stop`. Returns (identity, None) or (None, label).
    The identity is (device, inode, size, modification time) of the file. This looks; it does not lock."""
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        return None, "tool_path_not_absolute"
    try:
        st = os.lstat(path)
    except OSError:
        return None, "tool_unavailable"
    if stat.S_ISLNK(st.st_mode):
        return None, "tool_is_a_link"
    if not stat.S_ISREG(st.st_mode):
        return None, "tool_not_a_regular_file"
    if st.st_uid != owner_uid:
        return None, "tool_owner_not_allowed"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return None, "tool_writable_by_others"
    folder = os.path.dirname(path)
    while True:
        try:
            d = os.lstat(folder)
        except OSError:
            return None, "tool_unavailable"
        if stat.S_ISLNK(d.st_mode) or not stat.S_ISDIR(d.st_mode):
            return None, "tool_is_a_link"
        if d.st_uid != owner_uid:
            return None, "tool_folder_owner_not_allowed"
        if d.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return None, "tool_folder_writable_by_others"
        if folder == stop or folder == "/":
            break
        folder = os.path.dirname(folder)
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns), None


def _stop_child(proc) -> None:
    """Stop the program and anything it started, reap it, and close its pipe. Never raises; reads nothing more."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except BaseException:
        pass
    try:
        if proc.stdout is not None:
            proc.stdout.close()
    except BaseException:
        pass


def fetch_one(argv, env):
    """Run one fetch and return (value or None, item status). Output is read a piece at a time: past
    FETCH_MAX_OUTPUT bytes or FETCH_TIMEOUT_S seconds the program is stopped at once and nothing it printed
    is kept. For a value that is too short, too long or ambiguous the bytes are still returned with that
    status, so the caller can check them against the typed names before dropping them.
    KeyboardInterrupt is passed on after the same clean-up."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                close_fds=True, start_new_session=True, cwd="/", env=env, bufsize=0)
    except OSError:
        return None, "fetch_failed"
    chunks, total, status = [], 0, None
    deadline = time.monotonic() + FETCH_TIMEOUT_S
    try:
        fd = proc.stdout.fileno()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                status = "fetch_timed_out"
                break
            ready, _, _ = select.select([fd], [], [], left)
            if not ready:
                status = "fetch_timed_out"
                break
            piece = os.read(fd, FETCH_MAX_OUTPUT + 1 - total)
            if not piece:
                break
            total += len(piece)
            if total > FETCH_MAX_OUTPUT:
                status = "fetch_output_too_large"
                break
            chunks.append(piece)
        if status is None:
            try:
                code = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                status = "fetch_timed_out"
            else:
                if code != 0:
                    status = "item_unavailable"
    except BaseException:
        chunks = []
        _stop_child(proc)
        raise
    _stop_child(proc)
    if status is not None:
        return None, status
    value = b"".join(chunks)
    if value.endswith(b"\n"):
        value = value[:-1]
    if len(value) < MIN_VALUE_BYTES:
        return value, "value_too_short"
    if len(value) > MAX_VALUE_BYTES:
        return value, "value_too_long"
    if len(value) % 2 == 0 and all(b in _HEX for b in value):
        return value, "value_format_ambiguous"       # may be the program's hexadecimal rendering of other bytes
    return value, "fetched"


def fetch_items(labels, account):
    """Fetch every named item. Returns (values, statuses, label): `values` maps a value to the list of names
    that returned it; `statuses` is the list of item statuses in command-line order; `label` is a fixed
    reason nothing may be read, or None. No name is ever returned except inside `values`, and `values` is
    empty unless every item is usable and no name overlaps anything fetched."""
    if not labels:
        return {}, [], "no_item_named"
    if any(not isinstance(name, str) or not LABEL_RE.match(name) for name in labels):
        return {}, [], "item_name_not_allowed"
    if len(labels) > MAX_ITEMS:
        return {}, [], "too_many_items"
    if len(set(labels)) != len(labels):
        return {}, [], "item_named_twice"
    if not isinstance(account, str) or not LABEL_RE.match(account):
        return {}, [], "account_name_not_allowed"
    statuses = ["not_fetched"] * len(labels)
    try:
        import pwd
        record = pwd.getpwuid(os.geteuid())
        env = {"PATH": "/usr/bin:/bin", "HOME": record.pw_dir, "USER": record.pw_name, "LANG": "C"}
    except Exception:
        return {}, statuses, "user_record_unavailable"
    if not disable_core_dumps():
        return {}, statuses, "core_dump_limit_not_set"
    fetched = []                                          # every byte string that came back, usable or not
    values = {}
    for i, name in enumerate(labels):
        before, label = check_tool(SECURITY_BIN, TOOL_OWNER_UID)
        if label:
            return {}, statuses, label
        value, status = fetch_one([SECURITY_BIN, "find-generic-password", "-w", "-s", name, "-a", account], env)
        after, label = check_tool(SECURITY_BIN, TOOL_OWNER_UID)
        if label or after != before:
            return {}, ["not_fetched"] * len(labels), label or "tool_changed_during_run"
        statuses[i] = status
        if value is not None:
            fetched.append(value)
            if status == "fetched":
                values.setdefault(value, []).append(name)
    # Before anything else is decided: a typed name must not carry, or be carried by, anything that came back,
    # including bytes that are about to be dropped as too short, too long or ambiguous.
    for value in fetched:
        for name in labels:
            if value and (name.encode() in value or value in name.encode()):
                return {}, ["not_fetched"] * len(labels), "a_name_and_a_value_overlap"
    if any(status != "fetched" for status in statuses):
        return {}, statuses, "an_item_could_not_be_used"
    return values, statuses, None


def _new_file() -> dict:
    return {"status": "not_reached", "traversal_finished": False, "bytes_read": 0, "extent_bytes": 0, "change_observed": False}


def _new_result() -> dict:
    return {"contract": CONTRACT, "scans_contract": hs.ARTIFACT_CONTRACT, "files": {n: _new_file() for n in hs.ARTIFACTS},
            "items": [], "values_compared": 0, "supplied": [],
            "matches": {c: {"distinct": 0, "names": []} for c in MATCH_CLASSES},
            "distinct_counts_are_lower_bounds": False, "run": [], "finished": False}


def compare(home_fd: int, values: dict) -> dict:
    """Search both artifacts, through an open home descriptor, for the given values. Never raises; leaves the
    descriptor open. `values` maps each value (bytes, 16 to 4,096 long) to the list of names that supplied it."""
    res = _new_result()

    def note(label):
        if label not in res["run"]:
            res["run"].append(label)

    if "sqlite3" in sys.modules or "_sqlite3" in sys.modules:
        note("refused_sqlite_loaded_in_process")
        return res
    if not values or any(not (MIN_VALUE_BYTES <= len(v) <= MAX_VALUE_BYTES) for v in values):
        note("an_item_could_not_be_used")              # nothing is read unless every value is usable
        return res
    res["values_compared"] = len(values)
    counts = {v: {n: 0 for n in hs.ARTIFACTS} for v in values}
    keep = max(len(v) for v in values) - 1                  # bytes carried so a value across a seam is seen whole
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
        for v in values:
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
                    for v in values:
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
                            involved[MATCH_CLASSES[cls]].update(names)
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
        res["supplied"] = sorted(({"names": sorted(values[v]), "occurrences": dict(counts[v])} for v in values),
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
    out = ["Secret Guard artifact comparison: the item names you typed, and counts (contract %s)" % res["contract"],
           "  NOT a read of the conversations. No value, no byte of either file, no offset and no digest is printed.",
           "  Values are what this Mac's Keychain returned now for the names you typed. Nothing ties them to this home or to what Hermes uses.",
           "  A count above zero says those bytes are in this home's database. Treat this output as sensitive."]
    for i, status in enumerate(res["items"], 1):
        out.append("item %d: %s" % (i, status))
    for name in hs.ARTIFACTS:
        f = res["files"][name]
        out.append("%s: status %s, %d of %d byte(s) read, traversal finished %s, change observed %s"
                   % (name, f["status"], f["bytes_read"], f["extent_bytes"], "yes" if f["traversal_finished"] else "no",
                      "yes" if f["change_observed"] else "no"))
    found = [s for s in res["supplied"] if sum(s["occurrences"].values())]
    out.append("Part 1. Supplied values found as exact bytes: %d of %d compared" % (len(found), res["values_compared"]))
    for s in res["supplied"]:
        hit = sum(s["occurrences"].values()) > 0
        out.append("    %s  [%s]  state.db %d  state.db-wal %d" % ("FOUND    " if hit else "not found", ", ".join(s["names"]),
                                                                    s["occurrences"]["state.db"], s["occurrences"]["state.db-wal"]))
    low = res["distinct_counts_are_lower_bounds"]
    out.append("Part 2. Provider-key-shaped matches (%s), distinct byte strings, each in the first class that fits:" % res["scans_contract"])
    for c in MATCH_CLASSES:
        m = res["matches"][c]
        out.append("    %-28s %s%d%s" % (c, "at least " if low else "", m["distinct"], "  [%s]" % ", ".join(m["names"]) if m["names"] else ""))
    out.append("run notes: " + (", ".join(res["run"]) if res["run"] else "none"))
    out.append("Comparison " + ("finished: every named item was compared against both files in full."
                                if res["finished"] else "NOT FINISHED: this is a partial or inconclusive result."))
    if "an_item_could_not_be_used" in res["run"]:
        out.append("At least one item could not be fetched, was outside 16 to 4,096 bytes, or came back in an ambiguous form.")
        out.append("Items are numbered in the order you typed them. Nothing was read from the home.")
    if "home_path_changed_during_run" in res["run"]:
        out.append("The path you named no longer points at the folder that was read. The counts describe the folder opened at the start.")
    out.append("Zero does not show a credential was never in the database: only that these exact bytes were not found in one run.")
    out.append("no_supplied_value does not show a match is harmless, and finished does not mean every credential of the home was compared.")
    return "\n".join(out)


class _QuietParser(argparse.ArgumentParser):
    """A command line that cannot be parsed gets one fixed message. Nothing that was typed is repeated."""

    def error(self, message):
        sys.stderr.write("artifact_compare: the command line was not understood; nothing was run. See --help.\n")
        raise SystemExit(2)


def main(argv=None) -> int:
    ap = _QuietParser(prog="artifact_compare", allow_abbrev=False,
                      description="Names-and-counts comparison of database artifacts with Keychain items you name.")
    ap.add_argument("--home", required=True, help="the one Hermes home whose two files are read (no default)")
    ap.add_argument("--keychain-service", action="append", default=[], metavar="NAME",
                    help="a Keychain item (service name) to fetch and compare; repeat for up to 8 (no default)")
    ap.add_argument("--keychain-account", default=None, help="the Keychain account of those items (default: your user name)")
    ap.add_argument("--json", action="store_true", help="print the same names and counts as JSON")
    args = ap.parse_args(argv)
    try:
        attached = sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        attached = False
    if not attached:
        sys.stderr.write("artifact_compare: run this yourself at a terminal; it does not run unattended or into a pipe.\n")
        return 2
    pinned, values = None, {}
    try:
        res = None
        if "sqlite3" in sys.modules or "_sqlite3" in sys.modules:
            res = _new_result(); res["run"].append("refused_sqlite_loaded_in_process")
        if res is None:
            try:
                pinned = os.open(args.home, hs._DIR)
            except OSError:
                res = _new_result(); res["run"].append("home_unavailable")
        if res is None:                                  # the home is open and usable: only now is anything fetched
            account = args.keychain_account
            if account is None:
                try:
                    import pwd
                    account = pwd.getpwuid(os.geteuid()).pw_name
                except Exception:
                    account = ""
            values, statuses, label = fetch_items(list(args.keychain_service), account)
            if label:
                values = {}
                res = _new_result(); res["items"] = statuses; res["run"].append(label)
            else:
                res = compare(pinned, values)
                res["items"] = statuses
                if hs._home_moved(args.home, pinned):
                    res["run"].append("home_path_changed_during_run"); res["finished"] = False
        print(json.dumps(res, indent=2, sort_keys=True) if args.json else render(res))
        return 0 if res["finished"] else 1
    except KeyboardInterrupt:
        sys.stderr.write("artifact_compare: cancelled; no result.\n")
        return 1
    except BaseException:
        sys.stderr.write("artifact_compare: internal error; no result.\n")
        return 1
    finally:
        values.clear()                                   # drops the references; it does not erase memory
        if pinned is not None:
            try:
                os.close(pinned)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
