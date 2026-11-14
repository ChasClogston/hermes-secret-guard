"""Static inventory of Secret Guard across Hermes homes. Read-only.

Run inside Hermes as `hermes secret inventory`, or from a clone with no Hermes at all:

    python3 inventory.py [--root PATH ...] [--json] [--names] [--paths]

What it inspects, and nothing more: for each Hermes home, `config.yaml` and the manifest at
`<home>/plugins/secret-guard/plugin.yaml` (the user plugin directory), plus that folder's
`.git/HEAD` and ref files for the commit. Identity markers such as `.env` are checked for
existence only and never opened.

Run as a script, this module imports nothing from the plugin, runs no subprocess, opens no
socket and writes no file. (`hermes secret inventory` reaches the same code through the
plugin's command module, which Hermes has already loaded along with the rest of the plugin.)

What it reports is configuration found on disk at one location. Whether a running Hermes has
the guard loaded and enforcing is a different question; every row says `runtime: not tested`.
Bundled plugins, opt-in project plugins (`./.hermes/plugins`), pip entry-point plugins and
`HERMES_SAFE_MODE` are not inspected, so `absent` means absent from the user plugin directory.

Profile discovery follows Hermes's own rules as read from its source at commit 3b4215785882
(0.23): a folder under `profiles/` is a profile when its name is a valid profile id, it holds
at least one identity marker, and it has no tombstone under `profiles/.deleted/`. That commit is
a compatibility baseline. The installed Hermes is not detected; if its rules change, this file
needs maintenance. It never imports Hermes's profile code to find out.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import platform
import re
import socket
import stat
import sys

PLUGIN = "secret-guard"
LOCATION = "user plugin directory (<home>/plugins/%s)" % PLUGIN
EXPECTED_HOOKS = ("on_session_start", "pre_llm_call", "pre_tool_call", "transform_tool_result",
                  "transform_terminal_output", "transform_llm_output")
# Hermes 0.23, hermes_constants.py
IDENTITY_MARKERS = ("config.yaml", ".env", "SOUL.md", "profile.yaml", "auth.json", "state.db")
PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TOMBSTONES = ".deleted"
DISCOVERY_RULES = "Hermes 0.23 (source commit 3b4215785882)"

VERSION_RE = re.compile(r"^\d{1,5}(\.\d{1,5}){0,3}([-+.][0-9A-Za-z.]{1,16})?$")
MAX_FILE_BYTES = 2_000_000          # config.yaml / plugin.yaml: larger is not parsed
MAX_REF_BYTES = 4_096               # .git/HEAD and loose refs
MAX_PACKED_BYTES = 2_000_000        # .git/packed-refs
MAX_ENTRIES = 5_000                 # entries listed in one profiles/ folder
MAX_HOMES = 500                     # homes per run
RUNTIME = "not tested"

# The six states. None of them means "protected".
ABSENT, DISABLED, CONFIGURED, UNREADABLE, UNSUPPORTED, UNKNOWN = (
    "absent", "disabled", "configured", "unreadable", "unsupported", "unknown")
STATES = (CONFIGURED, DISABLED, ABSENT, UNSUPPORTED, UNREADABLE, UNKNOWN)


class _Unreadable(Exception):
    pass


class _Malformed(Exception):
    pass


def _yaml_loader():
    """A safe YAML loader, or None. Hermes's bundled reader first, then PyYAML. Safe loaders
    build plain data only; no custom tags or constructors are run."""
    for mod in ("hermes_yaml", "yaml"):
        try:
            return __import__(mod).safe_load
        except Exception:
            continue
    return None


def _read(path: str, limit: int = None) -> str:
    """Text of a regular file, at most `limit` bytes. Symlinks are followed (Hermes follows them
    too); what the link leads to must be a regular file. The file is opened without blocking and
    the open descriptor is checked, so a FIFO, device, socket or directory put in its place is
    refused instead of read. Raises FileNotFoundError, _Unreadable or _Malformed."""
    limit = MAX_FILE_BYTES if limit is None else limit
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ENXIO, errno.ELOOP, errno.ENOTDIR, errno.EISDIR):
            raise _Malformed("not a regular file")
        raise _Unreadable(type(exc).__name__)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _Malformed("not a regular file")
        chunks, total = [], 0
        while total <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk); total += len(chunk)
        if total > limit:
            raise _Malformed("larger than the size this tool parses")
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError:
            raise _Malformed("not valid UTF-8")
    except OSError as exc:
        raise _Unreadable(type(exc).__name__)
    finally:
        os.close(fd)


def _load_yaml(path: str, loader) -> dict:
    text = _read(path)
    if loader is None:
        raise _Malformed("no YAML reader available")
    try:
        data = loader(text)
    except Exception as exc:
        raise _Malformed("not valid YAML (%s)" % type(exc).__name__)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise _Malformed("top level is not a mapping")
    return data


def _clean(text) -> str:
    """Printable form of a name taken from disk: control characters and newlines are escaped."""
    return "".join(c if c.isprintable() else "\\x%02x" % ord(c) if ord(c) < 256 else "\\u%04x" % ord(c)
                   for c in str(text))[:200]


def _str_list(value, what: str) -> list:
    """A list of strings, or [] for a missing or null value. Anything else is malformed: a
    scalar where a list belongs is most likely a typo, and it must not pass silently."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise _Malformed("`%s` is not a list" % what)
    if not all(isinstance(v, str) for v in value):
        raise _Malformed("`%s` has a member that is not text" % what)
    return value


def _is_sha(s: str) -> bool:
    return len(s) == 40 and all(c in "0123456789abcdef" for c in s)


def _commit(plugin_dir: str) -> str:
    """The checked-out commit, read from .git files. No git is run. 'unknown' if it cannot be told."""
    git = os.path.join(plugin_dir, ".git")
    try:
        if not os.path.isdir(git):
            return "unknown"
        head = _read(os.path.join(git, "HEAD"), MAX_REF_BYTES).strip()
        if not head.startswith("ref:"):
            return head if _is_sha(head) else "unknown"
        ref = head[4:].strip()
        if not re.match(r"^refs/[A-Za-z0-9._/-]{1,200}$", ref) or ".." in ref:
            return "unknown"
        try:
            sha = _read(os.path.join(git, *ref.split("/")), MAX_REF_BYTES).strip()
            return sha if _is_sha(sha) else "unknown"
        except FileNotFoundError:
            for line in _read(os.path.join(git, "packed-refs"), MAX_PACKED_BYTES).splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref and _is_sha(parts[0]):
                    return parts[0]
    except (FileNotFoundError, _Unreadable, _Malformed, OSError):
        pass
    return "unknown"


def _identity(path: str):
    try:
        st = os.stat(path)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


def _exists(path: str) -> str:
    """'yes', 'no' or 'unreadable'. Existence only: the file is never opened."""
    try:
        os.lstat(path)
        return "yes"
    except (FileNotFoundError, NotADirectoryError):
        return "no"
    except OSError:
        return "unreadable"


def _tombstoned(path: str) -> str:
    """'yes', 'no' or 'unreadable', as Hermes decides it: `Path(tombstone).exists()`, which follows
    symlinks. A dangling tombstone link therefore does NOT delete a profile. This is deliberately
    different from identity markers, where a dangling link still counts."""
    try:
        os.stat(path)
        return "yes"
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
            return "no"
        return "unreadable"


def _markers(home: str) -> str:
    """Does this folder carry a Hermes identity marker? 'yes', 'no' or 'unreadable'. A marker
    counts when it is a regular file or any symlink, as in Hermes. Nothing is opened."""
    unreadable = False
    for m in IDENTITY_MARKERS:
        try:
            st = os.lstat(os.path.join(home, m))
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            unreadable = True
            continue
        if stat.S_ISLNK(st.st_mode) or stat.S_ISREG(st.st_mode):
            return "yes"
    return "unreadable" if unreadable else "no"


def discover(roots: list) -> dict:
    """Homes, and an account of everything else that was looked at.

    `roots` is a list of (path, source). Returns {homes, searched, skipped, failures}. A root that
    is missing, is not a folder or cannot be listed is a failure: the requested scope was not
    inspected. `skipped` entries carry a kind: 'not-a-profile' (Hermes ignores it too), 'deleted'
    (tombstoned), or 'ambiguous' (Hermes would not list it, yet it looks like a home)."""
    homes, searched, skipped, failures = [], [], [], []

    def skip(path, kind, reason):
        skipped.append({"path": path, "kind": kind, "reason": reason})

    for number, (root, source) in enumerate(roots, 1):
        root = os.path.abspath(os.path.expanduser(root))
        searched.append({"root": root, "source": source, "number": number})
        try:
            st = os.stat(root)
        except FileNotFoundError:
            failures.append({"root_no": number, "reason": "root %d does not exist" % number}); continue
        except OSError as exc:
            failures.append({"root_no": number, "reason": "root %d could not be examined (%s)" % (number, type(exc).__name__)}); continue
        if not stat.S_ISDIR(st.st_mode):
            failures.append({"root_no": number, "reason": "root %d is not a folder" % number}); continue
        base = {"root": root, "root_no": number}
        homes.append(dict(base, name="default", path=root, source=source, kind="default"))
        pdir = os.path.join(root, "profiles")
        state = _exists(pdir)
        if state == "no":
            continue
        names, truncated = [], False
        try:
            with os.scandir(pdir) as it:
                for entry in it:
                    if len(names) >= MAX_ENTRIES:
                        truncated = True
                        break
                    names.append(entry.name)
        except OSError as exc:
            failures.append({"root_no": number, "reason": "the profiles folder of root %d could not be listed (%s)"
                             % (number, type(exc).__name__)})
            continue
        if truncated:
            failures.append({"root_no": number, "reason": "the profiles folder of root %d has more than %d entries; "
                             "the rest were not examined" % (number, MAX_ENTRIES)})
        for name in sorted(names):
            if len(homes) > MAX_HOMES:
                break
            p = os.path.join(pdir, name)
            if name.startswith("."):
                skip(p, "not-a-profile", "dot-folder (Hermes bookkeeping)"); continue
            try:
                is_dir = stat.S_ISDIR(os.stat(p).st_mode)
            except FileNotFoundError:
                skip(p, "not-a-profile", "dangling link or vanished entry"); continue
            except OSError:
                homes.append(dict(base, name=name, path=p, source=source + ", profiles folder", kind="unexaminable")); continue
            if not is_dir:
                skip(p, "not-a-profile", "not a folder"); continue
            marked = _markers(p)
            valid = bool(PROFILE_ID_RE.match(name)) and name != "default"
            has_plugin = _exists(os.path.join(p, "plugins", PLUGIN)) == "yes"
            if marked == "unreadable":
                homes.append(dict(base, name=name, path=p, source=source + ", profiles folder", kind="unexaminable")); continue
            if valid and marked == "yes":
                tomb = _tombstoned(os.path.join(pdir, TOMBSTONES, name))
                if tomb == "yes":
                    skip(p, "deleted", "deleted profile (tombstone present)")
                elif tomb == "unreadable":
                    homes.append(dict(base, name=name, path=p, source=source + ", profiles folder", kind="unexaminable"))
                else:
                    homes.append(dict(base, name=name, path=p, source=source + ", profiles folder", kind="profile"))
            elif marked == "yes" or has_plugin:
                why = "name is not a valid profile id" if not valid else "no identity marker"
                skip(p, "ambiguous", "%s, so Hermes does not list it, yet it holds %s"
                     % (why, "an identity marker" if marked == "yes" else "Secret Guard plugin files"))
            else:
                skip(p, "not-a-profile", "no identity marker" if valid else "name is not a valid profile id")
    return {"homes": homes, "searched": searched, "skipped": skipped, "failures": failures}


def inspect(home: dict, loader, system: str) -> dict:
    """One row. Reads config.yaml and the manifest in the user plugin directory; nothing else."""
    path = home["path"]
    row = {"name": _clean(home["name"]), "source": home["source"], "state": UNKNOWN, "notes": [],
           "plugin_files": "unknown", "version": "unknown", "commit": "unknown", "listed_enabled": "unknown",
           "key_source": "unknown", "hooks_declared": "unknown", "runtime": RUNTIME, "location": LOCATION,
           "symlink": os.path.islink(path), "path": path, "root": home["root"], "root_no": home["root_no"]}
    notes = row["notes"]
    if home.get("kind") == "unexaminable":
        row["state"] = UNREADABLE
        notes.append("this entry could not be examined; whether it is a home is not known")
        return row

    # --- config.yaml
    cfg, cfg_state = None, "ok"
    try:
        cfg = _load_yaml(os.path.join(path, "config.yaml"), loader)
    except FileNotFoundError:
        cfg_state = "missing"
        notes.append("recognised as a home, but it has no config.yaml")
    except _Unreadable as exc:
        cfg_state = "unreadable"
        notes.append("config.yaml could not be read (%s)" % exc)
    except _Malformed as exc:
        cfg_state = "malformed"
        notes.append("config.yaml: %s" % exc)
    if cfg is not None:
        try:
            plugins = cfg.get("plugins")
            if plugins is not None and not isinstance(plugins, dict):
                raise _Malformed("`plugins` is not a mapping")
            plugins = plugins or {}
            enabled = _str_list(plugins.get("enabled"), "plugins.enabled")
            disabled = _str_list(plugins.get("disabled"), "plugins.disabled")
            secrets = cfg.get("secrets")
            if secrets is not None and not isinstance(secrets, dict):
                raise _Malformed("`secrets` is not a mapping")
            sg = (secrets or {}).get("secret_guard")
            if sg is not None and not isinstance(sg, dict):
                raise _Malformed("`secrets.secret_guard` is not a mapping")
            if sg is not None and "enabled" in sg and not isinstance(sg["enabled"], bool):
                raise _Malformed("`secrets.secret_guard.enabled` is not true or false")
            row["listed_enabled"] = "yes" if PLUGIN in enabled else "no"
            if PLUGIN in disabled:
                row["listed_enabled"] = "no"
                notes.append("listed in plugins.disabled" + (" and in plugins.enabled" if PLUGIN in enabled else ""))
            row["key_source"] = "not set" if not sg or "enabled" not in sg else ("on" if sg["enabled"] else "off")
        except _Malformed as exc:
            cfg_state = "malformed"
            notes.append("config.yaml: %s" % exc)

    # --- plugin files, at one location: <home>/plugins/secret-guard
    pdir = os.path.join(path, "plugins", PLUGIN)
    files_state = "ok"
    there = _exists(pdir)
    if there == "unreadable" or (there == "no" and _exists(os.path.join(path, "plugins")) == "unreadable"):
        files_state = "unreadable"
        notes.append("the plugins folder could not be examined")
    elif there == "no":
        try:                                     # absence must be established, not assumed
            parent = os.path.join(path, "plugins")
            if _exists(parent) == "yes":
                with os.scandir(parent):
                    pass
            row["plugin_files"] = "absent"
        except NotADirectoryError:
            row["plugin_files"] = "absent"
        except OSError:
            files_state = "unreadable"
            notes.append("the plugins folder could not be listed")
    elif not os.path.isdir(pdir):
        files_state = "malformed"
        notes.append("plugins/%s is not a folder" % PLUGIN)
    else:
        if os.path.islink(pdir):
            notes.append("plugin folder is a symlink")
        try:
            meta = _load_yaml(os.path.join(pdir, "plugin.yaml"), loader)
            name = meta.get("name")
            if name is not None and name != PLUGIN:
                raise _Malformed("the manifest names a different plugin")
            version = meta.get("version")
            if isinstance(version, (int, float)) and not isinstance(version, bool):
                version = str(version)
            if version is None:
                notes.append("the manifest has no version")
            elif not isinstance(version, str) or not VERSION_RE.match(version):
                raise _Malformed("the manifest version is not a version string")
            else:
                row["version"] = version
            hooks = meta.get("provides_hooks")
            platforms = meta.get("platforms")
            if hooks is not None:
                hooks = _str_list(hooks, "provides_hooks")
            if platforms is not None:
                platforms = _str_list(platforms, "platforms")
            row["plugin_files"] = "present"
            row["commit"] = _commit(pdir)
            if hooks is None:
                notes.append("the manifest declares no hook list")
            else:
                missing = [h for h in EXPECTED_HOOKS if h not in hooks]
                row["hooks_declared"] = "%d of %d" % (len(EXPECTED_HOOKS) - len(missing), len(EXPECTED_HOOKS))
                if missing:
                    notes.append("the manifest does not declare: " + ", ".join(missing))
            want = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}.get(system, "other")
            if platforms is not None and want not in [p.lower() for p in platforms]:
                files_state = "unsupported"
                notes.append("the manifest does not list this platform (%s)" % want)
        except FileNotFoundError:
            files_state = "malformed"
            notes.append("the plugin folder has no plugin.yaml")
        except _Unreadable as exc:
            files_state = "unreadable"
            notes.append("plugin.yaml could not be read (%s)" % exc)
        except _Malformed as exc:
            files_state = "malformed"
            row["version"] = "unknown"
            notes.append("plugin.yaml: %s" % exc)

    # --- one state. Worst evidence wins; nothing unreadable or unparsed becomes a positive result.
    if "unreadable" in (cfg_state, files_state):
        row["state"] = UNREADABLE
    elif "malformed" in (cfg_state, files_state) or cfg_state == "missing":
        row["state"] = UNKNOWN
    elif files_state == "unsupported" or (row["plugin_files"] == "present" and system != "Darwin"):
        row["state"] = UNSUPPORTED
        if system != "Darwin":
            notes.append("Secret Guard loads on macOS only; this host is not macOS")
    elif row["plugin_files"] == "absent":
        row["state"] = ABSENT
        if row["listed_enabled"] == "yes":
            notes.append("listed in plugins.enabled but there are no plugin files at this location")
    elif row["listed_enabled"] == "yes":
        row["state"] = CONFIGURED
        if row["key_source"] != "on":
            notes.append("key source is %s (secrets.secret_guard.enabled)" % row["key_source"])
    else:
        row["state"] = DISABLED
    return row


def run(roots: list, system: str = None, loader="auto", expect_version: str = None, expect_commit: str = None) -> dict:
    system = platform.system() if system is None else system
    loader = _yaml_loader() if loader == "auto" else loader
    found = discover(roots)
    homes = found["homes"]
    incomplete = [f["reason"] for f in found["failures"]]
    if len(homes) > MAX_HOMES:
        incomplete.append("more than %d homes; only the first %d were inspected" % (MAX_HOMES, MAX_HOMES))
        homes = homes[:MAX_HOMES]
    rows, seen = [], {}
    for n, h in enumerate(homes, 1):
        row = inspect(h, loader, system)
        row["id"] = "home-%d" % n
        ident = _identity(h["path"])
        if ident is not None and ident in seen:
            row["notes"].append("same folder as %s (duplicate or symlink); counted once" % seen[ident])
            row["duplicate_of"] = seen[ident]
        elif ident is not None:
            seen[ident] = row["id"]
        rows.append(row)
    present = [r for r in rows if r["plugin_files"] == "present"]
    differ = len({r["version"] for r in present}) > 1 or len({r["commit"] for r in present}) > 1
    for r in present:
        if expect_version and r["version"] != expect_version:
            r["notes"].append("version %s is not the expected one" % r["version"])
        if expect_commit and not (r["commit"] != "unknown" and r["commit"].startswith(expect_commit.lower())):
            r["notes"].append("commit %s is not the expected one" % r["commit"][:12])
        if differ:
            r["notes"].append("installed copies differ between homes")
    if loader is None:
        incomplete.append("no YAML reader (hermes_yaml or PyYAML): no configuration could be parsed")
    unique = [r for r in rows if "duplicate_of" not in r]
    counts = {s: sum(1 for r in unique if r["state"] == s) for s in STATES}
    if counts[UNREADABLE] or counts[UNKNOWN]:
        incomplete.append("%d home(s) unreadable or unknown" % (counts[UNREADABLE] + counts[UNKNOWN]))
    kinds = {}
    for s in found["skipped"]:
        kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
    return {"host": _clean(socket.gethostname()), "platform": system or "unknown", "discovery_rules": DISCOVERY_RULES,
            "location_inspected": LOCATION, "searched": found["searched"], "skipped": found["skipped"],
            "skipped_counts": kinds, "homes": rows, "unique_homes": len(unique), "counts": counts, "runtime": RUNTIME,
            "complete": not incomplete, "incomplete_reasons": incomplete,
            # `complete` means the stated rules were applied to everything in scope. It does not mean
            # every possible home is accounted for: ambiguous entries still need a person to look.
            "needs_attention": kinds.get("ambiguous", 0)}


def _public(report: dict, names: bool, paths: bool) -> dict:
    """The report as it may be shown. By default no path and no name taken from the file system
    appears: homes are home-1, home-2, ...; skipped entries are counted by kind. `names` adds
    profile names and skipped entry names. `paths` adds full paths as well."""
    names = names or paths
    out = {k: report[k] for k in ("host", "platform", "discovery_rules", "location_inspected", "skipped_counts",
                                  "unique_homes", "counts", "runtime", "complete", "incomplete_reasons", "needs_attention")}
    out["searched"] = [dict({"number": s["number"], "source": s["source"]}, **({"root": _clean(s["root"])} if paths else {}))
                       for s in report["searched"]]
    out["homes"] = []
    for r in report["homes"]:
        h = {k: r[k] for k in ("id", "state", "plugin_files", "listed_enabled", "version", "commit", "hooks_declared",
                               "key_source", "runtime", "symlink", "source", "root_no", "notes")}
        h["default_home"] = r["name"] == "default" and r["path"] == r["root"]
        if "duplicate_of" in r:
            h["duplicate_of"] = r["duplicate_of"]
        if names:
            h["name"] = r["name"]
        if paths:
            h["path"] = _clean(r["path"])
        out["homes"].append(h)
    if names:
        out["skipped"] = [dict({"kind": s["kind"], "reason": s["reason"], "name": _clean(os.path.basename(s["path"]))},
                               **({"path": _clean(s["path"])} if paths else {})) for s in report["skipped"]]
    return out


def render(report: dict, names: bool = False, paths: bool = False) -> str:
    pub = _public(report, names, paths)
    names = names or paths
    out = ["Secret Guard inventory (static, read-only)",
           "host %s, platform %s" % (pub["host"], pub["platform"]),
           "location inspected: %s" % pub["location_inspected"],
           "profile rules: %s" % pub["discovery_rules"], "",
           "Roots searched:"]
    for s in pub["searched"]:
        out.append("  root %d  [%s]%s" % (s["number"], s["source"], "  " + s["root"] if paths else ""))
    out += ["", "%-9s %-11s %-8s %-8s %-9s %-7s %-8s %s" % ("home", "state", "files", "enabled", "version", "hooks", "keysrc", "runtime")]
    for h in pub["homes"]:
        out.append("%-9s %-11s %-8s %-8s %-9s %-7s %-8s %s" % (
            h["id"], h["state"], h["plugin_files"], h["listed_enabled"], h["version"][:9],
            h["hooks_declared"], h["key_source"], h["runtime"]))
        label = "the default home of root %d" % h["root_no"] if h["default_home"] else "a named profile under root %d" % h["root_no"]
        out.append("    %s%s%s" % (label, ": " + h["name"] if names and not h["default_home"] else "",
                                   " (the home folder is a symlink)" if h["symlink"] else ""))
        if paths:
            out.append("    path %s" % h["path"])
        if h["commit"] != "unknown":
            out.append("    commit %s" % h["commit"][:12])
        for n in h["notes"]:
            out.append("    - " + _clean(n))
    c = pub["counts"]
    out += ["", "%d home(s), counted once each: " % pub["unique_homes"] + ", ".join("%d %s" % (c[s], s) for s in STATES)]
    sk = pub["skipped_counts"]
    out.append("Entries under profiles/ that are not counted as homes: %d" % sum(sk.values())
               + ("" if not sk else " (" + ", ".join("%d %s" % (sk[k], k) for k in sorted(sk)) + ")"))
    if sk.get("ambiguous"):
        out.append("  NEEDS ATTENTION: %d ambiguous entr%s. They look like homes but Hermes would not list them, so they are"
                   % (sk["ambiguous"], "y" if sk["ambiguous"] == 1 else "ies"))
        out.append("  not counted. Resolve them by hand (--names shows which).")
    for s in pub.get("skipped", []):
        out.append("  - %s: %s [%s]" % (s["path"] if paths else s["name"], s["reason"], s["kind"]))
    if not names:
        out.append("Names and paths are hidden. --names shows profile names; --paths shows full paths. Both can be sensitive.")
    out += ["",
            "'configured' means plugin files are present at the location inspected and the home's config lists the plugin.",
            "It does not mean the guard is loaded or enforcing: runtime behaviour was not tested.",
            "'absent' means absent from that location. Bundled, project and pip-installed plugins are not inspected.",
            "Inventory " + ("complete: the stated profile rules were applied to everything in scope."
                            if pub["complete"] else "INCOMPLETE: " + "; ".join(pub["incomplete_reasons"]) + "."),
            "The profile rules are a fixed baseline (%s). The installed Hermes is not detected and may differ." % pub["discovery_rules"]]
    return "\n".join(out)


def default_roots() -> list:
    env = os.environ.get("HERMES_HOME")
    if env:
        return [(env, "HERMES_HOME")]
    return [(os.path.join("~", ".hermes"), "default root")]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="inventory", description="Static, read-only inventory of Secret Guard across Hermes homes.")
    ap.add_argument("--root", action="append", default=[], help="a Hermes root to search (repeatable); default ~/.hermes or $HERMES_HOME")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--names", action="store_true", help="show profile names and skipped entry names (hidden by default)")
    ap.add_argument("--paths", action="store_true", help="show full paths as well (hidden by default)")
    ap.add_argument("--expect-version", help="note every installed copy whose version differs")
    ap.add_argument("--expect-commit", help="note every installed copy whose commit differs")
    args = ap.parse_args(argv)
    for flag, value, pattern in (("--expect-version", args.expect_version, VERSION_RE),
                                 ("--expect-commit", args.expect_commit, re.compile(r"^[0-9a-fA-F]{7,40}$"))):
        if value is not None and not pattern.match(value):
            ap.error("%s is not in the expected form" % flag)
    roots = [(r, "--root argument") for r in args.root] or default_roots()
    report = run(roots, expect_version=args.expect_version, expect_commit=args.expect_commit)
    if args.json:
        print(json.dumps(_public(report, args.names, args.paths), indent=2, sort_keys=True))
    else:
        print(render(report, names=args.names, paths=args.paths))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
