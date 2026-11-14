"""Static inventory of Secret Guard across Hermes homes. Read-only.

Run inside Hermes as `hermes secret inventory`, or from a clone with no Hermes at all:

    python3 inventory.py [--root PATH ...] [--json] [--paths]

It reads two files per home, `config.yaml` and `plugins/secret-guard/plugin.yaml`, and prints
status fields only. It does not import the plugin, start anything, resolve a credential, touch
the keychain, run a subprocess or write a file. What it reports is configuration found on disk.
Whether a running Hermes has the guard loaded and enforcing is a different question, which
this tool does not test and says so on every row.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys

PLUGIN = "secret-guard"
EXPECTED_HOOKS = ("on_session_start", "pre_llm_call", "pre_tool_call", "transform_tool_result",
                  "transform_terminal_output", "transform_llm_output")
MAX_FILE_BYTES = 2_000_000          # a config larger than this is not parsed: status unknown
MAX_HOMES = 500                     # per run; more than this and the inventory is marked incomplete
RUNTIME = "not tested"

# The six states. None of them means "protected".
ABSENT, DISABLED, CONFIGURED, UNREADABLE, UNSUPPORTED, UNKNOWN = (
    "absent", "disabled", "configured", "unreadable", "unsupported", "unknown")


class _Unreadable(Exception):
    pass


class _Malformed(Exception):
    pass


def _yaml_loader():
    """A safe YAML loader, or None. Hermes's bundled reader first, then PyYAML. Safe loaders
    build plain data only; no custom tags or constructors are run."""
    for mod in ("hermes_yaml", "yaml"):
        try:
            m = __import__(mod)
            return m.safe_load
        except Exception:
            continue
    return None


def _read(path: str) -> str:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            raise _Malformed("larger than the size this tool parses")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_FILE_BYTES + 1)
    except _Malformed:
        raise
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _Unreadable(type(exc).__name__)


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


def _commit(plugin_dir: str) -> str:
    """The checked-out commit, read from .git files. No git is run. 'unknown' if it cannot be told."""
    git = os.path.join(plugin_dir, ".git")
    try:
        if not os.path.isdir(git):
            return "unknown"
        head = _read(os.path.join(git, "HEAD")).strip()
        if not head.startswith("ref:"):
            return head[:40] if _is_sha(head) else "unknown"
        ref = head[4:].strip()
        if ".." in ref or ref.startswith("/"):
            return "unknown"
        try:
            sha = _read(os.path.join(git, *ref.split("/"))).strip()
            return sha[:40] if _is_sha(sha) else "unknown"
        except FileNotFoundError:
            for line in _read(os.path.join(git, "packed-refs")).splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref and _is_sha(parts[0]):
                    return parts[0][:40]
    except (FileNotFoundError, _Unreadable, _Malformed):
        pass
    return "unknown"


def _is_sha(s: str) -> bool:
    return len(s) >= 40 and all(c in "0123456789abcdef" for c in s[:40])


def _identity(path: str):
    try:
        st = os.stat(path)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


def discover(roots: list) -> tuple:
    """(homes, searched, skipped). `roots` is a list of (path, source). A home is the root itself
    and each directory under root/profiles that has a config.yaml. Everything looked at and not
    counted as a home is listed in `skipped` with the reason."""
    homes, searched, skipped = [], [], []
    for number, (root, source) in enumerate(roots, 1):
        root = os.path.abspath(os.path.expanduser(root))
        searched.append({"root": root, "source": source})
        if not os.path.isdir(root):
            skipped.append({"path": root, "reason": "root is not a directory or does not exist"})
            continue
        homes.append({"id": "default", "root": root, "path": root, "source": source, "root_no": number})
        pdir = os.path.join(root, "profiles")
        if not os.path.lexists(pdir):
            continue
        try:
            names = sorted(os.listdir(pdir))
        except OSError as exc:
            skipped.append({"path": pdir, "reason": "profiles folder could not be listed (%s)" % type(exc).__name__})
            homes.append({"id": "profiles/*", "root": root, "path": pdir, "source": source, "unlistable": True, "root_no": number})
            continue
        for name in names:
            p = os.path.join(pdir, name)
            if not os.path.isdir(p):
                skipped.append({"path": p, "reason": "not a directory"})
            elif not os.path.lexists(os.path.join(p, "config.yaml")) and os.access(p, os.R_OK | os.X_OK):
                skipped.append({"path": p, "reason": "no config.yaml: not a Hermes home"})
            else:
                homes.append({"id": "profiles/" + name, "root": root, "path": p, "source": source + ", profiles folder", "root_no": number})
    return homes, searched, skipped


def inspect(home: dict, loader, system: str) -> dict:
    """One row. Reads config.yaml and the plugin's plugin.yaml; nothing else."""
    path = home["path"]
    row = {"id": _clean(home["id"]), "source": home["source"], "state": UNKNOWN, "notes": [],
           "plugin_files": "unknown", "version": "unknown", "commit": "unknown", "listed_enabled": "unknown",
           "key_source": "unknown", "hooks_declared": "unknown", "runtime": RUNTIME,
           "symlink": os.path.islink(path), "path": path, "root": home["root"]}
    notes = row["notes"]
    if home.get("unlistable"):
        row["state"] = UNREADABLE
        notes.append("profiles folder could not be listed; the homes inside it are not counted")
        return row

    # --- config.yaml
    cfg, cfg_state = None, "ok"
    try:
        cfg = _load_yaml(os.path.join(path, "config.yaml"), loader)
    except FileNotFoundError:
        cfg_state = "missing"
        notes.append("no config.yaml")
    except _Unreadable as exc:
        cfg_state = "unreadable"
        notes.append("config.yaml could not be read (%s)" % exc)
    except _Malformed as exc:
        cfg_state = "malformed"
        notes.append("config.yaml: %s" % exc)
    if cfg is not None:
        plugins = cfg.get("plugins")
        enabled = plugins.get("enabled") if isinstance(plugins, dict) else None
        disabled = plugins.get("disabled") if isinstance(plugins, dict) else None
        if plugins is not None and not isinstance(plugins, dict):
            cfg_state = "malformed"; notes.append("config.yaml: `plugins` is not a mapping")
        elif enabled is not None and not isinstance(enabled, list):
            cfg_state = "malformed"; notes.append("config.yaml: `plugins.enabled` is not a list")
        else:
            row["listed_enabled"] = "yes" if PLUGIN in (enabled or []) else "no"
            if isinstance(disabled, list) and PLUGIN in disabled:
                row["listed_enabled"] = "no"
                notes.append("listed in plugins.disabled")
        secrets = cfg.get("secrets")
        sg = secrets.get("secret_guard") if isinstance(secrets, dict) else None
        if isinstance(sg, dict) and isinstance(sg.get("enabled"), bool):
            row["key_source"] = "on" if sg["enabled"] else "off"
        elif sg is None:
            row["key_source"] = "not set"

    # --- plugin files
    pdir = os.path.join(path, "plugins", PLUGIN)
    files_state = "ok"
    if not os.path.lexists(pdir):
        row["plugin_files"] = "absent"
        # is the plugins folder itself readable? if not, absence is not established
        parent = os.path.join(path, "plugins")
        if (os.path.lexists(parent) and not os.access(parent, os.R_OK | os.X_OK)) or not os.access(path, os.R_OK | os.X_OK):
            row["plugin_files"] = "unknown"; files_state = "unreadable"
            notes.append("plugins folder could not be read")
    elif not os.path.isdir(pdir):
        row["plugin_files"] = "unknown"; files_state = "malformed"
        notes.append("plugins/%s is not a directory" % PLUGIN)
    else:
        if os.path.islink(pdir):
            notes.append("plugin folder is a symlink")
        try:
            meta = _load_yaml(os.path.join(pdir, "plugin.yaml"), loader)
            row["plugin_files"] = "present"
            row["version"] = _clean(meta.get("version", "unknown"))
            row["commit"] = _commit(pdir)
            hooks = meta.get("provides_hooks")
            if isinstance(hooks, list):
                missing = [h for h in EXPECTED_HOOKS if h not in hooks]
                row["hooks_declared"] = "%d of %d" % (len(EXPECTED_HOOKS) - len(missing), len(EXPECTED_HOOKS))
                if missing:
                    notes.append("plugin.yaml does not declare: " + ", ".join(missing))
            else:
                notes.append("plugin.yaml declares no hook list")
            plats = meta.get("platforms")
            want = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}.get(system, system.lower())
            if isinstance(plats, list) and want not in [str(p).lower() for p in plats]:
                files_state = "unsupported"
                notes.append("plugin.yaml does not list this platform (%s)" % want)
        except FileNotFoundError:
            row["plugin_files"] = "unknown"; files_state = "malformed"
            notes.append("plugin folder has no plugin.yaml")
        except _Unreadable as exc:
            row["plugin_files"] = "unknown"; files_state = "unreadable"
            notes.append("plugin.yaml could not be read (%s)" % exc)
        except _Malformed as exc:
            row["plugin_files"] = "unknown"; files_state = "malformed"
            notes.append("plugin.yaml: %s" % exc)

    # --- one state. Worst evidence wins; nothing unreadable or unparsed becomes a positive result.
    if "unreadable" in (cfg_state, files_state):
        row["state"] = UNREADABLE
    elif cfg_state == "malformed" or files_state == "malformed":
        row["state"] = UNKNOWN
    elif files_state == "unsupported" or (row["plugin_files"] == "present" and system != "Darwin"):
        row["state"] = UNSUPPORTED
        if system != "Darwin":
            notes.append("Secret Guard loads on macOS only; this host is %s" % (system or "unknown"))
    elif row["plugin_files"] == "absent":
        row["state"] = ABSENT
        if row["listed_enabled"] == "yes":
            notes.append("listed in plugins.enabled but the plugin files are missing")
    elif cfg_state == "missing":
        row["state"] = UNKNOWN
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
    homes, searched, skipped = discover(roots)
    incomplete = []
    if len(homes) > MAX_HOMES:
        incomplete.append("more than %d homes found; only the first %d were inspected" % (MAX_HOMES, MAX_HOMES))
        homes = homes[:MAX_HOMES]
    rows, seen = [], {}
    for h in homes:
        row = inspect(h, loader, system)
        ident = _identity(h["path"])
        if ident is not None and ident in seen:
            row["notes"].append("same folder as %s (duplicate or symlink); counted once" % seen[ident])
            row["duplicate_of"] = seen[ident]
        elif ident is not None:
            seen[ident] = row["id"] if len(roots) == 1 else "%s under root %d" % (row["id"], h["root_no"])
        rows.append(row)
    versions = sorted({r["version"] for r in rows if r["plugin_files"] == "present"})
    commits = sorted({r["commit"] for r in rows if r["plugin_files"] == "present"})
    for r in rows:
        if r["plugin_files"] != "present":
            continue
        if expect_version and r["version"] != expect_version:
            r["notes"].append("version %s is not the expected %s" % (r["version"], _clean(expect_version)))
        if expect_commit and not (r["commit"] != "unknown" and r["commit"].startswith(expect_commit.lower())):
            r["notes"].append("commit %s is not the expected %s" % (r["commit"][:12], _clean(expect_commit)[:12]))
        if len(versions) > 1 or len(commits) > 1:
            r["notes"].append("installed copies differ between homes")
    if loader is None:
        incomplete.append("no YAML reader (hermes_yaml or PyYAML): no configuration could be parsed")
    unique = [r for r in rows if "duplicate_of" not in r]
    counts = {s: sum(1 for r in unique if r["state"] == s) for s in (ABSENT, DISABLED, CONFIGURED, UNREADABLE, UNSUPPORTED, UNKNOWN)}
    if counts[UNREADABLE] or counts[UNKNOWN]:
        incomplete.append("%d home(s) unreadable or unknown" % (counts[UNREADABLE] + counts[UNKNOWN]))
    return {"host": _clean(socket.gethostname()), "platform": system or "unknown", "searched": searched, "skipped": skipped,
            "homes": rows, "unique_homes": len(unique), "counts": counts, "runtime": RUNTIME,
            "complete": not incomplete, "incomplete_reasons": incomplete}


def render(report: dict, show_paths: bool = False) -> str:
    out = ["Secret Guard inventory (static, read-only)",
           "host %s, platform %s" % (report["host"], report["platform"]), "",
           "Roots searched:"]
    for i, s in enumerate(report["searched"], 1):
        out.append("  %d. %s  [%s]" % (i, _clean(s["root"]) if show_paths else "root %d" % i, s["source"]))
    if not show_paths:
        out.append("  (paths are hidden; add --paths to print them)")
    out += ["", "%-28s %-11s %-8s %-8s %-8s %-7s %-8s %s" % ("home", "state", "files", "enabled", "version", "hooks", "keysrc", "runtime")]
    for r in report["homes"]:
        out.append("%-28s %-11s %-8s %-8s %-8s %-7s %-8s %s" % (
            r["id"][:28], r["state"], r["plugin_files"], r["listed_enabled"], r["version"][:8],
            r["hooks_declared"], r["key_source"], r["runtime"]))
        if r["commit"] != "unknown":
            out.append("    commit %s" % r["commit"][:12])
        if show_paths:
            out.append("    path %s%s" % (_clean(r["path"]), " (symlink)" if r["symlink"] else ""))
        elif r["symlink"]:
            out.append("    home folder is a symlink")
        for n in r["notes"]:
            out.append("    - " + _clean(n))
    c = report["counts"]
    out += ["", "%d home(s), counted once each: " % report["unique_homes"]
            + ", ".join("%d %s" % (c[s], s) for s in (CONFIGURED, DISABLED, ABSENT, UNSUPPORTED, UNREADABLE, UNKNOWN))]
    out.append("Skipped: %d entr%s" % (len(report["skipped"]), "y" if len(report["skipped"]) == 1 else "ies"))
    for s in report["skipped"]:
        out.append("  - %s: %s" % (_clean(s["path"]) if show_paths else _clean(os.path.basename(s["path"])), s["reason"]))
    out += ["",
            "'configured' means the plugin files are present and the home's config lists the plugin.",
            "It does not mean the guard is loaded or enforcing: runtime behaviour was not tested.",
            "Inventory " + ("complete." if report["complete"] else "INCOMPLETE: " + "; ".join(report["incomplete_reasons"]) + ".")]
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
    ap.add_argument("--paths", action="store_true", help="print full paths (they can be sensitive; hidden by default)")
    ap.add_argument("--expect-version", help="note every installed copy whose version differs")
    ap.add_argument("--expect-commit", help="note every installed copy whose commit differs")
    args = ap.parse_args(argv)
    roots = [(r, "--root argument") for r in args.root] or default_roots()
    report = run(roots, expect_version=args.expect_version, expect_commit=args.expect_commit)
    if args.json:
        if not args.paths:
            report = json.loads(json.dumps(report))
            for i, s in enumerate(report["searched"], 1):
                s["root"] = "root %d" % i
            for r in report["homes"]:
                r.pop("path", None); r.pop("root", None)
            for s in report["skipped"]:
                s["path"] = _clean(os.path.basename(s["path"]))
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render(report, show_paths=args.paths))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
