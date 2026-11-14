"""Leak prevention: a fail-closed path gate, value redaction, and an inbound paste block.

Layer 1  pre_tool_call          block tool calls that would read a secret-shaped file, run a
                                secrets helper, or ask the keychain to print a value. Since 1.1
                                this includes reads that reach such a file without naming it:
                                folder-wide searches and archives, shell globs, file lists built
                                by another command, file:// addresses, and environment dumps.
Layer 2  value redaction        register every guarded value with Hermes's own model-egress scrub
                                (agent.redact vault registry), plus backup transform hooks that
                                catch their own errors and withhold output rather than fail open.
                                Since 1.1 the transform hooks also redact the base64, hex and
                                percent-encoded forms of each guarded value.
Layer 3  pre_llm_call           a key pasted into chat never reaches a model.

Values live only in this process's memory. Nothing here logs or returns a value.
"""

from __future__ import annotations

import base64
import contextvars
import fnmatch
import logging
import os
import re
import shlex
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

from . import keychain, registry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- values (memory only)

def _get_secret(name: str):
    """Hermes's own credential route (catalog rule 11): the value Hermes resolved for the active
    profile, normally from this plugin's own keychain secret source. Never reads the keychain."""
    try:
        from agent.secret_scope import get_secret
    except Exception:
        return None
    try:
        return get_secret(name)
    except Exception:  # UnscopedSecretError under multiplex with no scope: fail closed (no value)
        return None


# Values entered through this process's own dialog during this session. Hermes resolves secrets
# at startup, so without this a key added mid-session would go unprotected until a restart. Memory
# only; matched against the registry fingerprint like everything else.
_entered: dict[str, dict[str, str]] = {}   # profile home -> {env: value}


def _scope() -> str:
    try:
        from hermes_constants import get_hermes_home
        return str(get_hermes_home())
    except Exception:
        return ""


def remember_entered(env: str, value: str) -> bool:
    """Protect a just-entered value in THIS profile right away. Returns True only if the value is
    now in Hermes's redaction registry (the caller reports it; no silent failure)."""
    if not value or len(value) < 8:
        return False
    _entered.setdefault(_scope(), {})[env] = value
    try:
        register_values()
    except Exception:
        return False
    # Value-specific: the claim is "this key is redacted now", so test exactly that.
    return env in _load_values() and core_covers(value)


def _load_values() -> dict[str, str]:
    """env -> value for every registered secret this profile can resolve. Fresh each call: under a
    multiplex gateway the active profile can change between turns."""
    values: dict[str, str] = {}
    for env, e in registry.load().get("secrets", {}).items():
        for v in (_get_secret(env), _entered.get(_scope(), {}).get(env)):
            if v and len(v) >= 8 and keychain.fingerprint(v) == e.get("fingerprint"):
                values[env] = v
                break
    return values


def register_values() -> int:
    """Push every guarded value into Hermes's exact-value model-egress scrub (the vault registry
    Hermes uses for browser-vault passwords; it applies even when security.redact_secrets is off).
    Re-run each turn. The registry keeps 64 values per profile and evicts the oldest, so values
    entered in this session are registered LAST and survive a large guarded set. It is an
    undocumented module function: if an update removes it, the plugin's transform hooks still scrub
    tool results, terminal output and replies, and `hermes secret doctor` reports the change."""
    values = _load_values()
    try:
        from agent.redact import register_vault_redaction_value
    except Exception:
        return 0
    entered = _entered.get(_scope(), {})
    for env in sorted(values, key=lambda e: e in entered):  # entered values last = most recent
        register_vault_redaction_value(values[env])
    return len(values)


def core_covers(value: str) -> bool:
    """True only if Hermes's core exact-value redactor removes this specific value right now."""
    try:
        from agent.redact import redact_registered_vault_values
        return value not in redact_registered_vault_values("<" + value + ">")
    except Exception:
        return False


# Shortest encoded fragment matched. A guarded value is at least 8 bytes, and every base64
# alignment of 8 bytes leaves a 10-character core, so 10 covers every accepted value.
MIN_ENCODED = 10
_WS_RE = re.compile(r"\s")
_form_cache: dict[str, tuple[str, ...]] = {}   # value -> encoded forms; memory only, like the values


def _b64_cores(raw: bytes) -> set[str]:
    """The base64 text that `raw` produces wherever it sits in a larger stream. Base64 works in
    3-byte groups, so the value can start at three alignments; for each, keep only the characters
    that depend on the value alone (drop the ones shared with neighbouring bytes)."""
    out: set[str] = set()
    for off in (0, 1, 2):
        enc = base64.b64encode(b"\0" * off + raw).decode("ascii").rstrip("=")
        if (off + len(raw)) % 3:
            enc = enc[:-1]                      # last character also carries bits of the next byte
        core = enc[(0, 2, 3)[off]:]             # leading characters carry bits of the previous bytes
        if len(core) >= MIN_ENCODED:
            out.add(core)
            out.add(core.replace("+", "-").replace("/", "_"))   # URL-safe alphabet
    return out


def encoded_forms(value: str) -> tuple[str, ...]:
    """Encodings a command produces without trying: base64 (any alignment, both alphabets), hex and
    percent-encoding. Not covered, by design: compression, encryption, reversal, splitting."""
    cached = _form_cache.get(value)
    if cached is not None:
        return cached
    raw = value.encode("utf-8")
    forms = _b64_cores(raw)
    hx = raw.hex()
    if len(hx) >= MIN_ENCODED:
        forms.update((hx, hx.upper()))
    for quoted in (urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value)):
        if quoted != value and len(quoted) >= MIN_ENCODED:
            forms.add(quoted)
            forms.add(re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), quoted))
    forms.discard(value)
    result = tuple(sorted(forms, key=len, reverse=True))
    if len(_form_cache) > 512:
        _form_cache.clear()
    _form_cache[value] = result
    return result


def _spaced(form: str) -> "re.Pattern[str]":
    return re.compile(r"\s*".join(re.escape(c) for c in form))


def scrub(text: str) -> tuple[str, int]:
    values = _load_values()
    hits = 0
    ordered = sorted(values.items(), key=lambda kv: len(kv[1]), reverse=True)
    for env, v in ordered:
        if v in text:
            hits += text.count(v)
            text = text.replace(v, f"[secret:{env} redacted]")
    compact: Optional[str] = None
    for env, v in ordered:
        label = f"[secret:{env} redacted (encoded)]"
        for form in encoded_forms(v):
            if form in text:
                hits += text.count(form)
                text = text.replace(form, label)
                compact = None
            # base64 and xxd -p wrap long output. Always look again across line breaks: one result
            # can hold an unwrapped copy and a wrapped copy of the same encoding.
            if compact is None:
                compact = _WS_RE.sub("", text)
            if form in compact:
                text, n = _spaced(form).subn(label, text)
                hits += n
                compact = None
    return text, hits

# ---------------------------------------------------------------- layer 1: path gate

# Ported from ~/.hermes/secrets-provider/guard-raw-print.zsh (MBP).
SECRET_PATTERNS = ("*.env", "*.env.*", ".env", "openclaw.json", "*credential*", "*token*",
                   "*secret*", "*.pem", "*.pfx", "*.ppk", "id_rsa", "id_ed25519", "*-keys.json",
                   "auth.json")
SAFE_EXTENSIONS = (".sh", ".py", ".md")  # code and docs; a *secret*.log is still blocked
QUOTES = "\"'"
READERS = frozenset({"cat", "bat", "less", "more", "head", "tail", "sed", "awk", "gawk", "grep",
                     "egrep", "fgrep", "rg", "ag", "strings", "xxd", "od", "hexdump", "base64",
                     "python", "python3", "node", "perl", "ruby", "php", "jq", "yq", "cp", "scp",
                     "rsync", "curl", "nl", "tac", "cut", "sort", "uniq", "diff", "cmp", "vim",
                     "vi", "nano", "open", "pbcopy", "tee", "dd", "zip", "tar"})
# Argument names, not tool names, decide what is checked: any tool (built-in, plugin or MCP) that
# takes a command, code or a path gets the same check. v0.2 keyed on tool names and missed
# process_manage, browser_exec, browser_cdp and cronjob_manage.
COMMAND_KEYS = frozenset({"command", "cmd", "shell", "script"})
CODE_KEYS = frozenset({"code", "js", "javascript", "expression", "source", "python"})
PATH_KEYS = frozenset({"path", "file_path", "filepath", "filename", "file", "paths", "files",
                       "source_path", "image_path", "video_path", "workdir_file"})

# --- 1.1: reads that reach a secret file without naming it
# Folder scans use every name pattern, with one exception: names like tokenizer.json, which the
# "*token*" pattern would otherwise turn into a block on most machine-learning repositories.
BENIGN_DIR_NAMES = ("*tokeniz*",)
# rg and ag skip dotfiles and honour ignore files. These folders are assumed ignored for those two
# tools only; grep -r, tar, zip, cp -r and search_files are scanned without exclusions.
IGNORED_BY_RG = frozenset({"node_modules", "__pycache__", "venv"})
SCAN_MAX_DEPTH, SCAN_MAX_ENTRIES, SCAN_MAX_SECONDS = 12, 20000, 2.0
GLOB_MAX_MATCHES = 2000
SHELL_MAX_DEPTH = 3
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
GREP_FAMILY = frozenset({"grep", "egrep", "fgrep"})
HIDDEN_SKIPPERS = frozenset({"rg", "ag"})          # skip dotfiles unless told otherwise
ALWAYS_RECURSIVE = HIDDEN_SKIPPERS | {"tar", "zip", "rsync"}
# Options that take a value, so the value is not mistaken for a pattern or a path. An option
# outside these tables and the flag tables below makes the call "not understood": the working
# folder is then scanned as well as any folder named.
_VALUE_OPTS = {
    "grep": ("efmABCdD", {"regexp", "file", "max-count", "after-context", "before-context", "context",
                          "include", "exclude", "exclude-dir", "exclude-from", "label", "binary-files",
                          "devices", "directories", "color", "colour"}),
    "rg": ("efgtTABCmjMdEr", {"regexp", "file", "glob", "iglob", "type", "type-not", "type-add",
                              "type-clear", "after-context", "before-context", "context", "max-count",
                              "threads", "max-columns", "max-depth", "maxdepth", "encoding", "replace",
                              "color", "colors", "sort", "sortr", "pre", "pre-glob", "ignore-file",
                              "max-filesize", "path-separator", "context-separator",
                              "field-match-separator", "field-context-separator", "engine",
                              "dfa-size-limit", "regex-size-limit", "hyperlink-format", "generate"}),
    "ag": ("ABCGgmW", {"after", "before", "context", "file-search-regex", "ignore", "ignore-dir",
                       "max-count", "depth", "pager", "path-to-ignore", "workers", "width"}),
}
_FLAG_OPTS = {
    "grep": ("rRinvclLhHowxsqEFGPzZabUIT", {"recursive", "dereference-recursive", "ignore-case",
             "no-ignore-case", "line-number", "invert-match", "count", "files-with-matches",
             "files-without-match", "no-filename", "with-filename", "only-matching", "word-regexp",
             "line-regexp", "quiet", "silent", "no-messages", "extended-regexp", "fixed-strings",
             "basic-regexp", "perl-regexp", "null", "null-data", "text", "byte-offset", "binary",
             "initial-tab", "line-buffered"}),
    "rg": ("inSsvwxclLoHINpPUuzaFqbh.0", {"hidden", "no-hidden", "no-ignore", "no-ignore-vcs",
           "no-ignore-parent", "no-ignore-dot", "no-ignore-global", "ignore-case", "smart-case",
           "case-sensitive", "line-number", "no-line-number", "invert-match", "word-regexp",
           "line-regexp", "count", "count-matches", "files-with-matches", "files-without-match",
           "only-matching", "with-filename", "no-filename", "heading", "no-heading", "text", "binary",
           "fixed-strings", "pcre2", "multiline", "multiline-dotall", "unrestricted", "follow", "json",
           "vimgrep", "column", "no-column", "trim", "null", "null-data", "search-zip",
           "one-file-system", "pretty", "no-messages", "quiet", "stats", "no-config", "crlf",
           "line-buffered", "block-buffered", "mmap", "no-mmap", "passthru", "sort-files",
           "no-unicode", "glob-case-insensitive", "include-zero", "byte-offset", "files"}),
    "ag": ("aDfFiLlnQsSuUvwz0cHt", {"hidden", "unrestricted", "all-types", "all-text", "ignore-case",
           "smart-case", "case-sensitive", "literal", "count", "files-with-matches",
           "files-without-matches", "invert-match", "word-regexp", "follow", "nocolor", "color",
           "numbers", "nonumbers", "heading", "noheading", "filename", "nofilename", "null", "stats",
           "search-binary", "search-zip", "skip-vcs-ignores", "only-matching", "column", "vimgrep"}),
}
PLAIN_READERS = ("cat", "bat", "less", "more", "head", "tail", "nl", "tac", "strings", "xxd", "od",
                 "hexdump", "base64")
_SUBST_READ_RE = re.compile(r"(?:^|[|;&\n(]\s*)(?:sudo\s+)?(?:" + "|".join(PLAIN_READERS)
                            + r")\b[^|;&\n]*?(?:\$\(|`|<\()")
_ENV_DUMP_RE = re.compile(r"(?:print|pprint|dumps|log|write)\s*\(\s*(?:dict\s*\(\s*)?"
                          r"(?:os\.environ|process\.env)\s*\)?\s*[,)]")
_FILE_URL_RE = re.compile(r"file://[^\s\"'<>)]+")
SEARCH_GLOB_KEYS = ("file_glob", "glob", "include")
NAME_ONLY_TARGETS = frozenset({"files", "filenames", "names"})
_KEYCHAIN_PRINT_RE = re.compile(r"find-(?:generic|internet)-password[^\n]*?(?:^|\s|['\",])-[a-zA-Z]*[wg]\b|dump-keychain")


def _hermes_roots() -> list[str]:
    roots = [os.path.realpath(os.path.expanduser("~/.hermes"))]
    try:
        from hermes_constants import get_default_hermes_root, get_hermes_home
        roots += [os.path.realpath(str(get_hermes_home())), os.path.realpath(str(get_default_hermes_root()))]
    except Exception:
        pass
    return list(dict.fromkeys(roots))


def _abs(token: str, cwd: Optional[str]) -> str:
    t = os.path.expanduser(token.strip("\"'"))
    if not os.path.isabs(t) and cwd:
        t = os.path.join(cwd, t)
    return os.path.realpath(t)


def is_secret_path(token: str, cwd: Optional[str] = None) -> bool:
    name = os.path.basename(token.strip("\"'").rstrip("/")).lower()
    if not name or name.startswith("-"):
        return False
    if name.endswith(SAFE_EXTENSIONS):
        return False
    if any(fnmatch.fnmatch(name, p) for p in SECRET_PATTERNS):
        return True
    if name == "config.yaml" or name.startswith(("config.yaml.", "config.yaml~")):
        full = _abs(token, cwd)
        return any(full == r or full.startswith(r + os.sep) for r in _hermes_roots())
    return False


class _ScanTooBig(Exception):
    pass


class _ScanFailed(Exception):
    pass


class _Budget:
    """Work allowed for one tool call, shared by every folder scan and glob expansion in it."""
    def __init__(self) -> None:
        self.entries = 0
        self.deadline = time.monotonic() + SCAN_MAX_SECONDS

    def tick(self) -> None:
        self.entries += 1
        if self.entries > SCAN_MAX_ENTRIES or (self.entries % 256 == 0 and time.monotonic() > self.deadline):
            raise _ScanTooBig


_budget_var: "contextvars.ContextVar[Optional[_Budget]]" = contextvars.ContextVar("secret_guard_budget", default=None)


def _budget() -> _Budget:
    b = _budget_var.get()
    if b is None:
        b = _Budget()
        _budget_var.set(b)
    return b


def _dir_secret_name(path: str) -> bool:
    name = os.path.basename(path).lower()
    if any(fnmatch.fnmatch(name, p) for p in BENIGN_DIR_NAMES):
        return False
    return is_secret_path(path)


def _glob_regex(pattern: str) -> Optional["re.Pattern[str]"]:
    """A ripgrep/gitignore-style glob with a folder part, as a regex over the relative path.
    None when the glob uses syntax this does not model (the caller then applies no filter)."""
    if not pattern or pattern.startswith("!") or any(c in pattern for c in "{}\\"):
        return None
    pattern = pattern.lstrip("/")
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?"); i += 3
        elif pattern.startswith("**", i):
            out.append(".*"); i += 2
        elif c == "*":
            out.append("[^/]*"); i += 1
        elif c == "?":
            out.append("[^/]"); i += 1
        elif c == "[":
            j = pattern.find("]", i + 2)
            if j < 0:
                return None
            out.append("[" + pattern[i + 1:j].replace("\\", "\\\\") + "]"); i = j + 1
        else:
            out.append(re.escape(c)); i += 1
    try:
        return re.compile("".join(out) + r"\Z")
    except re.error:
        return None


def _name_filter(name_glob: Optional[str]):
    """How a search tool's file filter selects files, or None for "every file". A filter is used
    only when it can be modelled exactly; anything else is ignored, which can only block more."""
    if not name_glob:
        return None
    if "/" not in name_glob and not name_glob.startswith("!") and not any(c in name_glob for c in "{}\\"):
        return lambda rel: fnmatch.fnmatch(os.path.basename(rel), name_glob)
    rx = _glob_regex(name_glob)
    return (lambda rel: rx.match(rel) is not None) if rx else None


def secret_file_under(root: str, name_glob: Optional[str] = None, include_hidden: bool = True,
                      skip_dirs: frozenset = frozenset()) -> Optional[str]:
    """First secret-shaped file under `root` (relative path), or None. The work is bounded by the
    call's shared budget and by depth; exceeding either raises _ScanTooBig, and a folder that
    cannot be listed raises _ScanFailed. The caller blocks on both (never a silent pass).
    Symlinked folders are not followed."""
    budget = _budget()
    selects = _name_filter(name_glob)
    stack = [(root, 0)]
    while stack:
        folder, depth = stack.pop()
        try:
            with os.scandir(folder) as it:
                for e in it:
                    budget.tick()
                    if not include_hidden and e.name.startswith("."):
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if e.name in skip_dirs:
                            continue
                        if depth + 1 > SCAN_MAX_DEPTH:
                            raise _ScanTooBig
                        stack.append((e.path, depth + 1))
                    elif _dir_secret_name(e.path):
                        rel = os.path.relpath(e.path, root)
                        if selects is None or selects(rel):
                            return rel
        except OSError as exc:
            raise _ScanFailed from exc
    return None


def _folder_reason(folder: str, name_glob: Optional[str] = None, include_hidden: bool = True,
                   skip_dirs: frozenset = frozenset()) -> Optional[str]:
    try:
        hit = secret_file_under(folder, name_glob, include_hidden, skip_dirs)
    except _ScanTooBig:
        return ("reads a whole folder that is too large to check for secret files; "
                "name the files or a narrower folder")
    except _ScanFailed:
        return ("reads a whole folder that could not be checked for secret files "
                "(permission or I/O error); name the files you need")
    if hit:
        return (f"reads a whole folder that holds a secret-shaped file ({os.path.basename(hit)}); "
                "name the files you need or a narrower folder")
    return None


def _has_magic(token: str) -> bool:
    return any(c in token for c in "*?[")


def expand_glob(pattern: str, cwd: Optional[str]) -> list:
    """Paths a shell glob would produce, like the shell (dotfiles only when the pattern part starts
    with a dot). Walks lazily on the call's shared budget; more than GLOB_MAX_MATCHES matches, an
    exhausted budget or an unreadable folder raises, and the caller blocks. Never a checked prefix."""
    budget = _budget()
    pattern = os.path.expanduser(pattern.strip("\"'"))
    if not os.path.isabs(pattern):
        pattern = os.path.join(cwd or os.getcwd(), pattern)
    parts = [p for p in pattern.split("/") if p]
    results: list = []

    def listing(folder: str):
        try:
            with os.scandir(folder) as it:
                for e in it:
                    budget.tick()
                    yield e
        except (FileNotFoundError, NotADirectoryError):
            return
        except OSError as exc:
            raise _ScanFailed from exc

    def walk(base: str, idx: int, depth: int) -> None:
        if depth > SCAN_MAX_DEPTH + len(parts):
            raise _ScanTooBig
        if idx == len(parts):
            results.append(base)
            if len(results) > GLOB_MAX_MATCHES:
                raise _ScanTooBig
            return
        part = parts[idx]
        if part == "**":
            walk(base, idx + 1, depth)
            for e in listing(base):
                if not e.name.startswith(".") and e.is_dir(follow_symlinks=False):
                    walk(e.path, idx, depth + 1)
        elif _has_magic(part):
            for e in listing(base):
                if (part.startswith(".") or not e.name.startswith(".")) and fnmatch.fnmatchcase(e.name, part):
                    if idx == len(parts) - 1 or e.is_dir():
                        walk(e.path, idx + 1, depth + 1)
        else:
            nxt = os.path.join(base, part)
            if os.path.lexists(nxt):
                walk(nxt, idx + 1, depth)

    try:
        walk("/", 0, 0)
    except (_ScanTooBig, _ScanFailed):
        raise
    except OSError as exc:
        raise _ScanFailed from exc
    return results


def _guarded_names() -> frozenset:
    try:
        return frozenset(registry.load().get("secrets", {}))
    except Exception:
        return frozenset()


def _parse_search_args(prog: str, args: list) -> dict:
    """Options and operands of a grep/rg/ag call. `understood` is False when an option is not in
    the tables, so its value could be mistaken for a pattern or a path."""
    family = "grep" if prog in GREP_FAMILY else prog
    v_short, v_long = _VALUE_OPTS[family]
    f_short, f_long = _FLAG_OPTS[family]
    short, long_flags, operands = [], [], []
    understood, pattern_given, glob_given = True, False, False
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            operands.extend(args[i:])
            break
        if a.startswith("--"):
            name, eq, _val = a[2:].partition("=")
            long_flags.append(name)
            if name in v_long:
                pattern_given = pattern_given or name in ("regexp", "file")
                glob_given = glob_given or name in ("glob", "iglob")
                if not eq:
                    i += 1                       # value is the next token
            elif name not in f_long:
                understood = False
        elif a.startswith("-") and len(a) > 1:
            for j, ch in enumerate(a[1:], start=1):
                if ch in v_short:
                    pattern_given = pattern_given or ch in "ef"
                    glob_given = glob_given or (family == "rg" and ch == "g")
                    if j == len(a) - 1:
                        i += 1                   # value is the next token
                    break                        # the rest of the cluster is the value
                short.append(ch)
                if ch not in f_short and not ch.isdigit():
                    understood = False
        else:
            operands.append(a)
    return {"short": short, "long": long_flags, "operands": operands, "understood": understood,
            "pattern_given": pattern_given, "glob_given": glob_given}


def _recursive_folders(prog: str, args: list, cwd: Optional[str]) -> Optional[tuple[list, bool, frozenset]]:
    """(folders a recursive reader would walk, whether dotfiles count, folder names it skips), or
    None if the call is not recursive. Glob operands are expanded first. When the call is not
    understood, or names no existing path, the working folder is included."""
    here = _abs(".", cwd)
    if prog in GREP_FAMILY or prog in HIDDEN_SKIPPERS:
        parsed = _parse_search_args(prog, args)
        short, long_flags = parsed["short"], parsed["long"]
        if prog in GREP_FAMILY and not ("r" in short or "R" in short or "recursive" in long_flags
                                        or "dereference-recursive" in long_flags
                                        or "directories" in long_flags
                                        or any(re.fullmatch(r"-[A-Za-z]*d.*", a) for a in args if not a.startswith("--"))):
            return None                          # -d/--directories can mean recurse; treated as recursive
        operands = parsed["operands"]
        paths = operands if parsed["pattern_given"] else operands[1:]
        hidden, skip = True, frozenset()
        if prog in HIDDEN_SKIPPERS:
            hidden = ("hidden" in long_flags or "." in short or parsed["glob_given"]
                      or short.count("u") >= (2 if prog == "rg" else 1)
                      or long_flags.count("unrestricted") >= (2 if prog == "rg" else 1))
            skip = frozenset() if ("no-ignore" in long_flags or "u" in short or "unrestricted" in long_flags
                                   or "U" in short or "skip-vcs-ignores" in long_flags) else IGNORED_BY_RG
        folders, named_existing = [], False
        for p in paths:
            for m in (expand_glob(p, cwd) if _has_magic(p) else [_abs(p, cwd)]):
                if os.path.isdir(m):
                    folders.append(m); named_existing = True
                elif os.path.exists(m):
                    named_existing = True
        if not named_existing or not parsed["understood"]:
            folders.append(here)
        return list(dict.fromkeys(folders)), hidden, skip
    flags = [a for a in args if a.startswith("-")]
    pos = [a for a in args if not a.startswith("-")]
    short = "".join(f[1:] for f in flags if not f.startswith("--"))
    if prog in ALWAYS_RECURSIVE:
        recursive = True
    elif prog in ("cp", "scp"):
        recursive = any(c in short for c in "rRa") or "--recursive" in flags or "--archive" in flags
    elif prog == "diff":
        recursive = "r" in short or "--recursive" in flags
    else:
        recursive = False
    if not recursive:
        return None
    folders = []
    for p in pos:
        for m in (expand_glob(p, cwd) if _has_magic(p) else [_abs(p, cwd)]):
            if os.path.isdir(m):
                folders.append(m)
    return list(dict.fromkeys(folders)), True, frozenset()


def _find_roots(args: list, cwd: Optional[str]) -> list:
    roots = []
    for a in args:
        if a.startswith("-") or a in ("(", "!", "\\("):
            break
        roots.append(_abs(a, cwd))
    return roots or [_abs(".", cwd)]


def _is_secrets_helper(token: str, cwd: Optional[str]) -> bool:
    full = _abs(token, cwd)
    return "/secrets-provider/" in full or full.endswith("/secret_guard/emit-secrets.sh")


def _split_commands(command: str) -> list[str]:
    """Split a command line into simple commands at ; | & newline ( ) and around $( ... ) and
    backticks, respecting quotes: nothing inside single quotes splits, and inside double quotes
    only a command substitution does (its body is then read as unquoted shell)."""
    parts, buf, quote, i, n = [], [], "", 0, len(command)
    stack: list = []                            # (opener, quote state to restore) per open substitution

    def flush():
        seg = "".join(buf).strip()
        if seg and seg != '""':
            parts.append(seg)
        buf.clear()

    def enter(opener: str):
        nonlocal quote
        if quote == '"':
            buf.append('"')                     # close the open quote so the outer piece still parses
        flush()
        stack.append((opener, quote))
        quote = ""

    def leave():
        nonlocal quote
        flush()
        _opener, quote = stack.pop()
        if quote == '"':
            buf.append('"')

    while i < n:
        c = command[i]
        if quote == "'":
            buf.append(c)
            if c == "'":
                quote = ""
        elif c == "\\" and i + 1 < n:
            buf.append(c); buf.append(command[i + 1]); i += 1
        elif c == "$" and command.startswith("$(", i):
            enter("$("); i += 1
        elif c == "`":
            if stack and stack[-1][0] == "`" and not quote:
                leave()
            else:
                enter("`")
        elif quote == '"':
            buf.append(c)
            if c == '"':
                quote = ""
        elif c in "'\"":
            quote = c; buf.append(c)
        elif c == ")" and stack and stack[-1][0] == "$(":
            leave()
        elif c in ";|&\n()":
            flush()
        else:
            buf.append(c)
        i += 1
    flush()
    return parts


def _segments(command: str) -> list[list[str]]:
    out = []
    for seg in _split_commands(command):
        try:
            toks = shlex.split(seg, posix=True)
        except ValueError:
            toks = seg.split()
        if toks:
            out.append(toks)
    return out


def check_command(command: str, cwd: Optional[str] = None, _depth: int = 0) -> Optional[str]:
    """Return a refusal reason, or None if the command may run."""
    if not command:
        return None
    try:
        return _check_command(command, cwd, _depth)
    except _ScanTooBig:
        return "names files through a pattern too large to check; name the files instead"
    except _ScanFailed:
        return "names files in a folder that could not be checked (permission or I/O error)"


def _check_command(command: str, cwd: Optional[str], _depth: int) -> Optional[str]:
    if _SUBST_READ_RE.search(command):
        return "reads a file list produced by another command; name the files instead"
    guarded = _guarded_names()
    for toks in _segments(command):
        # skip leading VAR=value assignments and wrappers
        i = 0
        # a wrapper counts only when something follows it: a bare `env` is an environment dump
        while i + 1 < len(toks) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[i]) or toks[i] in ("sudo", "env", "command", "exec", "nohup", "time")):
            i += 1
        if i >= len(toks):
            continue
        prog = os.path.basename(toks[i])
        args = toks[i + 1:]
        # 0. a shell given its command as a string: check that string as a command too
        payloads = []
        if prog in SHELLS:
            for j, a in enumerate(args):
                if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a):
                    rest = [x for x in args[j + 1:] if not x.startswith("-")]
                    payloads.append(rest[0] if rest else "")
                    break
        elif prog == "eval" and args:
            payloads.append(" ".join(args))
        for payload in payloads:
            if _depth >= SHELL_MAX_DEPTH:
                return "nests shell commands too deeply to check"
            if not payload or re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$[@*0-9]", payload.strip()):
                return "runs a command string built at run time, which cannot be checked"
            reason = check_command(payload, cwd, _depth + 1) or check_code(payload)
            if reason:
                return reason
        # 1. the keychain printing a value
        if prog == "security":
            joined = " ".join(args)
            if re.search(r"\bfind-(generic|internet)-password\b", joined) and re.search(r"(^|\s)-[a-zA-Z]*[wg]", joined):
                return "asks the keychain to print a secret value (security find-*-password -w/-g)"
            if "dump-keychain" in joined:
                return "dumps the keychain"
        # 2. running or sourcing a secrets helper prints every secret
        if prog in ("source", ".", "sh", "bash", "zsh") and args and _is_secrets_helper(args[-1] if prog in ("source", ".") else args[0], cwd):
            return "runs a secrets helper script, which prints every secret"
        if "/" in toks[i] and _is_secrets_helper(toks[i], cwd):
            return "runs a secrets helper script, which prints every secret"
        # 3. inspection commands known to print stored credentials unmasked
        if prog == "openclaw" and args[:2] == ["mcp", "show"]:
            return "openclaw mcp show prints stored headers unmasked; use openclaw mcp doctor"
        if prog in ("printenv", "env") and not [a for a in args if not a.startswith("-")]:
            return "dumps the whole environment, which holds live keys"
        if prog == "set" and not args:
            return "dumps every shell variable, which holds live keys"
        if prog in ("export", "declare", "typeset") and not [a for a in args if not a.startswith("-")] \
                and (prog == "export" or any("p" in a or "x" in a for a in args)):
            return "dumps exported shell variables, which hold live keys"
        if prog == "printenv":
            for a in args:
                if a in guarded:
                    return f"prints a guarded variable ({a})"
        if prog in ("echo", "printf", "print"):
            for a in args:
                for name in re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", a):
                    if name in guarded:
                        return f"prints a guarded variable ({name})"
        # 3b. a file list built at run time: find -exec READER, xargs READER
        if prog == "find":
            for j, a in enumerate(args[:-1]):
                if a in ("-exec", "-execdir", "-ok") and os.path.basename(args[j + 1]) in READERS:
                    for root in _find_roots(args, cwd):
                        reason = _folder_reason(root)
                        if reason:
                            return reason
                    break
        if prog == "xargs" and any(os.path.basename(a) in READERS for a in args):
            reason = _folder_reason(_abs(".", cwd))
            if reason:
                return reason
        # 4. a reader pointed at a secret-shaped file
        if prog in READERS:
            walk = _recursive_folders(prog, args, cwd)
            if walk:
                for folder in walk[0]:
                    reason = _folder_reason(folder, include_hidden=walk[1], skip_dirs=walk[2])
                    if reason:
                        return reason
            for a in args:
                if not a.startswith("-") and _has_magic(a):
                    for m in expand_glob(a, cwd):
                        if is_secret_path(m, cwd):
                            return f"glob matches a secret-shaped file ({os.path.basename(m)})"
                if is_secret_path(a, cwd):
                    return f"reads a secret-shaped file ({os.path.basename(a.strip(QUOTES))})"
                # inline code (python -c, perl -e, node -e) naming a secret file
                for inner in re.findall(r"[\w./~-]+", a) if len(a) > 40 or " " in a else ():
                    if is_secret_path(inner, cwd):
                        return f"inline code references a secret-shaped file ({os.path.basename(inner)})"
    return None


BLOCK_HINT = ("To check a secret, use `hermes secret list` or `hermes secret verify <ENV_VAR>` "
              "(fingerprints only). To add or change one, use the secret_request tool.")


def check_code(code: str) -> Optional[str]:
    """Inline code (execute_code, browser JS, CDP expressions): refuse if it names a secret-shaped
    file or asks the keychain to print a value. Pattern-based, like the rest of layer 1."""
    if not code:
        return None
    if _KEYCHAIN_PRINT_RE.search(code):
        return "asks the keychain to print a secret value"
    if _ENV_DUMP_RE.search(code):
        return "prints the whole environment, which holds live keys"
    for name in _guarded_names():
        if re.search(r"(?:print|log|write)\s*\([^)\n]*(?:environ|getenv|process\.env)[^)\n]*\b"
                     + re.escape(name) + r"\b", code):
            return f"prints a guarded variable ({name})"
    for tok in re.findall(r"[\w./~-]+", code):
        if ("/" in tok or tok.startswith(".")) and is_secret_path(tok):
            return f"code references a secret-shaped file ({os.path.basename(tok)})"
        if tok.endswith("/secret_guard/emit-secrets.sh") or "/secrets-provider/" in tok:
            return "code runs a secrets helper script"
    return None


class _TooBig(Exception):
    pass


MAX_DEPTH, MAX_NODES, MAX_TEXT = 12, 5000, 2_000_000


def _check_string(key: str, val: str, cwd: Optional[str]) -> Optional[str]:
    if "file://" in val and len(val) <= MAX_TEXT:
        for url in _FILE_URL_RE.findall(val):
            target = urllib.parse.unquote(urllib.parse.urlparse(url).path)
            if target and is_secret_path(target, cwd):
                return f"opens a secret-shaped file through a file:// address ({os.path.basename(target)})"
    if key in COMMAND_KEYS:
        return check_command(val, cwd) or check_code(val)
    if key in CODE_KEYS:
        return check_code(val)
    if key in PATH_KEYS:
        return f"opens a secret-shaped file ({os.path.basename(val)})" if is_secret_path(val, cwd) else None
    return None


def _walk(obj: Any, key: str, cwd: Optional[str], depth: int, budget: dict) -> Optional[str]:
    """Visit nested dicts/lists, applying the rule for the nearest enclosing key name. Bounded:
    exceeding depth, node or text budgets raises _TooBig (the caller blocks; never a silent pass)."""
    budget["nodes"] += 1
    if depth > MAX_DEPTH or budget["nodes"] > MAX_NODES:
        raise _TooBig
    if isinstance(obj, str):
        if key in COMMAND_KEYS or key in CODE_KEYS or key in PATH_KEYS:
            budget["text"] += len(obj)
            if budget["text"] > MAX_TEXT:
                raise _TooBig
        return _check_string(key, obj, cwd)
    if isinstance(obj, dict):
        local = obj.get("workdir") or obj.get("cwd")
        cwd = local if isinstance(local, str) else cwd   # a nested workdir/cwd applies to its own object
        for k, v in obj.items():
            r = _walk(v, str(k).lower(), cwd, depth + 1, budget)
            if r:
                return r
        return None
    if isinstance(obj, (list, tuple)):
        for item in obj:
            r = _walk(item, key, cwd, depth + 1, budget)   # list items inherit the list's key
            if r:
                return r
    return None


SEARCH_PATH_KEYS = ("path", "directory", "dir", "root", "folder")


def _search_dicts(obj: Any, depth: int = 0, seen: Optional[list] = None) -> list:
    """Every nested dict of the arguments (bounded), so a wrapped schema such as
    {"input": {"path": ...}} is checked where its path actually is."""
    seen = [] if seen is None else seen
    if depth > MAX_DEPTH or len(seen) > 200:
        raise _TooBig
    if isinstance(obj, dict):
        seen.append(obj)
        for v in obj.values():
            _search_dicts(v, depth + 1, seen)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _search_dicts(v, depth + 1, seen)
    return seen


def _check_folder_search(tool_name: str, args: dict) -> Optional[str]:
    """A content search over a folder returns file contents without naming a file. Applies to
    search_files and to any tool named like a search that takes a path, at any nesting depth."""
    name = (tool_name or "").lower()
    searchy = "search" in name or "grep" in name
    if not (name == "search_files" or searchy):
        return None
    dicts = _search_dicts(args)
    with_path = [d for d in dicts if any(isinstance(d.get(k), str) for k in SEARCH_PATH_KEYS)]
    if not with_path:
        if name != "search_files":
            return None                          # web_search, session_search: no folder involved
        with_path = [args]                       # search_files with no path searches the cwd
    for d in with_path:
        if str(d.get("target", args.get("target", ""))).lower() in NAME_ONLY_TARGETS:
            continue                             # file names only: no contents returned
        path_key = next((k for k in SEARCH_PATH_KEYS if isinstance(d.get(k), str)), None)
        local = d.get("workdir") or d.get("cwd") or args.get("workdir") or args.get("cwd")
        cwd = local if isinstance(local, str) else None
        folder = _abs(d[path_key] if path_key else ".", cwd)
        if not os.path.isdir(folder):
            continue                             # a single file: the path rule already checked it
        name_glob = next((d[k] for k in SEARCH_GLOB_KEYS if isinstance(d.get(k), str) and d[k]), None)
        reason = _folder_reason(folder, name_glob)
        if reason:
            return reason
    return None


def check_tool_args(tool_name: str, args: dict) -> Optional[str]:
    _budget_var.set(_Budget())                   # one work budget for this whole tool call
    try:
        return _walk(args, "", None, 0, {"nodes": 0, "text": 0}) or _check_folder_search(tool_name, args)
    except (_TooBig, RecursionError):
        return "has arguments too large or too deeply nested to inspect"


def on_pre_tool_call(tool_name: str = "", args: Optional[dict] = None, **_kw) -> Optional[dict]:
    try:
        reason = check_tool_args(tool_name, args if isinstance(args, dict) else {})
    except Exception:
        # Fail closed explicitly (Hermes would also block on a raise, but with a less useful message).
        # Never echo the arguments: they may hold the very value being protected.
        logger.warning("secret-guard: tool check failed; blocking %s", tool_name)
        return {"action": "block", "message": f"Secret Guard could not check this {tool_name} call, so it "
                                              f"was blocked. {BLOCK_HINT}"}
    if reason:
        logger.info("secret-guard blocked %s: %s", tool_name, reason)
        return {"action": "block", "message": f"Secret Guard blocked this {tool_name} call: it {reason}. {BLOCK_HINT}"}
    return None

# ---------------------------------------------------------------- layer 2: backup transforms

WITHHELD = "[Secret Guard withheld this output: the redaction check failed, so it was not shown.]"


def _transform(text: Any) -> Optional[str]:
    if not isinstance(text, str) or not text:
        return None
    try:
        out, hits = scrub(text)
    except Exception:
        logger.warning("secret-guard: redaction failed; withholding output", exc_info=False)
        return WITHHELD
    if hits:
        logger.info("secret-guard redacted %d occurrence(s)", hits)
        return out
    return None


def on_transform_tool_result(result: Any = None, **_kw) -> Optional[str]:
    return _transform(result)


def on_transform_terminal_output(output: Any = None, **_kw) -> Optional[str]:
    return _transform(output)


def on_transform_llm_output(response_text: Any = None, **_kw) -> Optional[str]:
    return _transform(response_text)

# ---------------------------------------------------------------- layer 3: inbound paste block

KEY_FORMATS = [
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}"), re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bhf_[A-Za-z0-9]{30,}"), re.compile(r"\bxai-[A-Za-z0-9]{30,}"),
    re.compile(r"\bgsk_[A-Za-z0-9]{30,}"), re.compile(r"\bpplx-[A-Za-z0-9]{30,}"),
    re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}"),  # Telegram bot token
]


def _message_text(m: Any) -> str:
    """All text in a user message: a string, a list of parts, or a single part dict. Anything else
    is stringified rather than skipped, so an unexpected shape is still checked."""
    if m is None:
        return ""
    if isinstance(m, str):
        return m
    if isinstance(m, dict):
        return "\n".join(str(v) for k, v in m.items() if k in ("text", "content", "input_text") and v)
    if isinstance(m, (list, tuple)):
        return "\n".join(_message_text(p) for p in m)
    return str(m)


def find_key_in(text: str) -> Optional[str]:
    """Return a short label for what was found (never the value), or None."""
    for env, v in _load_values().items():
        if v in text:
            return f"the value of {env}"
    for rx in KEY_FORMATS:
        if rx.search(text):
            return "something shaped like an API key or token"
    return None


# Only surfaces that are on this machine by construction. "api" and "dashboard" can be remote.
LOCAL_PLATFORMS = frozenset({"cli", "local", "tui", "desktop"})


def on_pre_llm_call(user_message: Any = None, platform: str = "", **_kw) -> Optional[dict]:
    try:
        register_values()
    except Exception:
        logger.warning("secret-guard: could not register values for redaction", exc_info=False)
    try:
        found = find_key_in(_message_text(user_message))
    except Exception:
        # Fail closed: an uninspected message may hold a key. Never echo the message or the error.
        logger.warning("secret-guard: inbound check failed; turn blocked", exc_info=False)
        return {"action": "block", "message": "🔐 Secret Guard could not safely inspect this message, so the "
                                              "turn was blocked. Please send it again; if this repeats, run "
                                              "`hermes secret doctor`."}
    if not found:
        return None
    plat = (platform or "").lower()
    if plat in LOCAL_PLATFORMS:
        where = "It was typed on this machine."
    elif plat:
        where = (f"It has already passed through {platform.title()}, though, so treat the key as "
                 "exposed and rotate it at the provider.")
    else:
        where = "If it came through a chat app or a remote connection, treat the key as exposed and rotate it."
    return {"action": "block", "message": (
        f"🔐 Secret Guard stopped that message: it contains {found}. No model saw it, and it is not "
        f"stored in this session. {where} To store a key safely, ask me to add it — a hidden dialog "
        "will take the value instead of chat.")}


def on_session_start(**_kw) -> None:
    try:
        n = register_values()
        logger.info("secret-guard: %d guarded value(s) registered for redaction", n)
    except Exception:
        logger.warning("secret-guard: could not register values at session start", exc_info=False)
