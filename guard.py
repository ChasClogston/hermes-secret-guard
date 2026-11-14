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
import fnmatch
import glob as _glob
import logging
import os
import re
import shlex
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


MIN_ENCODED = 12   # shortest encoded fragment worth matching; shorter ones collide with real text
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
                continue
            # base64 and xxd -p wrap long output; match across the line breaks
            if compact is None:
                compact = _WS_RE.sub("", text)
            if form in compact:
                text, n = re.subn(r"\s*".join(re.escape(c) for c in form), label, text)
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
# Folder scans use the name patterns minus "*token*": a repository with tokenizer.json must stay
# searchable. A direct read of such a file is still blocked by SECRET_PATTERNS.
DIR_SCAN_PATTERNS = tuple(p for p in SECRET_PATTERNS if p != "*token*")
SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
                       ".mypy_cache", ".pytest_cache", ".ruff_cache"})
SCAN_MAX_DEPTH, SCAN_MAX_ENTRIES = 12, 20000
GREP_FAMILY = frozenset({"grep", "egrep", "fgrep"})
HIDDEN_SKIPPERS = frozenset({"rg", "ag"})          # skip dotfiles unless told otherwise
ALWAYS_RECURSIVE = HIDDEN_SKIPPERS | {"tar", "zip", "rsync"}
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


def _dir_secret_name(path: str) -> bool:
    name = os.path.basename(path).lower()
    if name.endswith(SAFE_EXTENSIONS):
        return False
    if any(fnmatch.fnmatch(name, p) for p in DIR_SCAN_PATTERNS):
        return True
    return (name == "config.yaml" or name.startswith(("config.yaml.", "config.yaml~"))) and is_secret_path(path)


def secret_file_under(root: str, name_glob: Optional[str] = None, include_hidden: bool = True) -> Optional[str]:
    """First secret-shaped file under `root` (relative path), or None. Bounded: a tree deeper or
    larger than the limits raises _ScanTooBig, and the caller blocks (never a silent pass).
    Symlinked folders are not followed."""
    seen = 0
    stack = [(root, 0)]
    while stack:
        folder, depth = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for e in entries:
            seen += 1
            if seen > SCAN_MAX_ENTRIES:
                raise _ScanTooBig
            if not include_hidden and e.name.startswith("."):
                continue
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if e.name in SKIP_DIRS:
                    continue
                if depth + 1 > SCAN_MAX_DEPTH:
                    raise _ScanTooBig
                stack.append((e.path, depth + 1))
            elif (name_glob is None or fnmatch.fnmatch(e.name, name_glob)) and _dir_secret_name(e.path):
                return os.path.relpath(e.path, root)
    return None


def _folder_reason(folder: str, name_glob: Optional[str] = None, include_hidden: bool = True) -> Optional[str]:
    try:
        hit = secret_file_under(folder, name_glob, include_hidden)
    except _ScanTooBig:
        return ("reads a whole folder that is too large to check for secret files; "
                "name the files or a narrower folder")
    if hit:
        return (f"reads a whole folder that holds a secret-shaped file ({os.path.basename(hit)}); "
                "name the files you need or a narrower folder")
    return None


def _guarded_names() -> frozenset:
    try:
        return frozenset(registry.load().get("secrets", {}))
    except Exception:
        return frozenset()


def _recursive_folders(prog: str, args: list, cwd: Optional[str]) -> Optional[tuple[list, bool]]:
    """(folders a recursive reader would walk, whether dotfiles count), or None if not recursive."""
    flags = [a for a in args if a.startswith("-")]
    pos = [a for a in args if not a.startswith("-")]
    short = "".join(f[1:] for f in flags if not f.startswith("--"))
    if prog in ALWAYS_RECURSIVE:
        recursive = True
    elif prog in GREP_FAMILY:
        recursive = "r" in short or "R" in short or any(f in ("--recursive", "--dereference-recursive") for f in flags)
    elif prog in ("cp", "scp"):
        recursive = any(c in short for c in "rRa") or "--recursive" in flags or "--archive" in flags
    elif prog == "diff":
        recursive = "r" in short or "--recursive" in flags
    else:
        recursive = False
    if not recursive:
        return None
    folders = [d for d in (_abs(a, cwd) for a in pos) if os.path.isdir(d)]
    if not folders and (prog in GREP_FAMILY or prog in HIDDEN_SKIPPERS) and len(pos) <= 1:
        folders = [_abs(".", cwd)]              # `grep -r PATTERN` and `rg PATTERN` search the cwd
    hidden = True
    if prog in HIDDEN_SKIPPERS:
        hidden = any(f in ("--hidden", "-.", "--unrestricted", "--no-ignore") or re.fullmatch(r"-u+", f)
                     for f in flags)
    return folders, hidden


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


def _segments(command: str) -> list[list[str]]:
    out = []
    for seg in re.split(r"\|\|?|&&|;|\n|\$\(|`|\)", command):
        seg = seg.strip()
        if not seg:
            continue
        try:
            toks = shlex.split(seg, posix=True)
        except ValueError:
            toks = seg.split()
        if toks:
            out.append(toks)
    return out


def check_command(command: str, cwd: Optional[str] = None) -> Optional[str]:
    """Return a refusal reason, or None if the command may run."""
    if not command:
        return None
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
                    reason = _folder_reason(folder, include_hidden=walk[1])
                    if reason:
                        return reason
            for a in args:
                if not a.startswith("-") and any(c in a for c in "*?["):
                    pattern = os.path.expanduser(a)
                    if not os.path.isabs(pattern) and cwd:
                        pattern = os.path.join(cwd, pattern)
                    for m in _glob.glob(pattern, recursive="**" in a)[:2000]:
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


def _check_folder_search(tool_name: str, args: dict) -> Optional[str]:
    """A content search over a folder returns file contents without naming a file. Applies to
    search_files and to any tool named like a search that takes a path."""
    name = (tool_name or "").lower()
    path_key = next((k for k in ("path", "directory", "dir", "root", "folder") if isinstance(args.get(k), str)), None)
    if not (name == "search_files" or (("search" in name or "grep" in name) and path_key)):
        return None
    if str(args.get("target", "")).lower() in NAME_ONLY_TARGETS:
        return None                              # file names only: no contents returned
    local = args.get("workdir") or args.get("cwd")
    cwd = local if isinstance(local, str) else None
    folder = _abs(args[path_key] if path_key else ".", cwd)
    if not os.path.isdir(folder):
        return None                              # a single file: the path rule already checked it
    name_glob = next((args[k] for k in SEARCH_GLOB_KEYS if isinstance(args.get(k), str) and args[k]), None)
    return _folder_reason(folder, name_glob)


def check_tool_args(tool_name: str, args: dict) -> Optional[str]:
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
