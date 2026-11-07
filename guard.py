"""Leak prevention: a fail-closed path gate, value redaction, and an inbound paste block.

Layer 1  pre_tool_call          block tool calls that would read a secret-shaped file, run a
                                secrets helper, or ask the keychain to print a value.
Layer 2  value redaction        register every guarded value with Hermes's own model-egress scrub
                                (agent.redact vault registry), plus backup transform hooks that
                                catch their own errors and withhold output rather than fail open.
Layer 3  pre_llm_call           a key pasted into chat never reaches a model.

Values live only in this process's memory. Nothing here logs or returns a value.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import shlex
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
        return register_values() > 0 and env in _load_values()
    except Exception:
        return False


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
    Re-run each turn: it keeps 64 values per profile and evicts the oldest. It is an undocumented
    module function, so if an update removes it the plugin's transform hooks still scrub tool
    results, terminal output and replies, and `hermes secret doctor` reports the change."""
    values = _load_values()
    try:
        from agent.redact import register_vault_redaction_value
    except Exception:
        return 0
    for v in values.values():
        register_vault_redaction_value(v)
    return len(values)


def scrub(text: str) -> tuple[str, int]:
    values = _load_values()
    hits = 0
    for env, v in sorted(values.items(), key=lambda kv: len(kv[1]), reverse=True):
        if v in text:
            hits += text.count(v)
            text = text.replace(v, f"[secret:{env} redacted]")
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
        # 4. a reader pointed at a secret-shaped file
        if prog in READERS:
            for a in args:
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
    for tok in re.findall(r"[\w./~-]+", code):
        if ("/" in tok or tok.startswith(".")) and is_secret_path(tok):
            return f"code references a secret-shaped file ({os.path.basename(tok)})"
        if tok.endswith("/secret_guard/emit-secrets.sh") or "/secrets-provider/" in tok:
            return "code runs a secrets helper script"
    return None


def _strings(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [x for x in v if isinstance(x, str)]
    return []


def check_tool_args(tool_name: str, args: dict) -> Optional[str]:
    cwd = args.get("workdir") or args.get("cwd")
    cwd = cwd if isinstance(cwd, str) else None
    for key, val in args.items():
        k = str(key).lower()
        for s_ in _strings(val):
            if k in COMMAND_KEYS:
                r = check_command(s_, cwd) or check_code(s_)
            elif k in CODE_KEYS:
                r = check_code(s_)
            elif k in PATH_KEYS:
                r = f"opens a secret-shaped file ({os.path.basename(s_)})" if is_secret_path(s_, cwd) else None
            else:
                r = None
            if r:
                return r
    return None


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


LOCAL_PLATFORMS = frozenset({"", "cli", "local", "tui", "desktop", "dashboard", "api"})


def on_pre_llm_call(user_message: Any = None, platform: str = "", **_kw) -> Optional[dict]:
    try:
        register_values()
    except Exception:
        logger.warning("secret-guard: could not register values for redaction", exc_info=False)
    try:
        found = find_key_in(_message_text(user_message))
    except Exception:
        logger.warning("secret-guard: inbound check failed (message allowed)", exc_info=False)
        return None
    if not found:
        return None
    if (platform or "").lower() in LOCAL_PLATFORMS:
        where = "It never left this machine."
    else:
        where = (f"It has already passed through {platform.title()}, though, so treat the key as "
                 "exposed and rotate it at the provider.")
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
