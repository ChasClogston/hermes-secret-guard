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
import threading
from pathlib import Path
from typing import Any, Optional

from . import keychain, registry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- values (memory only)

_lock = threading.Lock()
_cache: dict = {"mtime": None, "values": {}}   # values: env -> value


def _load_values() -> dict[str, str]:
    """env -> value for every registered secret, read once per registry change."""
    p = registry.registry_path()
    try:
        mtime = p.stat().st_mtime if p.exists() else None
    except OSError:
        mtime = None
    with _lock:
        if _cache["mtime"] == mtime and mtime is not None:
            return _cache["values"]
    values: dict[str, str] = {}
    for env, e in registry.load().get("secrets", {}).items():
        v = os.environ.get(env)
        if not (v and keychain.fingerprint(v) == e.get("fingerprint")):
            v = keychain.read_value(e["service"], e["account"], e.get("keychain"))
        if v and len(v) >= 8:  # never scrub trivially short strings
            values[env] = v
    with _lock:
        _cache.update(mtime=mtime, values=values)
    return values


_ctx = None                 # plugin context, kept for the public-API fallback
_pattern_registered: set = set()   # fingerprints already sent to ctx.register_redaction_patterns


def set_context(ctx) -> None:
    global _ctx
    _ctx = ctx


def register_values() -> int:
    """Push every guarded value into Hermes's model-egress scrub.

    Preferred: agent.redact's vault registry, a hard boundary that applies even when
    security.redact_secrets is off. Re-run each turn: it keeps 64 values per profile and evicts the
    oldest, and re-registering refreshes ours. It is a private module function, so if a Hermes update
    removes it, fall back to the public ctx.register_redaction_patterns with each value escaped as a
    literal (that path honours security.redact_secrets). The plugin's own transform hooks scrub too.
    """
    values = _load_values()
    try:
        from agent.redact import register_vault_redaction_value
    except Exception:
        register_vault_redaction_value = None
    if register_vault_redaction_value is not None:
        for v in values.values():
            register_vault_redaction_value(v)
        return len(values)
    if _ctx is not None:
        new = [v for v in values.values() if keychain.fingerprint(v) not in _pattern_registered]
        if new:
            _ctx.register_redaction_patterns([re.escape(v) for v in new])
            _pattern_registered.update(keychain.fingerprint(v) for v in new)
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
SAFE_EXTENSIONS = (".sh", ".py", ".md", ".log")
QUOTES = "\"'"
READERS = frozenset({"cat", "bat", "less", "more", "head", "tail", "sed", "awk", "gawk", "grep",
                     "egrep", "fgrep", "rg", "ag", "strings", "xxd", "od", "hexdump", "base64",
                     "python", "python3", "node", "perl", "ruby", "php", "jq", "yq", "cp", "scp",
                     "rsync", "curl", "nl", "tac", "cut", "sort", "uniq", "diff", "cmp", "vim",
                     "vi", "nano", "open", "pbcopy", "tee", "dd", "zip", "tar"})
SECRET_TOOLS_ARG = {"read_file": ("path",), "search_files": ("path",), "patch": ("path",),
                    "write_file": ("path",)}


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


def on_pre_tool_call(tool_name: str = "", args: Optional[dict] = None, **_kw) -> Optional[dict]:
    args = args or {}
    reason = None
    if tool_name in ("terminal", "process", "execute_code"):
        cmd = args.get("command") or args.get("code") or ""
        reason = check_command(str(cmd), args.get("workdir") or args.get("cwd"))
    elif tool_name in SECRET_TOOLS_ARG:
        for key in SECRET_TOOLS_ARG[tool_name]:
            v = args.get(key)
            if isinstance(v, str) and is_secret_path(v):
                reason = f"opens a secret-shaped file ({os.path.basename(v)})"
                break
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
    if isinstance(m, str):
        return m
    if isinstance(m, list):
        return "\n".join(p.get("text", "") for p in m if isinstance(p, dict))
    return ""


def find_key_in(text: str) -> Optional[str]:
    """Return a short label for what was found (never the value), or None."""
    for env, v in _load_values().items():
        if v in text:
            return f"the value of {env}"
    for rx in KEY_FORMATS:
        if rx.search(text):
            return "something shaped like an API key or token"
    return None


def on_pre_llm_call(user_message: Any = None, **_kw) -> Optional[dict]:
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
    return {"action": "block", "message": (
        f"🔐 Secret Guard stopped that message: it contains {found}. No model saw it, and it is not "
        "stored in this session. It has already passed through the chat app, though, so treat the key "
        "as exposed and rotate it at the provider. To store a key safely, ask me to add it — a hidden "
        "dialog will take the value instead of chat.")}


def on_session_start(**_kw) -> None:
    try:
        n = register_values()
        logger.info("secret-guard: %d guarded value(s) registered for redaction", n)
    except Exception:
        logger.warning("secret-guard: could not register values at session start", exc_info=False)
