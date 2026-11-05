"""Model-facing tool. It has no value parameter: the model cannot pass a secret, only ask for one."""

from __future__ import annotations

import json
import socket
from typing import Any

from . import intake as _intake, registry


def _host() -> str:
    name = socket.gethostname().split(".")[0]
    return name.replace("-", " ") or "this Mac"


SECRET_REQUEST_SCHEMA = {
    "name": "secret_request",
    "description": (
        "Ask the user to enter an API key or token safely. Opens a hidden-input dialog on the Mac "
        "Hermes runs on; the value goes straight to the OS keychain and you never see it. Returns only "
        "the name, a fingerprint and the length. Use this whenever the user wants to add, set or rotate "
        "a key. NEVER ask the user to paste a key into chat. The dialog appears on the host Mac, not on "
        "the user's phone: if the user is talking to you through a messaging app, first tell them a "
        "dialog will open on that Mac and confirm they are at it before you call this tool."),
    "parameters": {
        "type": "object",
        "properties": {
            "env_var": {"type": "string",
                        "description": "Environment variable name, UPPER_SNAKE_CASE, e.g. GROQ_API_KEY."},
            "scope": {"type": "string", "enum": list(registry.SCOPES),
                      "description": "all (default) or default-only. Messaging bot tokens are always default-only."},
        },
        "required": ["env_var"],
        "additionalProperties": False,
    },
}


def handle_secret_request(args: dict[str, Any], **_kw) -> str:
    env = str(args.get("env_var") or "").strip()
    host = _host()
    try:
        res = _intake.intake(env, scope=args.get("scope") or None)
    except (_intake.IntakeError, ValueError) as exc:
        msg = str(exc)
        hint = ""
        if "cancelled or empty" in msg:
            hint = (f" The dialog on {host} was cancelled or nobody answered it within 5 minutes "
                    "(it cannot show while the Mac is locked or asleep). To add the key later, run "
                    f"`hermes secret add {env}` on {host}.")
        return json.dumps({"ok": False, "error": msg + hint})
    try:
        from . import helper
        helper.write()
    except Exception:
        pass
    return json.dumps({"ok": True, **res, "entered_on": host,
                       "note": "Stored in the keychain. Start a new session (or restart Hermes) for "
                               "profiles to pick it up."})
