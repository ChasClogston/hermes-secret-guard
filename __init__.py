"""Secret Guard: safe key entry and leak prevention for Hermes Agent."""

from __future__ import annotations

import logging
import platform

logger = logging.getLogger(__name__)


def register(ctx) -> None:
    if platform.system() != "Darwin":
        logger.info("secret-guard: macOS only; not loading")
        return
    from . import guard
    from .cli import register_cli, secret_command
    from .tools import SECRET_REQUEST_SCHEMA, handle_secret_request

    ctx.register_cli_command(
        name="secret", help="Add, list and verify guarded secrets (keychain-backed)",
        setup_fn=register_cli, handler_fn=secret_command,
        description="Secret Guard: enter keys through a hidden dialog, never through chat.")
    ctx.register_tool(name="secret_request", toolset="secret_guard", schema=SECRET_REQUEST_SCHEMA,
                      handler=handle_secret_request, emoji="🔐")
    from .source import KeychainSource
    ctx.register_secret_source(KeychainSource())
    ctx.register_hook("on_session_start", guard.on_session_start)
    ctx.register_hook("pre_llm_call", guard.on_pre_llm_call)
    ctx.register_hook("pre_tool_call", guard.on_pre_tool_call)
    ctx.register_hook("transform_tool_result", guard.on_transform_tool_result)
    ctx.register_hook("transform_terminal_output", guard.on_transform_terminal_output)
    ctx.register_hook("transform_llm_output", guard.on_transform_llm_output)
