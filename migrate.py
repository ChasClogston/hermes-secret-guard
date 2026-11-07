"""Reading an existing keychain helper script by NAMES ONLY. Never runs it."""

from __future__ import annotations

import re
from pathlib import Path

_EMIT_RE = re.compile(r'^\s*emit\s+"([A-Za-z0-9._-]+)"\s+"([A-Z][A-Z0-9_]+)"', re.M)


def parse_existing_helper(path: Path) -> list[tuple[str, str]]:
    """(service, ENV) pairs from a keychain-secrets-env.sh-style script (emit "svc" "ENV" lines)."""
    return _EMIT_RE.findall(Path(path).read_text())
