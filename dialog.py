"""Native hidden-input dialog. Names travel to osascript as argv items, never spliced into script text."""

from __future__ import annotations

import subprocess
from typing import Optional

OSASCRIPT = "/usr/bin/osascript"
TITLE = "Secret Guard"


def ask_value(label: str, timeout_s: int = 300) -> Optional[str]:
    """Show a hidden-answer dialog. Returns the typed value, or None if cancelled or timed out."""
    script = [
        "on run argv",
        'set r to display dialog ("Paste the value for " & item 1 of argv & return & return & '
        '"It goes straight to your keychain. Hermes sees only a fingerprint.") '
        'default answer "" with hidden answer with title "' + TITLE + '" '
        'buttons {"Cancel", "Save"} default button "Save" cancel button "Cancel" '
        "giving up after " + str(int(timeout_s)),
        "if gave up of r then return \"\"",
        "return text returned of r",
        "end run",
    ]
    args = [OSASCRIPT]
    for line in script:
        args += ["-e", line]
    args.append(label)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout_s + 15)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        return None
    value = r.stdout.rstrip("\n")
    return value or None


def ask_replace(label: str, timeout_s: int = 120) -> bool:
    script = [
        "on run argv",
        'set r to display dialog ("An entry for " & item 1 of argv & " already exists." & return & "Replace it?") '
        'with title "' + TITLE + '" buttons {"Cancel", "Replace"} default button "Cancel" '
        'cancel button "Cancel" with icon caution giving up after ' + str(int(timeout_s)),
        'if gave up of r then error number -128',
        "end run",
    ]
    args = [OSASCRIPT]
    for line in script:
        args += ["-e", line]
    args.append(label)
    try:
        r = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s + 15)
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0
