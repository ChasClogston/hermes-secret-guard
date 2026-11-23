"""Pattern detection: keys Secret Guard has never been told about (1.3).

Exact-value redaction (guard.scrub) only knows the values in this profile's keychain. This module
recognises secrets by shape, so a key that arrives in a file, an email or a tool result is caught
even though it is not one of yours. It is a second layer behind exact values, never a replacement.

What counts as a match, and why each rule is narrow:
  * prefixed API keys    a vendor prefix (sk-ant-, ghp_, AKIA, ...) plus a long body
  * private key blocks   -----BEGIN ... PRIVATE KEY----- through the END line (or end of text)
  * JWTs                 three base64url parts whose first part decodes to JSON with "alg"
  * seed phrases         12-24 BIP39 words that pass the BIP39 checksum (1 in 16 random runs
                         of 12 words pass, 1 in 256 of 24; prose almost never forms such a run)
  * assigned secrets     a value of 20+ characters written right after a key-like name
                         (api_key=, "client_secret": , Authorization: Bearer ...)

Bare long hex or base64 with no prefix and no key-like name is NOT matched: git commit IDs,
checksums, UUIDs and content hashes look the same and are everywhere in tool output.

Nothing here logs, stores or returns a matched value; callers get spans and labels only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from typing import NamedTuple, Optional


class Hit(NamedTuple):
    start: int
    end: int
    label: str


# ---------------------------------------------------------------- prefixed API keys

# The first 13 are the 1.0 paste-block formats, unchanged, so nothing that was caught stops being
# caught. The rest are added in 1.3.
KEY_FORMATS = [
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}"), re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bhf_[A-Za-z0-9]{30,}"), re.compile(r"\bxai-[A-Za-z0-9]{30,}"),
    re.compile(r"\bgsk_[A-Za-z0-9]{30,}"), re.compile(r"\bpplx-[A-Za-z0-9]{30,}"),
    re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}"),  # Telegram bot token
    # 1.3
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),                       # AWS temporary access key id
    re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}"),              # Stripe live secret / restricted
    re.compile(r"\bwhsec_[A-Za-z0-9+/=]{24,}"),                # Stripe webhook signing secret
    re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{24,}"),                # Google OAuth client secret
    re.compile(r"\bya29\.[A-Za-z0-9_-]{30,}"),                 # Google OAuth access token
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),                    # npm automation token
    re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),                    # DigitalOcean
    re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),     # Shopify
    re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),  # SendGrid
    re.compile(r"\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}"),        # Square
    re.compile(r"\bglsa_[A-Za-z0-9]{32}_[a-fA-F0-9]{8}\b"),    # Grafana service account
    re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),   # PyPI upload token
]

# ---------------------------------------------------------------- private key blocks

_PEM_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
    r"[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)")

# ---------------------------------------------------------------- JWTs

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")


def _b64url_json(part: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        obj = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def _is_jwt(token: str) -> bool:
    header = _b64url_json(token.split(".", 1)[0])
    return bool(header) and isinstance(header.get("alg"), str)

# ---------------------------------------------------------------- assigned secrets

_NAME = (r"(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|"
         r"auth[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|bearer[_-]?token|"
         r"private[_-]?key|signing[_-]?key|password|passwd|pwd|token)")
# name, optional closing quote, separator, optional opening quote, value. The name may carry a
# prefix (OPENAI_API_KEY, x-api-key, db_password) but must END with one of the names above.
_ASSIGN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])([A-Za-z0-9_.-]{0,40}?" + _NAME + r")(?![A-Za-z0-9])"
    r"[\"']?\s*(?::|=|=>|:=)\s*[\"']?([A-Za-z0-9_\-+/=.~]{20,})")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9_\-+/=.~]{20,})")
# Names that end in "token" but hold no secret: pagination and sync cursors. Matched as whole name
# components right before "token" (next_page_token, pageToken, sync-token), never as substrings,
# so admin_password and account_api_key still count. Counters and settings (token_count,
# max_tokens, token_type) never reach this check: a name must END with a secret word.
_NOT_SECRET_NAME_RE = re.compile(
    r"(?:^|[_.\-])(?:next[_.\-]?page|page|next|prev|previous|continuation|cursor|sync|resume)[_.\-]?token$")
# Whole-value placeholder shapes only (R4): a leading placeholder word, a long run of x or *, an
# ellipsis (Hermes's own masked previews look like "sk-abc...wxyz"), or angle brackets.
_PLACEHOLDER_RE = re.compile(r"(?i)^(?:your|example|placeholder|changeme|dummy|redacted)|x{6,}|\*{4,}|"
                             r"\.{3}|<|>|^0+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _plausible_value(v: str) -> bool:
    v = v.rstrip(".,;")
    if len(v) < 20 or v[0] in "/~." or "/" in v[:2]:
        return False                          # a path, not a value
    if _PLACEHOLDER_RE.search(v) or len(set(v)) < 6 or _placeholder_key(v):
        return False
    if _HEX_RE.match(v):
        return len(v) >= 32                   # hex is fine next to a key name, but only if long
    return bool(re.search(r"[A-Za-z]", v) and re.search(r"[0-9]", v))


def _assigned(text: str) -> list[Hit]:
    hits = []
    for m in _ASSIGN_RE.finditer(text):
        name = m.group(1).lower()
        if _NOT_SECRET_NAME_RE.search(name):
            continue
        if _plausible_value(m.group(2)):
            end = m.start(2) + len(m.group(2).rstrip(".,;"))
            hits.append(Hit(m.start(2), end, "secret assigned to a key name"))
    for m in _BEARER_RE.finditer(text):
        if _plausible_value(m.group(1)):
            hits.append(Hit(m.start(1), m.start(1) + len(m.group(1).rstrip(".,;")), "bearer token"))
    return hits

# ---------------------------------------------------------------- BIP39 seed phrases

_WORDLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bip39_english.txt")
_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
_words: Optional[dict[str, int]] = None


def _wordlist() -> dict[str, int]:
    """word -> index. Verified against the published BIP39 English list hash; a damaged or
    swapped file raises, and the caller's fail-closed handling applies."""
    global _words
    if _words is None:
        with open(_WORDLIST_PATH, "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != _WORDLIST_SHA256:
            raise RuntimeError("secret-guard: bip39_english.txt does not match the BIP39 list")
        words = data.decode("ascii").split()
        if len(words) != 2048:
            raise RuntimeError("secret-guard: bip39_english.txt is not 2048 words")
        _words = {w: i for i, w in enumerate(words)}
    return _words


def bip39_valid(indices: list[int]) -> bool:
    n = len(indices)
    if n not in (12, 15, 18, 21, 24):
        return False
    bits = 0
    for i in indices:
        bits = (bits << 11) | i
    total = 11 * n
    cs_len = total // 33
    ent_len = total - cs_len
    entropy = (bits >> cs_len).to_bytes(ent_len // 8, "big")
    checksum = bits & ((1 << cs_len) - 1)
    return hashlib.sha256(entropy).digest()[0] >> (8 - cs_len) == checksum


# Between two words: whitespace or commas, optionally a list number ("3." "4)" "12:").
_WORD_RE = re.compile(r"[A-Za-z]+")
_GAP_RE = re.compile(r"[\s,;]*(?:\d{1,2}[.):\]-]?\s*)?")


def _seed_phrases(text: str) -> list[Hit]:
    wl = _wordlist()
    hits: list[Hit] = []
    run: list[tuple[int, int, int]] = []          # (start, end, index)

    def flush() -> None:
        i = 0
        while i + 12 <= len(run):
            for size in (24, 21, 18, 15, 12):
                if i + size <= len(run) and bip39_valid([w[2] for w in run[i:i + size]]):
                    hits.append(Hit(run[i][0], run[i + size - 1][1], "seed phrase"))
                    i += size
                    break
            else:
                i += 1
        run.clear()

    prev_end = 0
    for m in _WORD_RE.finditer(text):
        idx = wl.get(m.group(0).lower())
        gap_ok = bool(run) and _GAP_RE.fullmatch(text, prev_end, m.start()) is not None
        if idx is None:
            flush()
        else:
            if run and not gap_ok:
                flush()
            run.append((m.start(), m.end(), idx))
        prev_end = m.end()
    flush()
    return hits

# ---------------------------------------------------------------- look-alikes left alone

# Two explicit documentation-example shapes, nothing broader (a random key can contain "your"):
#   * almost no variety: "sk-" followed by twenty x's (fewer than 8 different characters in all)
#   * written words: every dash/underscore part lowercase letters or digits, 3+ parts, and at
#     least two of them placeholder words ("sk-proj-your-key-goes-here")
# Real keys of every listed format have high variety and mixed case or long random parts.
_PLACEHOLDER_WORDS = frozenset({"your", "my", "key", "here", "goes", "example", "placeholder",
                                "changeme", "dummy", "fake", "test", "insert", "replace", "redacted",
                                "token", "secret", "api"})


def _placeholder_key(v: str) -> bool:
    if len(set(v)) < 8:
        return True
    parts = [p for p in re.split(r"[-_]", v) if p]
    return (len(parts) >= 3 and all(re.fullmatch(r"[a-z]+|[0-9]+", p) for p in parts)
            and sum(p in _PLACEHOLDER_WORDS for p in parts) >= 2)

# ---------------------------------------------------------------- public interface

def detect(text: str, inbound: bool = False) -> list[Hit]:
    """Every pattern match in `text`, sorted, with overlaps merged (the earlier, longer label wins).

    inbound=True is the chat check: a vendor-format string is matched even when it looks like a
    placeholder, exactly as in 1.0, because a stopped message can be released with `as-is`. For
    output (inbound=False) placeholders are left alone, so documentation examples stay readable."""
    if not text:
        return []
    found: list[Hit] = []
    for rx in KEY_FORMATS:
        found += [Hit(m.start(), m.end(), "API key") for m in rx.finditer(text)
                  if inbound or not _placeholder_key(m.group(0))]
    found += [Hit(m.start(), m.end(), "private key block") for m in _PEM_RE.finditer(text)]
    found += [Hit(m.start(), m.end(), "JWT") for m in _JWT_RE.finditer(text) if _is_jwt(m.group(0))]
    found += _assigned(text)
    found += _seed_phrases(text)
    found.sort(key=lambda h: (h.start, -(h.end - h.start)))
    merged: list[Hit] = []
    for h in found:
        if merged and h.start < merged[-1].end:
            last = merged[-1]
            if h.end > last.end:
                merged[-1] = Hit(last.start, h.end, last.label)
            continue
        merged.append(h)
    return merged


def first_label(text: str, inbound: bool = False) -> Optional[str]:
    hits = detect(text, inbound)
    return hits[0].label if hits else None


def redact(text: str, inbound: bool = False) -> tuple[str, int]:
    """Replace each match with a label naming its kind. Returns (text, number of matches)."""
    hits = detect(text, inbound)
    if not hits:
        return text, 0
    out, pos = [], 0
    for h in hits:
        out.append(text[pos:h.start])
        out.append(f"[secret:possible {h.label} redacted]")
        pos = h.end
    out.append(text[pos:])
    return "".join(out), len(hits)
