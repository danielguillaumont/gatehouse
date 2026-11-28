"""Decodings of encoded substrings, for detectors that look through encoding (pure).

An attacker who knows a detector reads text can hide the same text as base64 or hex.
``decodings`` returns the plausible decodings of a string. A decoding counts only if
it is at least 90% printable ASCII, so random digests, image data and identifiers drop
out. Inputs and outputs are bounded: at most ``MAX_CANDIDATES`` substrings per
encoding, each up to 8 KiB.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote

# Maximal runs only: a leading lookbehind would run at every position (2.6x slower on
# 1 MiB of prose). Strict decoding rejects what isn't really base64.
_B64 = re.compile(r"[A-Za-z0-9+/=_\-]{16,8192}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){12,4096}")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
MAX_CANDIDATES = 32

BASE64 = " (base64-encoded)"
HEX = " (hex-encoded)"
PERCENT = " (percent-encoded)"


def _printable(raw: bytes) -> str | None:
    if not raw:
        return None
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    if printable < 0.9 * len(raw):
        return None
    return raw.decode("ascii", "replace")


def decode_b64(candidate: str) -> str | None:
    """Strict standard base64 (no base64url: runs with ``-``/``_`` are identifiers)."""
    if len(candidate) % 4 or "-" in candidate or "_" in candidate:
        return None
    try:
        return _printable(base64.b64decode(candidate, validate=True))
    except (binascii.Error, ValueError):
        return None


def decodings(text: str, *, percent: bool = False) -> list[tuple[str, str]]:
    """(decoded text, how) for each plausible encoded substring of ``text``.

    ``percent`` also adds the percent-decoded whole string when it has ``%XX``
    escapes (useful for secrets in URLs; noisy for prose)."""
    out: list[tuple[str, str]] = []
    tried = 0
    for m in _B64.finditer(text):
        tried += 1
        if tried > MAX_CANDIDATES:
            break
        decoded = decode_b64(m.group(0))
        if decoded is not None:
            out.append((decoded, BASE64))
    tried = 0
    for m in _HEX.finditer(text):
        tried += 1
        if tried > MAX_CANDIDATES:
            break
        decoded = _printable(bytes.fromhex(m.group(0)))
        if decoded is not None:
            out.append((decoded, HEX))
    if percent and _PCT.search(text):
        decoded = unquote(text)
        if decoded != text:
            out.append((decoded, PERCENT))
    return out
