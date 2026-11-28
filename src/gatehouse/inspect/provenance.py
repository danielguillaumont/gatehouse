"""Provenance: did private data the agent read end up in an outgoing call? (D-043)

When a result from a ``private_data`` tool reaches the agent, gatehouse records keyed
fingerprints of its text in the session's flow state. When the agent then calls an
``egress`` tool, gatehouse fingerprints the arguments the same way and looks for overlap.

Two kinds of evidence:

- **Spans.** Text is normalized (NFKC, casefolded, invisible characters removed,
  whitespace collapsed) and *winnowed*: every K-character substring is hashed, and the
  smallest hash in each window of W consecutive ones is kept (Schleimer, Wilkerson and
  Aiken, SIGMOD 2003). Any common substring of at least K + W - 1 = 39 characters
  shares at least one kept fingerprint, whatever surrounds it. Argument strings are
  also checked after base64, hex and percent-decoding, so an encoded copy matches too.
- **Secrets.** Secrets found in a private result (by the same detector that scans
  arguments) are recorded by their HMAC, and a secret in an egress argument with the
  same HMAC is an exact match.

Fingerprints are HMACs with the per-install key, truncated to 64 bits, so the flow
store never holds the text and a fingerprint can't be checked against a guess without
the key.

Limits, stated plainly: an agent that *paraphrases* or summarizes private data defeats
span matching. Highly repetitive text (``0000...``) has few distinct K-grams, so it
yields too few fingerprints to count as a copy. Provenance is evidence for the SOC and
for the approval prompt; the Rule of Two (flow.mode) is the guarantee.

Pure functions; inputs are bounded (``MAX_TEXT``, ``MAX_FINGERPRINTS``).
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import zlib
from collections import deque
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import unquote

from gatehouse.events.fingerprint import Fingerprinter
from gatehouse.inspect.invisible import strip_invisible
from gatehouse.inspect.secrets import detect_secrets
from gatehouse.inspect.walk import iter_strings

K = 24  # characters per hashed substring
W = 16  # window of consecutive substrings; copies of K + W - 1 = 39 chars always match
MIN_SPAN_MATCHES = 2  # span fingerprints to report a copy: guaranteed from K + 2W - 1 = 55 chars
MAX_TEXT = 32 * 1024  # characters fingerprinted per result or argument set (D-043)
MAX_FINGERPRINTS = 8192  # per result (32 KiB of text gives about 3,900)
MAX_DECODED = 64  # decoded variants per argument set
FP_HEX = 16  # 64-bit truncated HMAC

_WS = re.compile(r"\s+")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


def normalize(text: str) -> str:
    text = strip_invisible(unicodedata.normalize("NFKC", text)).casefold()
    return _WS.sub(" ", text).strip()


def _winnow(text: str) -> set[str]:
    """K-character substrings selected by winnowing (the substrings themselves).

    A sliding-window minimum over CRC-32 hashes of every K-gram, in O(n) with a
    monotonic deque; ties keep the rightmost position, as in the paper."""
    n = len(text)
    if n < K:
        return {text} if n >= K // 2 else set()
    hashes = [zlib.crc32(text[i : i + K].encode("utf-8")) for i in range(n - K + 1)]
    window: deque[int] = deque()
    picked: set[int] = set()
    last = len(hashes) - 1
    chosen = -1
    for i, h in enumerate(hashes):
        while window and hashes[window[-1]] >= h:
            window.pop()
        window.append(i)
        if window[0] <= i - W:
            window.popleft()
        if (i >= W - 1 or i == last) and window[0] != chosen:
            chosen = window[0]
            picked.add(chosen)
    return {text[j : j + K] for j in picked}


def _keyed(fp: Fingerprinter, grams: Iterable[str]) -> set[str]:
    return {"s:" + fp.short(g, FP_HEX // 2) for g in grams}


def _texts(value: object, root: str, budget: int = MAX_TEXT) -> list[str]:
    out: list[str] = []
    used = 0
    for _, text in iter_strings(value, root, include_keys=False):
        if used >= budget:
            break
        piece = text[: budget - used]
        used += len(piece)
        out.append(piece)
    return out


def result_fingerprints(result: Mapping[str, Any], fp: Fingerprinter) -> set[str]:
    """Fingerprints to record for a private result: spans and secrets."""
    out: set[str] = set()
    for text in _texts(result, "result"):
        out |= _keyed(fp, _winnow(normalize(text)))
        if len(out) >= MAX_FINGERPRINTS:
            break
    for finding in detect_secrets(result, "result", fp):
        if finding.fingerprint:
            out.add("k:" + finding.fingerprint[:FP_HEX])
    return set(sorted(out)[:MAX_FINGERPRINTS])


def _decoded(text: str) -> list[str]:
    """Plausible decodings of encoded substrings (base64/base64url, hex, percent)."""
    out: list[str] = []
    for m in _B64.finditer(text):
        chunk = m.group(0)
        pad = "=" * (-len(chunk) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(chunk + pad)
            except (binascii.Error, ValueError):
                continue
            decoded = raw.decode("utf-8", "ignore")
            if decoded and sum(c.isprintable() for c in decoded) >= 0.9 * len(decoded):
                out.append(decoded)
                break
        if len(out) >= MAX_DECODED:
            return out
    for m in _HEX.finditer(text):
        try:
            out.append(bytes.fromhex(m.group(0)).decode("utf-8", "ignore"))
        except ValueError:
            continue
        if len(out) >= MAX_DECODED:
            return out
    if _PCT.search(text):
        out.append(unquote(text))
    return out[:MAX_DECODED]


def argument_fingerprints(arguments: Mapping[str, Any], fp: Fingerprinter) -> set[str]:
    """Fingerprints of an outgoing call's arguments, including decoded variants."""
    out: set[str] = set()
    for text in _texts(arguments, "arguments"):
        for variant in (text, *_decoded(text)):
            out |= _keyed(fp, _winnow(normalize(variant)))
    for finding in detect_secrets(arguments, "arguments", fp):
        if finding.fingerprint:
            out.add("k:" + finding.fingerprint[:FP_HEX])
    return out


def is_copy(matches: Iterable[str]) -> bool:
    """Enough overlap to report: one secret, or MIN_SPAN_MATCHES span fingerprints."""
    found = set(matches)
    return any(m.startswith("k:") for m in found) or (
        sum(m.startswith("s:") for m in found) >= MIN_SPAN_MATCHES
    )
