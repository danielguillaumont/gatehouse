"""Deterministic JSON encoding used for hashing (pins, argument fingerprints).

JCS-like (RFC 8785 in spirit): sorted keys, no insignificant whitespace, UTF-8, no
NaN/Infinity. Differs from strict JCS in key ordering (code points, not UTF-16 units) and
number formatting (Python's repr); both are stable for a given gatehouse version, which
is all pinning needs. See docs/decisions.md.
"""

from __future__ import annotations

import hashlib
import json


def canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
