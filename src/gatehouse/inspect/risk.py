"""Coarse tool-risk classification: exec > egress > write > read > unknown.

Used for telemetry (``ToolRisk``) so analytics can ask "was a high-risk tool called
right after an injection?". Inputs are untrusted (names and annotations come from the
server), so classification only ever *raises* risk: a server claiming
``readOnlyHint: true`` cannot lower a name that says ``delete``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from gatehouse.policy.names import normalize_name

_ORDER = ("unknown", "read", "write", "egress", "exec")

_KEYWORDS: dict[str, frozenset[str]] = {
    "exec": frozenset(
        "exec execute run shell command cmd bash sh zsh powershell pwsh eval script terminal "
        "spawn process subprocess invoke".split()
    ),
    "egress": frozenset(
        "send post upload publish email mail webhook http https fetch request curl wget notify "
        "message tweet share push sync download browse navigate url".split()
    ),
    "write": frozenset(
        "write create update delete remove rm move mv rename set put edit patch insert drop "
        "merge commit append modify save replace truncate chmod chown install kill".split()
    ),
    "read": frozenset("get list read search find query describe show view cat ls stat".split()),
}

_SPLIT = re.compile(r"[^a-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokens(name: str) -> set[str]:
    spaced = _CAMEL.sub("_", name)
    return {t for t in _SPLIT.split(normalize_name(spaced)) if t}


def _max(a: str, b: str) -> str:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


def classify(name: str, annotations: Mapping[str, Any] | None = None) -> str:
    tokens = _tokens(name)
    risk = "unknown"
    for level in ("read", "write", "egress", "exec"):
        if tokens & _KEYWORDS[level]:
            risk = _max(risk, level)
    if annotations:
        if annotations.get("destructiveHint") is True:
            risk = _max(risk, "write")
        if annotations.get("openWorldHint") is True:
            risk = _max(risk, "egress")
        if annotations.get("readOnlyHint") is True:
            risk = _max(risk, "read")
    return risk
