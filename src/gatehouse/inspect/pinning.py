"""Tool-definition pinning: detect rug pulls (definitions that change after approval).

A pin is the SHA-256 of the canonical JSON of the fields that shape what the model sees
and what it can send: name, title, description, inputSchema, outputSchema, annotations.
``_meta`` and ``icons`` are excluded: they are not shown to the model and churn between
server releases (see docs/decisions.md).
"""

from __future__ import annotations

import difflib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict

from gatehouse.canonical import canonical_sha256

PINNED_FIELDS: tuple[str, ...] = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
)


def pinned_view(tool: Mapping[str, Any]) -> dict[str, Any]:
    """The subset of a tool definition that is pinned (absent fields stay absent)."""
    return {k: tool[k] for k in PINNED_FIELDS if k in tool}


def tool_digest(tool: Mapping[str, Any]) -> str:
    return canonical_sha256(pinned_view(tool))


class PinStatus(StrEnum):
    MATCH = "match"
    UNPINNED = "unpinned"
    CHANGED = "changed"


class PinCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: PinStatus
    digest: str
    pinned_digest: str | None = None
    changed_fields: tuple[str, ...] = ()


def check_pin(
    tool: Mapping[str, Any],
    pinned_digest: str | None,
    pinned_definition: Mapping[str, Any] | None = None,
) -> PinCheck:
    digest = tool_digest(tool)
    if pinned_digest is None:
        return PinCheck(status=PinStatus.UNPINNED, digest=digest)
    if digest == pinned_digest:
        return PinCheck(status=PinStatus.MATCH, digest=digest, pinned_digest=pinned_digest)
    fields = changed_fields(pinned_definition, tool) if pinned_definition is not None else ()
    return PinCheck(
        status=PinStatus.CHANGED,
        digest=digest,
        pinned_digest=pinned_digest,
        changed_fields=fields,
    )


def changed_fields(old: Mapping[str, Any], new: Mapping[str, Any]) -> tuple[str, ...]:
    old_v, new_v = pinned_view(old), pinned_view(new)
    return tuple(
        f for f in PINNED_FIELDS if canonical_sha256(old_v.get(f)) != canonical_sha256(new_v.get(f))
    )


def render_diff(old: Mapping[str, Any], new: Mapping[str, Any], tool_name: str) -> str:
    """Unified diff of the pinned views, for `gatehouse diff` (human output)."""
    a = json.dumps(pinned_view(old), indent=2, sort_keys=True, ensure_ascii=True).splitlines()
    b = json.dumps(pinned_view(new), indent=2, sort_keys=True, ensure_ascii=True).splitlines()
    return "\n".join(
        difflib.unified_diff(a, b, f"pinned/{tool_name}", f"current/{tool_name}", lineterm="")
    )
