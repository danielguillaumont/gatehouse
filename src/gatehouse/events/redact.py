"""Redaction applied to every event before any sink sees it.

Three passes on every free-text value:

1. Secrets are replaced by their masked form (same catalog as the ``args.secrets``
   detector). Tool names, descriptions and error messages come from untrusted servers and
   can carry secrets too.
2. Invisible format characters (zero-width, bidi controls, tag characters) are shown as
   ``\\uXXXX`` so an analyst sees what the agent saw, and a log line can't visually lie.
3. Length is capped.
"""

from __future__ import annotations

import unicodedata
from typing import Any, cast

from gatehouse.inspect.secrets import redact_text
from gatehouse.jsonutil import as_list, as_obj

MAX_FIELD_CHARS = 512
MAX_DETAIL_CHARS = 1024
MAX_DETAIL_ITEMS = 64
MAX_DETAIL_DEPTH = 4


def _visible(text: str) -> str:
    if not any(unicodedata.category(ch) == "Cf" for ch in text):
        return text
    return "".join(f"\\u{ord(ch):04x}" if unicodedata.category(ch) == "Cf" else ch for ch in text)


def redact_str(text: str, limit: int = MAX_FIELD_CHARS) -> str:
    cleaned = _visible(redact_text(text))
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def redact_value(value: Any, depth: int = 0) -> Any:
    """Redact a small JSON-like structure (event ``details``)."""
    if isinstance(value, str):
        return redact_str(value, MAX_DETAIL_CHARS)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if depth >= MAX_DETAIL_DEPTH:
        return "<truncated>"
    if (obj := as_obj(value)) is not None:
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= MAX_DETAIL_ITEMS:
                out["<truncated>"] = True
                break
            out[redact_str(str(k), 128)] = redact_value(v, depth + 1)
        return out
    if isinstance(value, tuple):
        value = list(cast(tuple[Any, ...], value))
    if (seq := as_list(value)) is not None:
        items = [redact_value(v, depth + 1) for v in seq[:MAX_DETAIL_ITEMS]]
        if len(seq) > MAX_DETAIL_ITEMS:
            items.append("<truncated>")
        return items
    return redact_str(str(value), MAX_DETAIL_CHARS)
