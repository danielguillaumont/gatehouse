"""Bounded traversal of untrusted JSON values.

Every detector reads strings through ``iter_strings`` so input size limits are enforced
in one place: depth, number of strings, and total characters scanned. Anything past a
limit is reported via ``WalkStats.truncated`` instead of being silently skipped.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from gatehouse.jsonutil import as_list, as_obj

MAX_DEPTH = 64
MAX_STRINGS = 20_000
MAX_TOTAL_CHARS = 4_000_000
MAX_STRING_CHARS = 1_000_000


@dataclass
class WalkStats:
    strings: int = 0
    chars: int = 0
    truncated: bool = False


def iter_strings(
    value: object,
    path: str,
    stats: WalkStats | None = None,
    *,
    include_keys: bool = True,
) -> Iterator[tuple[str, str]]:
    """Yield ``(json_path, text)`` for every string (and, optionally, mapping key)."""
    stats = stats if stats is not None else WalkStats()
    # Explicit stack instead of recursion: untrusted nesting depth can't blow the stack.
    stack: list[tuple[object, str, int]] = [(value, path, 0)]
    while stack:
        current, where, depth = stack.pop()
        if depth > MAX_DEPTH:
            stats.truncated = True
            continue
        if isinstance(current, str):
            if stats.strings >= MAX_STRINGS or stats.chars >= MAX_TOTAL_CHARS:
                stats.truncated = True
                return
            text = current
            if len(text) > MAX_STRING_CHARS:
                text = text[:MAX_STRING_CHARS]
                stats.truncated = True
            remaining = MAX_TOTAL_CHARS - stats.chars
            if len(text) > remaining:
                text = text[:remaining]
                stats.truncated = True
            stats.strings += 1
            stats.chars += len(text)
            yield where, text
        elif (obj := as_obj(current)) is not None:
            for key, child in reversed(list(obj.items())):  # reversed: pop order == doc order
                stack.append((child, f"{where}.{key}", depth + 1))
                if include_keys:
                    stack.append((key, f"{where}.{{key}}", depth + 1))
        elif (seq := as_list(current)) is not None:
            for index in range(len(seq) - 1, -1, -1):
                stack.append((seq[index], f"{where}[{index}]", depth + 1))
