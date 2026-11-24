"""Name normalization and glob matching for policy rules.

Server and tool names reach the policy engine from untrusted MCP servers, so both the
names and the rule patterns are normalized the same way before matching:

1. Drop Unicode format characters (category ``Cf``): zero-width spaces/joiners, bidi
   controls, soft hyphens, BOMs and tag characters. They are invisible to a human
   reviewing a tool list, so ``dele\\u200bte_repo`` must still match ``delete_*``.
2. NFKC: folds compatibility look-alikes (fullwidth letters, mathematical alphanumerics,
   ligatures, superscripts) onto their plain forms.
3. casefold: case-insensitive matching (``Delete_Repo`` matches ``delete_*``).
4. NFKC again: casefold can produce strings that are no longer NFKC-normalized.

Known gap: NFKC does not map cross-script confusables (e.g. CYRILLIC SMALL LETTER IE,
U+0435, vs Latin "e"). See docs/policy.md and the xfail test documenting it.
"""

from __future__ import annotations

import unicodedata
from enum import IntEnum
from fnmatch import fnmatchcase

_GLOB_CHARS = frozenset("*?[")


def normalize_name(name: str) -> str:
    """Return the canonical form of a server/tool name or pattern used for matching."""
    visible = "".join(ch for ch in name if unicodedata.category(ch) != "Cf")
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", visible).casefold())


class Specificity(IntEnum):
    """How narrowly a pattern selects names. Higher is more specific."""

    WILDCARD = 1  # only '*' characters: matches everything
    GLOB = 2  # contains glob syntax plus literal text, e.g. 'delete_*'
    EXACT = 3  # no glob syntax: matches one name


def specificity(normalized_pattern: str) -> Specificity:
    """Rank a normalized pattern. Deliberately coarse: see docs/policy.md."""
    if not any(ch in _GLOB_CHARS for ch in normalized_pattern):
        return Specificity.EXACT
    if set(normalized_pattern) == {"*"}:
        return Specificity.WILDCARD
    return Specificity.GLOB


def matches(normalized_pattern: str, normalized_name: str) -> bool:
    """Glob match on already-normalized strings.

    ``fnmatchcase`` rather than ``fnmatch``: ``fnmatch`` applies ``os.path.normcase``,
    which lowercases on Windows only and would make matching OS-dependent. Case
    insensitivity comes from ``normalize_name`` instead, identically on every OS.
    """
    return fnmatchcase(normalized_name, normalized_pattern)
