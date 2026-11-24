"""Invisible and look-alike Unicode: smuggled instructions and confusable names.

* Unicode **tag characters** (U+E0000-U+E007F) mirror ASCII but render as nothing; models
  read them. Any tag character in tool metadata or results is a strong signal.
* **Bidi controls** (U+202A-U+202E, U+2066-U+2069) reorder what a human sees.
* **Zero-width** characters (U+200B-U+200D, U+2060, U+FEFF) split words so phrase rules
  miss them. They also occur in legitimate text (emoji ZWJ sequences), so alone they're
  low severity.
* **Mixed-script names**: a tool name mixing Latin with Cyrillic or Greek letters
  (``read_file`` spelled with a Cyrillic U+0435 for the ``e``) impersonates another
  tool. NFKC can't fold these.

``strip_invisible`` gives other detectors a copy of the text with format characters
removed, so ``ig​nore previous instructions`` still matches.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding

DETECTOR_ID = "text.invisible"
_OWASP = ("LLM01",)
_MITRE = ("AML.T0068", "T1027")

_ZERO_WIDTH = frozenset("​‌‍⁠﻿")
_BIDI = frozenset("‪‫‬‭‮⁦⁧⁨⁩")


def is_tag(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def strip_invisible(text: str) -> str:
    """Remove every Unicode format (Cf) character, including tags, bidi and zero-width."""
    if text.isascii():
        return text
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def decode_tags(text: str) -> str:
    """The ASCII text hidden in tag characters (for a masked summary)."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)


def _summary(hidden: str) -> str:
    shown = hidden[:40] + ("..." if len(hidden) > 40 else "")
    return shown.replace("\n", " ")


def detect_invisible(strings: Iterable[tuple[str, str]]) -> list[Finding]:
    """One finding per (location, kind). ``strings`` is ``(json_path, text)`` pairs."""
    findings: list[Finding] = []
    for where, text in strings:
        if text.isascii():
            continue
        tags = sum(1 for ch in text if is_tag(ch))
        bidi = sum(1 for ch in text if ch in _BIDI)
        zw = sum(1 for ch in text if ch in _ZERO_WIDTH)
        if tags:
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    rule_id="unicode-tag-characters",
                    severity=Severity.HIGH,
                    summary=f"{tags} invisible Unicode tag character(s) hiding text: "
                    f"{_summary(decode_tags(text))!r}",
                    location=where,
                    mitre=_MITRE,
                    owasp=_OWASP,
                )
            )
        if bidi:
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    rule_id="bidi-control",
                    severity=Severity.MEDIUM,
                    summary=f"{bidi} bidirectional control character(s) (text can render "
                    "differently from what the model reads)",
                    location=where,
                    mitre=_MITRE,
                    owasp=_OWASP,
                )
            )
        if zw:
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    rule_id="zero-width",
                    severity=Severity.LOW,
                    summary=f"{zw} zero-width character(s)",
                    location=where,
                    mitre=_MITRE,
                    owasp=_OWASP,
                )
            )
    return findings


_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")


def _script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    for script in _SCRIPTS:
        if name.startswith(script):
            return script
    return "OTHER"


def detect_confusable_name(name: str, where: str) -> list[Finding]:
    """A tool name that mixes Latin letters with Cyrillic/Greek/... look-alikes."""
    scripts = {s for s in (_script(ch) for ch in name) if s is not None}
    if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}:
        mixed = sorted(scripts - {"LATIN"})
        visible = name.encode("ascii", "backslashreplace").decode("ascii")
        return [
            Finding(
                detector_id="listing.confusable_name",
                rule_id="mixed-script-name",
                severity=Severity.HIGH,
                summary=f"tool name mixes Latin with {', '.join(mixed)} letters: {visible}",
                location=where,
                mitre=("AML.T0010.005",),
                owasp=("LLM03",),
            )
        ]
    return []
