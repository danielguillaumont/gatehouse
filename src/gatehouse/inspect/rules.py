"""Shared machinery for regex-based content detectors.

Every rule:

* is linear-time with Python ``re``: no nested quantifiers, and every repetition is
  bounded (``{0,120}``), so input can't cause catastrophic backtracking;
* has lower-case ``keywords``: the regex only runs if one occurs in the lower-cased text
  (same prefilter as the secret catalog, D-026);
* runs on the text *and* on a copy with Unicode format characters removed, so zero-width
  characters can't split a phrase (``ig​nore previous instructions``).

Detectors stay pure: ``(json_path, text)`` in, ``Finding`` list out.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.invisible import strip_invisible

_QUOTES = "\"'`\u201c\u201d\u2018\u2019"  # ASCII quotes and curly quotes
SUMMARY_CHARS = 80


@dataclass(frozen=True, slots=True)
class PatternRule:
    rule_id: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity
    keywords: tuple[str, ...]
    mitre: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    # A phrase that is *quoted* is usually being talked about, not issued (a security
    # tool documenting "ignore previous instructions" payloads). Opt-in per rule.
    skip_if_quoted: bool = False
    # Optional extra check on the match (e.g. Luhn for card numbers).
    validate: Callable[[re.Match[str]], bool] | None = None


def ci(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _quoted(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 1) : start]
    after = text[end : end + 1]
    return bool(before) and before in _QUOTES and (not after or after in _QUOTES + " .,;:)")


def _excerpt(text: str, start: int, end: int) -> str:
    snippet = text[start:end]
    if len(snippet) > SUMMARY_CHARS:
        snippet = snippet[: SUMMARY_CHARS - 3] + "..."
    return " ".join(snippet.split())


def match_rules(
    text: str, rules: Iterable[PatternRule]
) -> list[tuple[PatternRule, re.Match[str], str]]:
    """Return (rule, match, scanned_text) for the first match of each rule."""
    variants = [text]
    stripped = strip_invisible(text)
    if stripped != text:
        variants.append(stripped)
    lowered = [v.lower() for v in variants]
    out: list[tuple[PatternRule, re.Match[str], str]] = []
    for rule in rules:
        for variant, low in zip(variants, lowered, strict=True):
            if rule.keywords and not any(k in low for k in rule.keywords):
                continue
            hit = None
            for m in rule.pattern.finditer(variant):
                if rule.skip_if_quoted and _quoted(variant, m.start(), m.end()):
                    continue
                if rule.validate is not None and not rule.validate(m):
                    continue
                hit = m
                break
            if hit is not None:
                out.append((rule, hit, variant))
                break
    return out


def scan(
    detector_id: str,
    strings: Iterable[tuple[str, str]],
    rules: tuple[PatternRule, ...],
    *,
    show_match: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    for where, text in strings:
        for rule, m, variant in match_rules(text, rules):
            detail = f": {_excerpt(variant, m.start(), m.end())!r}" if show_match else ""
            findings.append(
                Finding(
                    detector_id=detector_id,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    summary=f"{rule.description}{detail}",
                    location=where,
                    mitre=rule.mitre,
                    owasp=rule.owasp,
                )
            )
    return findings
