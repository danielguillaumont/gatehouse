"""Indirect prompt injection and exfiltration beacons in tool *results*.

Scans every string in a ``tools/call`` result: ``content[].text``, resource text,
``structuredContent`` and so on. Fetched web pages, tickets and documents are
attacker-controlled data that the model reads as if it came from the tool.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.decode import decodings
from gatehouse.inspect.invisible import detect_invisible, strip_invisible
from gatehouse.inspect.phrases import INSTRUCTION_RULES
from gatehouse.inspect.rules import PatternRule, ci, scan
from gatehouse.inspect.walk import WalkStats, iter_strings

DETECTOR_ID = "response.injection"
EXFIL_ID = "response.exfil_url"

RESULT_RULES: tuple[PatternRule, ...] = INSTRUCTION_RULES

_COMMENT_HINT = ci(
    r"\b(?:you\s+must|assistant|ai\s+model|ignore|instructions?|call\s+the|"
    r"send\s+(?:the|all|an?)\b)"
)
MAX_COMMENT_CHARS = 4000


def _html_comments(text: str) -> list[str]:
    """Bodies of ``<!-- ... -->`` comments, found in one linear pass (no regex
    backtracking: each search resumes after the previous terminator)."""
    out: list[str] = []
    i = text.find("<!--")
    while i != -1 and len(out) < 100:
        j = text.find("-->", i + 4)
        if j == -1:
            break
        out.append(text[i + 4 : min(j, i + 4 + MAX_COMMENT_CHARS)])
        i = text.find("<!--", j + 3)
    return out


def detect_html_comment_instructions(texts: list[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for where, text in texts:
        if "<!--" not in text:
            continue
        for body in _html_comments(strip_invisible(text)):
            if _COMMENT_HINT.search(body):
                findings.append(
                    Finding(
                        detector_id=DETECTOR_ID,
                        rule_id="html-comment-instruction",
                        severity=Severity.HIGH,
                        summary="hidden HTML comment contains instructions: "
                        f"{' '.join(body.split())[:80]!r}",
                        location=where,
                        mitre=("AML.T0051.001",),
                        owasp=("LLM01",),
                    )
                )
                break
    return findings


EXFIL_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "markdown-image-with-query",
        "markdown image whose URL carries a query string (zero-click exfiltration)",
        ci(r"!\[[^\]\n]{0,200}\]\(\s*<?https?://[^\s)?]{1,300}\?[^\s)]{1,3000}\)"),
        Severity.HIGH,
        ("![",),
        ("AML.T0086",),
        ("LLM05", "LLM02"),
        validate=lambda m: "=" in m.group(0).split("?", 1)[1],
    ),
    PatternRule(
        "templated-url",
        "URL with a template placeholder for the model to fill in",
        ci(r"https?://[^\s\"'<>{}]{1,600}\{[a-z_][a-z0-9_ ]{2,40}\}"),
        Severity.HIGH,
        ("http",),
        ("AML.T0086",),
        ("LLM05", "LLM02"),
    ),
    PatternRule(
        "html-image-with-query",
        "HTML img tag whose URL carries a query string",
        ci(r"<img\b[^>]{0,300}?\bsrc\s*=\s*[\"']?https?://[^\s\"'>?]{1,300}\?[^\s\"'>]{1,1500}"),
        Severity.HIGH,
        ("<img",),
        ("AML.T0086",),
        ("LLM05", "LLM02"),
    ),
)


# Reference-style markdown images: ``![x][ref]`` (or ``![ref][]``, ``![ref]``) with a
# ``[ref]: https://host/p?q=...`` definition elsewhere in the text. Renders exactly like
# an inline image, so it is the same zero-click beacon.
_REF_IMAGE = re.compile(r"!\[([^\]\n]{0,200})\](?:\[([^\]\n]{0,100})\])?")
_REF_DEFINITION = re.compile(
    r"^[ \t]{0,3}\[([^\]\n]{1,100})\]:[ \t]{0,10}<?(https?://[^\s?>]{1,300}\?[^\s>]{1,3000})",
    re.MULTILINE,
)


def _label(text: str) -> str:
    return " ".join(text.split()).casefold()


def detect_reference_images(texts: list[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for where, text in texts:
        if "![" not in text or "]:" not in text:
            continue
        definitions = {
            _label(m.group(1)): m.group(2)
            for m in _REF_DEFINITION.finditer(text)
            if "=" in m.group(2).split("?", 1)[1]
        }
        if not definitions:
            continue
        for m in _REF_IMAGE.finditer(text):
            label = _label(m.group(2) or m.group(1))
            url = definitions.get(label)
            if url is None:
                continue
            findings.append(
                Finding(
                    detector_id=EXFIL_ID,
                    rule_id="markdown-reference-image-with-query",
                    severity=Severity.HIGH,
                    summary="reference-style markdown image whose URL carries a query "
                    f"string: {url[:80]!r}",
                    location=where,
                    mitre=("AML.T0086",),
                    owasp=("LLM05", "LLM02"),
                )
            )
            break
    return findings


# Decoded copies scanned per result, in total (each up to 8 KiB; see decode.py).
MAX_DECODED = 64


def detect_injection(result: Mapping[str, Any], stats: WalkStats | None = None) -> list[Finding]:
    stats = stats if stats is not None else WalkStats()
    texts = list(iter_strings(result, "result", stats, include_keys=False))
    # Instructions and beacons hidden as base64 or hex are read through their encoding;
    # the location says which (``result.content[0].text (base64-encoded)``).
    decoded: list[tuple[str, str]] = []
    for where, text in texts:
        if len(decoded) >= MAX_DECODED:
            break
        decoded += [(f"{where}{how}", d) for d, how in decodings(text)]
    decoded = decoded[:MAX_DECODED]
    findings = scan(DETECTOR_ID, texts + decoded, RESULT_RULES)
    findings += detect_html_comment_instructions(texts + decoded)
    findings += scan(EXFIL_ID, texts + decoded, EXFIL_RULES)
    findings += detect_reference_images(texts + decoded)
    findings += detect_invisible(texts)
    return findings
