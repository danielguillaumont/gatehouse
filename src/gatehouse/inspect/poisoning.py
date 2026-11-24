"""Tool poisoning and shadowing: instructions hidden in tool *definitions*.

Runs on every tool in every ``tools/list`` result, pinned or not, because pinning only
catches *changes*, and a tool can be poisoned on day one. Scans the description, title,
annotations and every string in ``inputSchema`` / ``outputSchema`` (property
descriptions, enums, defaults), plus property *names*.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.invisible import detect_confusable_name, detect_invisible, strip_invisible
from gatehouse.inspect.phrases import INSTRUCTION_RULES
from gatehouse.inspect.rules import PatternRule, ci, scan
from gatehouse.inspect.walk import WalkStats, iter_strings
from gatehouse.jsonutil import as_str

DETECTOR_ID = "listing.poisoning"
SHADOW_ID = "listing.cross_tool_ref"
_MITRE = ("AML.T0110", "AML.T0051.001")
_OWASP = ("LLM01", "LLM03")

DEFINITION_RULES: tuple[PatternRule, ...] = (
    *INSTRUCTION_RULES,
    PatternRule(
        "sensitive-file-reference",
        "tool metadata references credential files",
        ci(
            r"~/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials\b|"
            r"\bmcp\.json\b|\.kube/config\b|\.git-credentials\b|/etc/(?:passwd|shadow)\b|"
            r"\.docker/config\.json\b|\bkeychain\b|\bwallet\.dat\b"
        ),
        Severity.HIGH,
        (".ssh", "id_", "credentials", "mcp.json", "kube", "/etc/", "docker", "keychain", "wallet"),
        _MITRE,
        ("LLM01", "LLM02"),
    ),
    PatternRule(
        "exfiltration-instruction",
        "tool metadata tells the model to send data to a URL",
        ci(
            r"\b(?:send|post|upload|forward|transmit|exfiltrate|submit|report)\b"
            r"[^\n]{0,160}?\bhttps?://"
        ),
        Severity.HIGH,
        ("http",),
        ("AML.T0110", "AML.T0086"),
        ("LLM01", "LLM02"),
    ),
)

_SHADOW = ci(
    r"\b(?:when|whenever|before|after|if)\s+(?:the\s+|you\s+(?:use|call)\s+(?:the\s+)?)?"
    r"[`'\"]?([a-z][a-z0-9_\-]{2,63})[`'\"]?\s+tool\s+(?:is\s+)?"
    r"(?:used|called|invoked|runs|executes)?"
)
_HIDDEN_RECIPIENT = ci(r"\b(?:always\s+)?(?:add|include|cc|bcc)\b[^\n]{0,60}?@[a-z0-9.\-]+\.[a-z]")


def _strings(tool: Mapping[str, Any], where: str, stats: WalkStats) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key in ("description", "title"):
        value = as_str(tool.get(key))
        if value:
            out.append((f"{where}.{key}", value))
    for key in ("inputSchema", "outputSchema", "annotations"):
        if key in tool:
            out += list(iter_strings(tool[key], f"{where}.{key}", stats))
    return out


def detect_shadowing(
    tool_name: str, texts: list[tuple[str, str]], other_tools: Sequence[str]
) -> list[Finding]:
    """A description that changes how a *different* tool must be used."""
    others = {t.lower() for t in other_tools if t != tool_name}
    for where, text in texts:
        clean = strip_invisible(text)
        for m in _SHADOW.finditer(clean):
            ref = m.group(1).lower()
            if ref == tool_name.lower():
                continue
            if ref in others or "_" in ref or "-" in ref:
                listed = " (listed by this server)" if ref in others else ""
                return [
                    Finding(
                        detector_id=SHADOW_ID,
                        rule_id="instructions-for-another-tool",
                        severity=Severity.HIGH,
                        summary=f"description gives instructions for tool {ref!r}{listed}",
                        location=where,
                        mitre=("AML.T0110",),
                        owasp=("LLM01", "LLM06"),
                    )
                ]
        if _HIDDEN_RECIPIENT.search(clean) and re.search(r"\b(?:must|always)\b", clean, re.I):
            return [
                Finding(
                    detector_id=SHADOW_ID,
                    rule_id="hidden-recipient",
                    severity=Severity.HIGH,
                    summary="description tells the model to add a recipient",
                    location=where,
                    mitre=("AML.T0110", "AML.T0086"),
                    owasp=("LLM01", "LLM02"),
                )
            ]
    return []


def detect_poisoning(
    tool: Mapping[str, Any], all_tool_names: Sequence[str], stats: WalkStats | None = None
) -> list[Finding]:
    stats = stats if stats is not None else WalkStats()
    name = as_str(tool.get("name")) or ""
    where = f"tools[{name}]"
    texts = _strings(tool, where, stats)
    findings = scan(DETECTOR_ID, texts, DEFINITION_RULES)
    findings += detect_shadowing(name, texts, all_tool_names)
    findings += detect_invisible([(f"{where}.name", name), *texts])
    findings += detect_confusable_name(name, f"{where}.name")
    return findings
