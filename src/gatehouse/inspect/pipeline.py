"""Which detectors run at which interception point.

The router calls only these three functions; adding a detector means adding it here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.commands import detect_commands
from gatehouse.inspect.injection import detect_injection
from gatehouse.inspect.invisible import detect_invisible
from gatehouse.inspect.paths import detect_paths
from gatehouse.inspect.pii import detect_pii
from gatehouse.inspect.poisoning import detect_poisoning
from gatehouse.inspect.secrets import Fingerprinter, detect_secrets
from gatehouse.inspect.self_protect import detect_self_protect
from gatehouse.inspect.walk import WalkStats, iter_strings
from gatehouse.jsonutil import as_str


@dataclass(frozen=True)
class ScanConfig:
    protected_paths: tuple[str, ...] = ()
    fingerprint: Fingerprinter | None = None
    # "detector_id/rule_id" glob -> severity (policy findings.rules, D-049)
    severity_overrides: tuple[tuple[str, Severity], ...] = ()


def _override(ref: str, overrides: Sequence[tuple[str, Severity]]) -> Severity | None:
    """The most specific matching override: an exact ref, else the longest glob."""
    best: tuple[int, Severity] | None = None
    for pattern, severity in overrides:
        if pattern == ref:
            return severity
        if fnmatchcase(ref, pattern) and (best is None or len(pattern) > best[0]):
            best = (len(pattern), severity)
    return best[1] if best else None


def apply_overrides(findings: list[Finding], cfg: ScanConfig) -> list[Finding]:
    """Re-rate findings whose rule the policy overrides (pure; no-op without overrides)."""
    if not cfg.severity_overrides:
        return findings
    out: list[Finding] = []
    for f in findings:
        severity = _override(f"{f.detector_id}/{f.rule_id}", cfg.severity_overrides)
        out.append(f if severity is None else f.model_copy(update={"severity": severity}))
    return out


def scan_arguments(
    server: str, tool: str, arguments: Mapping[str, Any], cfg: ScanConfig
) -> list[Finding]:
    """Client -> server: the arguments of a tools/call."""
    stats = WalkStats()
    findings = detect_secrets(arguments, "arguments", cfg.fingerprint, stats)
    findings += detect_self_protect(arguments, cfg.protected_paths)
    values = list(iter_strings(arguments, "arguments", WalkStats(), include_keys=False))
    findings += detect_commands(values)
    findings += detect_paths(values)
    findings += detect_pii(values)
    findings += [f for f in detect_invisible(values) if f.rule_id == "unicode-tag-characters"]
    return apply_overrides(findings, cfg)


def scan_tool_definition(
    tool: Mapping[str, Any], all_tools: Sequence[Mapping[str, Any]], cfg: ScanConfig
) -> list[Finding]:
    """Server -> client: one tool definition from a tools/list result."""
    names = [n for n in (as_str(t.get("name")) for t in all_tools) if n is not None]
    return apply_overrides(detect_poisoning(tool, names), cfg)


def scan_tool_result(
    server: str, tool: str, result: Mapping[str, Any], cfg: ScanConfig
) -> list[Finding]:
    """Server -> client: the result of a tools/call."""
    return apply_overrides(detect_injection(result), cfg)
