"""Which detectors run at which interception point.

The router calls only these three functions; adding a detector means adding it here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from gatehouse.inspect.base import Finding
from gatehouse.inspect.secrets import Fingerprinter, detect_secrets
from gatehouse.inspect.self_protect import detect_self_protect
from gatehouse.inspect.walk import WalkStats


@dataclass(frozen=True)
class ScanConfig:
    protected_paths: tuple[str, ...] = ()
    fingerprint: Fingerprinter | None = None


def scan_arguments(
    server: str, tool: str, arguments: Mapping[str, Any], cfg: ScanConfig
) -> list[Finding]:
    """Client -> server: the arguments of a tools/call."""
    stats = WalkStats()
    findings = detect_secrets(arguments, "arguments", cfg.fingerprint, stats)
    findings += detect_self_protect(arguments, cfg.protected_paths)
    return findings


def scan_tool_definition(
    tool: Mapping[str, Any], all_tools: Sequence[Mapping[str, Any]], cfg: ScanConfig
) -> list[Finding]:
    """Server -> client: one tool definition from a tools/list result."""
    return []


def scan_tool_result(
    server: str, tool: str, result: Mapping[str, Any], cfg: ScanConfig
) -> list[Finding]:
    """Server -> client: the result of a tools/call."""
    return []
