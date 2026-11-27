"""Protocol-level checks for MCP 2026-07-28: downgrades, ``x-mcp-header`` annotations and
server instructions. Pure functions; the router decides what to do with the findings.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.injection import detect_injection
from gatehouse.protocol import LEGACY_VERSIONS, MODERN_VERSIONS

DOWNGRADE_ID = "protocol.downgrade"
HEADER_ID = "listing.x_mcp_header"
INSTRUCTIONS_ID = "discover.instructions"

_DOWNGRADE_MITRE = ("AML.T0053", "T1562.010")  # Impair Defenses: Downgrade Attack

# ---------------------------------------------------------------------- downgrades


def _legacy_rank(version: str | None) -> int:
    return LEGACY_VERSIONS.index(version) if version in LEGACY_VERSIONS else -1


def detect_downgrade(
    pinned_versions: Sequence[str],
    *,
    discover_failed: bool = False,
    offered_versions: Sequence[str] | None = None,
    requested: str | None = None,
    negotiated: str | None = None,
) -> Finding | None:
    """Compare what a server answers now with the revisions it was seen speaking before.

    - ``discover_failed``: the server answered ``server/discover`` with an error, which
      makes a dual-era client fall back to the legacy ``initialize`` handshake.
    - ``offered_versions``: ``supportedVersions`` of a ``server/discover`` result.
    - ``requested`` / ``negotiated``: the ``initialize`` exchange (legacy era).
    """
    pinned_modern = [v for v in pinned_versions if v in MODERN_VERSIONS]
    if discover_failed and pinned_modern:
        return _downgrade(
            "modern-to-legacy",
            f"server answered server/discover with an error but was seen speaking "
            f"{', '.join(pinned_modern)}; a client would fall back to the legacy handshake",
        )
    if offered_versions is not None and pinned_modern:
        dropped = [v for v in pinned_modern if v not in offered_versions]
        if dropped:
            return _downgrade(
                "modern-version-dropped",
                f"server no longer offers {', '.join(dropped)}, which it was seen speaking",
            )
    if negotiated is not None and requested is not None:
        best_seen = max((_legacy_rank(v) for v in pinned_versions), default=-1)
        got, asked = _legacy_rank(negotiated), _legacy_rank(requested)
        if 0 <= got < best_seen <= asked:
            return _downgrade(
                "older-revision",
                f"server negotiated {negotiated} although the client asked for {requested} "
                f"and the server was seen speaking {LEGACY_VERSIONS[best_seen]}",
            )
    return None


def _downgrade(rule: str, summary: str) -> Finding:
    return Finding(
        detector_id=DOWNGRADE_ID,
        rule_id=rule,
        severity=Severity.HIGH,
        summary=summary,
        location="protocolVersion",
        mitre=_DOWNGRADE_MITRE,
        owasp=("LLM03",),
    )


# ---------------------------------------------------------------------- x-mcp-header

# RFC 9110 token: 1*tchar
_TCHAR = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")
_PRIMITIVE = frozenset({"string", "integer", "boolean"})
_SENSITIVE = re.compile(
    r"(?:pass(?:word|wd|phrase|code)?|secret|token|api[_-]?key|apikey|credential|"
    r"private[_-]?key|session|cookie|auth(?:orization)?|ssn|card)",
    re.IGNORECASE,
)
MAX_SCHEMA_NODES = 5000


@dataclass(frozen=True)
class HeaderParam:
    """One ``x-mcp-header`` annotation: header ``Mcp-Param-{name}`` mirrors ``path``."""

    name: str
    path: tuple[str, ...]
    type: str


def _walk(
    node: object, path: tuple[str, ...], budget: list[int]
) -> Iterator[tuple[tuple[str, ...], Mapping[str, Any]]]:
    """Yield (path, schema object) for every object node; path elements are JSON keys."""
    if budget[0] <= 0:
        return
    budget[0] -= 1
    if isinstance(node, Mapping):
        obj = cast(Mapping[str, Any], node)
        yield path, obj
        for key, value in obj.items():
            yield from _walk(value, (*path, str(key)), budget)
    elif isinstance(node, list):
        for i, value in enumerate(cast(list[Any], node)):
            yield from _walk(value, (*path, str(i)), budget)


def _property_path(path: tuple[str, ...]) -> tuple[str, ...] | None:
    """('properties','a','properties','b') -> ('a','b'); None if not a pure chain."""
    if len(path) % 2 or not path:
        return None
    out: list[str] = []
    for i in range(0, len(path), 2):
        if path[i] != "properties":
            return None
        out.append(path[i + 1])
    return tuple(out)


def x_mcp_headers(tool: Mapping[str, Any]) -> tuple[list[HeaderParam], list[Finding]]:
    """Validate a tool's ``x-mcp-header`` annotations (2026-07-28 transports/streamable-http,
    "Custom Headers from Tool Parameters").

    Returns the valid header parameters and findings. A finding with rule
    ``invalid-annotation`` makes the whole tool invalid: an HTTP client MUST exclude it
    from ``tools/list``.
    """
    name = str(tool.get("name", "?"))
    schema = tool.get("inputSchema")
    params: list[HeaderParam] = []
    findings: list[Finding] = []
    if not isinstance(schema, Mapping):
        return params, findings
    seen: dict[str, str] = {}
    budget = [MAX_SCHEMA_NODES]
    for path, node in _walk(cast(object, schema), (), budget):
        if "x-mcp-header" not in node:
            continue
        value = node["x-mcp-header"]
        where = f"tools[{name}].inputSchema/{'/'.join(path)}"
        problem: str | None = None
        prop_path = _property_path(path)
        ptype = node.get("type")
        if not isinstance(value, str) or not value:
            problem = "value must be a non-empty string"
        elif _TCHAR.fullmatch(value) is None:
            problem = "value is not an HTTP field-name token (CR/LF or separators)"
        elif value.lower() in seen:
            problem = f"duplicate header name (also on {seen[value.lower()]})"
        elif prop_path is None:
            problem = "annotation is not reachable through `properties` keys only"
        elif not isinstance(ptype, str) or ptype not in _PRIMITIVE:
            problem = "annotated parameter must be a string, integer or boolean"
        if problem is not None:
            findings.append(
                Finding(
                    detector_id=HEADER_ID,
                    rule_id="invalid-annotation",
                    severity=Severity.HIGH,
                    summary=f"invalid x-mcp-header annotation: {problem}",
                    location=where,
                    mitre=("AML.T0053",),
                    owasp=("LLM03",),
                )
            )
            continue
        assert isinstance(value, str) and prop_path is not None and isinstance(ptype, str)
        seen[value.lower()] = "/".join(prop_path)
        params.append(HeaderParam(value, prop_path, ptype))
        if _SENSITIVE.search(value) or any(_SENSITIVE.search(p) for p in prop_path):
            findings.append(
                Finding(
                    detector_id=HEADER_ID,
                    rule_id="sensitive-parameter-in-header",
                    severity=Severity.MEDIUM,
                    summary="a parameter that looks sensitive is mirrored into an HTTP "
                    "header, where every intermediary can read it",
                    location=where,
                    mitre=("AML.T0086",),
                    owasp=("LLM02",),
                )
            )
    if budget[0] <= 0:
        findings.append(
            Finding(
                detector_id=HEADER_ID,
                rule_id="schema-too-large",
                severity=Severity.HIGH,
                summary=f"inputSchema has more than {MAX_SCHEMA_NODES} nodes; "
                "x-mcp-header annotations could not be checked",
                location=f"tools[{name}].inputSchema",
                mitre=("AML.T0029",),
                owasp=("LLM10",),
            )
        )
    return params, findings


# ---------------------------------------------------------------------- instructions


def detect_instruction_injection(instructions: str) -> list[Finding]:
    """Server instructions are model-facing text, like a tool description. Scan them with
    the result rules (instruction phrases, hidden comments, beacons, invisible text)."""
    findings = detect_injection({"instructions": instructions})
    return [
        f.model_copy(update={"detector_id": INSTRUCTIONS_ID, "location": "instructions"})
        for f in findings
    ]
