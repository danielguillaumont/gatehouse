"""Streamable HTTP header rules for MCP 2026-07-28 (pure functions, no I/O).

Two jobs:

- **Ingress:** a modern request's routing headers (``MCP-Protocol-Version``,
  ``Mcp-Method``, ``Mcp-Name``, ``Mcp-Param-*``) must agree with its JSON body. A
  disagreement is how header/body smuggling works: an intermediary routes, rate-limits or
  authorises on the header while the server acts on the body. gatehouse rejects it with
  400 / -32020 (spec: transports/streamable-http, "Header and Body Consistency").
- **Egress:** gatehouse never forwards the client's routing headers. It rebuilds them
  from the body it inspected and is about to send, so upstream sees exactly one story.

Order and semantics follow the specification and the reference implementation in the
Python SDK 2.3.0 (``mcp/shared/inbound.py``), so a conforming client sees the same
answer from gatehouse as from a conforming server.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from gatehouse.inspect.protocol import HeaderParam, x_mcp_headers
from gatehouse.jsonutil import as_obj, as_str
from gatehouse.protocol import META_PROTOCOL_VERSION, PROMPTS_GET, RESOURCES_READ, TOOLS_CALL

PROTOCOL_VERSION = "mcp-protocol-version"
METHOD = "mcp-method"
NAME = "mcp-name"
SESSION_ID = "mcp-session-id"
PARAM_PREFIX = "mcp-param-"
ROUTING = frozenset({PROTOCOL_VERSION, METHOD, NAME})
# body parameter mirrored into Mcp-Name, per method
NAME_BEARING = {TOOLS_CALL: "name", PROMPTS_GET: "name", RESOURCES_READ: "uri"}

_SAFE = re.compile(r"[\x20-\x7E]{0,8192}")
_SENTINEL = re.compile(r"=\?base64\?(?P<payload>[A-Za-z0-9+/=]{0,65536})\?=")
_DECIMAL = re.compile(r"-?[0-9]{1,64}(?:\.[0-9]{1,64})?")


def encode_value(value: str) -> str:
    """Header form of a value: verbatim if printable ASCII without edge whitespace,
    otherwise the ``=?base64?…?=`` sentinel."""
    if _SAFE.fullmatch(value) and value == value.strip() and not value.startswith("=?base64?"):
        return value
    return f"=?base64?{base64.b64encode(value.encode('utf-8')).decode('ascii')}?="


def decode_value(value: str | None) -> str | None:
    """Inverse of ``encode_value``. A malformed sentinel decodes to None (never matches)."""
    if value is None:
        return None
    m = _SENTINEL.fullmatch(value)
    if m is None:
        return None if value.startswith("=?base64?") else value
    payload = m.group("payload")
    try:
        raw = base64.b64decode(payload, validate=True)
    except binascii.Error:
        return None
    if base64.b64encode(raw).decode("ascii") != payload:  # non-canonical
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def render_scalar(value: object) -> str | None:
    """How a body value is mirrored into a header; None if it can't be."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int | float):
        try:
            return str(value)
        except ValueError:  # int beyond the str-conversion digit limit
            return None
    return None


def _value_at(arguments: Mapping[str, Any], path: tuple[str, ...]) -> object:
    node: object = arguments
    for key in path:
        obj = as_obj(node)
        if obj is None or key not in obj:
            return None
        node = obj[key]
    return node


def _matches(param: HeaderParam, value: object, rendered: str, decoded: str) -> bool:
    if (
        param.type == "integer"
        and not isinstance(value, bool)
        and isinstance(value, int | float)
        and _DECIMAL.fullmatch(decoded)
    ):
        whole, _, fraction = decoded.partition(".")
        if fraction.strip("0"):
            return False
        try:
            return int(whole) == int(value)
        except (ValueError, OverflowError):
            return False
    return decoded == rendered


@dataclass(frozen=True)
class HeaderProblem:
    header: str
    reason: str


def duplicated_routing_header(pairs: Iterable[tuple[str, str]]) -> str | None:
    """A routing header sent twice: first-copy and last-copy readers would disagree."""
    seen: set[str] = set()
    for name, _ in pairs:
        key = name.lower()
        if key in ROUTING or key.startswith(PARAM_PREFIX):
            if key in seen:
                return key
            seen.add(key)
    return None


def check_request(
    body: Mapping[str, Any],
    headers: Mapping[str, str],
    tool: Mapping[str, Any] | None = None,
) -> HeaderProblem | None:
    """Ingress check for a modern request. ``headers`` keys must be lowercase.

    ``tool`` is the called tool's inspected definition (tools/call), used for
    ``Mcp-Param-*``; without it the parameter headers can't be checked here, and
    gatehouse's rebuilt upstream headers are what keep upstream consistent.
    """
    params = as_obj(body.get("params")) or {}
    meta = as_obj(params.get("_meta")) or {}
    version = meta.get(META_PROTOCOL_VERSION)
    got = headers.get(PROTOCOL_VERSION)
    if got is None or got != version:
        return HeaderProblem("MCP-Protocol-Version", "does not match the body's protocol version")
    method = body.get("method")
    if headers.get(METHOD) != method:
        return HeaderProblem("Mcp-Method", "does not match the body's method")
    key = NAME_BEARING.get(str(method))
    if key is not None:
        expected = params.get(key)
        if expected is not None and decode_value(headers.get(NAME)) != expected:
            return HeaderProblem("Mcp-Name", f"does not match the body's {key!r}")
    if method == TOOLS_CALL and tool is not None:
        arguments = as_obj(params.get("arguments")) or {}
        return _check_params(tool, arguments, headers)
    return None


def _check_params(
    tool: Mapping[str, Any], arguments: Mapping[str, Any], headers: Mapping[str, str]
) -> HeaderProblem | None:
    declared, findings = x_mcp_headers(tool)
    if any(f.rule_id == "invalid-annotation" for f in findings):
        return None  # a conforming client drops such a tool and sends no headers
    for param in declared:
        header = f"Mcp-Param-{param.name}"
        raw = headers.get(f"{PARAM_PREFIX}{param.name.lower()}")
        value = _value_at(arguments, param.path)
        rendered = render_scalar(value) if value is not None else None
        if rendered is None:
            if raw is not None:
                return HeaderProblem(header, "is present but its argument is absent")
            continue
        if raw is None:
            return HeaderProblem(header, "is missing but its argument is present")
        decoded = decode_value(raw)
        if decoded is None:
            return HeaderProblem(header, "carries a malformed base64 value")
        if not _matches(param, value, rendered, decoded):
            return HeaderProblem(header, "does not match its argument")
    return None


def upstream_headers(
    body: Mapping[str, Any],
    *,
    fallback_version: str | None,
    tool: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Routing headers for a message gatehouse sends upstream, derived from the body.

    Modern messages take the version from ``_meta``; legacy ones (after initialize)
    from ``fallback_version``, the negotiated revision.
    """
    out: dict[str, str] = {}
    params = as_obj(body.get("params")) or {}
    meta = as_obj(params.get("_meta")) or {}
    version = as_str(meta.get(META_PROTOCOL_VERSION)) or fallback_version
    if version is not None:
        out["MCP-Protocol-Version"] = version
    method = as_str(body.get("method"))
    if method is None or META_PROTOCOL_VERSION not in meta:
        return out  # legacy, or a response: only the version header
    out["Mcp-Method"] = method
    key = NAME_BEARING.get(method)
    name = as_str(params.get(key)) if key is not None else None
    if name is not None:
        out["Mcp-Name"] = encode_value(name)
    if method == TOOLS_CALL and tool is not None:
        declared, findings = x_mcp_headers(tool)
        if not any(f.rule_id == "invalid-annotation" for f in findings):
            arguments = as_obj(params.get("arguments")) or {}
            for param in declared:
                rendered = render_scalar(_value_at(arguments, param.path))
                if rendered is not None:
                    out[f"Mcp-Param-{param.name}"] = encode_value(rendered)
    return out
