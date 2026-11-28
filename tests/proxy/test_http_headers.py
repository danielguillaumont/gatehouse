"""Pure Streamable HTTP header rules (2026-07-28 header/body consistency)."""

from __future__ import annotations

from typing import Any

from gatehouse.proxy.http_headers import (
    check_request,
    decode_value,
    duplicated_routing_header,
    encode_value,
    upstream_headers,
)

MODERN = "2026-07-28"
META: dict[str, Any] = {
    "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientCapabilities": {},
}
TOOL: dict[str, Any] = {
    "name": "query",
    "inputSchema": {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "x-mcp-header": "Limit"},
            "region": {"type": "string", "x-mcp-header": "Region"},
        },
    },
}


def _call(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "query", "arguments": args, "_meta": META},
    }


def _headers(**extra: str) -> dict[str, str]:
    base = {"mcp-protocol-version": MODERN, "mcp-method": "tools/call", "mcp-name": "query"}
    return {**base, **{k.lower(): v for k, v in extra.items()}}


def test_encoding_round_trip() -> None:
    for value in ("plain", " edge ", "zürich", "line\nbreak", "=?base64?looks-like?=", ""):
        assert decode_value(encode_value(value)) == value
    assert encode_value("plain") == "plain"
    assert encode_value("zürich").startswith("=?base64?")


def test_malformed_sentinel_never_matches() -> None:
    assert decode_value("=?base64?not base64?=") is None
    assert decode_value("=?base64?YQ?=") is None  # missing padding: not canonical
    assert decode_value("=?base64?!!?=") is None


def test_incomplete_sentinel_is_a_literal() -> None:
    # Spec "Value Encoding": only a value wrapped in =?base64? ... ?= is encoded.
    # Conformance: sep-2243-server-validate-param-match (ServerLiteralMissingBase64Suffix).
    assert decode_value("=?base64?SGVsbG8=") == "=?base64?SGVsbG8="
    assert encode_value("=?base64?SGVsbG8=") == "=?base64?SGVsbG8="
    # A literal that *is* a complete sentinel must be wrapped to survive the trip.
    assert decode_value(encode_value("=?base64?SGVsbG8=?=")) == "=?base64?SGVsbG8=?="


def test_consistent_request_passes() -> None:
    hdr = _headers(**{"Mcp-Param-Limit": "10", "Mcp-Param-Region": "eu"})
    assert check_request(_call({"limit": 10, "region": "eu"}), hdr, TOOL) is None


def test_integer_header_compares_numerically() -> None:
    hdr = _headers(**{"Mcp-Param-Limit": "10.0", "Mcp-Param-Region": "eu"})
    assert check_request(_call({"limit": 10, "region": "eu"}), hdr, TOOL) is None
    hdr = _headers(**{"Mcp-Param-Limit": "10.5", "Mcp-Param-Region": "eu"})
    assert check_request(_call({"limit": 10, "region": "eu"}), hdr, TOOL) is not None


def test_header_for_an_absent_argument_is_a_mismatch() -> None:
    problem = check_request(_call({}), _headers(**{"Mcp-Param-Region": "eu"}), TOOL)
    assert problem is not None and "absent" in problem.reason


def test_name_and_method_mismatch() -> None:
    assert check_request(_call({}), _headers(**{"Mcp-Name": "other"}), None) is not None
    assert check_request(_call({}), _headers(**{"Mcp-Method": "tools/list"}), None) is not None


def test_duplicate_detection_is_case_insensitive() -> None:
    assert duplicated_routing_header([("Mcp-Method", "a"), ("mcp-method", "b")]) == "mcp-method"
    assert duplicated_routing_header([("Mcp-Method", "a"), ("Accept", "b")]) is None


def test_upstream_headers_are_derived_from_the_body() -> None:
    out = upstream_headers(
        _call({"limit": 5, "region": "zürich"}), fallback_version=None, tool=TOOL
    )
    assert out["Mcp-Method"] == "tools/call" and out["Mcp-Name"] == "query"
    assert out["Mcp-Param-Limit"] == "5"
    assert decode_value(out["Mcp-Param-Region"]) == "zürich"
    legacy: dict[str, Any] = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    assert upstream_headers(legacy, fallback_version="2025-11-25") == {
        "MCP-Protocol-Version": "2025-11-25"
    }
