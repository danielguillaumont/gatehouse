"""Pure detectors for MCP 2026-07-28: downgrades, x-mcp-header, server requests, and the
approval requestState signer."""

from __future__ import annotations

import time
from typing import Any

from gatehouse.inspect.protocol import detect_downgrade, x_mcp_headers
from gatehouse.inspect.server_requests import inspect_elicitation, inspect_server_request
from gatehouse.proxy.modern import STATE_PREFIX, StateSigner, call_binding, request_meta

MODERN = "2026-07-28"


# ---------------------------------------------------------------------- downgrade


def test_no_history_is_never_a_downgrade() -> None:
    assert detect_downgrade((), discover_failed=True) is None


def test_discover_error_after_modern_is_a_downgrade() -> None:
    f = detect_downgrade((MODERN,), discover_failed=True)
    assert f is not None and f.rule_id == "modern-to-legacy"


def test_dropping_a_pinned_modern_version_is_a_downgrade() -> None:
    f = detect_downgrade((MODERN,), offered_versions=["2025-11-25"])
    assert f is not None and f.rule_id == "modern-version-dropped"
    assert detect_downgrade((MODERN,), offered_versions=[MODERN, "2025-11-25"]) is None


def test_older_negotiated_legacy_revision_is_a_downgrade_only_if_client_asked_newer() -> None:
    seen = ("2025-11-25",)
    assert detect_downgrade(seen, requested="2025-11-25", negotiated="2024-11-05") is not None
    # the client itself asked for the old revision: not the server's doing
    assert detect_downgrade(seen, requested="2024-11-05", negotiated="2024-11-05") is None
    assert detect_downgrade(seen, requested="2025-11-25", negotiated="2025-11-25") is None


# ---------------------------------------------------------------------- x-mcp-header


def _tool(props: dict[str, Any]) -> dict[str, Any]:
    return {"name": "t", "inputSchema": {"type": "object", "properties": props}}


def test_valid_header_annotation_is_returned() -> None:
    params, findings = x_mcp_headers(
        _tool({"region": {"type": "string", "x-mcp-header": "Region"}})
    )
    assert [p.name for p in params] == ["Region"] and params[0].path == ("region",)
    assert not findings


def test_nested_property_chain_is_allowed() -> None:
    schema = {
        "a": {"type": "object", "properties": {"b": {"type": "integer", "x-mcp-header": "B"}}}
    }
    params, findings = x_mcp_headers(_tool(schema))
    assert params[0].path == ("a", "b") and not findings


def test_header_annotation_rules() -> None:
    bad = {
        "crlf": {"type": "string", "x-mcp-header": "A\r\nB"},
        "num": {"type": "number", "x-mcp-header": "N"},
        "empty": {"type": "string", "x-mcp-header": ""},
        "arr": {"type": "array", "items": {"type": "string", "x-mcp-header": "Item"}},
    }
    _, findings = x_mcp_headers(_tool(bad))
    assert len([f for f in findings if f.rule_id == "invalid-annotation"]) == 4


def test_duplicate_header_names_are_case_insensitive() -> None:
    props = {
        "a": {"type": "string", "x-mcp-header": "Region"},
        "b": {"type": "string", "x-mcp-header": "region"},
    }
    params, findings = x_mcp_headers(_tool(props))
    assert len(params) == 1
    assert any("duplicate" in f.summary for f in findings)


def test_sensitive_parameter_in_header_is_reported() -> None:
    _, findings = x_mcp_headers(_tool({"api_key": {"type": "string", "x-mcp-header": "Key"}}))
    assert [f.rule_id for f in findings] == ["sensitive-parameter-in-header"]


# ---------------------------------------------------------------------- elicitation


def _form(message: str, **props: Any) -> dict[str, Any]:
    return {
        "mode": "form",
        "message": message,
        "requestedSchema": {"type": "object", "properties": props},
    }


def test_benign_forms_are_clean() -> None:
    assert not inspect_elicitation(
        _form("Which branch should I deploy?", branch={"type": "string"})
    )
    # "password reset" talk without asking for one is common: only field names, titles and
    # the message are checked, and only the credential words themselves match
    assert not inspect_elicitation(
        _form("Pick a colour", colour={"type": "string", "title": "Colour"})
    )


def test_credential_forms_are_flagged() -> None:
    for prop in ("password", "api_key", "otp", "card_number", "ssh_private_key", "mfaCode"):
        findings = inspect_elicitation(_form("Continue", **{prop: {"type": "string"}}))
        rules = {f.rule_id for f in findings}
        assert "form-asks-for-credential" in rules, prop
    titled = _form(
        "Continue", value={"type": "string", "title": "Your GitHub personal access token"}
    )
    assert inspect_elicitation(titled)


def test_url_mode_checks() -> None:
    def rules(url: str) -> set[str]:
        return {
            f.rule_id
            for f in inspect_elicitation({"mode": "url", "message": "Sign in", "url": url})
        }

    assert rules("https://login.example.com/oauth") == set()
    assert "userinfo-in-url" in rules("https://login.example.com@evil.example/x")
    assert "non-https-url" in rules("http://example.com/")
    assert "punycode-host" in rules("https://xn--exmple-cua.com/")
    assert "ip-literal-host" in rules("https://10.0.0.5/login")


def test_unknown_input_request_method_is_flagged() -> None:
    assert inspect_server_request("tools/call", {})[0].rule_id == "unknown-input-request"
    assert inspect_server_request("roots/list", {}) == []


# ---------------------------------------------------------------------- requestState


def test_state_signer_round_trip_and_binding() -> None:
    signer = StateSigner(b"k" * 32)
    binding = call_binding("github", "tools/call", "send", "fp")
    token = signer.issue(binding)
    assert token.startswith(STATE_PREFIX)
    assert signer.verify(token, binding) is not None
    assert signer.verify(token, call_binding("github", "tools/call", "send", "other")) is None
    # The same call on another server's gatehouse (same install key) is not approved.
    assert signer.verify(token, call_binding("slack", "tools/call", "send", "fp")) is None
    assert StateSigner(b"x" * 32).verify(token, binding) is None  # other install key


def test_state_signer_rejects_tampering_and_expiry() -> None:
    signer = StateSigner(b"k" * 32, ttl_s=10)
    binding = "b"
    token = signer.issue(binding, now=time.time())
    body, mac = token[len(STATE_PREFIX) :].split(".")
    assert signer.verify(f"{STATE_PREFIX}{body}x.{mac}", binding) is None
    assert signer.verify(token, binding, now=time.time() + 11) is None
    assert signer.verify("not-ours", binding) is None


def test_request_meta_problems() -> None:
    assert request_meta({}).problem() is not None
    ok = request_meta(
        {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        }
    )
    assert ok.problem() is None and not ok.supports_elicitation_form()
    el = request_meta(
        {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
            }
        }
    )
    assert el.supports_elicitation_form()
    url_only = request_meta(
        {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"url": {}}},
            }
        }
    )
    assert not url_only.supports_elicitation_form()
