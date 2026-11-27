"""End-to-end with the official SDK on both sides, in both protocol eras.

A real gatehouse process sits between ``mcp.Client`` and the SDK weather server. The SDK
client probes ``server/discover`` (mode="auto"), so through gatehouse it must negotiate
2026-07-28 with a modern server, and still fall back to the handshake when asked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client, StdioServerParameters
from mcp_types import ElicitResult

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

SERVER = Path(__file__).resolve().parents[2] / "demo" / "weather_server.py"
MODERN = "2026-07-28"


def _params(
    tmp_path: Path, policy: str, env: dict[str, str] | None = None
) -> StdioServerParameters:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy, encoding="utf-8")
    args = [
        "-m", "gatehouse", "run", "--name", "weather", "--policy", str(policy_path),
        "--pins", str(tmp_path / "pins.json"), "--events-dir", str(tmp_path / "events"),
        "--approval-timeout", "20", "--", sys.executable, str(SERVER),
    ]  # fmt: skip
    return StdioServerParameters(command=sys.executable, args=args, env=env)


def _events(tmp_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in sorted((tmp_path / "events").glob("*.jsonl")):
        out += [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines()]
    return out


def _text(result: Any) -> str:
    return json.dumps(result.model_dump(mode="json"))


TOFU = "version: 1\ndefault_action: allow\npinning: tofu\n"


async def test_auto_mode_negotiates_2026_through_gatehouse(tmp_path: Path) -> None:
    with anyio.fail_after(60):
        async with Client(_params(tmp_path, TOFU), mode="auto", cache=None) as c:
            assert c.protocol_version == MODERN
            names = sorted(t.name for t in (await c.list_tools()).tools)
            assert names == ["get_forecast", "list_cities"]
            result = await c.call_tool("get_forecast", {"city": "Paris"})
            assert "Sunny in Paris" in _text(result)
    events = _events(tmp_path)
    negotiated = [e for e in events if e["EventType"] == "protocol.negotiated"]
    assert negotiated and negotiated[0]["Method"] == "server/discover"
    calls = [e for e in events if e["EventType"] == "tool.call"]
    assert calls and calls[0]["ProtocolVersion"] == MODERN


async def test_modern_rug_pull_is_blocked_even_without_relisting(tmp_path: Path) -> None:
    async with Client(_params(tmp_path, TOFU), mode=MODERN, cache=None) as c:
        await c.list_tools()  # pins both tools
    env = {"WEATHER_POISONED": "1"}
    with anyio.fail_after(60):
        # A stateless client may call straight from a cached listing: gatehouse lists
        # upstream itself first, so the changed definition is caught.
        async with Client(_params(tmp_path, TOFU, env), mode=MODERN, cache=None) as c:
            result = await c.call_tool("get_forecast", {"city": "x"})
            assert result.is_error
            assert "Sunny" not in _text(result)
    assert any(e.get("DetectorId") == "listing.pin_mismatch" for e in _events(tmp_path))


@pytest.mark.parametrize("approve", [True, False])
async def test_mrtr_approval_with_the_sdk_client(tmp_path: Path, approve: bool) -> None:
    policy = "version: 1\ndefault_action: require_approval\npinning: tofu\n"
    prompts: list[str] = []

    async def elicit(context: Any, params: Any) -> ElicitResult:
        prompts.append(params.message)
        return ElicitResult(action="accept", content={"approve": approve})

    with anyio.fail_after(60):
        async with Client(
            _params(tmp_path, policy), mode=MODERN, cache=None, elicitation_callback=elicit
        ) as c:
            await c.list_tools()
            result = await c.call_tool("get_forecast", {"city": "Paris"})
    assert len(prompts) == 1 and "get_forecast" in prompts[0]
    assert result.is_error is (not approve)
    assert ("Sunny in Paris" in _text(result)) is approve
    kinds = [e["EventType"] for e in _events(tmp_path) if e["EventType"].startswith("approval.")]
    assert kinds == ["approval.requested", "approval.granted" if approve else "approval.denied"]


async def test_legacy_mode_still_works_through_gatehouse(tmp_path: Path) -> None:
    with anyio.fail_after(60):
        async with Client(_params(tmp_path, TOFU), mode="legacy", cache=None) as c:
            assert c.protocol_version == "2025-11-25"
            await c.list_tools()  # legacy sessions are stateful: list before calling
            result = await c.call_tool("get_forecast", {"city": "Lyon"})
            assert "Sunny in Lyon" in _text(result)
