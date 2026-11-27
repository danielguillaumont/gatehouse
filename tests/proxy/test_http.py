"""The Streamable HTTP reverse proxy (``gatehouse serve``), in process.

Downstream requests go to ``HttpProxy`` through ``httpx2.ASGITransport``. Upstream is
either a recording mock (to see exactly which headers and bodies gatehouse sends) or
the official SDK server's Streamable HTTP app.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import pytest
from helpers import ALLOW_ALL_TOFU, FINGERPRINT_KEY, MODERN

from attacks.http_mock import Recorder
from gatehouse.events.emitter import Emitter, EventContext
from gatehouse.events.fingerprint import Fingerprinter
from gatehouse.events.sinks import MemorySink
from gatehouse.inspect.pipeline import ScanConfig
from gatehouse.policy.loader import load_policy
from gatehouse.proxy.http import HttpProxy, HttpProxyConfig
from gatehouse.proxy.modern import StateSigner
from gatehouse.proxy.router import RouterConfig

pytestmark = pytest.mark.anyio

UPSTREAM = "http://127.0.0.1:9000/mcp"
CAPS: dict[str, Any] = {}


def _meta(version: str = MODERN) -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": CAPS,
    }


def modern_body(rid: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": method,
        "params": {**(params or {}), "_meta": _meta()},
    }


def modern_headers(body: dict[str, Any], **extra: str) -> dict[str, str]:
    h = {
        "MCP-Protocol-Version": MODERN,
        "Mcp-Method": body["method"],
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    params: dict[str, Any] = body.get("params") or {}
    if body["method"] in ("tools/call", "prompts/get"):
        h["Mcp-Name"] = params["name"]
    if body["method"] == "resources/read":
        h["Mcp-Name"] = params["uri"]
    return {**h, **extra}


@dataclass
class Rig:
    proxy: HttpProxy
    client: httpx2.AsyncClient
    sink: MemorySink

    async def post(self, body: Any, headers: dict[str, str] | None = None) -> httpx2.Response:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        return await self.client.post("/mcp", content=data, headers=headers or {})

    async def modern(
        self, rid: int, method: str, params: dict[str, Any] | None = None, **hdr: str
    ) -> httpx2.Response:
        body = modern_body(rid, method, params)
        return await self.post(body, modern_headers(body, **hdr))

    def events(self, etype: str | None = None, **match: Any) -> list[dict[str, Any]]:
        out = [r for r in self.sink.records if etype is None or r["EventType"] == etype]
        return [r for r in out if all(r.get(k) == v for k, v in match.items())]


def _payload(resp: httpx2.Response) -> dict[str, Any]:
    """The JSON-RPC message of a JSON or single-event SSE response."""
    if resp.headers["content-type"].startswith("text/event-stream"):
        datas = [line[5:].strip() for line in resp.text.splitlines() if line.startswith("data:")]
        return json.loads(datas[-1])
    return resp.json()


@asynccontextmanager
async def rig(
    tmp_path: Path,
    upstream_app: Callable[..., Any],
    policy: str = ALLOW_ALL_TOFU,
    **cfg: Any,
) -> AsyncGenerator[Rig]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy, encoding="utf-8")
    load = load_policy(policy_path)
    sink = MemorySink()
    emitter = Emitter(
        EventContext(agent_session_id="a", server_name="srv", policy_sha256=load.sha256), [sink]
    )
    fp = Fingerprinter(FINGERPRINT_KEY)
    rcfg = RouterConfig(
        server_name="srv",
        policy=load,
        pins_path=tmp_path / "pins.json",
        scan=ScanConfig(fingerprint=fp),
        fingerprinter=fp,
        state_signer=StateSigner(FINGERPRINT_KEY),
        http=True,
    )
    upstream_client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=upstream_app))
    proxy = HttpProxy(HttpProxyConfig(upstream=UPSTREAM, **cfg), rcfg, emitter, upstream_client)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=proxy), base_url="http://127.0.0.1:8848"
    ) as client:
        yield Rig(proxy, client, sink)
    await upstream_client.aclose()


def _tool(name: str, **props: Any) -> dict[str, Any]:
    return {
        "name": name,
        "description": "A tool.",
        "inputSchema": {"type": "object", "properties": props or {"x": {"type": "string"}}},
    }


# ---------------------------------------------------------------------- modern happy path


async def test_modern_list_and_call_with_rebuilt_headers(tmp_path: Path) -> None:
    up = Recorder(tools=[_tool("a")])
    async with rig(tmp_path, up) as r:
        listed = await r.modern(1, "tools/list")
        assert listed.status_code == 200
        assert [t["name"] for t in listed.json()["result"]["tools"]] == ["a"]
        called = await r.modern(
            2,
            "tools/call",
            {"name": "a", "arguments": {"x": "1"}},
            Cookie="c=1",
            Authorization="Bearer client-token",
        )
        assert called.json()["result"]["content"][0]["text"] == "a: ok"
    headers, body = up.requests[-1]
    assert body["method"] == "tools/call"
    assert headers["mcp-method"] == "tools/call" and headers["mcp-name"] == "a"
    assert headers["mcp-protocol-version"] == MODERN
    # no token passthrough, no cookies: gatehouse rebuilds upstream headers
    assert "authorization" not in headers and "cookie" not in headers


async def test_upstream_sse_is_streamed_back_as_sse(tmp_path: Path) -> None:
    up = Recorder(tools=[_tool("a")], sse=True)
    async with rig(tmp_path, up) as r:
        resp = await r.modern(1, "tools/list")
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert _payload(resp)["result"]["tools"][0]["name"] == "a"


async def test_upstream_bearer_comes_from_gatehouse_config(tmp_path: Path) -> None:
    up = Recorder(tools=[_tool("a")])
    async with rig(tmp_path, up, upstream_headers={"Authorization": "Bearer gatehouse-own"}) as r:
        await r.modern(1, "tools/list", Authorization="Bearer client-token")
    assert up.requests[-1][0]["authorization"] == "Bearer gatehouse-own"


# ---------------------------------------------------------------------- header/body consistency


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("Mcp-Method", "tools/list"),
        ("Mcp-Name", "harmless_tool"),
        ("MCP-Protocol-Version", "2025-11-25"),
    ],
)
async def test_header_body_mismatch_is_rejected_before_upstream(
    tmp_path: Path, header: str, value: str
) -> None:
    up = Recorder(tools=[_tool("a"), _tool("harmless_tool")])
    async with rig(tmp_path, up) as r:
        await r.modern(1, "tools/list")
        before = len(up.requests)
        resp = await r.modern(2, "tools/call", {"name": "a", "arguments": {}}, **{header: value})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == -32020
        assert len(up.requests) == before
        assert r.events("protocol.header_mismatch")


async def test_missing_protocol_version_header_is_a_mismatch(tmp_path: Path) -> None:
    async with rig(tmp_path, Recorder()) as r:
        body = modern_body(1, "tools/list")
        headers = modern_headers(body)
        del headers["MCP-Protocol-Version"]
        resp = await r.post(body, headers)
    assert resp.status_code == 400 and resp.json()["error"]["code"] == -32020


async def test_duplicate_routing_header_is_rejected(tmp_path: Path) -> None:
    async with rig(tmp_path, Recorder()) as r:
        body = modern_body(1, "tools/list")
        raw = [(k, v) for k, v in modern_headers(body).items()] + [("Mcp-Method", "tools/call")]
        resp = await r.client.post("/mcp", content=json.dumps(body).encode(), headers=raw)
    assert resp.status_code == 400


def _region_tool(header: str = "Region") -> dict[str, Any]:
    return {
        "name": "query",
        "description": "Run a query in a region.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "region": {"type": "string", "x-mcp-header": header},
                "q": {"type": "string"},
            },
        },
    }


async def test_x_mcp_header_is_mirrored_and_checked(tmp_path: Path) -> None:
    up = Recorder(tools=[_region_tool()])
    async with rig(tmp_path, up) as r:
        await r.modern(1, "tools/list")
        args = {"name": "query", "arguments": {"region": "eu-west", "q": "select 1"}}
        ok = await r.modern(2, "tools/call", args, **{"Mcp-Param-Region": "eu-west"})
        assert ok.status_code == 200
        assert up.requests[-1][0]["mcp-param-region"] == "eu-west"
        # an intermediary routing on the header would send this to us-east; the body
        # says eu-west: smuggling attempt
        bad = await r.modern(3, "tools/call", args, **{"Mcp-Param-Region": "us-east"})
        assert bad.status_code == 400 and bad.json()["error"]["code"] == -32020
        missing = await r.modern(4, "tools/call", args)
        assert missing.status_code == 400


async def test_non_ascii_header_value_uses_the_base64_sentinel(tmp_path: Path) -> None:
    up = Recorder(tools=[_region_tool()])
    async with rig(tmp_path, up) as r:
        await r.modern(1, "tools/list")
        args = {"name": "query", "arguments": {"region": "zürich"}}
        sentinel = "=?base64?" + base64.b64encode("zürich".encode()).decode() + "?="
        resp = await r.modern(2, "tools/call", args, **{"Mcp-Param-Region": sentinel})
        assert resp.status_code == 200
    assert up.requests[-1][0]["mcp-param-region"] == sentinel


async def test_invalid_x_mcp_header_tool_is_filtered(tmp_path: Path) -> None:
    up = Recorder(tools=[_region_tool("Region: x\r\nX-Injected"), _tool("b")])
    async with rig(tmp_path, up) as r:
        resp = await r.modern(1, "tools/list")
    assert [t["name"] for t in resp.json()["result"]["tools"]] == ["b"]
    assert resp.json()["result"]["cacheScope"] == "private"


# ---------------------------------------------------------------------- transport security


async def test_foreign_origin_is_forbidden(tmp_path: Path) -> None:
    async with rig(tmp_path, Recorder()) as r:
        resp = await r.modern(1, "tools/list", Origin="https://evil.example")
        assert resp.status_code == 403
        ok = await r.modern(2, "tools/list", Origin="http://localhost:3000")
        assert ok.status_code == 200


async def test_allowed_origin_is_accepted(tmp_path: Path) -> None:
    async with rig(tmp_path, Recorder(), allowed_origins=frozenset({"https://app.example"})) as r:
        resp = await r.modern(1, "tools/list", Origin="https://app.example")
    assert resp.status_code == 200


async def test_dns_rebinding_host_is_rejected(tmp_path: Path) -> None:
    async with rig(tmp_path, Recorder()) as r:
        resp = await r.modern(1, "tools/list", Host="attacker.example")
    assert resp.status_code == 421


async def test_oversized_body_is_rejected(tmp_path: Path) -> None:
    async with rig(tmp_path, Recorder(), max_body_bytes=1000) as r:
        resp = await r.modern(1, "tools/call", {"name": "a", "arguments": {"x": "y" * 2000}})
    assert resp.status_code == 413


async def test_batch_is_rejected(tmp_path: Path) -> None:
    up = Recorder()
    async with rig(tmp_path, up) as r:
        resp = await r.post([modern_body(1, "tools/list")], {"Content-Type": "application/json"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600
    assert not up.requests


async def test_get_is_not_offered(tmp_path: Path) -> None:
    async with rig(tmp_path, Recorder()) as r:
        resp = await r.client.get("/mcp")
    assert resp.status_code == 405


async def test_unreachable_upstream_fails_with_an_error_response(tmp_path: Path) -> None:
    async def broken(scope: Any, receive: Any, send: Any) -> None:
        raise httpx2.ConnectError("refused")

    async with rig(tmp_path, broken) as r:
        resp = await r.modern(1, "tools/list")
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == -32000


# ---------------------------------------------------------------------- legacy sessions


def _legacy(rid: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}


async def test_legacy_session_ids_are_gatehouse_issued(tmp_path: Path) -> None:
    up = Recorder(tools=[_tool("a")])
    async with rig(tmp_path, up) as r:
        init = await r.post(
            _legacy(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
        )
        sid = init.headers["mcp-session-id"]
        assert sid != up.session_id
        await r.post(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}, {"Mcp-Session-Id": sid}
        )
        listed = await r.post(
            _legacy(2, "tools/list"), {"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"}
        )
        assert [t["name"] for t in _payload(listed)["result"]["tools"]] == ["a"]
        # upstream sees its own session id, never gatehouse's
        assert up.requests[-1][0]["mcp-session-id"] == up.session_id
        unknown = await r.post(_legacy(3, "tools/list"), {"Mcp-Session-Id": "guess"})
        assert unknown.status_code == 404
        missing = await r.post(_legacy(4, "tools/list"))
        assert missing.status_code == 400
        gone = await r.client.delete("/mcp", headers={"Mcp-Session-Id": sid})
        assert gone.status_code == 204
        after = await r.post(_legacy(5, "tools/list"), {"Mcp-Session-Id": sid})
        assert after.status_code == 404


# ---------------------------------------------------------------------- the real SDK server


def _sdk_app() -> tuple[Any, Any]:
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("weather")

    @server.tool(description="Get the weather forecast for a city.")
    def get_forecast(city: str) -> str:  # pyright: ignore[reportUnusedFunction]
        return f"Sunny in {city}, 21C."

    app = server.streamable_http_app()
    return server, app


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_sdk_client_through_gatehouse_to_sdk_server(tmp_path: Path, mode: str) -> None:
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    server, app = _sdk_app()
    async with server.session_manager.run(), rig(tmp_path, app) as r:
        transport = streamable_http_client("http://127.0.0.1:8848/mcp", http_client=r.client)
        async with Client(transport, mode=mode, cache=None) as c:
            assert c.protocol_version == (MODERN if mode == "auto" else "2025-11-25")
            tools = (await c.list_tools()).tools
            assert [t.name for t in tools] == ["get_forecast"]
            result = await c.call_tool("get_forecast", {"city": "Paris"})
            assert "Sunny in Paris" in json.dumps(result.model_dump(mode="json"))
    calls = r.events("tool.call")
    assert calls and calls[-1]["Action"] == "allowed"
