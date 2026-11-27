"""A raw ASGI MCP server for HTTP scenarios and tests: answers by method, records every
request it receives (headers and body), so a run can tell exactly what reached it.

    Recorder(tools=[...], results={"tool": "text"}, sse=False)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

MODERN = "2026-07-28"


@dataclass
class Recorder:
    tools: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    results: dict[str, str] = field(default_factory=dict[str, str])
    sse: bool = False
    session_id: str = "upstream-secret-session"
    requests: list[tuple[dict[str, str], dict[str, Any]]] = field(
        default_factory=list[tuple[dict[str, str], dict[str, Any]]]
    )

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        msg: dict[str, Any] = json.loads(body) if body else {}
        self.requests.append((headers, msg))
        if "id" not in msg or "method" not in msg:
            await send({"type": "http.response.start", "status": 202, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        method: str = msg["method"]
        params: dict[str, Any] = msg.get("params") or {}
        modern = "_meta" in params
        extra: list[tuple[bytes, bytes]] = []
        result: dict[str, Any]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "recorder", "version": "1"},
            }
            extra.append((b"mcp-session-id", self.session_id.encode()))
        elif method == "tools/list":
            result = {"tools": self.tools}
        elif method == "tools/call":
            name = str(params.get("name"))
            text = self.results.get(name, f"{name}: ok")
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        elif method == "server/discover":
            result = {
                "supportedVersions": [MODERN],
                "capabilities": {"tools": {}},
                "ttlMs": 0,
                "cacheScope": "public",
            }
        else:
            result = {}
        if modern:
            result = {"resultType": "complete", **result}
            if method == "tools/list":
                result.update({"ttlMs": 0, "cacheScope": "public"})
        reply = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}).encode()
        if self.sse:
            ctype, payload = b"text/event-stream", b"event: message\ndata: " + reply + b"\n\n"
        else:
            ctype, payload = b"application/json", reply
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", ctype), *extra],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    def calls(self) -> list[tuple[dict[str, str], dict[str, Any]]]:
        return [(h, m) for h, m in self.requests if m.get("method") == "tools/call"]
