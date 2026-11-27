"""Shared test helpers: an in-memory router harness."""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gatehouse.events.emitter import Emitter, EventContext
from gatehouse.events.fingerprint import Fingerprinter
from gatehouse.events.sinks import MemorySink
from gatehouse.inspect.pipeline import ScanConfig
from gatehouse.inspect.self_protect import protected_variants
from gatehouse.policy.loader import load_policy
from gatehouse.proxy.integrity import PolicyWatcher
from gatehouse.proxy.modern import StateSigner
from gatehouse.proxy.router import Approver, Router, RouterConfig

FINGERPRINT_KEY = b"k" * 32
MODERN = "2026-07-28"


def tool_def(name: str, description: str = "A tool.", **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
        **extra,
    }


@dataclass
class RouterHarness:
    router: Router
    sink: MemorySink
    to_client: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    to_server: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    raw_to_server: list[bytes] = field(default_factory=list[bytes])
    next_id: int = 100

    # -- frames from the client -------------------------------------------------------
    async def client(self, msg: dict[str, Any] | bytes) -> None:
        line = msg if isinstance(msg, bytes) else json.dumps(msg).encode()
        await self.router.handle_client_line(line)

    async def server(self, msg: dict[str, Any] | bytes) -> None:
        line = msg if isinstance(msg, bytes) else json.dumps(msg).encode()
        await self.router.handle_server_line(line)

    def _id(self) -> int:
        self.next_id += 1
        return self.next_id

    async def initialize(
        self, version: str = "2025-11-25", capabilities: dict[str, Any] | None = None
    ) -> None:
        rid = self._id()
        await self.client(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": capabilities or {},
                    "clientInfo": {"name": "test-client", "version": "1"},
                },
            }
        )
        await self.server(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "serverInfo": {"name": "up", "version": "2"},
                },
            }
        )
        await self.client({"jsonrpc": "2.0", "method": "notifications/initialized"})

    async def list_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rid = self._id()
        await self.client({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})
        await self.server({"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})
        reply = self.to_client[-1]
        assert reply["id"] == rid
        return reply["result"]["tools"]

    async def call(
        self, name: str, arguments: dict[str, Any] | None = None, result_text: str = "ok"
    ) -> dict[str, Any]:
        """Call a tool; if gatehouse forwards it, answer as the server would."""
        rid = self._id()
        before = len(self.to_server)
        await self.client(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        if len(self.to_server) > before:  # forwarded
            await self.server(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "content": [{"type": "text", "text": result_text}],
                        "isError": False,
                    },
                }
            )
        reply = self.to_client[-1]
        assert reply["id"] == rid
        return reply

    # -- modern era (2026-07-28) -------------------------------------------------------
    @staticmethod
    def meta(capabilities: dict[str, Any] | None = None, version: str = MODERN) -> dict[str, Any]:
        return {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": capabilities or {},
            "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
        }

    async def modern_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        capabilities: dict[str, Any] | None = None,
    ) -> int:
        rid = self._id()
        body = {**(params or {}), "_meta": self.meta(capabilities)}
        await self.client({"jsonrpc": "2.0", "id": rid, "method": method, "params": body})
        return rid

    async def modern_list_tools(self, tools: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
        rid = await self.modern_request("tools/list")
        result = {"resultType": "complete", "tools": tools, "ttlMs": 60000, "cacheScope": "public"}
        await self.server({"jsonrpc": "2.0", "id": rid, "result": {**result, **extra}})
        reply = self.to_client[-1]
        assert reply["id"] == rid
        return reply["result"]

    async def answer_internal_listing(self, tools: list[dict[str, Any]]) -> bool:
        """If gatehouse sent its own tools/list upstream, answer it."""
        for msg in reversed(self.to_server):
            rid = msg.get("id")
            if msg.get("method") == "tools/list" and str(rid).startswith("gatehouse-internal-"):
                await self.server(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "result": {
                            "resultType": "complete",
                            "tools": tools,
                            "ttlMs": 0,
                            "cacheScope": "public",
                        },
                    }
                )
                return True
        return False

    def forwarded(self, rid_or_method: str) -> bool:
        return any(m.get("method") == rid_or_method for m in self.to_server)

    def events(self, event_type: str | None = None, **match: Any) -> list[dict[str, Any]]:
        out = [r for r in self.sink.records if event_type is None or r["EventType"] == event_type]
        return [r for r in out if all(r.get(k) == v for k, v in match.items())]


def make_harness(
    tmp_path: Path,
    policy_yaml: str,
    *,
    server_name: str = "srv",
    approver: Approver | None = None,
    approval_timeout: float | None = None,
    http: bool = False,
) -> RouterHarness:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(textwrap.dedent(policy_yaml), encoding="utf-8")
    load = load_policy(policy_path)
    pins_path = tmp_path / "pins.json"
    sink = MemorySink()
    emitter = Emitter(
        EventContext(agent_session_id="agent", server_name=server_name, policy_sha256=load.sha256),
        [sink],
    )
    fp = Fingerprinter(FINGERPRINT_KEY)
    config = RouterConfig(
        server_name=server_name,
        policy=load,
        pins_path=pins_path,
        scan=ScanConfig(
            protected_paths=protected_variants([policy_path, pins_path]), fingerprint=fp
        ),
        fingerprinter=fp,
        policy_watcher=PolicyWatcher(policy_path, load.sha256),
        approver=approver,
        approval_timeout=approval_timeout,
        state_signer=StateSigner(FINGERPRINT_KEY),
        http=http,
    )
    harness: RouterHarness

    async def to_client(data: bytes) -> None:
        harness.to_client.append(json.loads(data))

    async def to_server(data: bytes) -> None:
        harness.raw_to_server.append(data)
        harness.to_server.append(json.loads(data))

    harness = RouterHarness(Router(config, emitter, to_client, to_server), sink)
    return harness


ALLOW_ALL_TOFU = """
version: 1
default_action: allow
pinning: tofu
"""

ALLOW_ALL_OFF = """
version: 1
default_action: allow
pinning: "off"
"""
