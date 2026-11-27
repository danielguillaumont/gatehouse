"""Scripted MCP stdio server used by every scenario.

Spec (JSON, path in $ATTACK_SPEC)::

    {"name": "srv", "tools": [...tool defs...],
     "results": {"tool": "text" | {"content": [...], "structuredContent": {...}}},
     "after_first_call": {"tools": [...]},  # optional in-session rug pull
     # 2026-07-28 (all optional):
     "modern": true,                        # answer server/discover and _meta requests
     "list_hints": {"ttlMs": 1, "cacheScope": "public"},  # cache hints on tools/list
     "input_required": {"tool": {"inputRequests": {...}, "requestState": "..."}},
     "elicit": {"tool": {...elicitation/create params...}}  # legacy server request
    }

``input_required``: the first call to that tool without ``inputResponses`` gets an
InputRequiredResult (MRTR); the retry gets the normal result. ``elicit``: in the legacy
era, a call to that tool first sends the client an ``elicitation/create`` request and
answers the call once the client has replied.

Every frame received is appended to $ATTACK_LOG (JSONL) so the harness can tell what
actually reached the server. This server is deliberately raw (no SDK) so scenarios can
send anything, including duplicate tool names.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, cast

SUPPORTED = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MODERN = "2026-07-28"
META_VERSION = "io.modelcontextprotocol/protocolVersion"


def main() -> int:
    with open(os.environ["ATTACK_SPEC"], encoding="utf-8") as fh:
        spec: dict[str, Any] = json.load(fh)
    log_path = os.environ.get("ATTACK_LOG")
    log = open(log_path, "a", encoding="utf-8") if log_path else None
    tools: list[dict[str, Any]] = spec.get("tools", [])
    results: dict[str, Any] = spec.get("results", {})
    swapped = False
    out = sys.stdout.buffer
    modern_ok = bool(spec.get("modern"))
    input_required: dict[str, Any] = spec.get("input_required", {})
    elicit: dict[str, Any] = spec.get("elicit", {})
    waiting: dict[str, tuple[Any, str]] = {}  # our elicitation id -> (call id, tool)
    counter = 0

    def send(msg: dict[str, Any]) -> None:
        out.write((json.dumps(msg) + "\n").encode("utf-8"))
        out.flush()

    def send_call_result(rid: Any, name: str, modern: bool) -> None:
        value: Any = results.get(name, f"{name}: ok")
        result: dict[str, Any] = (
            cast(dict[str, Any], value)
            if isinstance(value, dict)
            else {"content": [{"type": "text", "text": value}]}
        )
        if modern:
            result = {"resultType": "complete", **result}
        send({"jsonrpc": "2.0", "id": rid, "result": {"isError": False, **result}})

    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        if log:
            log.write(raw.decode("utf-8", "replace").rstrip("\r\n") + "\n")
            log.flush()
        try:
            parsed: Any = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(parsed, dict):
            continue
        msg = cast(dict[str, Any], parsed)
        if "method" not in msg:  # a response: the client answered our elicitation
            pending = waiting.pop(str(msg.get("id")), None)
            if pending is not None:
                send_call_result(pending[0], pending[1], False)
            continue
        method: Any = msg.get("method")
        rid: Any = msg.get("id")
        params: dict[str, Any] = msg.get("params") or {}
        if rid is None:
            continue  # notification
        meta: dict[str, Any] = params.get("_meta") or {}
        modern = modern_ok and meta.get(META_VERSION) == MODERN
        if method == "server/discover" and modern:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "resultType": "complete",
                        "supportedVersions": [MODERN, *reversed(SUPPORTED)],
                        "capabilities": {"tools": {"listChanged": True}},
                        "ttlMs": 0,
                        "cacheScope": "public",
                        "_meta": {
                            "io.modelcontextprotocol/serverInfo": {
                                "name": spec.get("name", "mock"),
                                "version": "1.0",
                            }
                        },
                        **spec.get("discover", {}),
                    },
                }
            )
        elif method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED else SUPPORTED[-1]
            send(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": True}},
                        "serverInfo": {"name": spec.get("name", "mock"), "version": "1.0"},
                    },
                }
            )
        elif method == "tools/list":
            listing: dict[str, Any] = {"tools": tools}
            if modern:
                listing = {"resultType": "complete", **listing, "ttlMs": 0, "cacheScope": "public"}
                listing.update(spec.get("list_hints", {}))
            send({"jsonrpc": "2.0", "id": rid, "result": listing})
        elif method == "tools/call":
            name = str(params.get("name"))
            if modern and name in input_required and "inputResponses" not in params:
                interim = {"resultType": "input_required", **input_required[name]}
                send({"jsonrpc": "2.0", "id": rid, "result": interim})
            elif not modern and name in elicit:
                counter += 1
                eid = f"mock-elicit-{counter}"
                waiting[eid] = (rid, name)
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": eid,
                        "method": "elicitation/create",
                        "params": elicit[name],
                    }
                )
            else:
                send_call_result(rid, name, modern)
                if not swapped and "after_first_call" in spec:
                    swapped = True
                    tools = spec["after_first_call"]["tools"]
                    send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": rid, "result": {}})
        else:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
