"""Streamable HTTP reverse proxy: ``gatehouse serve --upstream https://…/mcp``.

One POST from the client is one *channel*: a ``Router`` that shares the upstream's
``Session`` with every other channel of the same era, so a tool list inspected on one
request governs calls on the next. The router's two callbacks are wired to HTTP:

- ``to_server`` starts an upstream exchange in the channel's task group. The upstream
  answer (JSON, or an SSE stream of notifications and the final response) is fed back
  into ``router.handle_server_line``, exactly like stdout lines on stdio.
- ``to_client`` queues frames for the downstream response. If the upstream streamed, the
  downstream streams too (SSE). Otherwise the single response goes back as JSON.

Security properties (D-039):

- 2026-07-28 requests must have headers that agree with the body (-32020), checked
  before the router sees them. Upstream headers are rebuilt from the inspected body;
  the client's routing, cookie and authorization headers are never forwarded. Upstream
  credentials come from gatehouse's own configuration.
- ``Origin`` and ``Host`` are validated (403 / 421) against loopback by default,
  against DNS rebinding.
- Bodies are size-bounded; batches are rejected by the router.
- Legacy (handshake-era) clients get a gatehouse-issued ``Mcp-Session-Id`` mapped to
  the upstream's, so upstream session ids are never exposed or guessable downstream.

Only imported when ``gatehouse serve`` runs; needs the ``gatehouse[http]`` extra.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urlsplit

import anyio
import httpx2
from anyio.abc import TaskGroup

from gatehouse.events.emitter import Emitter
from gatehouse.events.schema import Direction, EventAction, EventType, Severity
from gatehouse.jsonutil import as_obj, as_str
from gatehouse.protocol import (
    DISCOVER,
    HEADER_MISMATCH,
    INITIALIZE,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    JSONRPC_VERSION,
    META_PROTOCOL_VERSION,
    PARSE_ERROR,
    PINNED_SPEC_VERSION,
    TOOLS_CALL,
    UPSTREAM_UNAVAILABLE,
)
from gatehouse.proxy import http_headers as hh
from gatehouse.proxy.framing import DEFAULT_MAX_FRAME_BYTES, encode
from gatehouse.proxy.router import Router, RouterConfig
from gatehouse.proxy.session import Session

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
SendASGI = Callable[[Message], Awaitable[None]]

LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
# JSON-RPC error code -> HTTP status for 2026-07-28 responses (transports/streamable-http)
_STATUS = {
    PARSE_ERROR: 400,
    INVALID_REQUEST: 400,
    -32601: 404,
    -32602: 400,
    HEADER_MISMATCH: 400,
    -32021: 400,
    -32022: 400,
    INTERNAL_ERROR: 500,
    UPSTREAM_UNAVAILABLE: 502,
}
# Client headers worth passing upstream (tracing only). Everything else is dropped.
_FORWARD = ("traceparent", "tracestate")
MAX_LEGACY_SESSIONS = 1024


@dataclass
class HttpProxyConfig:
    upstream: str
    path: str = "/mcp"
    allowed_origins: frozenset[str] = frozenset()
    allowed_hosts: frozenset[str] = frozenset()
    upstream_headers: dict[str, str] = field(default_factory=dict[str, str])
    max_body_bytes: int = DEFAULT_MAX_FRAME_BYTES
    request_timeout: float = 300.0
    connect_timeout: float = 10.0


@dataclass
class _Legacy:
    session: Session
    upstream_id: str | None = None


def _host_of(value: str) -> str:
    """Host part of a Host header or an Origin URL, lowercased, brackets removed."""
    netloc = urlsplit(value).netloc if "://" in value else value
    host = netloc.rsplit("@", 1)[-1]
    if host.startswith("["):
        return host[1 : host.find("]")].lower() if "]" in host else host.lower()
    return host.split(":", 1)[0].lower()


def _sse_events(lines: list[str]) -> str | None:
    data = [line[5:].removeprefix(" ") for line in lines if line.startswith("data:")]
    return "\n".join(data) if data else None


class HttpProxy:
    """ASGI application."""

    def __init__(
        self,
        config: HttpProxyConfig,
        router_config: RouterConfig,
        emitter: Emitter,
        client: httpx2.AsyncClient | None = None,
    ) -> None:
        self.cfg = config
        self.rcfg = router_config
        self.emit = emitter
        self.client = client or httpx2.AsyncClient(
            timeout=httpx2.Timeout(config.request_timeout, connect=config.connect_timeout),
            follow_redirects=False,
        )
        self.modern = Session()  # every stateless request shares this view of the server
        self.legacy: dict[str, _Legacy] = {}

    # ------------------------------------------------------------------ ASGI entry

    async def __call__(self, scope: Scope, receive: Receive, send: SendASGI) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        pairs = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]]
        if scope["path"] != self.cfg.path:
            await _plain(send, 404, b"not found")
            return
        problem = self._check_origin(headers)
        if problem is not None:
            status, why = problem
            self._event(
                EventType.PROTOCOL_INVALID_FRAME, Severity.MEDIUM, why, Header="Origin/Host"
            )
            await _plain(send, status, why.encode())
            return
        method = scope["method"]
        if method == "POST":
            await self._post(scope, receive, send, headers, pairs)
        elif method == "DELETE":
            await self._delete(send, headers)
        else:
            # 2026-07-28 has no GET stream; for legacy clients 405 is the allowed answer
            # when the server offers no server-initiated stream.
            await _plain(send, 405, b"method not allowed", [(b"allow", b"POST, DELETE")])

    async def _lifespan(self, receive: Receive, send: SendASGI) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await self.client.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return

    def _check_origin(self, headers: Mapping[str, str]) -> tuple[int, str] | None:
        origin = headers.get("origin")
        if origin is not None and origin != "null":
            if origin not in self.cfg.allowed_origins and _host_of(origin) not in LOOPBACK:
                return 403, "origin not allowed"
        elif origin == "null":
            return 403, "opaque origin not allowed"
        host = headers.get("host")
        if host is not None:
            name = _host_of(host)
            if name not in LOOPBACK and host not in self.cfg.allowed_hosts:
                return 421, "host not allowed"
        return None

    def _event(self, etype: EventType, severity: Severity, reason: str, **details: Any) -> None:
        self.emit.emit(
            etype,
            severity=severity,
            action=EventAction.BLOCKED,
            direction=Direction.CLIENT_TO_SERVER,
            reason=reason,
            details=dict(details),
        )

    # ------------------------------------------------------------------ POST

    async def _read_body(self, receive: Receive) -> bytes | None:
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return None
            chunk: bytes = message.get("body", b"")
            size += len(chunk)
            if size > self.cfg.max_body_bytes:
                return b""
            chunks.append(chunk)
            if not message.get("more_body", False):
                return b"".join(chunks)

    async def _post(
        self,
        scope: Scope,
        receive: Receive,
        send: SendASGI,
        headers: Mapping[str, str],
        pairs: list[tuple[str, str]],
    ) -> None:
        body = await self._read_body(receive)
        if body is None:
            return
        if body == b"":
            self._event(
                EventType.PROTOCOL_OVERSIZED_FRAME, Severity.MEDIUM, "request body too large"
            )
            await _plain(send, 413, b"request body too large")
            return
        try:
            parsed: Any = json.loads(body)
        except (ValueError, RecursionError):
            await _json(send, 400, _error(None, PARSE_ERROR, "Parse error"))
            return
        obj = as_obj(parsed)
        meta = as_obj((as_obj(obj.get("params")) or {}).get("_meta")) if obj else None
        modern = meta is not None and META_PROTOCOL_VERSION in meta
        rpc_method = as_str(obj.get("method")) if obj else None
        rid = obj.get("id") if obj else None
        is_request = rpc_method is not None and obj is not None and "id" in obj

        if modern and is_request:
            assert obj is not None
            dup = hh.duplicated_routing_header(pairs)
            tool = self.tool_def(obj) if rpc_method == TOOLS_CALL else None
            problem = (
                hh.HeaderProblem(dup, "appears more than once")
                if dup
                else hh.check_request(obj, headers, tool)
            )
            if problem is not None:
                self.emit.emit(
                    EventType.PROTOCOL_HEADER_MISMATCH,
                    severity=Severity.MEDIUM,
                    action=EventAction.BLOCKED,
                    direction=Direction.CLIENT_TO_SERVER,
                    method=rpc_method,
                    reason=f"{problem.header} header {problem.reason}",
                    details={"Header": problem.header},
                )
                msg = f"{problem.header} header {problem.reason}"
                await _json(send, 400, _error(rid, HEADER_MISMATCH, msg))
                return

        # Pick the session: legacy by Mcp-Session-Id, modern shared, new on initialize.
        sid = headers.get(hh.SESSION_ID)
        legacy: _Legacy | None = None
        new_sid: str | None = None
        if rpc_method == INITIALIZE:
            if len(self.legacy) >= MAX_LEGACY_SESSIONS:
                self.legacy.pop(next(iter(self.legacy)))
            legacy = _Legacy(Session())
            new_sid = secrets.token_urlsafe(24)
        elif sid is not None and not modern:
            legacy = self.legacy.get(sid)
            if legacy is None:
                await _json(send, 404, _error(rid, INVALID_REQUEST, "unknown session"))
                return
        elif not modern and rpc_method != DISCOVER and not isinstance(parsed, list):
            await _json(send, 400, _error(rid, INVALID_REQUEST, "missing Mcp-Session-Id"))
            return
        session = legacy.session if legacy is not None else self.modern

        channel = _Channel(self, session, legacy, modern, headers)
        if not is_request:
            async with anyio.create_task_group() as tg:
                channel.bind(tg)
                await channel.router.handle_client_line(body)
            reply = channel.pending_reply()
            if reply is not None:  # the router refused it (a batch, a malformed message)
                await _json(send, 400, reply)
            else:
                await _plain(send, 202, b"")
            return
        await channel.serve(body, rid, send, receive, new_sid)
        if new_sid is not None and legacy is not None and channel.initialized:
            self.legacy[new_sid] = legacy

    def tool_def(self, obj: Mapping[str, Any]) -> dict[str, Any] | None:
        name = as_str((as_obj(obj.get("params")) or {}).get("name"))
        tools = self.modern.tools
        info = tools.get(name) if tools is not None and name is not None else None
        return info.definition if info is not None else None

    async def _delete(self, send: SendASGI, headers: Mapping[str, str]) -> None:
        sid = headers.get(hh.SESSION_ID)
        legacy = self.legacy.pop(sid, None) if sid is not None else None
        if legacy is None:
            await _plain(send, 404, b"unknown session")
            return
        if legacy.upstream_id is not None:
            try:
                await self.client.delete(
                    self.cfg.upstream,
                    headers={**self.cfg.upstream_headers, "Mcp-Session-Id": legacy.upstream_id},
                )
            except httpx2.HTTPError:
                pass
        await _plain(send, 204, b"")


class _Channel:
    """One downstream POST: a router plus its upstream exchanges."""

    def __init__(
        self,
        proxy: HttpProxy,
        session: Session,
        legacy: _Legacy | None,
        modern: bool,
        headers: Mapping[str, str],
    ) -> None:
        self.proxy = proxy
        self.legacy = legacy
        self.modern = modern
        self.trace = {k: headers[k] for k in _FORWARD if k in headers}
        self.out_send, self.out_recv = anyio.create_memory_object_stream[bytes](256)
        # Legacy approval prompts need the answer on the same connection; over HTTP it
        # would arrive on another POST, so legacy require_approval calls are blocked.
        rcfg = proxy.rcfg if modern else replace(proxy.rcfg, approver=None, approval_timeout=None)
        self.router = Router(rcfg, proxy.emit, self._to_client, self._to_server, session)
        self.streamed = False  # upstream answered with SSE
        self.initialized = False
        self.tg: TaskGroup | None = None

    def pending_reply(self) -> dict[str, Any] | None:
        """An error the router already queued for the client, if any."""
        try:
            return as_obj(json.loads(self.out_recv.receive_nowait()))
        except (anyio.WouldBlock, anyio.EndOfStream, ValueError):
            return None

    def bind(self, tg: TaskGroup) -> None:
        self.tg = tg
        self.router.task_group = tg

    async def _to_client(self, data: bytes) -> None:
        await self.out_send.send(data)

    async def _to_server(self, data: bytes) -> None:
        assert self.tg is not None
        self.tg.start_soon(self._exchange, data)

    def _headers(self, msg: Mapping[str, Any]) -> dict[str, str]:
        session = self.router.session
        tool: dict[str, Any] | None = None
        if msg.get("method") == TOOLS_CALL:
            tool = self.proxy.tool_def(msg) if session is self.proxy.modern else None
        fallback = session.negotiated_version
        if fallback is None and self.modern:
            fallback = PINNED_SPEC_VERSION
        out = {
            **self.trace,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **hh.upstream_headers(msg, fallback_version=fallback, tool=tool),
            **self.proxy.cfg.upstream_headers,
        }
        if self.legacy is not None and self.legacy.upstream_id is not None:
            out["Mcp-Session-Id"] = self.legacy.upstream_id
        return out

    async def _exchange(self, data: bytes) -> None:
        msg: dict[str, Any] = json.loads(data)
        rid = msg.get("id")
        is_request = "method" in msg and rid is not None
        try:
            async with self.proxy.client.stream(
                "POST", self.proxy.cfg.upstream, content=data, headers=self._headers(msg)
            ) as resp:
                upstream_sid = resp.headers.get("mcp-session-id")
                if upstream_sid and self.legacy is not None and msg.get("method") == INITIALIZE:
                    self.legacy.upstream_id = upstream_sid
                ctype = resp.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if not is_request:
                    return
                if ctype == "text/event-stream":
                    self.streamed = True
                    await self._read_sse(resp)
                elif ctype == "application/json":
                    raw = await self._read_capped(resp)
                    if raw is None:
                        await self._fail(rid, "upstream response too large")
                    elif raw.strip():
                        await self.router.handle_server_line(raw)
                    else:
                        await self._fail(rid, f"upstream answered {resp.status_code} with no body")
                else:
                    await self._fail(
                        rid, f"upstream answered {resp.status_code} ({ctype or 'no type'})"
                    )
        except httpx2.HTTPError as exc:
            if is_request:
                await self._fail(rid, f"upstream unavailable: {type(exc).__name__}")

    async def _read_capped(self, resp: httpx2.Response) -> bytes | None:
        limit = self.proxy.cfg.max_body_bytes
        chunks: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > limit:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    async def _read_sse(self, resp: httpx2.Response) -> None:
        limit = self.proxy.cfg.max_body_bytes
        lines: list[str] = []
        size = 0
        async for line in resp.aiter_lines():
            if line == "":
                data = _sse_events(lines)
                lines, size = [], 0
                if data:
                    await self.router.handle_server_line(data.encode("utf-8"))
                continue
            size += len(line)
            if size > limit:
                self.proxy.emit.emit(
                    EventType.PROTOCOL_OVERSIZED_FRAME,
                    severity=Severity.MEDIUM,
                    action=EventAction.BLOCKED,
                    direction=Direction.SERVER_TO_CLIENT,
                    reason="upstream SSE event too large; stream closed",
                )
                return
            lines.append(line)
        data = _sse_events(lines)
        if data:
            await self.router.handle_server_line(data.encode("utf-8"))

    async def _fail(self, rid: object, why: str) -> None:
        """Answer a forwarded request the upstream didn't, through the router (which
        attributes it and fails closed for gatehouse's own requests)."""
        await self.router.handle_server_line(
            encode(_error(rid, UPSTREAM_UNAVAILABLE, f"gatehouse: {why}"))
        )

    async def serve(
        self,
        body: bytes,
        rid: object,
        send: SendASGI,
        receive: Receive,
        new_sid: str | None,
    ) -> None:
        started = False
        extra: list[tuple[bytes, bytes]] = []
        if new_sid is not None:
            extra.append((b"mcp-session-id", new_sid.encode()))
        async with anyio.create_task_group() as tg:
            self.bind(tg)
            tg.start_soon(_watch_disconnect, receive, tg)
            await self.router.handle_client_line(body)
            with anyio.move_on_after(self.proxy.cfg.request_timeout):
                async for frame in self.out_recv:
                    msg = as_obj(json.loads(frame)) or {}
                    final = msg.get("id") == rid and ("result" in msg or "error" in msg)
                    if final and as_obj(msg.get("result")) is not None and new_sid:
                        self.initialized = True
                    if not started and final and not self.streamed:
                        await _json(send, self._status(msg), msg, extra)
                        tg.cancel_scope.cancel()
                        return
                    if not started:
                        started = True
                        await send(
                            {
                                "type": "http.response.start",
                                "status": 200,
                                "headers": [
                                    (b"content-type", b"text/event-stream"),
                                    (b"cache-control", b"no-cache"),
                                    *extra,
                                ],
                            }
                        )
                    event = b"event: message\ndata: " + frame.rstrip(b"\n") + b"\n\n"
                    await send({"type": "http.response.body", "body": event, "more_body": True})
                    if final:
                        break
            tg.cancel_scope.cancel()
        if started:
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        else:
            await _json(send, 504, _error(rid, INTERNAL_ERROR, "gatehouse: upstream timed out"))

    def _status(self, msg: Mapping[str, Any]) -> int:
        error = as_obj(msg.get("error"))
        if error is None or not self.modern:
            return 200
        code = error.get("code")
        return _STATUS.get(code, 500) if isinstance(code, int) else 500


async def _watch_disconnect(receive: Receive, tg: TaskGroup) -> None:
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            tg.cancel_scope.cancel()
            return


def _error(rid: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": rid, "error": {"code": code, "message": message}}


async def _json(
    send: SendASGI,
    status: int,
    body: Mapping[str, Any],
    extra: list[tuple[bytes, bytes]] | None = None,
) -> None:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = [(b"content-type", b"application/json"), *(extra or [])]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data})


async def _plain(
    send: SendASGI, status: int, body: bytes, extra: list[tuple[bytes, bytes]] | None = None
) -> None:
    headers = [(b"content-type", b"text/plain; charset=utf-8"), *(extra or [])]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
