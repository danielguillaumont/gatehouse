"""A small synchronous MCP stdio client, legacy (handshake) or modern (2026-07-28) era.

Used by ``gatehouse pin`` / ``gatehouse diff``, the attack harness, the latency benchmark
and the integration tests. It speaks raw JSON-RPC so tests can also send frames a
well-behaved SDK client never would.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, cast

from gatehouse.jsonutil import as_list, as_obj
from gatehouse.protocol import (
    LATEST_LEGACY_VERSION,
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
    PINNED_SPEC_VERSION,
)
from gatehouse.proxy.stdio import kill_tree, resolve_command

ServerRequestHandler = Callable[[dict[str, Any]], dict[str, Any] | None]
# MRTR: given an InputRequiredResult, return inputResponses (None: give up).
InputHandler = Callable[[dict[str, Any]], dict[str, Any] | None]
MAX_INPUT_ROUNDS = 5


class ClientError(Exception):
    pass


class StdioClient:
    def __init__(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
        on_server_request: ServerRequestHandler | None = None,
    ) -> None:
        self.argv = resolve_command(argv)
        self.timeout = timeout
        self.on_server_request = on_server_request
        merged = dict(os.environ)
        if env:
            merged.update(env)
        self.proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=merged,
            cwd=cwd,
        )
        self._next_id = 1
        self._waiters: dict[str, queue.Queue[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self.notifications: list[dict[str, Any]] = []
        self.server_requests: list[dict[str, Any]] = []
        self.unparsed: list[bytes] = []
        self.stderr_lines: list[str] = []
        # modern era: _meta added to every request (set by use_modern / connect)
        self.meta: dict[str, Any] | None = None
        self.era: str | None = None
        self.input_rounds: list[dict[str, Any]] = []
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._err_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()
        self._err_reader.start()

    # ---------------------------------------------------------------- io threads

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                self.unparsed.append(line)
                continue
            if not isinstance(msg, dict):
                self.unparsed.append(line)
                continue
            frame: dict[str, Any] = msg  # type: ignore[assignment]
            if "method" in frame and "id" in frame:
                self.server_requests.append(frame)
                self._answer_server_request(frame)
            elif "method" in frame:
                self.notifications.append(frame)
            else:
                key = json.dumps(frame.get("id"))
                with self._lock:
                    waiter = self._waiters.get(key)
                if waiter is not None:
                    waiter.put(frame)
                else:
                    self.unparsed.append(line)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.stderr_lines.append(line.decode("utf-8", "replace"))

    def _answer_server_request(self, frame: dict[str, Any]) -> None:
        result = self.on_server_request(frame) if self.on_server_request else None
        if result is None:
            reply: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": frame["id"],
                "error": {"code": -32601, "message": "Method not found"},
            }
        else:
            reply = {"jsonrpc": "2.0", "id": frame["id"], "result": result}
        self.send(reply)

    # ---------------------------------------------------------------- api

    def send_raw(self, data: bytes) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ClientError(f"server closed stdin: {exc}") from None

    def send(self, msg: Mapping[str, Any]) -> None:
        self.send_raw((json.dumps(msg) + "\n").encode("utf-8"))

    def request(
        self, method: str, params: Mapping[str, Any] | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
            waiter: queue.Queue[dict[str, Any]] = queue.Queue()
            self._waiters[json.dumps(request_id)] = waiter
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            msg["params"] = dict(params)
        if self.meta is not None and method != "initialize":
            body: dict[str, Any] = msg.setdefault("params", {})
            body["_meta"] = {**self.meta, **cast(dict[str, Any], body.get("_meta") or {})}
        self.send(msg)
        try:
            return waiter.get(timeout=timeout or self.timeout)
        except queue.Empty:
            raise ClientError(f"timeout waiting for {method} (id {request_id})") from None
        finally:
            with self._lock:
                self._waiters.pop(json.dumps(request_id), None)

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = dict(params)
        self.send(msg)

    def initialize(
        self,
        capabilities: Mapping[str, Any] | None = None,
        protocol_version: str = LATEST_LEGACY_VERSION,
        client_name: str = "gatehouse-client",
    ) -> dict[str, Any]:
        resp = self.request(
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": dict(capabilities or {}),
                "clientInfo": {"name": client_name, "version": "0"},
            },
        )
        if "error" in resp:
            raise ClientError(f"initialize failed: {resp['error']}")
        self.notify("notifications/initialized")
        self.era = "legacy"
        return resp["result"]

    # ---------------------------------------------------------------- modern era

    def use_modern(
        self,
        capabilities: Mapping[str, Any] | None = None,
        protocol_version: str = PINNED_SPEC_VERSION,
        client_name: str = "gatehouse-client",
    ) -> None:
        """Send every later request with the 2026-07-28 per-request _meta."""
        self.meta = {
            META_PROTOCOL_VERSION: protocol_version,
            META_CLIENT_CAPABILITIES: dict(capabilities or {}),
            META_CLIENT_INFO: {"name": client_name, "version": "0"},
        }
        self.era = "modern"

    def discover(self) -> dict[str, Any]:
        return self.request("server/discover", {})

    def connect(
        self,
        mode: str = "legacy",
        capabilities: Mapping[str, Any] | None = None,
        client_name: str = "gatehouse-client",
    ) -> dict[str, Any]:
        """``legacy``: initialize. ``modern``: per-request _meta, probing server/discover.
        ``auto``: probe server/discover and fall back to initialize on any error other
        than -32022 (the dual-era client of the spec's stdio "Backward Compatibility")."""
        if mode == "legacy":
            return self.initialize(capabilities, client_name=client_name)
        self.use_modern(capabilities, client_name=client_name)
        resp = self.discover()
        if "result" in resp:
            discovered = as_obj(resp["result"]) or {}
            versions = as_list(discovered.get("supportedVersions")) or []
            if PINNED_SPEC_VERSION in versions or mode == "modern":
                return resp["result"]
        elif mode == "modern" or resp["error"].get("code") == -32022:
            raise ClientError(f"server/discover failed: {resp['error']}")
        self.meta = None
        return self.initialize(capabilities, client_name=client_name)

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(100):
            resp = self.request("tools/list", {"cursor": cursor} if cursor else {})
            if "error" in resp:
                raise ClientError(f"tools/list failed: {resp['error']}")
            result = resp["result"]
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools
        raise ClientError("tools/list pagination did not terminate")

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        on_input: InputHandler | None = None,
    ) -> dict[str, Any]:
        """Call a tool. Modern era: answer InputRequiredResults with ``on_input`` and
        retry (MRTR), echoing requestState, up to ``MAX_INPUT_ROUNDS`` times."""
        params: dict[str, Any] = {"name": name, "arguments": dict(arguments or {})}
        self.input_rounds = []
        resp: dict[str, Any] = {}
        for _ in range(MAX_INPUT_ROUNDS):
            resp = self.request("tools/call", params)
            result = as_obj(resp.get("result"))
            if result is None or result.get("resultType") != "input_required":
                return resp
            interim = result
            self.input_rounds.append(interim)
            answers = on_input(interim) if on_input is not None else None
            if answers is None:
                return resp
            params = {"name": name, "arguments": dict(arguments or {}), "inputResponses": answers}
            if "requestState" in interim:
                params["requestState"] = interim["requestState"]
        return resp

    def close(self, grace: float = 5.0) -> int:
        try:
            if self.proc.stdin is not None:
                self.proc.stdin.close()
        except OSError:
            pass
        deadline = time.monotonic() + grace
        while self.proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if self.proc.poll() is None:
            kill_tree(self.proc.pid)
        self.proc.wait(timeout=5)
        self._reader.join(timeout=2)
        self._err_reader.join(timeout=2)
        return self.proc.returncode

    def __enter__(self) -> StdioClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
