"""A small synchronous MCP stdio client (handshake era).

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
from typing import Any

from gatehouse.protocol import PINNED_SPEC_VERSION
from gatehouse.proxy.stdio import kill_tree, resolve_command

ServerRequestHandler = Callable[[dict[str, Any]], dict[str, Any] | None]


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
        protocol_version: str = PINNED_SPEC_VERSION,
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
        return resp["result"]

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

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": dict(arguments or {})})

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
