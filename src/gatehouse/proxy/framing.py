"""Strict JSON-RPC framing for MCP's stdio transport (newline-delimited JSON).

gatehouse inspects what it parses and forwards the original bytes, so the parser must
not disagree with the peers about what a frame means. To shrink the room for parser
differentials, a frame is rejected (fail closed) if it:

- is not valid UTF-8,
- contains duplicate object keys (parsers disagree on first-wins vs last-wins),
- contains NaN/Infinity (not JSON),
- is a JSON-RPC batch (an array): inspected per element nowhere else, so never forwarded,
- does not have the shape of a JSON-RPC 2.0 request, notification or response.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from gatehouse.protocol import JSONRPC_VERSION

DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024


class FrameKind(StrEnum):
    REQUEST = "request"
    NOTIFICATION = "notification"
    RESPONSE = "response"


class FrameError(Exception):
    def __init__(self, kind: str, message: str, request_id: object = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.request_id = request_id  # set when the bad frame still had a usable id


class BatchFrame(Exception):
    """The frame is a JSON array (JSON-RPC batch)."""

    def __init__(self, size: int) -> None:
        super().__init__(f"batch of {size}")
        self.size = size


@dataclass(frozen=True, slots=True)
class Frame:
    kind: FrameKind
    obj: dict[str, Any]
    raw: bytes  # the original line, without the trailing newline
    method: str | None
    id: str | int | None

    @property
    def id_key(self) -> str | None:
        """Hashable key that keeps 1 and "1" distinct."""
        return None if self.id is None else json.dumps(self.id)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise FrameError("duplicate_key", f"duplicate key {key!r}")
        out[key] = value
    return out


def _no_constants(name: str) -> Any:
    raise FrameError("invalid_json", f"non-standard JSON constant {name}")


def _valid_id(value: object) -> bool:
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def parse_frame(line: bytes) -> Frame:
    raw = line.rstrip(b"\r\n")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise FrameError("invalid_utf8", "frame is not valid UTF-8") from None
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except FrameError:
        raise
    except (ValueError, RecursionError) as exc:
        raise FrameError("invalid_json", f"invalid JSON: {exc}") from None
    if isinstance(obj, list):
        raise BatchFrame(len(obj))  # type: ignore[arg-type]
    if not isinstance(obj, dict):
        raise FrameError("invalid_shape", "frame is not a JSON object")
    msg: dict[str, Any] = obj  # type: ignore[assignment]
    raw_id = msg.get("id")
    usable_id = raw_id if _valid_id(raw_id) else None
    if msg.get("jsonrpc") != JSONRPC_VERSION:
        raise FrameError("invalid_shape", "missing or wrong 'jsonrpc' version", usable_id)

    method = msg.get("method")
    if "method" in msg:
        if not isinstance(method, str) or not method:
            raise FrameError("invalid_shape", "'method' must be a non-empty string", usable_id)
        if "result" in msg or "error" in msg:
            raise FrameError("invalid_shape", "request carries result/error", usable_id)
        params = msg.get("params")
        if params is not None and not isinstance(params, dict | list):
            raise FrameError("invalid_shape", "'params' must be an object", usable_id)
        if "id" not in msg:
            return Frame(FrameKind.NOTIFICATION, msg, raw, method, None)
        if usable_id is None:
            raise FrameError("invalid_shape", "request 'id' must be a string or integer")
        return Frame(FrameKind.REQUEST, msg, raw, method, usable_id)

    has_result, has_error = "result" in msg, "error" in msg
    if has_result == has_error:
        raise FrameError("invalid_shape", "response needs exactly one of result/error", usable_id)
    if usable_id is None and not (has_error and raw_id is None):
        raise FrameError("invalid_shape", "response 'id' must be a string or integer")
    if has_result and not isinstance(msg["result"], dict):
        raise FrameError("invalid_shape", "'result' must be an object", usable_id)
    return Frame(FrameKind.RESPONSE, msg, raw, None, usable_id)


def encode(obj: dict[str, Any]) -> bytes:
    """Serialize one frame. json.dumps escapes newlines, so the output is one line."""
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


class Oversized:
    """Returned by LineReader instead of a line that exceeded the size limit."""

    def __init__(self, size: int) -> None:
        self.size = size


Receive = Callable[[], Awaitable[bytes]]  # returns b"" at EOF


class LineReader:
    """Newline framing over a byte stream with a hard per-line limit.

    A line longer than ``max_bytes`` is never buffered whole: its bytes are discarded as
    they arrive and an ``Oversized`` marker is returned once its newline is seen.
    """

    def __init__(self, receive: Receive, max_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> None:
        self._receive = receive
        self._max = max_bytes
        self._buf = bytearray()
        self._eof = False

    async def next(self) -> bytes | Oversized | None:
        discarding = 0
        while True:
            newline = self._buf.find(b"\n")
            if newline != -1:
                if discarding:
                    size = discarding + newline
                    del self._buf[: newline + 1]
                    return Oversized(size)
                if newline > self._max:
                    del self._buf[: newline + 1]
                    return Oversized(newline)
                line = bytes(self._buf[:newline])
                del self._buf[: newline + 1]
                if not line.strip():
                    continue  # tolerate blank lines
                return line
            if len(self._buf) > self._max:
                discarding += len(self._buf)
                self._buf.clear()
            if self._eof:
                if discarding:
                    return Oversized(discarding + len(self._buf))
                if self._buf.strip():
                    line = bytes(self._buf)
                    self._buf.clear()
                    return line
                return None
            chunk = await self._receive()
            if not chunk:
                self._eof = True
            else:
                self._buf += chunk
