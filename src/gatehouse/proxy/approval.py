"""Human approval of tool calls through MCP elicitation.

When the policy (or a finding) says ``require_approval`` and the client declared the
``elicitation`` capability, gatehouse asks the *user* through the client:
gatehouse sends ``elicitation/create`` to the client as if it were the server, and the
client shows a form. The model never sees or answers this request.

Fail-closed: anything but an explicit ``accept`` with ``approve: true`` is a denial. That
includes ``decline``, ``cancel``, a JSON-RPC error, a malformed result and a timeout.

Non-blocking: the answer arrives on the client reader loop, so the call waiting for it
must not run on that loop. The router runs it in the stdio task group (see
``Router.task_group``) while the loop keeps reading.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import anyio

from gatehouse.jsonutil import as_obj, as_str
from gatehouse.protocol import JSONRPC_VERSION
from gatehouse.proxy.framing import Frame, encode

ELICITATION_CREATE = "elicitation/create"
ID_PREFIX = "gatehouse-approval-"
MAX_MESSAGE_CHARS = 1000
DEFAULT_TIMEOUT_S = 120.0

Send = Callable[[bytes], Awaitable[None]]


@dataclass(frozen=True)
class ApprovalRequest:
    server: str
    tool: str
    reason: str
    arg_keys: tuple[str, ...]


class ApprovalError(Exception):
    """The client answered with an error, or not at all."""


def approval_message(req: ApprovalRequest) -> str:
    """What the user reads. Argument *names* only, never values (they may be secrets)."""
    keys = ", ".join(req.arg_keys) if req.arg_keys else "none"
    msg = (
        f"gatehouse: the agent wants to call tool '{req.tool}' on server '{req.server}'.\n"
        f"Why approval is needed: {req.reason}\n"
        f"Argument names: {keys}\n"
        "Approve this call?"
    )
    if len(msg) > MAX_MESSAGE_CHARS:
        msg = msg[: MAX_MESSAGE_CHARS - 3] + "..."
    return msg


def elicitation_params(req: ApprovalRequest) -> dict[str, Any]:
    return {
        "message": approval_message(req),
        "requestedSchema": {
            "type": "object",
            "properties": {
                "approve": {
                    "type": "boolean",
                    "title": "Approve this tool call",
                    "description": "Leave unchecked or decline to block the call.",
                    "default": False,
                }
            },
            "required": ["approve"],
        },
    }


def is_approval(result: object) -> bool:
    """Only ``{"action": "accept", "content": {"approve": true}}`` approves."""
    obj = as_obj(result)
    if obj is None or as_str(obj.get("action")) != "accept":
        return False
    content = as_obj(obj.get("content")) or {}
    return content.get("approve") is True


@dataclass
class _Slot:
    done: anyio.Event = field(default_factory=anyio.Event)
    result: object = None
    error: str | None = None


class Elicitor:
    """Sends approval requests to the client and matches the client's answers."""

    def __init__(self, send_to_client: Send, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self._send = send_to_client
        self.timeout = timeout
        self._pending: dict[str, _Slot] = {}

    @property
    def pending(self) -> int:
        return len(self._pending)

    async def __call__(self, req: ApprovalRequest) -> bool:
        # A random id: the server can't predict it, so it can't answer for the user, and
        # it can't collide with ids the server uses for its own requests.
        rid = ID_PREFIX + uuid.uuid4().hex
        slot = _Slot()
        self._pending[rid] = slot
        try:
            await self._send(
                encode(
                    {
                        "jsonrpc": JSONRPC_VERSION,
                        "id": rid,
                        "method": ELICITATION_CREATE,
                        "params": elicitation_params(req),
                    }
                )
            )
            with anyio.fail_after(self.timeout):
                await slot.done.wait()
        finally:
            self._pending.pop(rid, None)
        if slot.error is not None:
            raise ApprovalError(slot.error)
        return is_approval(slot.result)

    def resolve(self, frame: Frame) -> bool:
        """If ``frame`` answers one of our requests, record it and return True."""
        if not isinstance(frame.id, str) or not frame.id.startswith(ID_PREFIX):
            return False
        slot = self._pending.get(frame.id)
        if slot is None:
            return True  # late answer to a request that timed out: ours, so drop it
        error = as_obj(frame.obj.get("error"))
        if error is not None:
            slot.error = f"client error {error.get('code')}: {as_str(error.get('message'))}"
        else:
            slot.result = frame.obj.get("result")
        slot.done.set()
        return True
