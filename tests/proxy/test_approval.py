"""Approval of require_approval calls through MCP elicitation."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import pytest
from helpers import RouterHarness, make_harness, tool_def

from gatehouse.proxy.approval import (
    ELICITATION_CREATE,
    ID_PREFIX,
    ApprovalRequest,
    approval_message,
    is_approval,
)

pytestmark = pytest.mark.anyio

APPROVAL_POLICY = """
version: 1
default_action: require_approval
pinning: tofu
"""
SECRET_VALUE = "value-the-user-must-not-see-in-events-7f3a"


# ---------------------------------------------------------------- pure helpers


@pytest.mark.parametrize(
    ("result", "ok"),
    [
        ({"action": "accept", "content": {"approve": True}}, True),
        ({"action": "accept", "content": {"approve": False}}, False),
        ({"action": "accept", "content": {"approve": "true"}}, False),
        ({"action": "accept"}, False),
        ({"action": "decline"}, False),
        ({"action": "cancel"}, False),
        ({}, False),
        (None, False),
        ("accept", False),
    ],
)
def test_only_an_explicit_accept_approves(result: object, ok: bool) -> None:
    assert is_approval(result) is ok


def test_message_names_arguments_but_never_values() -> None:
    msg = approval_message(ApprovalRequest("srv", "write_file", "policy: */*", ("path", "x")))
    assert "write_file" in msg and "path, x" in msg
    long = approval_message(ApprovalRequest("srv", "t", "r" * 5000, ()))
    assert len(long) <= 1000


# ---------------------------------------------------------------- router flow


@asynccontextmanager
async def approving(
    tmp_path: Path, timeout: float = 5.0, elicitation: bool = True
) -> AsyncGenerator[RouterHarness]:
    h = make_harness(tmp_path, APPROVAL_POLICY, approval_timeout=timeout)
    await h.initialize(capabilities={"elicitation": {}} if elicitation else {})
    await h.list_tools([tool_def("write_file")])
    async with anyio.create_task_group() as tg:
        h.router.task_group = tg
        yield h
        tg.cancel_scope.cancel()


async def wait_for(cond: Callable[[], bool], timeout: float = 2.0) -> None:
    with anyio.fail_after(timeout):
        while not cond():
            await anyio.sleep(0.005)


async def start_call(h: RouterHarness, rid: int = 900) -> dict[str, Any]:
    """Send a tools/call that needs approval; return the elicitation request it causes."""
    with anyio.fail_after(1):  # must not block the client loop
        await h.client(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {"x": SECRET_VALUE}},
            }
        )
    await wait_for(lambda: any(m.get("method") == ELICITATION_CREATE for m in h.to_client))
    return next(m for m in h.to_client if m.get("method") == ELICITATION_CREATE)


async def answer(h: RouterHarness, request: dict[str, Any], result: dict[str, Any]) -> None:
    await h.client({"jsonrpc": "2.0", "id": request["id"], "result": result})


def _no_secret_anywhere(h: RouterHarness) -> None:
    for record in h.sink.records:
        assert SECRET_VALUE not in str(record)
    for msg in h.to_client:
        if msg.get("method") == ELICITATION_CREATE:
            assert SECRET_VALUE not in str(msg)


async def test_approved_call_is_forwarded(tmp_path: Path) -> None:
    async with approving(tmp_path) as h:
        req = await start_call(h)
        assert req["id"].startswith(ID_PREFIX)
        assert "x" in req["params"]["message"]
        await answer(h, req, {"action": "accept", "content": {"approve": True}})
        await wait_for(lambda: h.forwarded("tools/call"))
        assert not any(str(m.get("id", "")).startswith(ID_PREFIX) for m in h.to_server)
        await h.server({"jsonrpc": "2.0", "id": 900, "result": {"content": [], "isError": False}})
        assert h.to_client[-1]["id"] == 900 and "result" in h.to_client[-1]
    assert [e["EventType"] for e in h.events() if e["EventType"].startswith("approval.")] == [
        "approval.requested",
        "approval.granted",
    ]
    assert h.events("tool.call")[-1]["Action"] == "approved"
    _no_secret_anywhere(h)


@pytest.mark.parametrize(
    "result",
    [
        {"action": "decline"},
        {"action": "cancel"},
        {"action": "accept", "content": {"approve": False}},
    ],
)
async def test_declined_call_is_blocked(tmp_path: Path, result: dict[str, Any]) -> None:
    async with approving(tmp_path) as h:
        req = await start_call(h)
        await answer(h, req, result)
        await wait_for(lambda: h.to_client[-1].get("id") == 900)
    assert h.to_client[-1]["result"]["isError"] is True
    assert not h.forwarded("tools/call")
    assert h.events("approval.denied")
    assert h.events("tool.call")[-1]["Action"] == "denied"


async def test_client_error_is_a_denial(tmp_path: Path) -> None:
    async with approving(tmp_path) as h:
        req = await start_call(h)
        await h.client(
            {"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32600, "message": "nope"}}
        )
        await wait_for(lambda: h.to_client[-1].get("id") == 900)
    assert not h.forwarded("tools/call")
    assert "ApprovalError" in h.events("approval.denied")[0]["Reason"]


async def test_timeout_is_a_denial_and_a_late_answer_is_dropped(tmp_path: Path) -> None:
    async with approving(tmp_path, timeout=0.05) as h:
        req = await start_call(h)
        await wait_for(lambda: h.to_client[-1].get("id") == 900)
        await answer(h, req, {"action": "accept", "content": {"approve": True}})
        await anyio.sleep(0.05)
    assert not h.forwarded("tools/call")
    assert not any(str(m.get("id", "")).startswith(ID_PREFIX) for m in h.to_server)
    assert "TimeoutError" in h.events("approval.denied")[0]["Reason"]
    assert not h.events("protocol.unsolicited_response")


async def test_other_traffic_flows_while_approval_is_pending(tmp_path: Path) -> None:
    async with approving(tmp_path) as h:
        req = await start_call(h)
        await h.client({"jsonrpc": "2.0", "id": 901, "method": "ping"})
        assert h.forwarded("ping")
        await answer(h, req, {"action": "decline"})


async def test_tool_change_during_approval_blocks_the_call(tmp_path: Path) -> None:
    """A rug pull timed to the approval prompt: approval covers the tool the user saw."""
    async with approving(tmp_path) as h:
        req = await start_call(h)
        await h.server({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        await answer(h, req, {"action": "accept", "content": {"approve": True}})
        await wait_for(lambda: h.to_client[-1].get("id") == 900)
    assert h.to_client[-1]["result"]["isError"] is True
    assert not h.forwarded("tools/call")
    ev = h.events("tool.call")[-1]
    assert ev["Action"] == "blocked" and "(after approval)" in ev["Reason"]


async def test_client_without_elicitation_is_blocked_without_asking(tmp_path: Path) -> None:
    async with approving(tmp_path, elicitation=False) as h:
        with anyio.fail_after(1):
            await h.client(
                {
                    "jsonrpc": "2.0",
                    "id": 900,
                    "method": "tools/call",
                    "params": {"name": "write_file", "arguments": {}},
                }
            )
    assert not any(m.get("method") == ELICITATION_CREATE for m in h.to_client)
    assert h.to_client[-1]["result"]["isError"] is True
    assert h.events("tool.call")[-1]["Action"] == "approval_required"
