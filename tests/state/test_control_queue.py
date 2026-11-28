"""Remote control signals (M7, D-055): the Sentinel playbook -> queue -> kill switch loop,
against a local fake of the Azure Queue Storage REST API."""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from attacks.fake_queue import FakeQueue, serve
from gatehouse.control_queue import (
    AzureQueue,
    Listener,
    QueueError,
    QueueMessage,
    SignalError,
    parse_messages,
    parse_signal,
)
from gatehouse.events.emitter import Emitter, EventContext
from gatehouse.events.sinks import MemorySink
from gatehouse.state.control import ControlStore, ControlStoreError
from tests.helpers import make_harness, tool_def

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 28, 9, 0, tzinfo=UTC)
SIG = "test-sas-signature"


def _sig(**kw: Any) -> str:
    return json.dumps(
        {"v": 1, "action": "kill", "reason": "incident 7", "issued": NOW.isoformat(), **kw}
    )


# ---------------------------------------------------------------------- parsing


def test_valid_signals() -> None:
    assert parse_signal(_sig(), NOW).action == "kill"
    lock = parse_signal(_sig(action="lock_session", session="s-1"), NOW)
    assert lock.session == "s-1"
    encoded = base64.b64encode(_sig().encode()).decode()
    assert parse_signal(encoded, NOW).reason == "incident 7"  # Functions-style base64


@pytest.mark.parametrize(
    ("text", "why"),
    [
        (_sig(action="release"), "only tighten"),
        (_sig(action="unlock", session="s"), "only tighten"),
        (_sig(action="grant"), "only tighten"),
        (_sig(action="lock_session"), "needs a session"),
        (_sig(action="revoke_grants"), "needs a grant"),
        (_sig(issued=(NOW - timedelta(hours=2)).isoformat()), "expired"),
        (_sig(issued=(NOW + timedelta(hours=1)).isoformat()), "future"),
        (_sig(extra="x"), "invalid signal"),
        (_sig(v=2), "invalid signal"),
        (_sig(action="shutdown"), "invalid signal"),
        ("not json at all", "neither JSON"),
        ("{" + "x" * 9000, "too large"),
    ],
)
def test_invalid_signals(text: str, why: str) -> None:
    with pytest.raises(SignalError, match=why):
        parse_signal(text, NOW)


def _render(template: Path, **values: str) -> str:
    """Stand-in for the Logic App runtime: each @{...} expression becomes a sample value."""
    raw = template.read_text(encoding="utf-8")
    keys = iter(values.values())
    return re.sub(r"@\{[^}]*\}", lambda _: next(keys), raw)


def test_playbook_templates_produce_valid_signals() -> None:
    kill = _render(
        ROOT / "infra" / "playbook" / "kill-message.json",
        number="42",
        title="MCP rug pull: weather/get_forecast changed after approval",
        url="https://portal.azure.com/#asset/incident/42",
        issued="2026-11-28T09:00:00.1234567Z",  # utcNow(): seven fractional digits
    )
    signal = parse_signal(kill, NOW)
    assert signal.action == "kill" and signal.reason.startswith("Sentinel incident 42: MCP")
    lock = _render(
        ROOT / "infra" / "playbook" / "lock-message.json",
        title="Injection followed by egress",
        session="eval-chain",
        alert="alert-1",
        issued="2026-11-28T09:00:00Z",
    )
    assert parse_signal(lock, NOW).session == "eval-chain"


def test_messages_xml() -> None:
    body = (
        b'<?xml version="1.0" encoding="utf-8"?><QueueMessagesList><QueueMessage>'
        b"<MessageId>m1</MessageId><InsertionTime>Fri, 09 Oct 2009 21:04:30 GMT</InsertionTime>"
        b"<PopReceipt>p1</PopReceipt><DequeueCount>3</DequeueCount>"
        b"<MessageText>{&quot;v&quot;: 1}</MessageText></QueueMessage></QueueMessagesList>"
    )
    assert parse_messages(body) == [QueueMessage("m1", "p1", 3, '{"v": 1}')]
    with pytest.raises(QueueError, match="DTD"):
        parse_messages(b'<!DOCTYPE x [<!ENTITY a "b">]><QueueMessagesList/>')


def test_queue_url_must_be_https_unless_loopback() -> None:
    with pytest.raises(ValueError, match="https"):
        AzureQueue("http://acct.queue.core.windows.net/q?sig=x")
    with pytest.raises(ValueError, match="queue name"):
        AzureQueue("https://acct.queue.core.windows.net/?sig=x")
    assert AzureQueue("https://a.queue.core.windows.net/q?sv=1&sig=SECRET").display == (
        "https://a.queue.core.windows.net/q"  # the SAS never appears in output
    )


# ---------------------------------------------------------------------- the listener


@pytest.fixture
def fake() -> Iterator[tuple[str, FakeQueue]]:
    server = serve(0, SIG)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/gatehouse-control", server.fake  # type: ignore[attr-defined]
    finally:
        server.shutdown()


def _listener(url: str, store: ControlStore) -> tuple[Listener, MemorySink]:
    sink = MemorySink()
    emitter = Emitter(
        EventContext(agent_session_id="control-listener", server_name="control"), [sink]
    )
    return Listener(AzureQueue(f"{url}?sv=2021&sig={SIG}"), store, emitter), sink


def test_listener_applies_and_deletes(fake: tuple[str, FakeQueue], tmp_path: Path) -> None:
    url, q = fake
    store = ControlStore(tmp_path / "control.sqlite3")
    grant = store.add_grant(server="mail", tool="send_email", conditions={}, ttl_s=600.0, uses=None)
    q.put("gatehouse-control", _sig(incident="https://portal/inc/7"))
    q.put("gatehouse-control", _sig(action="lock_session", session="agent-9"))
    q.put("gatehouse-control", _sig(action="revoke_grants", grant="*"))
    q.put("gatehouse-control", _sig(action="release"))
    listener, sink = _listener(url, store)
    assert listener.poll_once(NOW) == 4
    state = store.kill_state()
    assert state is not None and "incident 7" in state.reason and "portal/inc/7" in state.reason
    assert store.locked("agent-9") is not None
    assert grant.id and store.grants() == []
    assert q.depth("gatehouse-control") == 0  # applied or rejected, every message is deleted
    signals = [e for e in sink.records if e["EventType"] == "control.signal"]
    assert [(e["Details"]["Outcome"], e["Details"]["SignalAction"]) for e in signals] == [
        ("applied", "kill"),
        ("applied", "lock_session"),
        ("applied", "revoke_grants"),
        ("rejected", None),
    ]
    assert signals[0]["Severity"] == "high" and signals[0]["Action"] == "blocked"
    assert signals[2]["Details"]["Revoked"] == 1


def test_listener_reports_an_outage_once(fake: tuple[str, FakeQueue], tmp_path: Path) -> None:
    url, _ = fake
    store = ControlStore(tmp_path / "control.sqlite3")
    sink = MemorySink()
    emitter = Emitter(EventContext(agent_session_id="l", server_name="control"), [sink])
    listener = Listener(AzureQueue(f"{url}?sig=wrong"), store, emitter)
    for _ in range(3):
        assert listener.poll_once(NOW) == 0
    errors = [e for e in sink.records if e["EventType"] == "gatehouse.internal_error"]
    assert len(errors) == 1 and "HTTP 403" in errors[0]["Reason"]


class _Broken(ControlStore):
    def engage(self, reason: str) -> Path:
        raise ControlStoreError("disk full")


def test_store_failure_retries_then_drops(fake: tuple[str, FakeQueue], tmp_path: Path) -> None:
    url, q = fake
    q.put("gatehouse-control", _sig())
    listener, sink = _listener(url, _Broken(tmp_path / "control.sqlite3"))
    listener.visibility_s = 0  # visible again at once
    for _ in range(5):
        listener.poll_once(NOW)
    outcomes = [e["Details"]["Outcome"] for e in sink.records if e["EventType"] == "control.signal"]
    assert outcomes == ["retry", "retry", "retry", "retry", "dropped"]
    assert q.depth("gatehouse-control") == 0


# ---------------------------------------------------------------------- the whole loop


@pytest.mark.anyio
async def test_playbook_to_kill_switch_loop(fake: tuple[str, FakeQueue], tmp_path: Path) -> None:
    """Playbook message -> queue -> `gatehouse listen --once` (a real process) -> every
    running gatehouse on the machine blocks the next call."""
    url, q = fake
    home = tmp_path / "home"
    home.mkdir()
    control = ControlStore(home / "control.sqlite3")
    h = make_harness(
        tmp_path, "version: 1\ndefault_action: allow\npinning: 'off'\n", control=control
    )
    await h.initialize()
    await h.list_tools([tool_def("read_inbox")])
    assert not (await h.call("read_inbox")).get("result", {}).get("isError")

    issued = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.1234567Z")
    message = _render(
        ROOT / "infra" / "playbook" / "kill-message.json",
        number="42",
        title="Injection followed by egress on another server",
        url="https://portal.azure.com/#asset/incident/42",
        issued=issued,
    )
    q.put("gatehouse-control", message)
    env = {
        **os.environ,
        "GATEHOUSE_HOME": str(home),
        "GATEHOUSE_CONTROL_QUEUE_URL": f"{url}?sv=2021&sig={SIG}",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "gatehouse", "listen", "--once", "--quiet"],
        env=env,
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == b""
    assert SIG.encode() not in proc.stderr  # the SAS is a secret

    reply = await h.call("read_inbox")
    assert reply["result"]["isError"] is True
    assert "Sentinel incident 42" in reply["result"]["content"][0]["text"]
    logged = [
        json.loads(line)
        for f in (home / "events").glob("*.jsonl")
        for line in f.read_text(encoding="utf-8").splitlines()
    ]
    (applied,) = [e for e in logged if e["EventType"] == "control.signal"]
    assert applied["Details"]["Outcome"] == "applied"
    assert applied["Details"]["Incident"] == "https://portal.azure.com/#asset/incident/42"
