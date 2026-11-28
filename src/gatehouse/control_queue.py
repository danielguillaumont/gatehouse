"""Remote control signals: Sentinel playbook -> Azure Storage queue -> kill switch (M7).

``gatehouse control listen`` polls a Storage queue and applies each control signal to
the machine's control store (ADR-0006), which every running gatehouse checks on each
call. A Sentinel automation rule runs a Logic App playbook on an incident, and the
playbook puts one JSON message on the queue (``infra/playbook.bicep``):

    {"v": 1, "action": "kill", "reason": "Sentinel incident 42", "incident": "...",
     "issued": "2026-11-28T09:00:00Z"}

Rules (D-055):

- **Remote signals only tighten.** ``kill`` engages the kill switch, ``lock_session``
  locks one agent session (as the circuit breaker does), and ``revoke_grants`` revokes
  one scoped grant or all of them. Releasing the kill switch, unlocking or granting
  stays a local, human action (``gatehouse kill --off``, ``gatehouse unlock``).
- **Stale and future signals are refused.** ``issued`` must be within ``ttl_s``
  (default 1 hour, at most 1 day) of now, and no more than 5 minutes ahead.
- **The queue is the trust boundary.** Only the playbook's managed identity can write
  to it (RBAC ``Storage Queue Data Message Sender``). gatehouse holds a SAS that can
  only read and delete (``p``). The SAS URL is a secret: it comes from an environment
  variable and is never logged.
- **Every message is accounted for.** Applied or rejected, it emits ``control.signal``
  and is deleted. A message that keeps failing to apply (the store is unavailable) is
  retried until its dequeue count passes 5, then dropped with an event. A failing poll
  emits ``gatehouse.internal_error`` once per outage, not once per poll.

Parsing and validation are pure. ``AzureQueue`` is the only I/O, with stdlib
``urllib`` so the listener needs no extra.
"""

from __future__ import annotations

import base64
import json
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from urllib.parse import quote, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from gatehouse.events.emitter import Emitter
from gatehouse.events.schema import EventAction, EventType, Severity
from gatehouse.state.control import ControlStore, ControlStoreError

MAX_MESSAGE_CHARS = 8 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_DEQUEUE = 5
FUTURE_SKEW = timedelta(minutes=5)
API_VERSION = "2021-12-02"
LOOPBACK = ("127.0.0.1", "localhost", "::1")

SignalAction = Literal["kill", "lock_session", "revoke_grants"]
_LOOSENING = frozenset({"release", "unkill", "unlock", "unlock_session", "grant", "allow"})


class SignalError(ValueError):
    """A message that is not a valid control signal. It is rejected and deleted."""


class Signal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    v: Literal[1]
    action: SignalAction
    reason: str = Field(min_length=1, max_length=2000)  # truncated to 200 when applied
    issued: datetime
    ttl_s: int = Field(default=3600, ge=60, le=86400)
    session: str | None = Field(default=None, min_length=1, max_length=128)
    grant: str | None = Field(default=None, min_length=1, max_length=64)  # an id or "*"
    incident: str | None = Field(default=None, max_length=512)


def _decode_text(text: str) -> str:
    """Logic Apps put the JSON as is; Azure Functions and some SDKs base64-encode it."""
    stripped = text.strip()
    if stripped.startswith("{"):
        return stripped
    try:
        return base64.b64decode(stripped, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise SignalError("message is neither JSON nor base64-encoded JSON") from None


def parse_signal(text: str, now: datetime) -> Signal:
    if len(text) > MAX_MESSAGE_CHARS:
        raise SignalError("message too large")
    raw = _decode_text(text)
    try:
        data = json.loads(raw)
    except ValueError:
        raise SignalError("message is not JSON") from None
    if isinstance(data, dict) and str(data.get("action", "")).lower() in _LOOSENING:  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
        raise SignalError("remote signals can only tighten controls; release them locally")
    try:
        signal = Signal.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "message"
        raise SignalError(f"invalid signal: {where}: {first['msg']}") from None
    issued = signal.issued if signal.issued.tzinfo else signal.issued.replace(tzinfo=UTC)
    if issued > now + FUTURE_SKEW:
        raise SignalError("signal issued in the future")
    if issued + timedelta(seconds=signal.ttl_s) < now:
        raise SignalError("signal expired")
    if signal.action == "lock_session" and not signal.session:
        raise SignalError("lock_session needs a session")
    if signal.action == "revoke_grants" and not signal.grant:
        raise SignalError('revoke_grants needs a grant id or "*"')
    return signal


def apply_signal(store: ControlStore, signal: Signal) -> dict[str, object]:
    """Apply one valid signal. Raises ``ControlStoreError`` if the store fails."""
    label = f"remote signal: {signal.reason}"
    if signal.incident:
        label += f" ({signal.incident[:120]})"
    if signal.action == "kill":
        store.engage(label[:200])
        return {}
    if signal.action == "lock_session":
        assert signal.session is not None
        store.lock(signal.session, label[:200])
        return {"Session": signal.session}
    assert signal.grant is not None
    n = store.revoke_grant(None if signal.grant == "*" else signal.grant)
    return {"Grant": signal.grant, "Revoked": n}


# ---------------------------------------------------------------------- the queue


@dataclass(frozen=True)
class QueueMessage:
    id: str
    pop_receipt: str
    dequeue_count: int
    text: str


class Queue(Protocol):
    def receive(self, max_messages: int, visibility_s: int) -> list[QueueMessage]: ...
    def delete(self, message: QueueMessage) -> None: ...


class QueueError(Exception):
    pass


def parse_messages(body: bytes) -> list[QueueMessage]:
    """The Get Messages response (``<QueueMessagesList>``)."""
    if len(body) > MAX_RESPONSE_BYTES:
        raise QueueError("queue response too large")
    if b"<!DOCTYPE" in body or b"<!ENTITY" in body:
        raise QueueError("queue response has a DTD")  # no entity expansion, ever
    try:
        root = ET.fromstring(body)  # noqa: S314 (bounded, DTDs refused above)
    except ET.ParseError:
        raise QueueError("queue response is not XML") from None
    out: list[QueueMessage] = []
    for m in root.findall("QueueMessage"):
        mid = m.findtext("MessageId") or ""
        pop = m.findtext("PopReceipt") or ""
        if not mid or not pop:
            continue
        try:
            count = int(m.findtext("DequeueCount") or "1")
        except ValueError:
            count = 1
        out.append(QueueMessage(mid, pop, count, m.findtext("MessageText") or ""))
    return out


class AzureQueue:
    """Azure Queue Storage REST API with a SAS URL (``https://<acct>.queue.core.windows.net
    /<queue>?sv=…&sig=…``). http:// is allowed on loopback only (a fake queue in CI)."""

    def __init__(
        self, sas_url: str, timeout: float = 30.0, token: Callable[[], str] | None = None
    ) -> None:
        parts = urlsplit(sas_url)
        host = parts.hostname or ""
        if not (parts.scheme == "https" or (parts.scheme == "http" and host in LOOPBACK)):
            raise ValueError("control queue URL must be https:// (or http:// on loopback)")
        if not parts.path.strip("/"):
            raise ValueError("control queue URL has no queue name")
        self._parts = parts
        self.timeout = timeout
        self.token = token  # Microsoft Entra bearer token instead of a SAS
        self.display = f"{parts.scheme}://{host}{parts.path}"  # without the SAS

    def _url(self, suffix: str, extra: str = "") -> str:
        query = "&".join(q for q in (self._parts.query, extra) if q)
        path = self._parts.path.rstrip("/") + suffix
        return urlunsplit((self._parts.scheme, self._parts.netloc, path, query, ""))

    def _request(self, method: str, url: str) -> bytes:
        headers = {"x-ms-version": API_VERSION}  # >= 2017-11-09, needed for Entra auth
        if self.token is not None:
            headers["Authorization"] = f"Bearer {self.token()}"
        req = urllib.request.Request(url, method=method, headers=headers)  # noqa: S310 (scheme checked)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (scheme checked)
                return resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise QueueError(f"queue answered HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise QueueError(f"queue unreachable ({type(exc).__name__})") from None

    def receive(self, max_messages: int, visibility_s: int) -> list[QueueMessage]:
        n = max(1, min(32, max_messages))
        url = self._url("/messages", f"numofmessages={n}&visibilitytimeout={visibility_s}")
        return parse_messages(self._request("GET", url))

    def delete(self, message: QueueMessage) -> None:
        url = self._url(
            f"/messages/{quote(message.id, safe='')}",
            f"popreceipt={quote(message.pop_receipt, safe='')}",
        )
        self._request("DELETE", url)


# ---------------------------------------------------------------------- the listener


@dataclass
class Listener:
    queue: Queue
    store: ControlStore
    emitter: Emitter
    visibility_s: int = 60
    _failing: bool = False

    def _emit(self, msg: QueueMessage, outcome: str, reason: str, **details: object) -> None:
        applied = outcome == "applied"
        action = str(details.pop("SignalAction", "") or "")
        self.emitter.emit(
            EventType.CONTROL_SIGNAL,
            severity=(Severity.HIGH if action == "kill" else Severity.MEDIUM)
            if applied
            else Severity.LOW,
            action=EventAction.BLOCKED if applied else EventAction.NONE,
            reason=reason,
            details={
                "Outcome": outcome,
                "SignalAction": action or None,
                "MessageId": msg.id[:64],
                "Source": "azure-queue",
                **details,
            },
        )

    def handle(self, msg: QueueMessage, now: datetime) -> None:
        try:
            signal = parse_signal(msg.text, now)
        except SignalError as exc:
            self._emit(msg, "rejected", str(exc))
            self._delete(msg)
            return
        common: dict[str, object] = {"SignalAction": signal.action, "Incident": signal.incident}
        try:
            result = apply_signal(self.store, signal)
        except ControlStoreError as exc:
            if msg.dequeue_count >= MAX_DEQUEUE:
                self._emit(
                    msg, "dropped", f"control store failed {msg.dequeue_count}x: {exc}", **common
                )
                self._delete(msg)
            else:  # left on the queue: visible again after the visibility timeout
                self._emit(msg, "retry", f"control store failed: {exc}", **common)
            return
        self._emit(msg, "applied", signal.reason, **common, **result)
        self._delete(msg)

    def _delete(self, msg: QueueMessage) -> None:
        try:
            self.queue.delete(msg)
        except QueueError as exc:  # it reappears and is applied again: every action is idempotent
            sys.stderr.write(f"gatehouse control listen: delete failed: {exc}\n")

    def poll_once(self, now: datetime | None = None) -> int:
        try:
            messages = self.queue.receive(32, self.visibility_s)
        except QueueError as exc:
            if not self._failing:
                self._failing = True
                self.emitter.emit(
                    EventType.INTERNAL_ERROR,
                    severity=Severity.HIGH,
                    reason=f"control queue poll failed: {exc}; remote kill signals can't arrive",
                    details={"Component": "control-queue"},
                )
            return 0
        if self._failing:
            self._failing = False
            sys.stderr.write("gatehouse control listen: queue reachable again\n")
        for msg in messages:
            self.handle(msg, now or datetime.now(UTC))
        return len(messages)

    def run(self, interval_s: float, stop_after: int | None = None) -> None:
        polls = 0
        while stop_after is None or polls < stop_after:
            n = self.poll_once()
            polls += 1
            if n == 0 and (stop_after is None or polls < stop_after):
                time.sleep(interval_s)
