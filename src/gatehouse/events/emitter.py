"""Build, redact and fan out security events.

The emitter is the only way events reach sinks, which is what makes "redact before
logging" enforceable: there is no code path that hands a raw value to a sink.
"""

from __future__ import annotations

import os
import platform
import socket
import sys
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from gatehouse import __version__
from gatehouse.events.redact import redact_str, redact_value
from gatehouse.events.schema import (
    Direction,
    EventAction,
    EventType,
    SecurityEvent,
    Severity,
)
from gatehouse.events.sinks import Sink
from gatehouse.inspect.base import Finding

# Fields whose values are produced by gatehouse itself from trusted, fixed vocabularies or
# hashes. Everything else that is a string is redacted.
_TRUSTED_STR_FIELDS = frozenset(
    {
        "event_id",
        "agent_session_id",
        "proxy_session_id",
        "args_hmac",
        "policy_sha256",
        "decision_basis",
        "detector_id",
        "rule_id",
        "tool_risk",
        "protocol_version",
    }
)


@dataclass
class EventContext:
    """Per-process values stamped on every event; some are filled in as the session runs."""

    agent_session_id: str
    server_name: str
    proxy_session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    policy_sha256: str | None = None
    protocol_version: str | None = None
    client_name: str | None = None
    client_version: str | None = None
    upstream_name: str | None = None
    upstream_version: str | None = None
    host: str = field(default_factory=socket.gethostname)
    os_platform: str = field(default_factory=lambda: f"{sys.platform}/{platform.release()}")
    process_id: int = field(default_factory=os.getpid)


class Emitter:
    def __init__(self, context: EventContext, sinks: Iterable[Sink]) -> None:
        self.context = context
        self.sinks = list(sinks)
        self.sink_errors = 0

    def emit(
        self,
        event_type: EventType,
        *,
        severity: Severity = Severity.INFORMATIONAL,
        action: EventAction = EventAction.NONE,
        direction: Direction = Direction.INTERNAL,
        **fields: Any,
    ) -> SecurityEvent:
        ctx = self.context
        values: dict[str, Any] = {
            "agent_session_id": ctx.agent_session_id,
            "proxy_session_id": ctx.proxy_session_id,
            "server_name": ctx.server_name,
            "policy_sha256": ctx.policy_sha256,
            "protocol_version": ctx.protocol_version,
            "client_name": ctx.client_name,
            "client_version": ctx.client_version,
            "upstream_name": ctx.upstream_name,
            "upstream_version": ctx.upstream_version,
            "host": ctx.host,
            "os_platform": ctx.os_platform,
            "process_id": ctx.process_id,
            "gatehouse_version": __version__,
        }
        values.update(fields)
        event = SecurityEvent(
            time_generated=datetime.now(UTC),
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            action=action,
            direction=direction,
            **_redact_fields(values),
        )
        record = event.to_record()
        for sink in self.sinks:
            try:
                sink.write(record)
            except Exception as exc:  # a broken sink must not take down the proxy
                self.sink_errors += 1
                if self.sink_errors <= 3:
                    sys.stderr.write(f"gatehouse: event sink error: {type(exc).__name__}: {exc}\n")
        return event

    def emit_finding(
        self,
        finding: Finding,
        *,
        action: EventAction,
        direction: Direction,
        **fields: Any,
    ) -> SecurityEvent:
        details = dict(fields.pop("details", {}) or {})
        if finding.fingerprint:
            details["MatchFingerprint"] = finding.fingerprint
        return self.emit(
            EventType.DETECTION,
            severity=finding.severity,
            action=action,
            direction=direction,
            detector_id=finding.detector_id,
            rule_id=finding.rule_id,
            match_summary=finding.summary,
            location=finding.location,
            mitre=list(finding.mitre),
            owasp=list(finding.owasp),
            details=details,
            **fields,
        )

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception:  # noqa: S110 - best effort on shutdown
                pass


def _redact_fields(values: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in values.items():
        if key in _TRUSTED_STR_FIELDS or value is None:
            out[key] = value
        elif key == "details":
            out[key] = redact_value(value)
        elif isinstance(value, str):
            out[key] = redact_str(value)
        elif isinstance(value, list) and key in {"arg_keys", "mitre", "owasp"}:
            out[key] = [redact_str(str(v), 128) for v in value[:64]]  # type: ignore[union-attr]
        else:
            out[key] = value
    return out
