"""The gatehouse security event: one schema for every sink and for Sentinel.

Python fields are snake_case; serialized events use PascalCase keys that match the
``GatehouseEvents_CL`` custom-table columns (``detections/schema/GatehouseEvents_CL.json``,
generated from this model by ``sentinel_columns()`` and checked by a test).

Events must never contain raw tool arguments, raw tool results or secrets. The emitter
(``gatehouse.events.emitter``) redacts every free-text field before a sink sees it.
"""

from __future__ import annotations

import types
import typing
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import AliasGenerator, BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_pascal

SCHEMA_VERSION = 1


class EventType(StrEnum):
    # lifecycle
    SESSION_STARTED = "session.started"
    SESSION_ENDED = "session.ended"
    UPSTREAM_EXITED = "upstream.exited"
    # protocol
    PROTOCOL_NEGOTIATED = "protocol.negotiated"
    PROTOCOL_UNSUPPORTED_VERSION = "protocol.unsupported_version"
    PROTOCOL_INVALID_FRAME = "protocol.invalid_frame"
    PROTOCOL_BATCH_REJECTED = "protocol.batch_rejected"
    PROTOCOL_OVERSIZED_FRAME = "protocol.oversized_frame"
    PROTOCOL_UNSOLICITED_RESPONSE = "protocol.unsolicited_response"
    # protocol, 2026-07-28 (v2)
    PROTOCOL_INVALID_META = "protocol.invalid_meta"
    PROTOCOL_ERA_CONFLICT = "protocol.era_conflict"
    PROTOCOL_INVALID_RESULT = "protocol.invalid_result"
    PROTOCOL_HEADER_MISMATCH = "protocol.header_mismatch"
    PROTOCOL_UNSOLICITED_NOTIFICATION = "protocol.unsolicited_notification"
    PROTOCOL_CACHE_HINT_CAPPED = "protocol.cache_hint_capped"
    # policy
    POLICY_LOADED = "policy.loaded"
    POLICY_LOAD_FAILED = "policy.load_failed"
    POLICY_TAMPERED = "policy.tampered"
    # tools
    TOOLS_LISTED = "tools.listed"
    TOOLS_LIST_CHANGED = "tools.list_changed"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    SERVER_REQUEST = "server.request"
    SERVER_INPUT_REQUIRED = "server_request.input_required"  # MRTR (2026-07-28)
    # pinning
    PIN_CREATED = "pin.created"
    PIN_STORE_ERROR = "pin.store_error"
    # approval (M2)
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"
    # session flow control (M5, D-040)
    FLOW_RULE_OF_TWO = "flow.rule_of_two"
    FLOW_PROVENANCE_MATCH = "flow.provenance_match"
    RESPONSE_QUARANTINED = "response.quarantined"
    RESPONSE_RELEASED = "response.released"  # a reviewed result delivered from quarantine
    CONTROL_CIRCUIT_BREAKER = "control.circuit_breaker"
    CONTROL_KILL_SWITCH = "control.kill_switch"
    CONTROL_SIGNAL = "control.signal"  # a remote signal from the control queue (M7)
    # HTTP authorization (M7, ADR-0008)
    AUTH_DENIED = "auth.denied"
    # model-based detectors (M6, ADR-0007): one verdict per classifier per input
    CLASSIFIER_VERDICT = "classifier.verdict"
    # detections: DetectorId / RuleId say what was found
    DETECTION = "detection"
    # gatehouse health
    INTERNAL_ERROR = "gatehouse.internal_error"
    FAIL_OPEN = "gatehouse.fail_open"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class EventAction(StrEnum):
    """What gatehouse did. ``none`` for purely informational events."""

    NONE = "none"
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FILTERED = "filtered"  # removed from a tools/list result
    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    DENIED = "denied"
    REDACTED = "redacted"
    LOGGED = "logged"
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


class Direction(StrEnum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"
    INTERNAL = "internal"


class SecurityEvent(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        alias_generator=AliasGenerator(serialization_alias=to_pascal),
    )

    # --- when / what ---------------------------------------------------------------
    time_generated: datetime
    event_id: str
    event_type: EventType
    severity: Severity = Severity.INFORMATIONAL
    action: EventAction = EventAction.NONE
    direction: Direction = Direction.INTERNAL
    reason: str | None = None

    # --- correlation -------------------------------------------------------------
    agent_session_id: str  # shared by every wrapper under one agent process
    proxy_session_id: str  # one gatehouse process
    server_name: str  # the --name given to gatehouse run
    upstream_name: str | None = None  # serverInfo.name reported by the MCP server
    upstream_version: str | None = None
    client_name: str | None = None  # clientInfo.name reported by the agent
    client_version: str | None = None
    protocol_version: str | None = None

    # --- the request ---------------------------------------------------------------
    method: str | None = None
    request_id: str | None = None
    tool_name: str | None = None
    tool_risk: str | None = None  # exec | egress | write | read | unknown
    arg_keys: list[str] | None = None  # argument names only, never values
    args_hmac: str | None = None  # HMAC-SHA256 over canonical arguments
    args_bytes: int | None = None
    result_bytes: int | None = None
    latency_ms: float | None = None

    # --- decision / detection ------------------------------------------------------
    decision_basis: str | None = None
    policy_rule: str | None = None
    detector_id: str | None = None
    rule_id: str | None = None
    match_summary: str | None = None  # masked; never a raw secret
    location: str | None = None  # where in the message, e.g. arguments.path
    mitre: list[str] = Field(default_factory=list[str])
    owasp: list[str] = Field(default_factory=list[str])

    # --- integrity / provenance ----------------------------------------------------
    policy_sha256: str | None = None
    host: str
    os_platform: str
    process_id: int
    gatehouse_version: str
    schema_version: int = SCHEMA_VERSION

    # --- event-specific, redacted, small -------------------------------------------
    details: dict[str, Any] = Field(default_factory=dict[str, Any])

    def to_record(self) -> dict[str, Any]:
        """Serialize with PascalCase keys (the on-disk / Sentinel shape)."""
        return self.model_dump(mode="json", by_alias=True)


# --- Sentinel table schema -------------------------------------------------------------

_SCALAR_TYPES: dict[Any, str] = {
    str: "string",
    int: "int",
    float: "real",
    bool: "boolean",
    datetime: "datetime",
}


def _sentinel_type(annotation: Any) -> str:
    origin = typing.get_origin(annotation)
    if origin in (typing.Union, types.UnionType):
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(args) != 1:
            raise TypeError(f"ambiguous union {annotation!r}")
        return _sentinel_type(args[0])
    if origin in (list, dict) or annotation in (list, dict):
        return "dynamic"
    if isinstance(annotation, type) and issubclass(annotation, StrEnum):
        return "string"
    if annotation in _SCALAR_TYPES:
        return _SCALAR_TYPES[annotation]
    raise TypeError(f"no Sentinel type for {annotation!r}")


def sentinel_columns() -> list[dict[str, str]]:
    """Columns for the ``GatehouseEvents_CL`` table, in model order."""
    return [
        {"name": to_pascal(name), "type": _sentinel_type(field.annotation)}
        for name, field in SecurityEvent.model_fields.items()
    ]
