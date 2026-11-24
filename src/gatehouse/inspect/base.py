"""Common types for detectors. Detectors are pure functions that return Findings."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from gatehouse.events.schema import Severity


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    detector_id: str  # e.g. "args.secrets"
    rule_id: str  # e.g. "aws-access-key-id"
    severity: Severity
    summary: str  # human-readable and already masked: never contains a raw secret
    location: str  # JSON path, e.g. "arguments.body" or "tools[weather].description"
    mitre: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    fingerprint: str | None = Field(
        default=None, description="HMAC of the matched value, for correlation without disclosure"
    )
