"""Policy load errors and the security event emitted when a policy fails to load."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import AliasGenerator, BaseModel, ConfigDict
from pydantic.alias_generators import to_pascal

MAX_ERROR_MESSAGE_LEN = 2000


class PolicyErrorKind(StrEnum):
    IO = "io"  # missing, unreadable, or a directory
    TOO_LARGE = "too_large"
    ENCODING = "encoding"  # not valid UTF-8
    YAML = "yaml"  # syntax error, or nesting too deep
    DUPLICATE_KEY = "duplicate_key"
    ALIAS = "alias"  # YAML anchors / aliases / merge keys
    SCHEMA = "schema"  # valid YAML, invalid policy
    INTERNAL = "internal"  # bug in gatehouse: still fails closed


class PolicyError(Exception):
    """Raised by ``parse_policy`` for any reason a policy cannot be used."""

    def __init__(self, kind: PolicyErrorKind, message: str) -> None:
        super().__init__(f"{kind.value}: {message}")
        self.kind = kind
        self.message = message


class PolicyLoadFailed(BaseModel):
    """Security event: the policy could not be loaded, so gatehouse blocks everything.

    Serialized with PascalCase keys (``to_event``) to match the planned Sentinel
    ``GatehouseEvents_CL`` columns. Will move under ``gatehouse.events`` once the shared
    event schema exists.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        alias_generator=AliasGenerator(serialization_alias=to_pascal),
    )

    time_generated: datetime
    event_type: Literal["policy.load_failed"] = "policy.load_failed"
    severity: Literal["critical"] = "critical"
    action: Literal["fail_closed"] = "fail_closed"
    policy_path: str
    policy_sha256: str | None
    error_kind: PolicyErrorKind
    message: str

    def to_event(self) -> dict[str, object]:
        return self.model_dump(mode="json", by_alias=True)
