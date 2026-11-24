"""Per-connection protocol state held by the router."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Pending:
    """A request forwarded in one direction, awaiting its response from the other."""

    method: str
    request_id: str  # JSON-encoded id, for events
    started: float = field(default_factory=time.monotonic)
    tool_name: str | None = None
    tool_risk: str | None = None
    args_bytes: int | None = None
    has_cursor: bool = False


@dataclass
class ToolInfo:
    """A tool the client is allowed to see (after pinning and listing checks)."""

    name: str
    digest: str
    risk: str
    definition: dict[str, Any]
    requires_approval: bool = False  # set by listing findings mapped to require_approval
    approval_reason: str | None = None


@dataclass
class Session:
    # requests from the client, keyed by JSON-encoded id
    client_pending: dict[str, Pending] = field(default_factory=dict[str, Pending])
    # requests from the server (sampling, elicitation, roots, ping)
    server_pending: dict[str, Pending] = field(default_factory=dict[str, Pending])
    # tools visible to the client; None until a tools/list result has been inspected
    tools: dict[str, ToolInfo] | None = None
    tools_stale: bool = False
    # TOFU window: True while the first listing of a server with no pins is being read
    # (including its pagination pages). Tools that appear after it closes are not trusted.
    tofu_window: bool | None = None
    client_capabilities: dict[str, Any] = field(default_factory=dict[str, Any])
    requested_version: str | None = None
    negotiated_version: str | None = None
    version_rejected: bool = False
    initialized: bool = False

    def client_supports_elicitation(self) -> bool:
        return isinstance(self.client_capabilities.get("elicitation"), dict)
