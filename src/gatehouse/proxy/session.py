"""Protocol state held by the router.

``Session`` is what gatehouse knows about *one upstream server*: the inspected tool list,
the era, approval grants. On stdio there is one session per process. On Streamable HTTP a
modern-era session is shared by every client request, and a legacy session belongs to
one ``Mcp-Session-Id``.

``Pending`` maps live on the router channel that forwarded the request (one per stdio
process, one per HTTP request), so concurrent HTTP clients reusing the same JSON-RPC ids
can't answer each other's requests.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Era(StrEnum):
    LEGACY = "legacy"  # initialize handshake (2024-11-05 ... 2025-11-25)
    MODERN = "modern"  # per-request _meta (2026-07-28)


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
    # modern era: what this request declared in _meta
    modern: bool = False
    version: str | None = None
    client_caps: dict[str, Any] | None = None
    # subscriptions/listen: the notification filter the client asked for
    listen_filter: dict[str, Any] | None = None
    # requested protocolVersion of an initialize (downgrade detection)
    requested_version: str | None = None
    # tools/call with flow control on: the tool's effective capability labels
    flow_labels: frozenset[str] = frozenset()


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
class Grant:
    """A human approval that covers retries of the same call (MRTR, D-036)."""

    expires: float
    uses_left: int


@dataclass
class Session:
    # requests from the server (legacy era: sampling, elicitation, roots, ping)
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
    # era of this connection: legacy on a successful initialize, modern on a successful
    # 2026-07-28 probe or the first enveloped request (ADR-0002)
    era: Era | None = None
    # supportedVersions of the last server/discover result gatehouse delivered
    offered_versions: tuple[str, ...] = ()
    # set when a downgrade was detected and the policy refuses it
    downgrade_blocked: bool = False
    # (tool, args fingerprint) -> grant; see router._grant_key
    grants: dict[str, Grant] = field(default_factory=dict[str, Grant])
    # single-use nonces of gatehouse approval requestStates already redeemed
    redeemed_states: set[str] = field(default_factory=set[str])

    def client_supports_elicitation(self) -> bool:
        return isinstance(self.client_capabilities.get("elicitation"), dict)
