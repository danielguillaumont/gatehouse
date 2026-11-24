"""MCP protocol constants gatehouse is built and tested against.

gatehouse speaks the *handshake era* of MCP (the ``initialize`` handshake). The newer
"modern" revision (2026-07-28, stateless per-request envelope, ``server/discover`` probe)
is not inspected yet. gatehouse answers ``server/discover`` with "method not found",
which makes spec-compliant clients fall back to ``initialize``. See docs/decisions.md.
"""

from __future__ import annotations

from typing import Final

# Pinned spec revision: the newest handshake-era revision. Tests assert that the pinned
# MCP SDK (dev dependency) still lists every version below as a handshake version.
PINNED_SPEC_VERSION: Final = "2025-11-25"

# Versions gatehouse accepts after negotiation. 2025-03-26 allowed JSON-RPC batches;
# gatehouse rejects batch frames regardless of version (see router).
SUPPORTED_VERSIONS: Final = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")

JSONRPC_VERSION: Final = "2.0"

# JSON-RPC / MCP error codes used by gatehouse.
PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603
UNSUPPORTED_PROTOCOL_VERSION: Final = -32022
UPSTREAM_UNAVAILABLE: Final = -32000  # implementation-defined server error range

# Methods with special handling.
INITIALIZE: Final = "initialize"
INITIALIZED: Final = "notifications/initialized"
DISCOVER: Final = "server/discover"
TOOLS_LIST: Final = "tools/list"
TOOLS_CALL: Final = "tools/call"
TOOLS_LIST_CHANGED: Final = "notifications/tools/list_changed"
CANCELLED: Final = "notifications/cancelled"
ELICITATION_CREATE: Final = "elicitation/create"
SAMPLING_CREATE: Final = "sampling/createMessage"
ROOTS_LIST: Final = "roots/list"
