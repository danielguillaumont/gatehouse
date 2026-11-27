"""MCP protocol constants gatehouse is built and tested against.

gatehouse is a *dual-era* intermediary (spec 2026-07-28, "Versioning and Compatibility"):

- **legacy** revisions (2024-11-05 ... 2025-11-25) open with the ``initialize`` handshake;
- **modern** revisions (2026-07-28) are stateless: every request carries its protocol
  version and client capabilities in ``_meta``, and ``server/discover`` replaces the
  handshake.

See docs/decisions.md D-035 (spec source) and D-036 (how gatehouse handles both eras).
"""

from __future__ import annotations

from typing import Final

# Newest revision gatehouse inspects (modern era) and newest handshake revision.
PINNED_SPEC_VERSION: Final = "2026-07-28"
LATEST_LEGACY_VERSION: Final = "2025-11-25"

# Handshake-era versions gatehouse accepts after negotiation. 2025-03-26 allowed JSON-RPC
# batches; gatehouse rejects batch frames regardless of version (see router).
LEGACY_VERSIONS: Final = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
# Per-request-envelope versions gatehouse inspects.
MODERN_VERSIONS: Final = ("2026-07-28",)
ALL_VERSIONS: Final = (*LEGACY_VERSIONS, *MODERN_VERSIONS)
# Backwards-compatible name used by v0.1 code and tests: the handshake-era set.
SUPPORTED_VERSIONS: Final = LEGACY_VERSIONS

JSONRPC_VERSION: Final = "2.0"

# JSON-RPC / MCP error codes used by gatehouse.
PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603
# Reserved for the MCP specification (-32020 ... -32099), 2026-07-28.
HEADER_MISMATCH: Final = -32020
MISSING_REQUIRED_CLIENT_CAPABILITY: Final = -32021
UNSUPPORTED_PROTOCOL_VERSION: Final = -32022
# Implementation-defined. The spec asks new code not to allocate in -32000 ... -32019;
# this one predates that rule (v0.1) and keeps its meaning.
UPSTREAM_UNAVAILABLE: Final = -32000

# _meta keys (2026-07-28 basic/index "_meta").
META_PROTOCOL_VERSION: Final = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES: Final = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO: Final = "io.modelcontextprotocol/clientInfo"
META_SERVER_INFO: Final = "io.modelcontextprotocol/serverInfo"
META_SUBSCRIPTION_ID: Final = "io.modelcontextprotocol/subscriptionId"
META_LOG_LEVEL: Final = "io.modelcontextprotocol/logLevel"

# resultType values (2026-07-28 basic/index "ResultType").
RESULT_COMPLETE: Final = "complete"
RESULT_INPUT_REQUIRED: Final = "input_required"

# Methods with special handling.
INITIALIZE: Final = "initialize"
INITIALIZED: Final = "notifications/initialized"
DISCOVER: Final = "server/discover"
TOOLS_LIST: Final = "tools/list"
TOOLS_CALL: Final = "tools/call"
PROMPTS_GET: Final = "prompts/get"
RESOURCES_READ: Final = "resources/read"
SUBSCRIPTIONS_LISTEN: Final = "subscriptions/listen"
SUBSCRIPTIONS_ACKNOWLEDGED: Final = "notifications/subscriptions/acknowledged"
TOOLS_LIST_CHANGED: Final = "notifications/tools/list_changed"
CANCELLED: Final = "notifications/cancelled"
PING: Final = "ping"
ELICITATION_CREATE: Final = "elicitation/create"
SAMPLING_CREATE: Final = "sampling/createMessage"
ROOTS_LIST: Final = "roots/list"

# Requests a server may answer with an InputRequiredResult (MRTR "Supported Requests").
MRTR_METHODS: Final = frozenset({TOOLS_CALL, PROMPTS_GET, RESOURCES_READ})
# Request objects allowed inside InputRequests, and the client capability each needs.
INPUT_REQUEST_CAPABILITY: Final = {
    ELICITATION_CREATE: "elicitation",
    SAMPLING_CREATE: "sampling",
    ROOTS_LIST: "roots",
}
# Results that must carry ttlMs / cacheScope (2026-07-28 server/utilities/caching).
CACHEABLE_METHODS: Final = frozenset(
    {
        DISCOVER,
        TOOLS_LIST,
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        RESOURCES_READ,
    }
)


def is_modern(version: str | None) -> bool:
    return version in MODERN_VERSIONS


def is_legacy(version: str | None) -> bool:
    return version in LEGACY_VERSIONS
