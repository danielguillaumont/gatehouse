# ADR-0001: Fail closed by default

- Status: accepted (2026-11-24)
- Context: gatehouse sits between an AI agent and MCP servers. Every failure inside
  gatehouse (bad config, unreadable state, a bug, an unexpected message) has two possible
  defaults: let traffic through (fail open) or stop it (fail closed).

## Decision

gatehouse fails **closed** for anything security-relevant, and every exception to that
is explicit and visible in telemetry.

| Situation | Behavior | Event |
|---|---|---|
| Policy missing / unreadable / invalid | Proxy runs; **every tools/call is blocked** | `policy.load_failed` (critical) |
| Policy hash ≠ `--expect-policy-sha256` | Same as invalid policy | `policy.load_failed`, `ErrorKind=integrity` |
| Policy file changes during a session | Original policy stays in force (no hot reload) | `policy.tampered` (high) |
| Detector/policy error while deciding | No valid policy → findings block; malformed params → JSON-RPC error | `protocol.invalid_frame` |
| Pin store unreadable or corrupt | All tools filtered from `tools/list` | `pin.store_error` (high, `fail_closed`) |
| TOFU pins can't be saved | Tools stay visible this session (already inspected), retried next session | `pin.store_error` (high) |
| Tool not in the last inspected listing | tools/call blocked (unless `pinning: off`) | `tool.call` blocked, `DecisionBasis=unlisted_tool` |
| Server sent `tools/list_changed` | Calls blocked until the client lists again | `tools.list_changed`, `DecisionBasis=stale_tool_list` |
| `require_approval` but no approval channel | Blocked | `tool.call`, `Action=approval_required` |
| Approval times out / errors | Blocked | `approval.denied` |
| Frame over size limit | Dropped | `protocol.oversized_frame` |
| Malformed frame, duplicate keys, NaN, batch | Dropped (JSON-RPC error to client when an id is known) | `protocol.invalid_frame` / `protocol.batch_rejected` |
| Response to an id gatehouse never forwarded | Dropped | `protocol.unsolicited_response` |
| Unsupported negotiated protocol version | initialize answered with -32022; later requests refused | `protocol.unsupported_version` (high) |
| Upstream server exits | Pending requests get JSON-RPC errors | `upstream.exited` |
| gatehouse itself crashes | Closed by construction: the agent never talks to the server directly | — |

## The one deliberate fail-open: telemetry

If an event sink fails (disk full, permissions), traffic is **not** blocked: the error is
written to stderr (up to three times) and counted. Blocking an agent because a log file
cannot be written would turn every disk problem into an outage, and the stderr channel is
still captured by MCP clients. Revisit when the Sentinel sink exists: a
`--require-telemetry` flag that blocks on sink failure is a reasonable option for
regulated deployments.

## Why "block everything" instead of "refuse to start" for a bad policy

A wrapper that exits at startup looks, from the agent, like a broken server: the user
sees a vague connection error and the SOC sees nothing. A wrapper that runs but blocks
every call returns an explicit reason to the agent on each call and emits a critical
`policy.load_failed` event that an analytics rule alerts on.

## Consequences

- Misconfiguration is loud: users see blocked calls with reasons, the SOC sees events.
- Some availability is traded for safety (e.g. a corrupt pin store hides all tools).
- Tests assert each row of the table above.
