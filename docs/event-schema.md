# Event schema: `GatehouseEvents_CL`

Every event is one JSON object per line (JSONL), with PascalCase keys that match the
custom Log Analytics table `GatehouseEvents_CL` column for column. The machine-readable
schema is `detections/schema/GatehouseEvents_CL.json`. It is generated from the Pydantic
model (`uv run gatehouse table-schema`), and a test fails if the file and the model
disagree. `SchemaVersion` is 1.

## Columns

| Column | Type | Meaning |
|---|---|---|
| TimeGenerated | datetime | UTC time the event was emitted |
| EventId | string | UUID of this event |
| EventType | string | See the event types below |
| Severity | string | informational, low, medium, high, critical |
| Action | string | none, allowed, blocked, filtered, approval_required, approved, denied, redacted, logged, fail_closed, fail_open |
| Direction | string | client_to_server, server_to_client, internal |
| Reason | string | Human-readable explanation (redacted) |
| AgentSessionId | string | Shared by every gatehouse wrapper under one agent process (D-015) |
| ProxySessionId | string | One gatehouse process |
| ServerName | string | The `--name` given to `gatehouse run` (the policy uses this) |
| UpstreamName / UpstreamVersion | string | `serverInfo` reported by the server (untrusted) |
| ClientName / ClientVersion | string | `clientInfo` reported by the agent |
| ProtocolVersion | string | Negotiated MCP protocol version |
| Method | string | JSON-RPC method, for example `tools/call` |
| RequestId | string | JSON-encoded JSON-RPC id |
| ToolName | string | Tool name as sent (redacted; invisible characters shown as `\uXXXX`) |
| ToolRisk | string | exec, egress, write, read or unknown (name heuristic, can only be raised by annotations) |
| ArgKeys | dynamic | Argument **names** only, never values |
| ArgsHmac | string | HMAC-SHA256 of the canonical arguments, with a per-install key |
| ArgsBytes / ResultBytes | int | Sizes |
| LatencyMs | real | Server round trip for `tool.result` |
| DecisionBasis | string | fail_closed, explicit_block, most_specific, tie, default, flow, engine_disagreement, detection, unlisted_tool, stale_tool_list, kill_switch, circuit_breaker, grant, approval_budget |
| PolicyRule | string | Policy rules that matched |
| DetectorId / RuleId | string | For `detection` events, e.g. `args.secrets` / `aws-access-key-id` |
| MatchSummary | string | Masked description of the match, e.g. `AKIA************MPL1` |
| Location | string | JSON path, e.g. `arguments.text` or `tools[get_forecast]` |
| Mitre / Owasp | dynamic | ATLAS / ATT&CK and OWASP LLM ids |
| PolicySha256 | string | Hash of the policy in force |
| Host / OsPlatform / ProcessId | string / string / int | Where gatehouse ran |
| GatehouseVersion / SchemaVersion | string / int | Provenance |
| Details | dynamic | Small, event-specific, redacted extras (see below) |

## Event types

| EventType | When | Notable Details |
|---|---|---|
| `session.started` / `session.ended` | gatehouse process start and stop | PinnedSpecVersion, Command, ReturnCode |
| `policy.loaded` / `policy.load_failed` | startup | PolicyPath, ErrorKind (failure means every call is blocked) |
| `policy.tampered` | policy file changed on disk mid-session | CurrentSha256, Path |
| `protocol.negotiated` | `initialize` completed, or a `server/discover` result was inspected | SupportedVersions, Removed (versions gatehouse can't inspect, filtered out) |
| `protocol.unsupported_version` | a version gatehouse can't inspect, or a refused downgrade | Supported |
| `protocol.invalid_meta` | a 2026-07-28 request without a valid `_meta` envelope (-32602) | |
| `protocol.era_conflict` | `initialize` and 2026-07-28 requests mixed on one connection | Era |
| `protocol.invalid_result` | a 2026-07-28 result with a missing or unknown `resultType`, or `input_required` where it is not allowed | |
| `protocol.header_mismatch` | Streamable HTTP headers that disagree with the body (-32020) | Header |
| `protocol.unsolicited_notification` | a subscription notification the client never asked for (dropped) | |
| `protocol.cache_hint_capped` | `ttlMs` lowered to the policy maximum | TtlMs, MaxTtlMs |
| `server_request.input_required` | a server answered with an MRTR `InputRequiredResult` | Methods, HasRequestState, FindingCount |
| `protocol.invalid_frame` / `batch_rejected` / `oversized_frame` / `unsolicited_response` | framing violations | |
| `tools.listed` | a `tools/list` result was inspected | Offered, Visible, Filtered, PinningMode, ListedBy (`client`, or `gatehouse` for its own listing before a stateless call) |
| `tools.list_changed` | server sent `notifications/tools/list_changed` | |
| `tool.call` | every `tools/call` request | FindingCount |
| `tool.result` | every `tools/call` response | IsError, HasError, FindingCount |
| `server.request` | server-initiated request (sampling, elicitation, roots); 2026-07-28 servers must not send any | FindingCount |
| `pin.created` | a tool was pinned (TOFU) | Sha256, PinnedBy |
| `pin.store_error` | pin store unreadable or unwritable | |
| `approval.requested` / `granted` / `denied` | human approval via elicitation, or via MRTR for 2026-07-28 clients; `granted` also when a scoped grant answers (D-044) | Channel (`mrtr`, `grant`), GrantId |
| `flow.provenance_match` | an egress call's arguments copy text or a secret from a `private_data` result the session read (D-043); high severity if the session also holds `untrusted_input` | DetectorId `flow.provenance`; RuleId `private-data-copied`, `private-secret-copied` or `provenance-unavailable`; MatchSummary names the source tools; Details.FindingAction |
| `flow.rule_of_two` | a call completes the Rule-of-Two trifecta (any `flow.mode` but `off`); Action says what happened | FlowMode, SessionLabels, ToolLabels |
| `detection` | one per detector finding | MatchFingerprint, FindingAction, ChangedFields (pin mismatch) |
| `response.quarantined` | a withheld result was kept for review (`gatehouse review`) | QuarantineId, Kept (false if over 1 MiB: withheld but not kept) |
| `response.released` | a reviewed, released result was delivered when the agent repeated the call; the server is not called again | QuarantineId |
| `control.kill_switch` | this process saw the kill switch engage or release (once per change) | State (`engaged`, `released`), Source (`file`, `signal`) |
| `control.circuit_breaker` | the agent session was locked after N calls or results with high findings | Strikes, Threshold |
| `gatehouse.internal_error` | a bug, an upstream that can't start, or a flow or control store that can't be read or written (fails closed) | Component (`flow_store`, `control_store`) |
| `gatehouse.fail_open` | telemetry lost (the only fail-open path, ADR-0001) | Component |

## Guarantees

- **No raw secrets.** Free-text fields go through the secret catalog before they are
  written. Values are masked (`mask()` keeps at most 4 characters at each end).
  Fingerprints are keyed HMACs, so two identical secrets correlate within one
  installation but can't be brute-forced from the log. The attack suite's
  `canary-check` fails CI if any scenario canary appears in events or stderr.
- **Arguments are never logged,** only `ArgKeys`, `ArgsBytes` and `ArgsHmac`.
- **Bounded size.** Strings are capped (512 characters for most fields), `Details` depth
  and length are capped, and lists are capped at 64 items.
- **One file per process** (`events-<utc>-<server>-<proxy8>.jsonl`). Windows has no
  atomic cross-process append, so concurrent wrappers never share a file.

## Getting events into Sentinel

See `docs/sentinel-setup.md` (M2): a DCR-based custom table plus the Logs Ingestion
API, or the Kusto emulator for local testing (`detections/kusto.py`).
