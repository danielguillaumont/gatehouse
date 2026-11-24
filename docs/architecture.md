# Architecture

gatehouse is a **per-server stdio proxy**. The MCP client (Claude Code, Cursor, an SDK
agent) launches `gatehouse run ... -- <real server command>` instead of the server.
gatehouse starts the real server as a child process and sits on both pipes.

```
                 stdin/stdout (MCP)                   stdin/stdout (MCP)
  MCP client  <---------------------->  gatehouse  <---------------------->  MCP server
  (agent)                                   |                                (child process)
                                            |  stderr: human-readable alerts
                                            v
                         JSONL events (GatehouseEvents_CL schema)
                                            |
                                            v
                Microsoft Sentinel / Log Analytics (Logs Ingestion API, M2)
                analytics rules + hunting queries in detections/
```

One gatehouse process runs per MCP server. The **AgentSessionId** column stitches the
wrappers belonging to one agent process back together in KQL (D-015).

## Components

| Path | Role | Pure? |
|---|---|---|
| `proxy/framing.py` | Strict newline-delimited JSON-RPC parsing. Rejects duplicate keys, NaN, batches, invalid UTF-8, bad id types and oversized frames | yes |
| `proxy/router.py` | Every decision: what is forwarded, filtered, blocked or answered by gatehouse itself | no (async I/O through injected `send` callables) |
| `proxy/session.py` | Per-connection state: pending requests, visible tools, the TOFU window | data only |
| `proxy/stdio.py` | Child process, binary pipes, `.cmd` shim resolution on Windows, process-tree kill | I/O |
| `proxy/integrity.py` | Watches the policy file; a change raises `policy.tampered` (no hot reload) | small I/O |
| `policy/` | Hardened YAML loader, Pydantic schema, precedence engine | engine yes; loader reads one file |
| `inspect/` | Detectors (`secrets`, `self_protect`, `pinning`, `risk`; content detectors in M2) and `pipeline.py`, the only place they are wired to interception points | yes |
| `events/` | `SecurityEvent` model, redaction, HMAC fingerprints, sinks | sinks do I/O |
| `state/pinstore.py` | Pin store: lock file plus atomic replace | I/O |
| `client.py` | Raw synchronous MCP client used by `pin`/`diff`, the tests, the attack suite, the benchmark and the demo | I/O |

## Interception points

| Direction | Message | What happens |
|---|---|---|
| client → server | `initialize` | Version negotiation recorded; unsupported versions rejected |
| client → server | `server/discover` (2026 stateless era) | Answered with -32601 so the client falls back to `initialize`, the era gatehouse fully inspects (D-003) |
| client → server | `tools/call` | Availability (was the tool listed and pinned?), policy decision, argument detectors. Blocked calls get an MCP tool error (`isError: true`) from gatehouse and never reach the server |
| server → client | `tools/list` result | Duplicate names, pin check (strict / TOFU / off), definition detectors (M2). Filtered tools are removed from the result; an unchanged listing is forwarded byte for byte |
| server → client | `notifications/tools/list_changed` | Marks the tool list stale: calls are blocked until the client lists again |
| server → client | `tools/call` result | Result detectors (M2). A flagged result is withheld |
| both | anything else | Forwarded unchanged (message-level proxy: unknown methods and fields survive) |

## Design rules

- **Stdout carries only MCP frames.** `sys.stdout` is redirected to stderr at startup, so
  a stray `print` cannot corrupt the protocol stream. Ruff's T20 rule bans `print`.
- **Fail closed** (ADR-0001). An invalid policy, an unreadable pin store or a malformed
  frame always ends in a block. The one fail-open path, telemetry loss, emits
  `gatehouse.fail_open` on the sinks that still work.
- **Redact before logging.** Every free-text event field goes through the secret catalog,
  and invisible characters are made visible. Arguments are never logged: only their names,
  their size and an HMAC fingerprint.
- **Detectors are pure functions** over size-bounded input (`inspect/walk.py`), with
  linear-time regexes. They are unit-testable and safe against ReDoS.
- **No MCP SDK at runtime** (D-002). gatehouse parses JSON-RPC itself, so it can't be
  broken by SDK changes and sees exactly the bytes that are forwarded. The SDK is a dev
  dependency, used for interop tests against a real SDK server.

## Data flow for one tool call

1. The client sends `tools/call get_forecast {"city": "Paris"}`.
2. `framing.parse_frame` validates the frame (strict JSON, single object, valid id).
3. `router._verdict` combines four signals and the strictest one wins:
   - **availability:** is the tool visible in this session?
   - **policy decision:** `policy.engine.decide`
   - **listing flags:** was the definition flagged when listed?
   - **argument findings:** `pipeline.scan_arguments`, mapped through `findings:`
4. On allow, the original bytes are forwarded and a `Pending` entry records the request.
   On block, gatehouse answers the client itself.
5. Events emitted: `tool.call` always, plus one `detection` per finding.
6. The server's response is matched to the `Pending` entry, the result detectors run,
   and a `tool.result` event records latency and sizes.
