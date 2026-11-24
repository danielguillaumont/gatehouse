# Decision log

Each entry: what was decided, why, and what was considered instead. Newest last.
Dates are when the decision was made.

## 2026-11-24

**D-001 Topology: one gatehouse process per MCP server.**
`gatehouse run --name X --policy P -- <server cmd>` in the agent's MCP config. Simplest
transparent design; each server is isolated. *Alternative:* one aggregating gateway
(tool namespacing, multiplexing) — deferred; cross-server correlation is solved in
telemetry instead (D-015).

**D-002 Message-level proxy written by hand; no MCP SDK at runtime.**
gatehouse parses and forwards raw JSON-RPC frames and forwards the original bytes for
anything it does not change. The official SDK (v2.3.0) is a pinned **dev** dependency for
mock servers and interop tests. *Why:* a security proxy should not renegotiate
capabilities or drop unknown fields, and `mcp` 2.x pulls a large web stack (starlette,
uvicorn, httpx) into the trust boundary. *Alternative:* back-to-back `ClientSession` /
`Server` — rejected (lossy, larger attack surface).

**D-003 Handshake-era MCP only; `server/discover` answered with "method not found".**
SDK 2.3.0 knows a "modern" revision (2026-07-28, stateless per-request envelope) that
clients probe with `server/discover`. The SDK's own client falls back to `initialize` on
any JSON-RPC error other than a modern-only -32022 (read in `mcp/client/_probe.py`).
gatehouse answers the probe itself, so clients use the handshake era it fully inspects.
*Consequence:* modern-only servers are not supported yet (fail closed). Modern-era
support is planned with Streamable HTTP (M4).

**D-004 Pinned spec revision 2025-11-25; accepted versions 2024-11-05 … 2025-11-25.**
Anything else negotiated is answered with -32022 and blocked. A test asserts the pinned
SDK still lists all of these as handshake versions.

**D-005 Strict framing.** Frames with duplicate keys, NaN/Infinity, invalid UTF-8, wrong
`jsonrpc`, bad id types, or JSON-RPC batches are dropped and reported. *Why:* gatehouse
inspects what it parses but forwards original bytes; any parser disagreement (first-wins
vs last-wins duplicate keys) would let a message mean one thing to gatehouse and another
to the server. Batches would otherwise need a second inspection path.

**D-006 Policy precedence:** explicit block anywhere wins (IAM-style); otherwise the most
specific matching rules win (partial order over server/tool specificity); incomparable
rules that disagree → `require_approval`; no match → required `default_action`. Rule
order never matters. (Owner-approved; see `docs/policy.md`.)

**D-007 Name normalization:** strip Unicode format characters, NFKC, casefold, NFKC.
Defeats case/fullwidth/math-alphanumeric/zero-width evasions. Cross-script confusables
(Cyrillic `е`) are a documented gap with a strict xfail test (planned for M2).

**D-008 Invalid policy → run and block everything** (not refuse to start). See ADR-0001.

**D-009 Pinning defaults to `strict`; `tofu` never re-trusts a change.** Pinned fields:
name, title, description, inputSchema, outputSchema, annotations. `_meta` and `icons`
are excluded (not shown to the model, churn between releases). TOFU pins only tools it
has never seen (`only_new`), so a rug pull can't be "learned".

**D-010 Pin store:** one JSON file shared by all wrappers, written under an O_EXCL lock
file (stale after 30 s) with atomic `os.replace` and Windows sharing-violation retries.
*Considered:* HMAC-signing the store with the install key — skipped: an agent that can
write the store can usually read the key in the same directory; self-protection (D-018)
is the stronger control.

**D-011 A tools/call must name a tool from the last inspected listing** (unless
`pinning: off`). Calls before any listing, to filtered tools, or after
`notifications/tools/list_changed` (until the client re-lists) are blocked. *Why:*
otherwise a filtered rug-pulled tool is still callable by name.

**D-012 Block semantics:** a blocked tools/call returns a normal tool result with
`isError: true` and a reason built only from trusted text (policy reasons, detector ids),
so the model understands and doesn't retry blindly; protocol problems get JSON-RPC errors;
failed tools are removed from `tools/list`.

**D-013 Findings → actions by severity** (`findings:` in policy; defaults critical/high =
block, medium/low/informational = log). One mapping for argument, listing and result
detectors.

**D-014 Events:** one Pydantic model, PascalCase on the wire to match the Sentinel table,
generated table schema checked by a test; all free text redacted (secret catalog +
visible escapes for invisible characters + length caps); arguments never logged — only
argument names, byte size and an HMAC-SHA256 fingerprint with a per-install key.
One JSONL file per gatehouse process (Windows has no atomic cross-process append).

**D-015 AgentSessionId** = hash(host, PID and start time of the nearest non-launcher
ancestor). Lets KQL correlate wrappers under the same agent without IPC.
`GATEHOUSE_AGENT_SESSION_ID` overrides it (used by tests and the attack harness).

**D-016 Telemetry is the one fail-open:** sink errors go to stderr, traffic continues.
See ADR-0001 for rationale and the future `--require-telemetry` option.

**D-017 Secret patterns anchor on alphanumeric look-arounds, not `\b`.** A test caught
`tool_ghp_…` slipping past `\b` (underscore is a word character). All prefix-anchored
rules now use `(?<![A-Za-z0-9])`.

**D-018 Self-protection** blocks tool arguments that reference gatehouse's policy, pin
store, HMAC key, state or event directories. Spellings (absolute, drive-less, `~`,
`%LOCALAPPDATA%`, `$HOME`, …) are computed once at startup so the detector stays pure;
`..` segments are collapsed before matching.

**D-019 Tool risk (exec > egress > write > read) is derived from the tool name and can
only be raised by annotations,** never lowered: annotations come from the untrusted
server.

**D-020 CI matrix reduced** to ubuntu 3.11, ubuntu 3.13, windows 3.12 (+ lint, attack
suite). The repo is private; Windows minutes count double. Docs-only pushes skip CI.

**D-021 Competitor comparison targets: gateward and mcp-watchdog.** They are the stdio
proxies with a non-interactive `-- <command>` interface (see `docs/prior-art.md`).
mcpsafetywarden and Snyk agent-scan are not transparent proxies; mcpkernel and Arbitus
need bespoke configs. Competitors are installed and run in CI / isolated venvs only.

**D-022 Approval** uses MCP elicitation only when the client declared the capability;
otherwise `require_approval` blocks with `Action=approval_required`.
