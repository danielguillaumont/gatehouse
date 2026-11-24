# gatehouse — Project Plan

> A detection-engineering and SOC layer for AI agent tool use over MCP.
> Status: planning. Last revised: 2026-11-24.

## 1. Positioning

Several MCP security proxies/gateways already exist (gateward/mcpgate, mcp-watchdog,
mcpkernel, Arbitus, mcpsafetywarden, plus Invariant Labs' `mcp-scan` research on tool
poisoning and rug pulls). gatehouse does **not** try to be "another MCP firewall".
It is the **detection-engineering layer** for agent tool use:

1. **Telemetry-first.** Every MCP interaction produces a structured, redacted, schema-stable
   security event designed for a SIEM, not just a local allow/deny log.
2. **SOC-grade analytics.** Microsoft Sentinel KQL analytics rules with session correlation
   across MCP servers (e.g. "injection from server A followed by egress via server B"),
   shipped as detection-as-code with tests against fixtures.
3. **Rigorous evaluation.** A published attack suite with precision/recall per detector,
   false-positive rate on realistic benign servers, a known-bypasses section, and the same
   suite run against 1–2 competing tools.

Enforcement (policy, pinning, blocking) exists because a detection layer that can't act is
weaker — but the differentiator is the telemetry, analytics and evaluation.

See `docs/prior-art.md` (to be written; claims about each tool must be verified against its
repository and docs, with version/commit noted).

## 2. Key decisions

| ID | Decision | Choice |
|---|---|---|
| D1 | Topology | Per-server stdio wrapper: `gatehouse run --policy p.yaml -- <server cmd>`. Aggregating gateway is a later option. |
| D2 | Proxy layer | Message-level JSON-RPC proxy using the MCP SDK's transports and Pydantic types — **not** back-to-back high-level `ClientSession`/`Server` (which would renegotiate capabilities and drop unknown methods). |
| D3 | Approval UX | MCP elicitation (if the client declares the capability), fallback block + `approval_required` event. **MVP: block + event only; elicitation in M2.** |
| D4 | Detection approach | Deterministic, explainable rules first. ML/LLM layer later, evaluated against the rules. |
| D5 | Failure mode | **Fail-closed** by default (see §6). |
| D6 | MCP spec | Pin one spec revision and one exact `mcp` SDK version (see §7). |
| D7 | Log hygiene | Redact before logging; never log raw arguments or raw secrets (see §8). |
| D8 | Sentinel | Custom table `GatehouseEvents_CL` via the Logs Ingestion API + DCR. Free trial starts ~week 2 once real logs exist. Before that, rules are tested on a JSONL fixture in an ADX free cluster or with `externaldata()`. |

## 3. Architecture

```
 Claude Code (MCP client)
     │  stdio (newline-delimited JSON-RPC)
     ▼
┌──────────────── gatehouse run --policy p.yaml -- <server cmd> ─────────────────┐
│ ClientSide transport ◄──► Router / Session ◄──► UpstreamSide transport          │
│                              │                                                  │
│          ┌───────────────────┼──────────────────┬───────────────┐               │
│          ▼                   ▼                  ▼               ▼               │
│     Normalizer          Detectors         Policy engine    Approval (M2)        │
│     (size, unicode)     (pure funcs)      (pure func)                           │
│          └───────────────────┴────────┬─────────┴───────────────┘               │
│                                       ▼                                         │
│        Redactor → Event emitter → sinks (JSONL, stderr; M2: Logs Ingestion)     │
│        Pin store (shared across wrapper instances)                              │
└─────────────────────────────────────────────────────────────────────────────────┘
     │  stdio
     ▼
 Real MCP server
```

- **Interception points**
  - client→server `tools/call`: argument detectors → policy → forward | block.
  - server→client `tools/list` result: pin check (MVP), poisoning scan (M2) → filter tools.
  - server→client `tools/call` result: injection/exfil-URL scan (M2).
  - `notifications/tools/list_changed`: re-verify pins on next list.
  - Everything else passes through unmodified; metadata is logged.
- **Correlation**: session keeps `pending[direction][id] = (method, params_digest, t0)`;
  responses carry no method, so this map is the only way to attribute a response.
- **Block semantics**: blocked `tools/call` → tool result with `isError: true` and a short
  reason (the model learns why); protocol violations → JSON-RPC error; failed/unpinned
  tools → removed from `tools/list`.
- **Stdout discipline**: only protocol frames on stdout; all logs to stderr/file.
- **Cross-wrapper correlation**: `AgentSessionId` derived from the parent (agent) process
  PID + start time via `psutil`, so all wrappers under one Claude Code session share it.

## 4. Repo layout

```
gatehouse/
├─ pyproject.toml                 # uv, src layout, ruff, pyright; exact pin of `mcp`
├─ src/gatehouse/
│  ├─ cli.py                      # run | pin | diff | validate-policy | verify-policy
│  ├─ proxy/ stdio.py router.py session.py
│  ├─ inspect/
│  │  ├─ base.py normalize.py
│  │  ├─ pinning.py secrets.py                    # MVP
│  │  ├─ injection.py poisoning.py commands.py paths.py pii.py   # M2
│  │  └─ rules/*.yaml
│  ├─ policy/ models.py engine.py integrity.py
│  ├─ events/ schema.py redact.py sinks.py
│  └─ state/ pinstore.py
├─ tests/ unit/ integration/
├─ attacks/
│  ├─ servers/  benign/  scenarios.yaml
│  ├─ harness.py                  # target-agnostic: drives gatehouse OR a competitor via command template
│  └─ report.py                   # precision/recall, FP rate → Markdown + JSON
├─ bench/latency.py               # direct vs through-gatehouse overhead
├─ detections/
│  ├─ schema/GatehouseEvents_CL.json
│  ├─ rules/*.yaml  hunting/*.kql
│  ├─ sample_data/events.jsonl    # generated by the attack suite
│  └─ tests/
├─ demo/                          # poisoned demo server, Claude Code config, recording script
├─ docs/
│  ├─ PLAN.md  architecture.md  threat-model.md  event-schema.md  policy.md
│  ├─ evaluation.md  known-bypasses.md  prior-art.md
│  └─ adr/0001-fail-closed.md ...
├─ examples/policy-*.yaml
└─ .github/workflows/ci.yml       # ubuntu + windows × py3.11–3.13; suite; report → job summary
```

### Example policy

Schema v1 and precedence are specified in [`docs/policy.md`](policy.md) (explicit block
always wins; otherwise most specific match; incomparable disagreement → require_approval).

```yaml
version: 1
default_action: block            # allowlist style; required
servers:
  filesystem:
    tools:
      read_file: allow
      "search_*": allow
      write_file:
        action: require_approval  # MVP: treated as block + event
        reason: "File writes need a human"
```

Later milestones add fields such as `pinning`, finding-severity mappings and argument
constraints. Unknown keys are rejected, so older gatehouse versions refuse newer policies.

### Example event

```json
{"TimeGenerated":"2026-11-24T10:02:11.123Z","EventId":"<uuid>","EventType":"detection",
 "Severity":"high","Action":"blocked","DetectorId":"args.secrets","RuleId":"aws-access-key",
 "ServerName":"github","ToolName":"create_issue","Direction":"client_to_server",
 "AgentSessionId":"<id>","ProxySessionId":"<id>","MatchSummary":"AKIA************WXYZ",
 "ArgsHmac":"<hmac>","PolicySha256":"<sha256>","ProtocolVersion":"<negotiated>",
 "Mitre":["AML.T0057","T1552"],"Owasp":["LLM02"],"Host":"<host>","GatehouseVersion":"0.1.0"}
```

## 5. Threat model

Trust boundaries: agent ↔ gatehouse, gatehouse ↔ server, server ↔ its own network
(invisible to gatehouse), policy/pin files on disk (reachable by the agent's own tools).

| # | Attack | Seen at | Detector | Milestone | OWASP LLM 2025 | ATLAS / ATT&CK |
|---|---|---|---|---|---|---|
| 1 | Rug pull (definition changed after approval) | `tools/list`, `list_changed` | `listing.pin_mismatch` | MVP | LLM03 | AML.T0010 · T1195 |
| 2 | Unapproved tool (strict pinning) | `tools/list`, `tools/call` | `listing.unpinned` | MVP | LLM03, LLM06 | AML.T0010 |
| 3 | Secrets in arguments | `tools/call` params | `args.secrets` | MVP | LLM02 | AML.T0057 · T1552, T1567 |
| 4 | Policy/pin tampering by the agent | `tools/call` params, disk | `self_protect`, `policy.integrity` | MVP | LLM06 | T1562.001 |
| 5 | Resource exhaustion | any | `limits` | MVP | LLM10 | AML.T0029 |
| 6 | Indirect prompt injection in output | `tools/call` result | `response.injection` | M2 | LLM01 | AML.T0051.001 |
| 7 | Tool poisoning (description or schema) | `tools/list` | `listing.poisoning` | M2 | LLM01, LLM03 | AML.T0051.001, AML.T0010 |
| 8 | Tool shadowing (cross-tool instructions) | `tools/list` | `listing.cross_tool_ref` | M2 | LLM01, LLM06 | AML.T0051 |
| 9 | Unicode smuggling | any text | `normalize.invisible` | M2 | LLM01 | AML.T0051 · T1027 |
| 10 | Markdown/URL exfil beacon | `tools/call` result | `response.exfil_url` | M2 | LLM05, LLM02 | AML.T0057 |
| 11 | Dangerous commands | `tools/call` params | `args.commands` | M2 | LLM06, LLM05 | AML.T0053 · T1059 |
| 12 | Sensitive path access | `tools/call` params | `args.paths` | M2 | LLM06, LLM02 | T1552.004, T1005 |
| 13 | PII in arguments | `tools/call` params | `args.pii` | M2 | LLM02 | AML.T0057 |
| 14 | Malicious sampling / elicitation phishing | server→client requests | `server_request.*` | M5 | LLM01 | AML.T0051 |

ATLAS was renamed (ML → AI) and extended with agent techniques in 2025: verify every ID
against the current release and record the ATLAS version in `threat-model.md`.

> **Superseded (2026-11-24):** the IDs in this table were checked against ATLAS 2026.10
> and several were remapped (AML.T0057 no longer exists). `docs/threat-model.md` is the
> source of truth; `tests/test_atlas_ids.py` enforces it.

**Non-goals**: a malicious server misusing data it legitimately received or making its own
network calls; a compromised host or client; guaranteed prompt-injection prevention
(deterministic detection is inherently incomplete — gatehouse is defense-in-depth and signal).

**gatehouse's own attack surface**: ReDoS (use `google-re2` or bounded patterns + size
limits), log injection (JSON-encode everything), stdout pollution, approval-prompt injection
(quote/truncate/escape attacker-controlled text in approval messages), and the log itself as
an exfil sink (→ §8).

## 6. Fail-closed vs fail-open (ADR-0001)

| Situation | Default | Notes |
|---|---|---|
| Detector or policy engine raises | **Block** the message, emit `gatehouse.internal_error` | Per-server `on_internal_error: allow` is opt-in and emits `gatehouse.fail_open` (high severity) on every use. |
| Policy file missing / invalid at startup | **Block every call**, emit `policy.load_failed` (critical) | The proxy still runs so the failure is visible to the agent and in telemetry. No implicit allow-all. See `docs/policy.md`. |
| Pin store unreadable / corrupt | Strict mode: **block all tools**; TOFU mode: refuse to start | |
| Approval required but unavailable or timed out | **Block** | MVP: always block. |
| Message exceeds size limit | **Block**, emit `limits.exceeded` | |
| Upstream server crashes | Return errors to the client; no restart in MVP | Emit `upstream.exited`. |
| gatehouse itself crashes | Closed by construction | The agent loses the server; it never talks to it directly. |
| Unsupported negotiated protocol version | Configurable `warn` / `block`, default **block** | See §7. |

Fail-open decisions are always visible in telemetry; a KQL rule alerts on `gatehouse.fail_open`.

## 7. Pinned MCP spec version

- Pin the `mcp` SDK to an exact version in `pyproject.toml` (Day 1).
- Target the latest **stable** spec revision that SDK supports (read
  `mcp.types.LATEST_PROTOCOL_VERSION` on Day 1) and record it in `docs/architecture.md`
  and the README.
- gatehouse records the negotiated `protocolVersion` from `initialize` in every event and
  blocks (default) or warns on versions outside its tested set.
- Upgrading the spec/SDK is an explicit PR that re-runs the attack suite and benchmark.

## 8. Secret redaction before logging

- **Nothing raw reaches a sink.** Events are built from a redacted view of the message; raw
  arguments and results are never serialized into events.
- `MatchSummary` shows a masked form (prefix/suffix only, e.g. `AKIA************WXYZ`).
- Argument fingerprints use **HMAC-SHA256 with a per-install key**, not a plain hash, so a
  log reader cannot confirm guessed secrets offline.
- The redactor runs the same secret catalog as `args.secrets` over every string field that
  goes into an event (including tool names/descriptions from untrusted servers).
- **Canary test**: the attack suite plants known canary secrets; CI fails if any canary
  appears in any sink output, stderr, or the generated fixture.

## 9. Policy-file integrity

- Policy is loaded **once** at startup; no hot reload in MVP.
- `PolicySha256` is logged in a `policy.loaded` event and on every subsequent event.
- Optional `--expect-policy-sha256 <hash>`: refuse to start on mismatch
  (`gatehouse verify-policy` prints the hash).
- The file is re-hashed periodically / on each `tools/call`; a change mid-session emits
  `policy.tampered` (high) — the running process keeps the original policy.
- `self_protect` denies tool calls whose arguments reference gatehouse's policy, pin store,
  or log paths (normalized, case-insensitive on Windows).
- KQL: alert on `policy.tampered`, and on `PolicySha256` changing for a host outside a
  change window.
- Later: signed policies (e.g. minisign/sigstore).

## 10. Evaluation methodology

- **Scenarios** (`attacks/scenarios.yaml`): each has an id, attack category, server,
  client script, expected detector + action, and OWASP/ATLAS ids.
- **Benign set**: realistic benign servers (filesystem, notes, weather, git-like, search)
  and a benign text corpus, used to measure false positives.
- **Metrics per detector and category**: TP, FN, FP, precision, recall, FP rate on benign
  traffic; reported as Markdown in the CI job summary and JSON as an artifact.
- **Anti-overfitting**: held-out paraphrase variants written after the detectors, public
  payloads from published research (attributed), and a `known-bypasses.md` that documents
  misses honestly with reasons.
- **Competitor comparison (M3)**: `harness.py` is target-agnostic (a command template), so
  the identical suite runs against 1–2 competitors. Record versions, configs, and run date;
  report on the categories each tool claims to cover; invite corrections.

## 11. Latency benchmark

- `bench/latency.py`: echo MCP server, `tools/call` round trips **direct vs through
  gatehouse**, payload sizes 1 KB / 100 KB / 1 MB, N ≥ 1000 calls each.
- Report p50 / p95 / p99 overhead and startup time; run on Windows and Linux.
- Target (initial, revisit after measurement): **p95 overhead < 5 ms at 1 KB**.
- CI publishes the numbers but does not gate on them (shared runners are noisy); a local
  run is recorded in `docs/evaluation.md` with hardware details.

## 12. MVP — 1 week (~30 h at 4–6 h/day)

**Ownership**

- **You write**: pinning (`inspect/pinning.py`, canonical hashing, diff), KQL analytics
  rules.
- **Claude writes, then teaches** (you approve the design, review, and must be able to
  explain it): policy engine (`policy/`). Done ahead of schedule; see `docs/policy.md`.
- **Paired**: router/session (`proxy/router.py`, `proxy/session.py`).
- **Generated, you review**: scaffold, CI, Pydantic models (after you design the schemas),
  CLI, sinks, secret catalog + redactor, mock servers, harness, report, benchmark, fixture
  generator, demo server.

| Day | Deliverable | Owner | Done when |
|---|---|---|---|
| 1 | uv scaffold, CI matrix, exact SDK pin + spec version recorded, event/policy schemas, ADR-0001, `prior-art.md` draft | you design schemas; I generate | CI green on Windows + Linux |
| 2 | Passthrough proxy with id correlation and stdout discipline | **paired** | Claude Code works unchanged through gatehouse on Windows |
| 3 | Pinning: canonical hash, pin store, `gatehouse pin` / `diff`, strict + TOFU, list filtering, `list_changed` | **you** | Mutating a pinned tool removes it and emits `listing.pin_mismatch` |
| 4 | Wire the policy engine into the router, `validate-policy`, policy integrity (§9), fail-closed paths (§6), `self_protect` | generated (engine already done) | Decisions applied end-to-end; tamper test emits `policy.tampered` |
| 5 | `args.secrets`, redactor (§8), HMAC fingerprints, JSONL sink, canary test | generated, you review | No canary ever appears in any output |
| 6 | Attack + benign mock servers, target-agnostic harness, evaluation report, `known-bypasses.md` stub, latency benchmark | generated, you review | CI job summary shows precision/recall/FP rate and latency table |
| 7 | `GatehouseEvents_CL` schema, 4–5 KQL rules, fixture, ADX validation; **demo**; README | **you** (KQL); generated (demo scaffolding) | Rules return expected rows on the fixture; demo recorded |

**KQL rules in MVP** (all against the fixture):
1. Rug pull: `listing.pin_mismatch`.
2. Unpinned tool invoked or listed in strict mode, repeated per session.
3. Secret detected in arguments to an egress-capable tool.
4. `policy.tampered` or `gatehouse.fail_open`.
5. Burst of blocked calls per `AgentSessionId` (with `row_window_session` or `bin`).
(Cross-server injection → egress sequence rules arrive with the M2 detectors.)

**Demo**: Claude Code configured with gatehouse wrapping `demo/weather_server.py`.
(a) Pin the clean server; (b) restart it in "poisoned" mode where `get_forecast`'s
description carries hidden instructions to read `~/.ssh/id_rsa`; (c) gatehouse removes the
tool from `tools/list`, Claude Code never sees it, the event is logged, and the KQL rug-pull
rule fires on the resulting JSONL. In the MVP the block comes from **pinning**, not
content detection — the README says so explicitly; content-based poisoning detection is M2.

**Out of MVP**: elicitation approval, content heuristics (injection/poisoning/commands/
paths/PII), Streamable HTTP, Sentinel ingestion, resources/prompts/sampling inspection.

**Slack if behind**: drop TOFU mode (strict only), drop `--expect-policy-sha256`, reduce KQL
rules to 3. Keep: passthrough correctness, pinning, redaction, evaluation report, demo.

## 13. Roadmap after MVP

- **M2 — Content detectors + Sentinel (weeks 2–3; start the 31-day trial)**
  - Detectors: `response.injection`, `listing.poisoning` (incl. schema property
    descriptions/names), `listing.cross_tool_ref`, `normalize.invisible`,
    `response.exfil_url`, `args.commands`, `args.paths`, `args.pii`.
  - Elicitation approval (capability check, proxy-owned id namespace, non-blocking, timeout).
  - Logs Ingestion API sink (`azure-monitor-ingestion`, DCR, Entra app), Bicep for table +
    DCR + analytics rules; cross-server sequence rules (injection → egress within N minutes
    by `AgentSessionId`); validate all rules on real data.
- **M3 — Evaluation v1 + comparison (weeks 3–4)**
  - Full benign corpus, held-out variants, `known-bypasses.md` populated.
  - Identical suite against 1–2 competitors; `prior-art.md` finalized with results.
  - Sentinel workbook; rule tuning from real data; write-up / blog post #1.
- **M4 — Streamable HTTP**: reverse-proxy mode, `Mcp-Session-Id`, SSE pass-through,
  protocol-version headers, OAuth (no token passthrough per spec).
- **M5 — Full protocol coverage**: resources, prompts, server-initiated sampling and
  elicitation, roots.
- **M6 — Cross-server data flow**: shared state across wrappers (SQLite), tracking
  sensitive values from server A's output into server B's arguments ("lethal trifecta");
  optional aggregating-gateway mode. KQL detection-as-code in CI via the Kusto emulator.
- **M7 — ML layer**: small local injection classifier + Ollama LLM judge; precision/recall/
  latency compared against rules in the same report.
- **M8 — Hardening & release**: fuzzing (hypothesis/atheris) on router/parser, signed
  policies, PyPI release with SBOM and signed artifacts, blog post #2.

## 14. What's genuinely hard

1. Transparent JSON-RPC correctness: bidirectional requests, notifications, cancellation of
   blocked requests, progress tokens, version-dependent features — without ever breaking
   the stream.
2. Proxy-originated requests (elicitation, M2): non-colliding id namespace, swallowing
   responses, not blocking other traffic while waiting for a human.
3. Windows subprocesses: `.cmd` shims, process-tree cleanup, UTF-8 pipes, Ctrl+C.
4. Pinning semantics: what counts as "approved", canonicalization, which fields to pin,
   and a usable diff when servers legitimately upgrade.
5. Detection quality (M2): Unicode evasion, poisoning hidden in schemas, and above all an
   honest FP rate on benign traffic.
6. Not overfitting the suite you also wrote; fair, reproducible competitor comparisons.
7. KQL correlation: time-windowed joins across servers, session windows, entity mapping.

## 15. Working agreement

- Small, incremental commits; no bulk-generated drops. You should be able to explain every
  line.
- Run `/code-review` on your hand-written modules before each milestone.
- Every claim in README, `prior-art.md` and `evaluation.md` must be reproducible from the
  repo (command + version + date).
