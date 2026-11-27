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
order never matters. (See `docs/policy.md`.)

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

**D-023 (2026-11-24) TOFU trusts a server's *first* listing only.** Trust-on-first-use
pins tools seen in the first `tools/list` (and its pagination pages) of a server with no
pins. Tools that appear later, whether in the same session or after a restart, are filtered
with `listing.unpinned/new-tool-on-pinned-server` until `gatehouse pin --tool NAME`
approves them. The attack suite showed the old behaviour silently trusted a newly added
`upload_everything` tool. Alternative considered: keep trusting new tools and only alert.
Rejected because it contradicts fail-closed (ADR-0001), and `gatehouse pin --tool` makes
approving a legitimate new tool cheap.

**D-024 (2026-11-24) The attack suite runs gatehouse with a permissive policy**
(`attacks/policy-eval.yaml`: `default_action: allow`, `pinning: tofu`). A deny-by-default
policy would "prevent" every attack trivially and measure nothing. The suite measures the
detectors and listing checks.

**D-025 (2026-11-24) Benign false positive = any change to traffic.** A benign scenario
fails if a tool is hidden or altered, a call is blocked, or a result differs from what the
mock server sent. Alerts on benign traffic are reported separately as the alert rate,
because a logged-only finding costs analyst time but does not break the agent. The
`direct` target must show every attack succeeding, otherwise the scenario is broken and
`python -m attacks run` exits 1.

**D-026 (2026-11-24) Keyword prefilter for secret rules.** The first latency benchmark
showed about 940 ms of overhead for a 1 MiB call. Every secret regex ran over the whole
payload, and rules that start with a lookbehind cannot use `re`'s literal-prefix search.
Each rule now has lower-case `keywords`, and its regex runs only if one of them occurs in
the lower-cased text (the gitleaks approach). A test asserts every regex match contains
a keyword, so the prefilter can't hide a match. Argument scanning of 1 MiB dropped from
590 ms to 33 ms, and end-to-end overhead from about 940 ms to about 100 ms. Alternative
considered: rewrite the patterns to start with literals. Rejected for now: more invasive,
and the prefilter also skips rules entirely in the common no-secret case.

**D-027 (2026-11-24) KQL rules are tested in the Kusto emulator (Kustainer).** The plan
put this in M6. I moved it into the MVP because the emulator runs the same engine as Log
Analytics, so the rules' syntax and semantics are checked, not just their YAML shape.
`detections/kusto.py` creates `GatehouseEvents_CL` from the generated schema, ingests
`sample_data/events.jsonl` with a JSON mapping, runs every rule, and compares the results
with `expected.yaml`. Hunting queries must execute. CI runs the emulator as a service
container. Caveats: the emulator is Azure Data Explorer, not Log Analytics, so
Sentinel-only operators and functions (for example `_GetWatchlist` or ASIM parsers) can't
be tested there, and the rules avoid them. The sample data comes from real gatehouse
sessions, scrubbed of host names and paths. The one exception is a single synthetic
`gatehouse.fail_open` row, marked `Details.Synthetic`. Alternative considered: a
free-tier ADX cluster. Rejected because it needs an account and network access in CI.

**D-028 (2026-11-24) MITRE ATLAS IDs follow release 2026.10.** I checked them against
`mitre-atlas/atlas-data` `dist/v6/ATLAS-2026.10.yaml`. AML.T0057 (LLM Data Leakage) no
longer exists: it was folded into "Data from AI Services". Data leaving through a tool
argument now maps to AML.T0086 (Exfiltration via AI Agent Tool Invocation). The other
remaps:
- rug pulls and look-alikes: AML.T0010.005 (Supply Chain Compromise: AI Agent Tool)
- tool poisoning: adds AML.T0110 (AI Agent Tool Poisoning)
- self-protection: AML.T0081 (Modify AI Agent Configuration)
- sensitive paths: AML.T0098 (AI Agent Tool Credential Harvesting)
- protocol smuggling: AML.T0053 (AI Agent Tool Invocation), not prompt injection
`tests/test_atlas_ids.py` fails if any ID outside the verified list appears.

**D-029 (2026-11-24) M2 content detectors are keyword-gated, bounded regex rules.** Each
rule (`inspect/rules.py` `PatternRule`) has lower-case keywords that *every* match must
contain, so the regex only runs when one occurs. Each rule also runs on a copy of the text
with Unicode format characters removed (zero-width splits), and phrase rules can skip
matches that are quoted ("a scanner for 'ignore previous instructions' payloads"). Rules
that need more than a regex use a `validate` hook: Luhn, mod-97 and SSA rules for PII,
and boundary checks done in Python instead of a leading lookbehind. The benchmark showed
why that matters: Python evaluates a leading lookbehind or a case-insensitive
alternation at every position, which cost about 200 ms per MiB; one rule keyed on "tool"
ran on every agent message. Splitting rules so each has tight keywords and moving
boundary checks into validators halved the 1 MiB cost. Severity drives the action
(HIGH/CRITICAL block, MEDIUM/LOW log), so the bulk-email finding is evidence, not a
block. Alternatives considered: an ML classifier (Prompt Guard style) for injection.
Deferred, not rejected: it needs a model download and GPU or CPU time per call. The
deterministic rules are the explainable baseline it would be measured against, and
`docs/known-bypasses.md` lists what they miss. Also considered: Aho-Corasick over all
keywords (`pyahocorasick`). Rejected for now: a C dependency for a gain the benchmark
doesn't need yet.

**D-030 (2026-11-24) Approval runs through MCP elicitation, off the client reader loop.**
gatehouse acts as the server toward the client and sends `elicitation/create` under a
random `gatehouse-approval-<uuid>` id. The server can't predict that id, so it can't
answer for the user, and it can't collide with the server's own request ids. The answer
arrives on the client reader loop, which would deadlock if the call waiting for it ran
inline. So the router hands a call that needs approval to the stdio task group, and the
loop keeps reading. Fail-closed: anything except `accept` with `approve: true` denies,
including a timeout (`--approval-timeout`, default 120 s). After approval, gatehouse
re-checks the tool list: a server that changes tools during the prompt (a rug pull timed
to the approval) gets the call blocked. The prompt lists argument names, never values.
Alternatives considered:
- A terminal prompt on gatehouse's own TTY. Rejected: under an MCP client, gatehouse has
  no interactive terminal (stdin and stdout are the protocol).
- An out-of-band approval service (web page or chat). Deferred: it needs a network
  listener and auth, which is out of scope for a stdio proxy.
- Blocking with a "re-run after approving" message, like `gatehouse pin`. That stays the
  behaviour for clients without elicitation.

**D-031 (2026-11-24) Sentinel infrastructure is generated from the tested sources.** The
Bicep doesn't restate the table columns or the rule KQL. `detections/build_infra.py`
writes `infra/generated/columns.json` and `rules.json` from the event schema and the rule
YAML, and Bicep reads them with `loadJsonContent`. A test fails if they're stale. So the
rules deployed are byte-for-byte the ones validated in the Kusto emulator. The ingestion
path is a DCE plus a DCR with `transformKql: source`: gatehouse already redacts and
shapes events, and a transform would be a second, untested place where fields change.
CI compiles the Bicep and fails on BCP081 (unknown resource type or API version). Nothing
is deployed. The cross-server rule GH006 joins `response.*` findings on one server to
egress/exec calls on another in the same `AgentSessionId`; per-server wrappers can't see
that chain on their own. Alternatives considered:
- Hand-written ARM rule JSON. Rejected: it duplicates the KQL.
- The Sentinel "repositories" (CI/CD) feature. Not chosen: it needs a connected GitHub
  repo in the workspace, and a plain deployment shows the same thing more portably.

**D-032 (2026-11-24) The held-out set is written after the detectors, never tuned on, and
never gated.** I wrote both the scenarios and the rules, so the M2 numbers (97–100%) say
the rules do what they were designed for, not how they generalize. The held-out set is
the generalization estimate: 18 attacks and 6 benign scenarios, written after the rules
were frozen, in the phrasing an attacker or a real tool would use. Results: 6/18
prevented, 2/6 benign false positives. Rules are not changed in response: a fix would
make the set a training set. Misses go to `docs/known-bypasses.md`; a later rule change
needs a *new* held-out set to measure it. CI reports held-out results but doesn't fail on
them, for the same reason. Alternative considered: fix the obvious misses (hex decoding,
`find -delete`, globs) now. Rejected for this release: the honest 33% is more useful in
an evaluation than a tuned 70%, and each fix is listed with a reproducing scenario.

**D-033 (2026-11-24) Competitors are scored on what they're designed to do, and every
adjustment is disclosed.** Two adjustments: (1) gateward appends `<!-- gw:XXXXXXXX -->` to
every text result as its canary tripwire (`src/gateward/canary.py`). The harness strips
exactly that marker before comparing benign results and records how many it stripped.
Counting it would have made every benign scenario a false positive. (2) mcp-watchdog only
alerts, on stderr, so CRITICAL, HIGH and MEDIUM panels count as "alerted". LOW panels are
excluded because one fires on every session. Both tools run with default configuration
(neither has a policy file), in their own virtualenv, on the same runner and commit as
gatehouse. Alternative: compare only "prevented". Rejected: it would score mcp-watchdog
on a job it doesn't claim to do.

**D-034 (2026-11-24) Public-release hygiene is enforced by CI, not by a one-off check.**
gitleaks v8.24.2 scans the full history on every push in its own workflow, so docs-only
commits (which `ci.yml` skips) are scanned too. The 27 reviewed findings, all synthetic
canaries or vendor documentation examples, are ignored by fingerprint (commit, file, rule,
line) in `.gitleaksignore`, so the same string in a new place still fails. The README
demo GIF is rendered by VHS on Ubuntu from `demo/demo.tape` and committed by hand, so the
workflow needs no write access. Alternatives: an allowlist regex for "CANARY" (rejected:
it would also hide a real secret pasted next to that word); a bot commit of the GIF
(rejected: needs `contents: write`).

## 2026-11-27 (v2)

**D-035 (2026-11-27) v2 targets MCP 2026-07-28, read from the specification repository.**
Before writing protocol code I fetched the spec pages and the TypeScript schema from
`modelcontextprotocol/modelcontextprotocol` at commit `fdc75bd0668db05f5b43e4fc76c2e5aa54296a42`
(main, 2026-11-27): `docs/specification/2026-07-28/{changelog, basic/index, basic/versioning,
basic/transports/stdio, basic/transports/streamable-http, basic/patterns/mrtr,
basic/patterns/subscriptions, server/discover, server/utilities/caching, server/tools,
client/elicitation, basic/authorization/*}.mdx` and `schema/2026-07-28/schema.ts`. Fetched
2026-11-27. The facts the v2 design depends on, all checked against that text:
- No `initialize`; every request carries `io.modelcontextprotocol/protocolVersion` and
  `io.modelcontextprotocol/clientCapabilities` in `_meta` (missing → -32602).
  `server/discover` is mandatory for servers. Version mismatch → -32022 with
  `data.supported`.
- Error codes: -32020 HeaderMismatch, -32021 MissingRequiredClientCapability, -32022
  UnsupportedProtocolVersion. -32000…-32019 is a legacy range new code should not use.
- Every result carries `resultType` (`complete` or `input_required`); unknown values are
  invalid; absent means `complete` only for earlier-protocol servers.
- MRTR: `InputRequiredResult` with `inputRequests` (elicitation/create,
  sampling/createMessage, roots/list only) and an opaque `requestState`, allowed only on
  `tools/call`, `resources/read`, `prompts/get`. The retry is a new request id carrying
  `inputResponses` and the echoed `requestState`.
- **On stdio the server MUST NOT write JSON-RPC requests**, and on Streamable HTTP it must
  not send requests on any stream. So in the modern era gatehouse's own approval prompt
  (D-030, a server-initiated `elicitation/create`) is not allowed: it has to be an MRTR
  `InputRequiredResult`.
- **"An open connection, such as a STDIO process, is not a conversation or session."**
  Clients may cache `tools/list` (`ttlMs`) across processes, so the D-011 rule "a call
  must follow a listing inspected in this process" can't be assumed to hold.
- Streamable HTTP: `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers are
  required and must match the body (else 400 + -32020); `x-mcp-header` mirrors tool
  parameters into `Mcp-Param-{Name}` with a `=?base64?…?=` sentinel encoding; no sessions,
  no GET stream, no resumability; `subscriptions/listen` replaces both.
- `ttlMs` and `cacheScope` are required on `server/discover`, `*/list` and
  `resources/read` results. `cacheScope: public` lets shared intermediaries reuse a
  response across authorization contexts.
- `serverInfo`/`clientInfo` are self-reported and "SHOULD NOT" drive security decisions;
  tool annotations are untrusted unless the server is trusted.
The SDK used for interop tests (`mcp` 2.3.0, already the pinned dev dependency) implements
this revision on stdio and Streamable HTTP, with a dual-era `mode="auto"` client that probes
`server/discover` and falls back to `initialize` on any error except a disjoint -32022
(`mcp/client/_probe.py`).

**D-037 (2026-11-27) Session flow control stays the core of v2, but it is not a first.**
The landscape check (`docs/research/landscape-2026-11.md`) found that Pipelock already
ships a `lethal-trifecta` chain detector at its MCP proxy (`internal/mcp/chains/matcher.go`
at `aef5bade83`), and that AWS AgentCore Policy's Dogwood language adds session-aware
temporal policies. The roadmap's working rule says to stop an item when a competitor
already does it and pick the next-best option. I checked what they actually do. Pipelock's
check is an *ordered* untrusted → sensitive → sink subsequence inside a 20-call / 60-second
window, with tools classified by keywords in their (server-chosen) names. It warns by
default, and stdio MCP results raise no taint unless declared external. AgentCore's
temporal policies are a managed-gateway feature. Neither tracks values from a result into
a later argument. So the item continues, with three changes:
- **No novelty claim.** README and docs say gatehouse implements the Rule of Two at the
  proxy and cite Pipelock's trifecta detector and AgentCore Dogwood as related work.
- **The differences become design requirements and are tested:** order-independent (any
  order of the three properties trips it); no time window (the whole agent session, across
  every wrapped server); labels from the policy, never from tool names or annotations;
  value-level provenance as evidence on egress; invariants provable in CI.
- **Pipelock with its `strict` preset joins the M6 comparison** on the `flow.*` chains,
  including padded chains (more than 20 calls, or a pause longer than 60 s) and reordered
  ones, because those are exactly where the designs differ.
Alternatives considered: drop flow control and compete on detection (rejected: the
held-out set shows detection is the weak layer); claim novelty for the cross-server part
(rejected: not verified that no one else does it).

**D-038 (2026-11-27) Cedar via `cedarpy`; proofs via the Cedar CLI's `symcc` in Linux CI.**
`cedar-python` (0.1.4) requires Python ≥ 3.12 and gatehouse supports 3.11, so the plan's
primary choice is out. `cedarpy` 4.12.2 (`k9securityio/cedar-py`, Apache-2.0) has wheels
for Windows, Linux and macOS on cp310–cp314 and passed an `is_authorized` smoke test with
context conditions on Windows under 3.11, 3.12 and 3.13. It sits behind gatehouse's own
`PolicyEngine` interface so it can be swapped. No Python package does symbolic policy
analysis in-process, so `gatehouse policy prove` writes the Cedar policy and schema to
files and runs `cedar symcc …` from cedar-policy-cli 4.15.0 (experimental flavour, needs
the cvc5 solver), installed only in a Linux CI job. Without the CLI, `policy prove` falls
back to a bounded check that enumerates the generated schema's actions against
representative contexts, and says so in its output. Alternatives: cedar-python's
`cedar.lean` (shells out to Lean + cvc5 as well, and is 3.12+), or a small Rust prover on
`cedar-policy-symcc` (more code to maintain).
