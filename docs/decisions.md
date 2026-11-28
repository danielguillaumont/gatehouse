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

**D-036 (2026-11-27) One gatehouse, two protocol eras; approval for 2026-07-28 clients goes
through MRTR.** The 2026-07-28 revision removes `initialize`. Each request carries its
version and client capabilities in `_meta`, and servers may answer `tools/call`,
`prompts/get` and `resources/read` with an `InputRequiredResult`, which the client then
retries. gatehouse keeps the 2024-11-05 … 2025-11-25 handshake and adds the new era:
- **Era latching.** A connection's era is set by its first request other than
  `server/discover`: `initialize` means legacy, and a `_meta` protocol version means
  modern. Mixing them gets -32600 and `protocol.era_conflict`. A modern request with a
  broken envelope gets -32602 and `protocol.invalid_meta`. A modern version gatehouse
  can't inspect gets -32022, which lists the versions it can. Requests with neither are
  forwarded as in v0.1, because a client is allowed to probe.
- **`server/discover` is forwarded and inspected.** In v0.1 gatehouse answered it with
  -32601 so that clients fell back to the handshake. Now:
  - `supportedVersions` is filtered to versions gatehouse inspects;
  - `instructions` are scanned like a tool description, and removed if they would block;
  - `ttlMs` is capped;
  - modern versions are pinned per server.
  A discover error after a server was pinned as modern is a downgrade
  (`protocol.downgrade`, HIGH), and so is a version that disappears from
  `supportedVersions`. The policy refuses it unless `protocol.allow_downgrade` is set,
  and the later `initialize` gets -32022. The same applies when the client asks for the
  pinned legacy revision and the handshake negotiates an older one.
- **`resultType` is validated.** A missing `resultType` is treated as complete and
  logged, as earlier servers omit it. `input_required` on a method that may not use it,
  or any unknown value, is withheld, because gatehouse can't inspect what it doesn't
  understand (ADR-0001).
- **MRTR from servers is inspected, not trusted.**
  - Each input request must use a capability the request declared.
  - Elicitations are checked for credential fields, phishing URLs and impersonation of
    gatehouse.
  - Sampling requests get the injection rules, or are refused when the policy sets
    `protocol.sampling: block`.
  - A `requestState` that imitates gatehouse's own is flagged.
  Anything flagged is withheld, since nothing can be approved after the fact. What the
  user answers is scanned for secrets: `inputResponses`, and legacy elicitation results.
  A hit blocks the call, or the server gets a decline. On stdio, a modern server must
  not send JSON-RPC requests at all, so gatehouse drops any it sends.
- **Approval through MRTR.** A modern client can't be sent an `elicitation/create`
  request. So gatehouse answers a `require_approval` call with its own
  `InputRequiredResult` that asks the user to approve. The client's retry carries
  gatehouse's `requestState`, which is:
  - HMAC-signed with a key derived from the install key;
  - bound to the method, tool and argument fingerprint;
  - valid for 10 minutes, and redeemable once.
  gatehouse strips its own fields before forwarding, so the server sees a plain request.
  It also records a short grant for that exact call (10 minutes, 8 uses), so the
  server's own MRTR rounds for it don't prompt the user again. Without the elicitation
  capability, the call is blocked.
- **Stateless calls get a fresh listing.** A modern client may call a tool it listed in
  another process or took from its cache. If this connection has no inspected listing,
  or its listing is stale, gatehouse lists upstream itself. It runs the usual pin and
  definition checks on that listing, and only then decides. A timeout fails closed.
- **Caching and subscriptions.** A listing gatehouse filtered is marked
  `cacheScope: private`, so a shared cache can't serve one policy's view to a caller
  behind another policy. Subscription notifications must match a `subscriptions/listen`
  on the same channel and its filter; any others are dropped.
Alternatives considered:
- Keep answering `server/discover` with -32601 and force every client onto the
  handshake. Rejected: 2026-07-28 servers may drop the handshake, and SDK 2.3.0 already
  defaults to `mode="auto"`.
- Terminate the protocol and run SDK client and server objects back to back. Rejected:
  it violates message-level proxying, and new fields would be lost.
- Approve by blocking with a message. Kept only for clients without elicitation.

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

**D-039 (2026-11-27) Streamable HTTP: a raw ASGI reverse proxy that rebuilds upstream
headers from the inspected body.** `gatehouse serve --upstream URL` puts the same router
in front of a Streamable HTTP server. Design:
- **One channel per POST, one shared session per era.** Each downstream POST gets its
  own `Router` with its own pending-request map, so subscription notifications and MRTR
  results are matched to the request that opened them. All 2026-07-28 requests share
  one `Session`, so a listing inspected on one request governs calls on the next.
  Legacy clients get one `Session` per `Mcp-Session-Id`. That id is issued by gatehouse
  and mapped to the upstream's own id, so upstream ids never leave gatehouse and can't be
  guessed downstream. An unknown id gets 404, a missing one 400, as the spec requires.
- **Header/body consistency on ingress.** A 2026-07-28 request whose
  `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` or `Mcp-Param-*` headers disagree with
  the body gets 400 / -32020 and `protocol.header_mismatch` before the router sees it.
  So does a duplicated routing header. Rule order and value comparison (including the
  `=?base64?…?=` sentinel and numeric comparison of integer parameters) follow the
  spec and SDK 2.3.0's `mcp/shared/inbound.py`, so a conforming client gets the same
  answer from gatehouse as from a conforming server.
- **Headers are rebuilt upstream, never forwarded.** gatehouse computes the upstream
  routing headers from the body it actually sends, using the tool definition it
  inspected for `Mcp-Param-*`. The client's `Authorization`, cookies and every other
  header are dropped, except `traceparent` and `tracestate`. Upstream credentials come
  from gatehouse's own configuration (`--upstream-bearer-env`). The authorization spec
  forbids token passthrough, so there is no option to forward the client's token.
- **x-mcp-header is enforced in HTTP mode.** An invalid annotation (CR/LF or a separator
  in the name, a duplicate, a non-primitive type, unreachable through `properties`)
  removes the tool from the listing, as the spec requires of HTTP clients. On stdio it
  is reported at LOW, since stdio clients may ignore the annotation. A parameter that
  looks sensitive and is mirrored into a header is reported at MEDIUM: every
  intermediary and access log sees headers.
- **Transport hygiene.** It listens on loopback by default (`--allow-remote` to change
  that). A foreign `Origin` gets 403 and a foreign `Host` gets 421, against DNS
  rebinding. Bodies and SSE events are size-bounded. Batches are rejected. GET gets 405,
  since 2026-07-28 has no GET stream and 405 is the allowed answer for legacy servers
  that offer none. uvicorn's access log is off: it would write request lines to stdout,
  and gatehouse's events are the audit trail.
- **Downstream framing mirrors upstream.** If the upstream streams (SSE), so does
  gatehouse, frame by frame after inspection. Single responses, and anything gatehouse
  answers itself, go back as JSON with the status the spec assigns to each error code.
- **Legacy approval prompts are off over HTTP.** The user's answer to a gatehouse
  `elicitation/create` would arrive on another POST, so legacy `require_approval` calls
  are blocked. 2026-07-28 clients approve through MRTR (D-036), which works over HTTP.
- **Raw ASGI and httpx2, not Starlette and httpx.** The plan named Starlette. The proxy
  needs one task group that spans the upstream exchange and the downstream response
  (JSON or SSE, decided by the first upstream frame), which plain ASGI expresses
  directly. Starlette's response classes would have had to be worked around. httpx
  0.29.0 was uploaded on 2026-11-26, too recently to adopt. `httpx2` (pydantic/httpx2)
  is the maintained fork the MCP SDK 2.3.0 itself depends on, so the dev lock already
  tests it. The `gatehouse[http]` extra is `httpx2` + `uvicorn`.
- **Upstream stream resumption is gatehouse's job (added 2026-11-27 after the
  conformance run).** When a 2025-11-25 upstream closes an SSE stream before answering
  (polling, SEP-1699), gatehouse resumes it itself with GET + `Last-Event-ID` on the
  upstream session, at most 5 times. The client gets the inspected answer on its
  original stream. Upstream event ids, priming events and `retry` hints are not
  passed downstream, so a client never resumes against gatehouse. That means
  gatehouse needs no event store and has no unauthenticated GET path into the session.
  Without an event id, the request fails at once instead of at the request timeout.
- **A 2026-07-28 header classifies the request.** A request whose
  `MCP-Protocol-Version` header names 2026-07-28 but whose envelope is missing gets
  400 / -32602 from gatehouse, as from a 2026-07-28 server. It used to be treated as
  legacy and sent upstream without a session. -32022 for an enveloped request lists the
  versions discover advertised through gatehouse.
Known limits: the event context (client name, protocol version) is shared across
concurrent requests, so with several clients at once an event can carry another
request's client name. Server-initiated legacy streams (GET) are not offered.
Alternatives considered: forwarding the client's headers and only validating them
(rejected: one parser difference away from smuggling); terminating MCP and re-issuing
requests through the SDK client (rejected: violates message-level proxying).

**D-040 (2026-11-27) Policy engine v2: YAML compiles to Cedar; a native evaluator is
the reference; argument conditions and flow labels are additive to schema v1.**
- **One authoring format.** Policies stay YAML (`version: 1`, all new keys optional, so
  every v0.1 policy means what it meant). New: per-rule `when:` argument conditions
  with an `otherwise:` action, per-server `labels:` (capability labels per tool
  pattern), a top-level `flow:` block (Rule-of-Two mode), and an optional
  `cedar_forbid:` file of extra Cedar `forbid` policies.
- **Two engines, one semantics.** `PolicyEngine.decide(AuthzRequest)` has two
  implementations. The native evaluator (the v0.1 engine, extended) is the reference.
  The Cedar engine compiles the policy to Cedar, evaluates it with cedarpy, and runs
  by default. Property-based tests (hypothesis) generate random policies, names,
  condition outcomes and labels and require both engines to agree. At runtime the
  native engine also explains the decision (matched rules, basis); if the two ever
  disagree, gatehouse takes the stricter action and emits
  `policy.engine_disagreement`. A missing or broken cedarpy is a policy load failure,
  so every call is blocked (fail closed).
- **Precedence in Cedar.** Cedar has forbid-overrides-permit and default deny, and no
  "most specific wins". The compiler encodes it explicitly, using two actions:
  - `call` is permitted means allow. Otherwise `call_with_approval` permitted means
    require approval. Otherwise the call is blocked.
  - A rule with conditions becomes two variants: conditions hold (`action`), and
    conditions fail (`otherwise`).
  - A block variant is a `forbid`.
  - An allow variant permits `call` only if it is a winner (no matching rule
    dominates it) and no approval variant that it doesn't dominate is also a winner.
    That is the v0.1 tie rule.
  - Every non-block winner permits `call_with_approval`.
  - The default action applies when no rule matches.
- **Names in Cedar.** Exact patterns compile to `==` and `*`-only globs to `like`, so
  analysis is exact for them. Patterns with `?` or `[...]` cannot be expressed in
  Cedar. gatehouse computes them (`fnmatchcase` on normalized names, as in v0.1) and
  passes them as entity-group membership, which analysis treats as unconstrained.
  Proofs are therefore sound but may report counterexamples that can't happen for
  those patterns; they never prove something false.
- **Argument conditions are gatehouse's pure functions, not Cedar expressions.** The
  condition kinds are:
  - `email_domains`, `url_hosts` (exact or `*.` suffix);
  - `path_under` (lexically normalized, `..` escapes fail);
  - `max`/`min` (numbers only, bools rejected);
  - `one_of`.
  Each applies to every value in a string or list argument, and a missing or
  unparseable argument fails the condition. The results reach Cedar as
  `context.when`, the set of rule ids whose conditions hold. Parsing emails, URLs
  and paths inside Cedar isn't possible, and conditions as opaque booleans keep
  proofs sound. `otherwise` must be stricter than `action`, so a condition that
  can't be evaluated always yields the stricter outcome.
- **Rule of Two** (Meta, 2025: an agent should have at most two of untrusted input,
  private data, and state change/external communication).
  - Labels are `untrusted_input`, `private_data`, `state_change`, `egress`. They come
    from the policy. Server annotations and the v0.1 name heuristic can only *add*
    labels, because a server choosing its own labels could otherwise remove them.
  - A call violates the rule when the session's labels plus the tool's labels cover
    all three properties and the tool contributes at least one.
  - Modes:
    - `off` is the default, for v0.1 compatibility;
    - `monitor` logs `flow.rule_of_two`;
    - `approve` turns allow into require approval;
    - `enforce` blocks.
  - In Cedar this is a `forbid` on `call` (approve) or on both actions (enforce), so
    `policy prove` can check flow invariants.
  - A tool's labels join the session when gatehouse forwards the call. A detected
    injection in a result adds `untrusted_input` whatever the tool's labels.
- **Session labels are shared across servers.** One gatehouse process per server means
  flow state must be shared: a SQLite store (WAL, busy timeout) keyed by
  `AgentSessionId`, in the state directory. Labels are a grow-only set written with
  `INSERT OR IGNORE`, so concurrent writers cannot lose an update. The v0.1 pin
  store (D-010) lost updates under lock contention (fixed in `7577e2d`), so a stress
  test runs 40+ concurrent writers.
Alternatives considered:
- Cedar only, with no native engine: no reference to test the compiler against, and
  no explanation for events.
- Rule ids passed as entity groups for every pattern: proofs would lose exactness even
  for exact names.
- Conditions written in Cedar: no email/URL/path parsing in Cedar.
- A broker process for the session store: more moving parts than a grow-only table
  needs.

**D-041 (2026-11-27) `gatehouse policy prove`: invariants are policy-set implications,
proved by SymCC in Linux CI and checked by a bounded enumerator everywhere.**
- **Invariants** are a separate YAML file (`examples/invariants.yaml`), not part of the
  runtime policy. Each names a scope (server/tool `*` globs, tool labels, session
  labels) and `never: allow` (never allowed without a human) or `never:
  allow_or_approve` (always blocked). Each compiles to a Cedar policy `Q` that permits
  everything outside the scope, and the check is `P => Q` for the forbidden action(s),
  with `P` the compiled policy.
- **SymCC through the CLI.** `cedar symcc … implies --policies1 P --policies2 Q` from
  cedar-policy-cli 4.15.0, built with `--features analyze`, plus cvc5 1.3.1 (the
  version the cedar-policy-symcc README pins; the release zip is checked against the
  digest in its GitHub release metadata).
  - The CLI exits 0 when a property does **not** hold. It prints `DOES NOT HOLD` and a
    counterexample (checked in `cedar-policy-cli/src/command/symcc.rs` at v4.15.0), so
    gatehouse reads the verdict from the output and treats anything else as an error
    (exit 2), never as a pass.
  - Verified here: the CLI builds on Windows from crates.io, accepts gatehouse's
    arguments (it got as far as "CVC5 solver not found"), and `cedar validate` accepts
    the compiled policy against gatehouse's schema with no warnings. Running cvc5 on the
    development machine was not possible, so the proofs themselves run in the
    `policy-prove` workflow (Linux) only.
- **The bounded check is the fallback and runs first.** It builds names that match each
  pattern and names that just miss it (`rm_?` gives `rm_q` and `rm_qq`), adds pinned
  tools if `--pins` is given, and enumerates every outcome of the matching rules'
  conditions.
  - It doesn't enumerate label sets. Labels only occur in `forbid` policies and only
    through `contains`, so adding a label can only make a decision stricter (a
    hypothesis test checks this). The most permissive request in scope therefore
    carries exactly the invariant's labels.
  - A bounded counterexample is concrete and always wins over a symcc "verified". It
    can't prove absence beyond what it enumerated, and its output says "not a proof".
- **Policy labels are compiled into Cedar.** A tool carries a label if the request says
  so (hints) or a `labels:` pattern matches it. The first version of the encoding only
  read labels from the request, so a proof treated `send_email` as possibly unlabelled.
  `policy prove` found that gap on the example policy. The reference evaluator now also
  always adds the policy's labels, so a caller can't leave them out.
- **"Schema generated from pinned tools" (roadmap) is reinterpreted.** A Cedar schema
  can't restrict a string attribute to the set of pinned names. Pinned tools instead
  become `entities.json` from `policy compile --pins` (labels included) and the
  bounded check's universe. The symbolic proof covers every name, which is stronger
  than covering the pinned ones.
- Two real bugs in the first drafts of `examples/policy-flow.yaml`:
  - **The bounded check found the first.** `delete_*: require_approval` left a tool named
    `delete` (or `bulk_delete`) allowed by `"*": allow`.
  - **SymCC found the second; the bounded check had missed it.** On `mail`,
    `read_*: allow` also allowed a tool named `read_delete`. A server-specific glob
    beats a global rule, so the global `*delete*` didn't apply (CI run 46093960682,
    counterexample `mail/read_delete`). The bounded check now also builds names that
    match a policy pattern and an invariant pattern at once, and says when it hits its
    pair cap.
  - The symbolic proof is the guarantee; the bounded check is a fast local screen.
Alternatives considered:
- Invariants inside the policy file: whoever edits the policy would also edit what it
  is checked against.
- Raw Cedar invariants: more expressive but unreviewable for most operators. They can
  be added later as an `expert:` key.
- A small Rust prover on `cedar-policy-symcc`: more code to maintain than parsing two
  CLI output lines.

**D-042 (2026-11-27) Flow state: SQLite WAL, grow-only rows, fail closed on both read
and write.** The roadmap left the choice open between "SQLite WAL with a single-writer
discipline" and "a tiny local broker, pick by measuring". The store holds a grow-only
set, so there's nothing to merge and no single writer is needed. Each fact is one
`INSERT OR IGNORE` row keyed `(session, kind, value)`, and concurrent processes can't
lose an update.
- **Measured** (`tests/state/test_flow_store.py`, Windows 11, Python 3.12): 48 writer
  processes, 40 provenance facts and 40 label writes each, against one database: 1920/1920
  facts present, about 15 s including process start-up. A broker would add a process to
  supervise and a socket to protect, for no correctness gain.
- **Reads and writes are synchronous** in the router. Each is one indexed query on a
  local file. The busy timeout is 2 s, so a long lock wait blocks only the call that hit it.
- **Failures:**
  - An unreadable store counts as holding every label.
  - An unwritable store blocks the call, or withholds the result for an injection
    taint, and emits `gatehouse.internal_error` with `Component: flow_store`. So
    ADR-0001's single fail-open path (telemetry loss) stays the only one.
  - A store that can't be opened at start-up is replaced by one that fails every
    operation, so the same rules apply.
- **Retention.** Rows older than 14 days are deleted when a process opens the store.
- **What counts as a taint from a result.** A finding from `response.injection` or
  `text.invisible` on a result that is delivered (findings mapped to `log`). A withheld
  result never reached the agent, so it adds nothing.
Alternatives considered:
- A per-process in-memory set: misses every cross-server chain, which is the whole point.
- The JSON pin-store pattern (lock file plus atomic replace): the read-modify-write that
  lost updates in v0.1.
- A broker: see above.

**D-043 (2026-11-27) Provenance: winnowed, keyed span fingerprints of private results,
checked against egress arguments.** The roadmap asks for "provenance fingerprints
(`private_data` results checked against `egress` arguments)" without saying how.
- **Spans.** gatehouse normalizes the text (NFKC, casefold, invisible characters
  removed, whitespace collapsed) and winnows its 24-character substrings with a window of
  16 (Schleimer, Wilkerson and Aiken, SIGMOD 2003). Any shared substring of K + W - 1 =
  39 characters shares a selected substring, whatever surrounds it. A match needs two
  span fingerprints, which a copy of 55 characters always gives (a hypothesis test
  checks this; periodic text such as `0000…` has too few distinct substrings and is
  excluded).
- **Encodings.** Argument strings are also checked after base64, base64url, hex and
  percent decoding, so `?d=<base64 of the note>` matches.
- **Secrets.** A secret the secrets detector finds in a private result is recorded by its
  HMAC, and the same secret in an egress argument is an exact match.
- **Storage.** Fingerprints are the per-install HMAC truncated to 64 bits, stored as
  flow-store facts of kind `fp` with the server and tool that produced them. The store
  never holds text, and without the key a fingerprint can't be tested against a guess.
- **Decision.** A match emits `flow.provenance_match`. If the session also holds
  `untrusted_input` it is high severity and maps to `flow.provenance` (default
  `require_approval`). Otherwise it is medium and logged: forwarding your own notes to a
  colleague is a normal task.
- **Fail closed.**
  - A private result whose fingerprints can't be recorded is withheld.
  - An egress call whose arguments can't be checked gets a high-severity
    `provenance-unavailable` finding.
- **Bounds.** 32 KiB of text per result or argument set, 8192 fingerprints per result
  and 64 decoded variants.
- **Measured** (Windows 11, Python 3.12.2, median of 15):
  - a 4 KiB result takes 15 ms and a 32 KiB result 141 ms, both in a worker thread;
  - egress arguments take 0.6 ms at 200 bytes, 7 ms at 2 KiB and 117 ms at 32 KiB,
    inline, and only for egress-labelled tools.
- **Limit.** A paraphrase or summary of private data doesn't match. Provenance is
  evidence for the SOC and the approval prompt, not the guarantee. The Rule of Two is the
  guarantee, and it doesn't depend on spotting the copy.

Alternatives considered:
- Exact hashes of whole results: a one-character change defeats them.
- Embedding similarity: needs a model in the data path, isn't keyed, and can't be bounded
  as tightly.
- Storing the text: unacceptable under the redaction invariant.

**D-044 (2026-11-27) Response controls: one control store, a kill file, replayed
quarantine releases, grants only for structural approvals.** The roadmap lists
quarantine and review, scoped grants, an approval budget, a circuit breaker and a kill
switch (file, signal, CLI) without saying how they fit together. ADR-0006 has the
architecture. These are the choices within it:
- **Kill switch.** The file `<state dir>/KILL` is checked on every call and every
  result. When it's absent, the check is one failed `open`.
  - Engaged: every tool call is blocked (`DecisionBasis: kill_switch`) and in-flight
    results are withheld. Each process emits `control.kill_switch` once per change.
  - SIGUSR1 kills one process (POSIX only).
  - Other methods (`initialize`, `tools/list`, `ping`) still flow, so the client sees
    why calls fail rather than a dead server.
- **Circuit breaker.**
  - One strike per call or result that has at least one high or critical finding.
    Ten findings in one result count as one strike.
  - Gatehouse's own `provenance-unavailable` doesn't count.
  - Default threshold: 5 per agent session, with no window. A session that has been
    blocked five times for high findings is either under attack or misconfigured, and
    either way a human should look.
  - Locks are shared across servers. `gatehouse unlock` resets the strikes.
- **Approval budget.**
  - Default: 20 prompts per agent session per 60 minutes.
  - Spent only when a prompt is actually shown (MRTR or elicitation), not for calls
    that can't be asked anyway.
  - Past the budget the call is blocked (`approval_budget`) with a pointer to
    `gatehouse grant add`. Approval fatigue is the risk the roadmap names. Blocking
    asks the human for one deliberate grant rather than many reflexive yeses.
- **Scoped grants.**
  - A grant has a server, a tool glob, rule-style argument conditions, a TTL (at most 7
    days) and optional uses.
  - It answers a `require_approval` only when nothing but the policy decision asked for
    approval. That includes Rule-of-Two approvals, which are part of the decision. It
    excludes detector findings, tools flagged at listing time and provenance matches.
  - A grant spends one use per call, atomically. A grant whose conditions don't parse
    grants nothing.
- **Quarantine.**
  - Only results withheld for findings are kept. A withheld result because the flow or
    control store failed, or because the kill switch is engaged, isn't kept: it wasn't
    judged.
  - Payloads over 1 MiB are withheld but not kept. At most 1000 items are kept, for 7
    days.
  - Release delivery replays the stored result on the next identical call (ADR-0006).
- **Self-protection.** A new rule, `args.self_protect/gatehouse-control-command`
  (high), covers `review show|release|discard`, `grant add|revoke`, `unlock` and
  `kill --off`, with or without `.exe`, `uv run` or `python -m`.
  - Read-only commands (`status`, `review list`) and engaging the kill switch stay
    allowed: an agent that stops itself is fine.
  - It's a new scenario set (`self.*`, milestone `m5`) with a benign twin full of
    near-miss words (`benign.gatehouse-words`). It wasn't tuned on held-out data.
- **Failures** (all fail closed):

  | Failure | Behaviour |
  |---|---|
  | Unreadable kill file | engaged |
  | Unreadable locks | session locked |
  | Strike not recorded | this process locks the session |
  | Budget unreadable | not asked, so blocked |
  | Grants unreadable | none apply |
  | Quarantine write fails | still withheld |
  | Store can't open at start-up | a stand-in that fails every operation except the kill file |

  Each emits `gatehouse.internal_error` with `Component: control_store`.
- **Measured** (Windows 11, Python 3.12.2, `timeit` over 20,000 runs):
  - Per-call overhead is about 0.1 ms: the kill-file check 73 µs, the lock read 13 µs,
    and the released-result check 14 µs.
  - The released-result check reads first and takes the write lock only when something
    has been released. Before that change it was 66 µs, and it serialized every call
    across processes.
  - `tests/state/test_control_store.py` runs 16 processes × 25 strikes and 25 prompts
    against one database, and every increment is counted.

Alternatives considered:
- Locks and grants in the grow-only flow store: they need delete and decrement.
- A gatehouse-owned `quarantine_release` tool in `tools/list`: it would change what the
  server offered and would need its own pin and policy story.
- Grants covering detector approvals: they would pre-approve exactly what an injection
  asks for.
- A time window on the breaker: an attacker could pace its attempts.

**D-045 (2026-11-28) flow.* scenarios: several real gatehouse processes, scripted
agent, a user who declines attacks and approves benign tasks.** The M5 acceptance is
"0 `flow.*` chains complete in approve/enforce" and "the README reports approvals per
benign task". Measuring that honestly needed these choices:
- **Real processes.** Each server in a scenario runs behind its own `gatehouse run`,
  sharing `GATEHOUSE_HOME` and `GATEHOUSE_AGENT_SESSION_ID` as the processes under one
  agent do. That way the SQLite flow store is exercised across processes, not just
  within one router (`attacks/harness.py`, `servers:`).
- **The agent is scripted and always follows the injection.** That's the worst case for
  gatehouse. A chain "completes" when the server receives the exfiltrating call (or,
  for the reverse-order chain, when the private result reaches the agent).
- **The injections are written to pass the content rules.** They're polite requests
  with no trigger phrases, and the results show no `response.injection` finding on any
  of them. So a prevented chain is prevented by structure: `tool.call/flow` is the only
  enforcing detection, with provenance adding evidence on the two verbatim copies.
- **The simulated user** declines gatehouse's approval prompts in attack scenarios and
  accepts them in benign tasks (`user_approves: true`).
  - This models a user who reads the prompt. A user who approves everything turns
    `approve` into `monitor`, and that row is in the table too.
  - Approvals per benign task count `approval.requested` events.
- **Benign tasks** cover each two-property combination, which needs no approval, and
  the three-property tasks a real user does, which need one: research then email,
  inbox reply, issue then note. The set is small. The 200+ benign corpus is M6.
- `python -m attacks flow` runs every flow-policy scenario under all three modes. CI
  fails if a chain completes in approve or enforce, or if a benign task fails in
  monitor or approve. Enforce is expected to block the three-property benign tasks, and
  the table reports that.

**D-046 (2026-11-28) Held-out v2: written seeds, a deterministic mutation engine and
frozen model rewrites, hashed before any M6 detector change.** The M3 held-out set (18
hand-written attacks) was too small to say much. Its misses are now public and are what
the M6 rule fixes address, so measuring those fixes on it would make it a tuning set
(D-032).
- **Seeds first.** `attacks/heldout2/seeds.yaml` has 34 attack seeds and 20 benign ones,
  written on 2026-11-28 after v0.2.0 and committed (`d8643f5`) before any M6 code. Each
  attack seed has a `marker`: the attacker's goal (an address, a host, a path, a
  secret).
- **Deterministic operators** (`attacks/heldout2/mutate.py`):
  - lexical substitution from a fixed table;
  - zero-width characters, Cyrillic homoglyphs and upper case, all outside the marker;
  - base64, ROT13, hex and percent encoding;
  - splitting across content blocks, schema fields or arguments; nesting in
    structured content or objects; HTML comments, `<details>` and code fences;
  - for shell commands: `r''m`, `${IFS}`, `base64 -d | sh` and PowerShell
    `-EncodedCommand`;
  - for paths: `/./`, `x/../`, doubled separators, case and `$HOME`.

  Meaning-preserving operators keep the marker verbatim. Encodings change it, and their
  success condition is a slice of the encoded payload.
- **Model rewrites.** A paraphrase, a German and a Spanish version of every prose seed
  come from Qwen2.5 7B (Apache-2.0) on Ollama 0.40.16, at temperature 0 and seed 7.
  - They were generated once in the `heldout2-llm` workflow
    ([run 46102494282](https://github.com/danielguillaumont/gatehouse/actions/runs/46102494282))
    and committed as `llm.json`.
  - 79 of 84 rewrites kept the marker. The other 5 are dropped, not repaired.
- **Frozen.** `MANIFEST.json` holds the SHA-256 of the seeds, the generator, `llm.json`
  and the output (CRLF folded to LF).
  - `tests/attacks/test_heldout2.py` and `mutate --check` in CI fail if any of them
    changes, or if the generator no longer reproduces the output.
  - Result: 330 attacks and 119 benign scenarios, milestone `m6`, kept out of the main
    suite.
  - Like `m3`, it's measured and never gated: a false positive here doesn't fail CI.
- **Honest limits.**
  - The seeds were written by the same author as the detectors, so they're less
    independent than an outside set. The external corpora (D-047) cover that.
  - The lexical table is a weak paraphrase. The model rewrites are the real one.
  - The mutation operators were chosen knowing which kinds of evasion exist. They
    weren't chosen knowing which ones gatehouse misses: no gatehouse run informed them.
    Only one seed's variants were run, as a smoke test of the generator.
- **Alternatives:**
  - generating at test time: rejected, because a mutation engine that can change can
    be tuned against;
  - committing the model weights or running the model locally: rejected, because the
    output is what has to be frozen, not the model.

**D-047 (2026-11-28) External corpora are fetched at pinned commits in CI and converted,
never committed.**
- **MCPTox** (zhiqiangwang4/MCPTox-Benchmark at `630121b`):
  - its benchmark data is CC BY 4.0 "to the extent the MCPTox contributors hold the
    rights", and the authentic tool definitions come from third-party servers. So
    nothing is committed;
  - `python -m attacks.external prepare` downloads `pure_tool.json` and
    `response_all.json`, checks pinned SHA-256 digests, and converts them;
  - **485 poisoned tools** each become one listing scenario next to their server's
    authentic tools;
  - **362 authentic tools** each become one benign listing scenario. That's the
    real-definition part of the 200+ benign corpus.
- **agent-egress-bench** (v1.2.0, commit `451a5db`, Apache-2.0): only the `mcp_stdio`
  cases are converted, 32 attacks and 12 benign. 28 are skipped and listed in
  `SOURCES.json`:
  - `mcp_http` transport;
  - call-budget cases;
  - `initialize` instructions, which the mock server doesn't serve;
  - one tool with no name.

  The digest covers every case file, so a changed corpus fails `prepare`.
- **Changes from the originals** are listed in the `attacks/external.py` docstring, as
  CC BY requires: each case is re-expressed as a scripted stdio scenario, and success
  is "the client or server received the payload unchanged". That's stricter for
  gatehouse than the corpora's own verdicts: a `warn` doesn't count.
- **Alternative:** vendoring a subset. Rejected, because of the third-party rights in
  the authentic definitions.

**D-048 (2026-11-28) Ablation and comparison: one workflow run, named layer overlays, a
user who approves benign prompts.** The M6 acceptance is "one command per table, every
number links to a workflow run".
- **Layers are overlays, not separate policies** (`attacks/layers.py`). Each row merges
  `pinning`, `findings` and `flow.mode` into the policy the scenario would use anyway,
  so the rows differ only in the layers.
  - The rows are `observe`, `pinning`, `detectors`, `v0.1` (detectors + pinning),
    `structural` (pinning + flow control, with detectors only logging) and `full`.
  - `structural` is the row that answers "what if every content rule is evaded".
- **Prompts are counted, not scored as false positives.** In ablation runs the scripted
  client offers elicitation, and the simulated user approves gatehouse's prompts in
  benign scenarios and declines them in attacks (as in D-045).
  - So a benign task that needs a prompt costs a prompt, and the table reports prompts
    per benign scenario next to the FP rate.
  - Without this, every flow-control row would look like a false-positive machine.
    With it, the prompt rate is the honest cost to read.
- **One workflow** (`.github/workflows/evaluation.yml`): ablation (layers × sets),
  baseline (direct × sets), compare (other gateways × sets) and latency (bench per
  layer, one runner) all run on one commit. Then `python -m attacks.evaluate collate`
  builds the tables, and the run URL goes in the header.
- **Bypass scenarios** (milestone `bypass`) are excluded from "attacks to prevent" in
  these tables. They're documented misses, kept to show the suite can fail.
- **Alternatives:** a policy file per row was rejected, because the files drift. A
  local run was rejected because of the user's constraint and runner-to-runner noise:
  every row should come from the same run.

**D-049 (2026-11-28) Per-rule severity overrides re-rate the finding, not just the
action.** `findings.rules` maps `detector_id/rule_id` globs to a severity.
- **It's applied inside the pure detector pipeline** (`apply_overrides` in
  `inspect/pipeline.py`, configured once from the policy because policies don't hot
  reload). So the event, the circuit breaker, quarantine and the severity-to-action
  table all see the same severity.
- **Why a severity, not an action.** An action override would leave the event saying
  `high` while gatehouse only logged it, and the SOC would see "high, allowed" and
  wonder why. A re-rated severity keeps the event and the decision consistent.
- **Precedence:** an exact key, then the longest glob. This is simple and
  order-independent. A key that matches nothing is accepted rather than rejected,
  because rule ids are an open set as detectors are added. `docs/policy.md` says to
  check event names.
- **This fixes the two held-out v1 false positives without `high: log` everywhere**
  (NEXT.md). That fix is policy configuration, so it isn't evidence of better
  detection, and the evaluation policies don't use it.

**D-051 (2026-11-28) Competitors in evaluation v2: Pipelock strict and
mcp-context-protector added, with invocations taken from their source.** These facts
were checked against each project's source at the pinned version, not against READMEs
alone.
- **Both new gateways start the server with a cleaned environment.**
  - Pipelock passes only the variables named with `--env`.
  - mcp-context-protector passes only HOME, PATH and a few others.
  - So the harness also writes the scenario spec and log path under the scenario's
    `$HOME`, and `attacks/mockserver.py` falls back to them. Without this, every
    scenario would error, and the scores would be meaningless.
- **Pipelock v3.8.0** (`pipelock mcp proxy --config strict.yaml --env ... -- <server>`):
  - the signed release binary, verified with cosign and `checksums.txt`;
  - the config from `pipelock generate config --preset strict`;
  - blocks come back as JSON-RPC errors, and its stderr finding lines count as
    detections (`attacks/targets.py`). Chain detections that only warn are left out.
- **mcp-context-protector** at `05e56c1` (archived):
  - **It runs without a guardrail provider.** LlamaFirewall needs the gated Prompt Guard
    2 model and a Hugging Face token, so this is its pinning-only configuration, and the
    tables say so.
  - **Approval.** It refuses every configuration until a person approves it. Before
    each scenario the harness answers its own `--review-server` prompt with "yes" for
    the first phase, which is trust on first use, like gatehouse's `tofu`.
  - **Result envelope.** Its results come wrapped as `{"status": "completed", ...}`.
    `ContextProtector.unwrap_results` removes only that envelope before benign
    results are compared.
- **What is counted.** Things a tool does by design are counted as what they are:
  - Pipelock's per-process pinning baseline can't see a rug pull across restarts.
  - mcp-context-protector rebuilds tool schemas and drops `structuredContent` and
    server instructions.
  - Under the suite's definition, a change to benign traffic is a false positive. The
    fairness notes in `docs/evaluation.md` list these cases so a reader can discount
    them.
- **gateward's audit log.** Its SQLite rows add no scorable signal: blocks are already
  counted from the client side, and its only `warn` rows are framing errors. The
  NEXT.md item is closed with this finding.

**D-050 (2026-11-28) Classifiers: a mode per classifier; enforce fails closed within a
budget; shadow is the default (ADR-0007).**
- **Decision.**
  - `policy.classifiers` lists up to 8 model-based detectors (`prompt_guard`,
    `ollama`, `prompt_shields`), each with a `mode`.
  - `enforce` waits up to `budget_ms`. No answer becomes a HIGH
    `classifier-unavailable` finding.
  - `alert` and `shadow` run in the task group and never delay or change traffic.
  - The default is `shadow`, so adding a model never changes behaviour until it has
    been measured.
- **Why.** The roadmap sets the failure behaviour: timeouts fail closed for enforce
  and open for shadow. A model whose precision on your traffic is unknown shouldn't
  block by default. Shadow verdicts cost no latency, and they are what the evaluation
  scores.
- **Not `gatehouse.fail_open`.** A shadow or alert timeout bypasses no control, since no
  decision depends on it. So it is recorded in its `classifier.verdict` event and not
  as `gatehouse.fail_open`. ADR-0001's single fail-open path is unchanged.
- **Not a strike.** `classifier-unavailable` is excluded from circuit-breaker strikes,
  like `provenance-unavailable`. Otherwise a model outage would lock every session.
- **Data boundaries.**
  - Ollama must be loopback `http://`, checked when the policy loads.
  - Prompt Shields must be `https://`, with the key from an environment variable.
  - The text sent is strings only, without MCP framing fields: at most 5 chunks of
    2,000 characters, which fits Prompt Shields' 5 documents and 10K characters and
    is about Prompt Guard's 512 tokens per chunk.
- **Testing without the real models.**
  - Prompt Guard 2 is gated (Llama license, Hugging Face token), so CI tests it with an
    injected fake session and tokenizer.
  - The Prompt Shields request shape follows Microsoft's quickstart, verified
    2026-11-28 (`text:shieldPrompt`, api-version 2024-09-01, `userPrompt` and
    `documents`, `documentsAnalysis[].attackDetected`). It is tested with a stubbed
    HTTP layer until M7 provides an Azure resource.
  - No detection numbers are claimed for either model.
- **Alternatives.**
  - Classifiers inside the pure pipeline: rejected, because inference is I/O.
  - Fail open in enforce: rejected by ADR-0001.
  - Enforce as the default: rejected, because of unmeasured false positives.

**D-052 (2026-11-28) M6 rule fixes: the NEXT.md list, measured on held-out v2.** The
fixes, each with attack scenarios and benign twins in `attacks/scenarios/rules_m6.yaml`
(milestone `m6-rules`, 10 attacks and 9 benign):
- **Decoding.** Moved into `inspect/decode.py`.
  - Secrets: base64 (as before), plus hex and percent-encoding.
  - Results: base64 and hex, at most 64 decoded copies per result.
  - A decoding counts only if it is at least 90% printable ASCII. So digests, image
    data and identifiers drop out, and the benign twins cover them.
- **Commands.** `destructive-disk-or-tree`:
  - `find` from `/`, `~` or `$HOME` with `-delete` or `-exec rm`;
  - `dd of=/dev/<disk>`;
  - `mkfs`, `mke2fs`, `wipefs` or `shred` on a device;
  - PowerShell `Clear-Disk`, `Format-Volume` and `Initialize-Disk`.
  - `diskpart ... clean` was dropped: it also matched a script that happened to be
    named `clean.txt`.
- **Paths.** `credential-directory`: bare directories and globs for `.ssh`, `.aws`,
  `.gnupg`, `.azure`, `.kube`, `.password-store` and `.config/gcloud`. `known_hosts`
  and `.ssh/config` are not flagged.
- **Card numbers sent as JSON numbers.** A Luhn check alone would flag about 1 in 10
  integer IDs, so these numbers also need a card-network prefix and length (Visa,
  Mastercard including the 2-series, Amex, Discover, JCB, Diners, UnionPay). String
  matching is unchanged.
- **Reference-style markdown images.** `![x][ref]`, `![ref][]` or `![ref]`, together
  with a `[ref]: URL?k=v` definition and case-insensitive labels, give
  `response.exfil_url/markdown-reference-image-with-query`.
- **Held-out v1.** These fixes address held-out v1 misses by name, so v1 can no longer
  measure them (D-032).
  - The numbers reported for this change come from held-out v2, which was frozen and
    hashed before any of these rules were written (D-046, MANIFEST.json).
  - The v1 ids that are now caught are listed in `docs/known-bypasses.md` as a
    regression check only.
- **Not fixed:** plain links with data in the query (they need a click) and rot13.
  Both are still documented as bypasses.

**D-053 (2026-11-28) Benign listings are compared up to no-op schema keywords, and a
judge layer is measured in CI.**
- **Listing comparison.**
  - *What happened.* Run
    [46106751618](https://github.com/danielguillaumont/gatehouse/actions/runs/46106751618)
    scored mcp-context-protector at 66.9% false positives. 344 of its 349 were "tools/list
    altered". It rebuilds each schema and adds `"required": []` and
    `"description": ""` to every property, which changes nothing about what a client
    may send.
  - *Decision.* Benign listings now compare equal when the only difference is an empty
    `required` list or an empty `description` inside `inputSchema` or `outputSchema`
    (`attacks/harness.py::_listing`). Everything else still counts, including a
    changed tool description, a new `required` entry, a changed type or added
    annotations. The same rule applies to every target. gatehouse and direct are
    unaffected, since neither rewrites schemas.
  - *Alternative.* A target-specific normalizer for mcp-context-protector. Rejected:
    "equivalent schema" is a property of JSON Schema, not of one tool.
- **Judge layer.**
  - *Decision.* `judge` = `full` plus an Ollama judge in `enforce` mode on tool
    results. The model is Qwen2.5 1.5B Instruct (Apache-2.0, verified on its Hugging
    Face card on 2026-11-28), and it runs on a CPU runner (Ollama v0.40.17, with the
    tarball's sha256 pinned in the workflow).
  - *Scope.* It covers suite and held-out v2 only. The judge reads results, while
    MCPTox attacks tool definitions and egress-bench attacks arguments.
  - *Sharding.* The sets are sharded (`attacks run --shard k/n`), and
    `attacks.evaluate` merges `<set>.<k>` reports.
  - *Why measure it at all.* The roadmap names an Ollama judge. ADR-0007 says no
    classifier number is claimed unmeasured, and this is the one model CI can run
    without a gated download.
  - *Alternative.* Prompt Guard 2 in CI. Rejected: it is gated behind a Hugging Face
    token.

**D-054 (2026-11-28) gatehouse serve validates OIDC bearer tokens in-process
(ADR-0008).**
- *Decision.* When `--oidc-issuer` and `--oidc-audience` are set, gatehouse checks:
  - the JWT's signature against the issuer's JWKS;
  - `iss`, `aud`, `exp` and `nbf`;
  - optionally a required role or scope.

  The principal is `<tid>/<oid>` (Entra ID) or `<iss>#<sub>`. It goes into Cedar and
  into `Details.Principal`. Refusals give 401/403 with an RFC 9728 `resource_metadata`
  challenge, plus an `auth.denied` event. The token is never forwarded.
- *Why.*
  - It is the MCP authorization spec's resource-server role.
  - The principal must come from a verified token, not from a header that a front
    proxy could be bypassed to set.
  - PyJWT is the most widely used Python JWT library, and it rejects `alg: none`
    unless it is explicitly allowed. gatehouse also pins the algorithm list itself.
- *Alternatives.*
  - An authenticating front proxy: still possible, but the principal would only be
    trusted indirectly.
  - Token introspection: Entra ID doesn't offer it for access tokens.
  - OBO exchange: a different feature, deferred.
- *Testing.* CI uses a local issuer process (`attacks/oidc_issuer.py`). The tests
  cover:
  - the missing-token challenge and the metadata document;
  - expired, wrong-audience, wrong-issuer, wrong-key, unknown-kid, HS256 and `none`
    tokens;
  - the role requirement;
  - JWKS refresh rate-limiting;
  - no passthrough;
  - a real-TCP end-to-end run.

**D-055 (2026-11-28) Remote control signals arrive on an Azure Storage queue and can
only tighten controls.**
- *Decision.* `gatehouse listen` polls a Storage queue through a SAS URL taken from an
  environment variable. It applies:
  - `kill` (the kill-switch file);
  - `lock_session` (a circuit-breaker lock for one AgentSessionId);
  - `revoke_grants` (one grant, or `*`).

  The poll uses the stdlib only, and it runs one daemon per machine, since every
  gatehouse on the machine already shares the control store.
  - Release, unlock and grant messages are rejected. Loosening a control stays a local
    human action.
  - Signals older than `ttl_s` (default 1 hour) or more than 5 minutes in the future
    are rejected.
  - Every message, applied or rejected, emits `control.signal` and is deleted.
  - A store failure leaves the message on the queue, which retries it up to a dequeue
    count of 5 before dropping it with an event.
  - A failing poll emits one `gatehouse.internal_error` per outage.
- *Why a queue.* A Logic App playbook can write to it with its managed identity
  (`Storage Queue Data Message Sender`). The machine needs no inbound port; it only
  polls outbound over HTTPS. gatehouse's SAS has only the process permission (read
  and delete).
- *Why no message signature.* The Logic Apps expression language has no HMAC
  function, so signing would need an extra Function app. The queue's RBAC is the trust
  boundary. Because signals can only tighten, a forged message can deny service (a
  kill), but it can never widen access.
- *Alternatives.*
  - Event Grid or webhook push: needs an inbound endpoint.
  - Service Bus: costs more, for no gain at this volume.
  - Polling Sentinel incidents directly: needs workspace read rights on every
    machine.
- *Testing.* `attacks/fake_queue.py` is a local fake of the Queue REST API (Put, Get
  and Delete Messages, a SAS check, visibility timeout, dequeue count). The tests:
  - render `infra/playbook/*-message.json` (the messages the playbooks put on the
    queue) with sample values;
  - put them on the fake queue;
  - run `gatehouse listen --once` as a real process;
  - check that a running router blocks the next call with the incident in the
    reason.

**D-056 (2026-11-28) Release tags point at the evaluated commit.**
- *Decision.* v0.3.0 is tagged at `37da760`, the commit evaluation run 46112090830
  measured, not at the later commit that holds its write-up. The release notes carry
  the numbers and the run link, and `docs/evaluation.md` on `main` carries the full
  tables.
- *Why.* The tag must be exactly what was measured. M7 commits had already landed on
  `main` by the time the run finished (OIDC in `serve`, `gatehouse listen`), and they
  belong to v0.4.0.
- *Alternative.* Tag HEAD and rerun the evaluation. Rejected: that costs about an hour
  of CI and would measure code that the release notes don't describe.

