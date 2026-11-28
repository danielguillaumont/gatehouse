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
- The check found a real bug in the first draft of `examples/policy-flow.yaml`:
  `delete_*: require_approval` left a tool named `delete` (or `bulk_delete`) allowed by
  `"*": allow`.
Alternatives considered:
- Invariants inside the policy file: whoever edits the policy would also edit what it
  is checked against.
- Raw Cedar invariants: more expressive but unreviewable for most operators. They can
  be added later as an `expert:` key.
- A small Rust prover on `cedar-policy-symcc`: more code to maintain than parsing two
  CLI output lines.
