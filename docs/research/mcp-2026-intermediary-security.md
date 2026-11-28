# What MCP 2026-07-28 changes for security intermediaries

*gatehouse research note, 2026-11-27. Spec: MCP 2026-07-28 as of
modelcontextprotocol/modelcontextprotocol commit `fdc75bd` (fetched 2026-11-27).
Everything measured here can be rerun from the gatehouse repository; commands are at
the end.*

MCP 2026-07-28 is the first revision that treats intermediaries (gateways, load
balancers, security proxies) as part of the design rather than an afterthought. It
makes every request self-describing, mirrors routing fields into HTTP headers, adds
cache hints, and replaces server-to-client requests with a retry pattern. Each of these
helps a proxy that knows about it. Each also opens a gap for a proxy that doesn't, or
that trusts the new fields more than it should.

This note covers what changed, the attacks that follow, and what an intermediary has to
do about each. It comes from building 2026-07-28 support into gatehouse, an MCP
security proxy, and from running the official conformance suite and an attack suite
through it.

## 1. Requests no longer share a session

Up to 2025-11-25 a connection starts with `initialize`, and the client's capabilities
and protocol version hold for the rest of it. In 2026-07-28 there is no handshake. Every
request carries `_meta` with `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities`, and `server/discover` gives server
metadata to clients that want it.

For a proxy that enforces "only tools I inspected in a listing may be called", this is
the important change: a stateless client may send `tools/call` without ever sending
`tools/list` on that connection. A proxy that waits to see a listing before allowing
calls breaks those clients. A proxy that allows unlisted calls has lost its rug-pull
defence. gatehouse resolves this by listing the server itself, under its own client
identity, before the first call it has to decide, and pinning what it sees.

**Era confusion.** Real clients speak both revisions and decide at connect time.
Claude Code 2.1.332 sends `server/discover` and `initialize` back to back. A
2026-07-28 server answers the probe and refuses the handshake with -32022, and the
client carries on in 2026-07-28. gatehouse originally decided the era when it
*forwarded* the `initialize`. Every later 2026-07-28 request was then refused as a
protocol mix, and the server's tools never loaded. The rule that works: latch the era
on evidence (a handshake that succeeded, a modern probe that succeeded, an enveloped
request), never on what the client merely sent. And refuse to inspect one connection
under two sets of rules.

## 2. Downgrade is now an attack

A dual-era client falls back to the legacy handshake when the 2026-07-28 probe fails
"with any error that is not a" recognised modern error (versioning page). An attacker
who controls the server, or anything between client and server, can force that
fallback: make `server/discover` fail, or advertise only handshake versions. The legacy
revision has weaker properties for an intermediary. Capabilities are declared once
instead of per request. Servers may send requests to the client on stdio. And the
legacy elicitation path (below) comes back.

Defence: remember which revisions a server has offered (gatehouse pins them next to its
tool pins). Treat "this server spoke 2026-07-28 yesterday and only offers 2025-11-25
today" as a detection, and refuse the legacy handshake unless policy allows it.

## 3. Input requests moved into results

2026-07-28 says a server "MUST NOT write JSON-RPC requests to stdout". When a server
needs input from the user (an elicitation form, a sampling call, the roots list), it
returns `resultType: "input_required"` with `inputRequests` and an opaque
`requestState`, and the client retries the original call with `inputResponses`.
That's Multi Round-Trip Requests (MRTR).

A proxy that inspected `elicitation/create` *requests* to catch credential phishing now
sees none: the same form arrives inside a `tools/call` *result*. The elicitation page
is explicit that servers "MUST NOT use form mode elicitation to request sensitive
information such as passwords, API keys, access tokens", but nothing enforces that
except whoever reads the form. gatehouse inspects `inputRequests` with the same rules
it applies to legacy elicitation. It looks for sensitive fields in form schemas,
injection text in messages, sampling requests the policy blocks, and input requests for
capabilities the client never declared. It also scans the user's answers for secrets
before they go back to the server. Two more cases are worth calling out:

- **Impersonating the proxy.** If the proxy asks for approval through the same
  mechanism, a malicious server can imitate the proxy's approval prompt to get the user
  to "approve" something. gatehouse withholds input requests that claim to come from
  gatehouse.
- **The old path as a bypass.** A 2026-07-28 server that sends an `elicitation/create`
  *request* on stdio anyway breaks the spec. It's also trying to reach the user by the
  route a proxy may not be checking any more. gatehouse drops it and answers the server
  with an error.

**MRTR as the proxy's own approval channel.** The same mechanism gives a proxy a clean
way to ask for human approval without holding a request open. gatehouse answers a
`require_approval` call with its own `input_required` round. Its `requestState` is
HMAC-protected and bound to the server, tool and argument fingerprint, expires after
600 s, and is accepted once. The spec says a server "MUST treat requestState as an
attacker-controlled input" and SHOULD defend against replay, and that applies to a
proxy issuing its own state too. The binding has to include the server name: an install
key shared by several proxy processes otherwise lets a state issued for one server's
tool approve the same call on another (gatehouse had exactly this bug, fixed in
`dbc2452`).

## 4. Headers that mirror the body

On Streamable HTTP, 2026-07-28 mirrors selected body fields into headers "so that
intermediaries (load balancers, gateways, observability tooling) can route and inspect
requests without parsing the body". `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`
(the tool or prompt name, or the resource URI) are always mirrored. So is any tool
parameter annotated with `x-mcp-header`, as `Mcp-Param-{Name}`.

The spec names the risk itself: servers MUST reject mismatches, which "prevents
potential security vulnerabilities when different components in the network rely on
different sources of truth (e.g., a load balancer routing on the header value while the
MCP server executes based on the body value)". This is request smuggling with a new
surface. A request whose `Mcp-Name` says `get_forecast` while its body calls
`delete_repo` passes any gateway rule written against the header.

An intermediary has two jobs here:

1. **On ingress, reject disagreement** with 400 and -32020, as a server must. Use the
   spec's value rules exactly: case-insensitive header names, case-sensitive values,
   `=?base64?…?=` decoding (a value missing the closing `?=` is a literal, not broken
   base64), numeric comparison of integers. Reject repeated routing headers too. Any
   difference between your parser and the server's is a smuggling primitive.
2. **On egress, don't forward client headers at all.** gatehouse rebuilds every upstream
   routing header from the body it actually sends, and the `Mcp-Param-*` set from the
   tool definition it inspected. The upstream only ever sees headers that agree with
   what was inspected and allowed. The same rule drops the client's `Authorization` and
   cookies. The authorization spec forbids token passthrough, and a proxy that forwarded
   client tokens would make its own policy the only thing between any caller and the
   upstream.

**`x-mcp-header` is attacker-controlled.** The annotation comes from the server's tool
definition, so a malicious server chooses which arguments get copied into headers. Two
consequences:
- *Header injection.* The spec constrains the name (no CR/LF or separators,
  case-insensitively unique, only on primitive parameters reachable through
  `properties`), and HTTP clients "MUST exclude the invalid tool from the result of
  `tools/list`". An intermediary should do the same.
- *Exfiltration into logs.* A server can annotate `api_key` with `x-mcp-header`. The
  value then travels in a header, and headers end up in access logs, tracing systems
  and WAF consoles that never see bodies. gatehouse reports a sensitive-looking
  parameter mirrored into a header, and scans argument values in headers like any other
  argument.

## 5. Caches are shared state

Results can carry `ttlMs` and `cacheScope`. `"public"` means "any client, shared
gateway, or caching proxy MAY store and serve the cached response to any user". The
spec itself notes that a public result from an authenticated endpoint "may be shared
outside of the initial request's authorization context".

Two attacks follow:

- **Cached rug pull.** A long TTL on a tool listing lets a client keep calling a tool
  without relisting. If the server changes the tool's behaviour or definition behind the
  cache, a proxy that only re-checks on relisting never notices. gatehouse caps `ttlMs`
  (policy `max_ttl_ms`), and its self-listing before a stateless call re-checks the pin
  whatever the client cached.
- **Filtered results marked public.** A proxy that filters a listing (hiding a tool
  whose pin failed, removing one with an invalid `x-mcp-header`) produces a result for
  *this* client under *this* policy. If it keeps the server's `cacheScope: "public"`, a
  shared cache downstream may serve that filtered view to someone else, or keep serving
  the unfiltered upstream view to clients that should get the filtered one. gatehouse
  marks every tool listing it filtered as `private`.

## 6. Subscriptions are long-lived streams

`subscriptions/listen` replaces the legacy GET stream. The client asks for the
notification types it wants, and the server tags each notification with the
subscription id, which equals the listen request's id. A proxy should check both: drop
notifications the client didn't subscribe to, and drop notifications carrying another
subscription's id. A server that pushes `tools/list_changed` to a stream that never
asked for it is trying to make the client relist at a moment the server chose.

## What we measured

Run on 2026-11-27, gatehouse at commit `8bcb6f7`:

- **Attack suite**, 2026-07-28 scenarios (`attacks/scenarios/protocol_2026.yaml`):
  - nine attacks, covering both downgrades, MRTR phishing in both eras, an impersonated
    approval prompt, sampling injection, an undeclared capability, the cached rug pull
    and injection in discover `instructions`;
  - all nine succeed without a proxy and are prevented through gatehouse;
  - the six benign twins behave the same with and without it.
- **HTTP scenarios** (`attacks/http_scenarios.yaml`):
  - six attacks: `Mcp-Name`, `Mcp-Method` and `Mcp-Param-*` smuggling, a CRLF
    `x-mcp-header` name, an unreachable annotation, and a secret mirrored into a header;
  - all six succeed against a header-routed upstream without a proxy and are prevented
    through `gatehouse serve`;
  - both benign twins pass.
- **Official conformance suite**:
  - harness `@modelcontextprotocol/conformance@0.2.0-alpha.11` against the MCP Python
    SDK 2.3.0 everything-server, directly and through `gatehouse serve`;
  - every scenario that passes directly also passes through gatehouse: 33/33 at
    2025-11-25 and 40/40 at 2026-07-28;
  - the first run found five gatehouse bugs, all listed in `docs/evaluation.md`.
- **A real client.** Claude Code 2.1.332 worked through gatehouse with a dual-era stdio
  server (2026-07-28 negotiated), a legacy-only stdio server, and an HTTP server behind
  `gatehouse serve`.

## Checklist for intermediary authors

- Latch the protocol era on the server's answer, not the client's first message. Never
  inspect one connection under two eras.
- Pin the protocol versions a server offers and treat a downgrade as a detection.
- Inspect `input_required` results with the same rules as legacy elicitation and
  sampling requests, and drop server-to-client requests on 2026-07-28 stdio.
- If you issue `requestState`, protect its integrity, bind it to the server and the
  exact call, expire it, and accept it once.
- Reject header/body disagreement exactly as the spec defines it. Then rebuild upstream
  headers from the body instead of forwarding them, and never pass client credentials
  through.
- Validate `x-mcp-header` as an HTTP client must, and watch for sensitive parameters
  routed into headers.
- Cap TTLs you can't verify, and mark results you filtered as `cacheScope: private`.
- Enforce subscription filters and subscription ids on listen streams.

## Reproduce

```
uv sync --all-extras
uv run python -m attacks run --target direct --out reports/direct
uv run python -m attacks run --target gatehouse --out reports/gatehouse
uv run python -m attacks http --target direct --out reports/direct-http
uv run python -m attacks http --target gatehouse --out reports/gatehouse-http
uv run --with click python scripts/conformance.py --server-dir <SDK v2.3.0>/examples/servers/everything-server --out reports/conformance
```

Design records: ADR-0002 (protocol eras), ADR-0003 (HTTP header rebuilding), ADR-0004
(MRTR approval), and decisions D-036 and D-039 in `docs/decisions.md`.
