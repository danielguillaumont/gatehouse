# ADR-0002: One router, two protocol eras, latched on evidence

- Status: accepted (2026-11-27)
- Spec: MCP 2026-07-28 (modelcontextprotocol/modelcontextprotocol commit `fdc75bd`,
  fetched 2026-11-27), alongside 2024-11-05 through 2025-11-25.
- Decision log: D-036, and the era-latching fix in `ea8473e`.

## Context

MCP 2026-07-28 drops the `initialize` handshake. Every request carries its protocol
version and client capabilities in `_meta`, `server/discover` replaces the handshake for
clients that want server metadata, and servers ask the user for input by returning
`resultType: "input_required"` (MRTR) instead of sending `elicitation/create` requests.
Clients and servers in the field speak both eras, and a dual-era client decides which one
to use at connect time.

gatehouse must keep inspecting legacy servers (the v0.1 attack suite is the regression
bar) and must not become a reason to stay on the old protocol.

## Decision

- **One router, one session model.** The same policy, pinning, detectors and events
  apply to both eras. Era-specific code is limited to reading the envelope, the
  discover/initialize results, and the two ways of asking the user for input.
- **The era is latched by evidence, not by the client's first message.** A connection
  becomes legacy when an `initialize` *succeeds*, and modern when a 2026-07-28 probe
  succeeds or an enveloped request arrives first. Until then gatehouse forwards and lets
  the server decide. Claude Code 2.1.332 pipelines `server/discover` and `initialize`,
  and a modern server refuses the handshake with -32022. Latching on the forwarded
  `initialize` locked that connection into the wrong era.
- **Mixing eras on one connection is refused.** An `initialize` on a modern connection
  gets -32022 naming the modern versions, which is what a 2026-07-28 server answers. An
  enveloped request on a legacy connection gets `protocol.era_conflict`. gatehouse never
  inspects one connection under two sets of rules.
- **Downgrades are a detection.** gatehouse pins the protocol versions a server offered.
  If a server that spoke 2026-07-28 later offers only handshake versions (or fails
  discover so the client falls back), gatehouse reports `protocol.downgrade` and, unless
  the policy sets `allow_downgrade`, refuses the legacy handshake.
- **Modern servers can't send requests on stdio.** The spec says they MUST NOT. gatehouse
  drops such requests and returns an error to the server, so a server can't fall back to
  the legacy elicitation path to get around MRTR inspection.

## Consequences

- The legacy suite and the 2026-07-28 suite run through the same code, and the benign
  twins of each check that inspection doesn't break normal use.
- A client that uses each era on a different connection to the same server works. A
  client that switches era within one connection doesn't, by design.
- The latching rule depends on the server's answer, so a slow server delays the era
  decision. Requests that arrive before it are forwarded under the rules of the era they
  claim, and the first answer settles it.
