# ADR-0003: The HTTP proxy rebuilds headers from the inspected body

- Status: accepted (2026-11-27)
- Spec: MCP 2026-07-28 Streamable HTTP transport (commit `fdc75bd`, fetched 2026-11-27).
- Decision log: D-039.

## Context

In 2026-07-28 a Streamable HTTP request repeats parts of its body in headers:
`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (the tool or prompt name, or the
resource URI), and `Mcp-Param-*` for tool parameters annotated with `x-mcp-header`. Load
balancers, gateways and WAFs route and filter on those headers without parsing the body.
A server must reject a request whose headers disagree with its body (-32020), but an
intermediary that decides from one and forwards the other can be fooled: a header that
says `get_forecast` on a body that calls `delete_repo`.

## Decision

- **Ingress: reject disagreement.** A 2026-07-28 request whose routing headers disagree
  with the body, or that repeats a routing header, gets 400 / -32020 and
  `protocol.header_mismatch` before policy runs. Comparison follows the spec and the
  Python SDK 2.3.0 validation order.
- **Egress: rebuild, don't forward.** gatehouse computes every upstream routing header
  from the body it actually sends, and the `Mcp-Param-*` set from the tool definition it
  inspected. No client header reaches the upstream except W3C trace context. Whatever
  the client claimed in its headers, the upstream sees headers that match what gatehouse
  inspected and allowed.
- **No token passthrough.** The client's `Authorization` and cookies are dropped.
  gatehouse authenticates to the upstream with its own credential
  (`--upstream-bearer-env`). The MCP authorization spec forbids passing client tokens
  through, and a proxy that did would let any caller reach the upstream with the
  caller's own credential and gatehouse's policy as the only check.
- **x-mcp-header is a security surface.** A tool whose annotation is invalid is removed
  from HTTP listings, since conforming clients must not call it. A sensitive-looking
  parameter mirrored into a header is reported, because headers end up in access logs
  that bodies don't reach.
- **Raw ASGI.** One task group spans the upstream exchange and the downstream response.
  Whether the response is JSON or SSE is decided by the first upstream frame. The
  proxy is a single ASGI callable served by uvicorn, without a web framework.

## Consequences

- An intermediary in front of gatehouse that routes on headers sees only requests whose
  headers match their bodies. An intermediary behind it sees only headers gatehouse
  wrote.
- Clients that rely on custom headers reaching the server (API keys in `X-Api-Key`, for
  example) need that credential configured on gatehouse instead. That is the point.
- Legacy (2025-11-25) HTTP clients are supported with gatehouse-issued session ids, but
  without approval prompts, because the answer to a gatehouse elicitation would arrive on
  a different POST. Those calls are blocked. 2026-07-28 clients approve through MRTR
  (ADR-0004).
