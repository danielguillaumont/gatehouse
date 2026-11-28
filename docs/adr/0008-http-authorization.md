# ADR-0008: gatehouse serve validates bearer tokens itself, as an MCP resource server

- Status: accepted (2026-11-28)
- Decision log: D-054.

## Context

`gatehouse serve` (ADR-0003) listens on loopback by default. To put it in front of a
remote MCP server for a team, it needs to know who is calling, and the v2 plan asks for
Entra ID tokens mapped to the Cedar principal. The MCP authorization specification makes
an MCP server an OAuth 2.1 *resource server*:

- an unauthenticated request gets `401` with a `WWW-Authenticate` header whose
  `resource_metadata` parameter points at RFC 9728 Protected Resource Metadata;
- tokens are audience-bound to the server;
- a server must not pass the client's token through to an upstream API.

## Decision

- **Validate in-process** (`gatehouse.proxy.auth`, PyJWT with `cryptography`, in the
  `http` extra) when `--oidc-issuer` and `--oidc-audience` are given:
  - signature against the issuer's JWKS, found through
    `<issuer>/.well-known/openid-configuration` or given with `--oidc-jwks-url`.
    Asymmetric algorithms only (RS*, PS*, ES256/384), chosen per token from that
    allow-list, so `none` and HS256 key confusion are refused before any key lookup;
  - `iss` equal to the configured issuer, `aud` equal to the configured audience, and
    `exp`, `iss`, `aud` and `sub` all required. `exp` and `nbf` get 60 seconds of
    leeway;
  - optionally one of `--oidc-require-role` (Entra app roles, the `roles` claim) or
    `--oidc-require-scope` (the `scp` claim). Missing ones give `403
    insufficient_scope`.
- **Fail closed.** If the identity provider can't be reached or the JWKS is broken, the
  request is refused (401). Nothing is allowed through unauthenticated.
- **The JWKS is refreshed when a token names an unknown `kid`**, at most once a minute.
  Garbage tokens can't make gatehouse hammer the identity provider.
- **The principal is `<tid>/<oid>`** for Entra tokens (tenant and object id, stable and
  not reassigned) and `<iss>#<sub>` otherwise. It becomes the Cedar `Principal` entity
  and `Details.Principal` on `tool.call` events. No token, and no claim other than these
  identifiers, is logged.
- **Every refusal emits `auth.denied`** (reason, status, OAuth error code) so Sentinel
  can alert on token spraying.
- **No passthrough.** The upstream request headers are still rebuilt from gatehouse's
  own configuration (`--upstream-bearer-env`), as before. A test checks that the
  client's token never reaches the upstream.
- **The issuer must be `https://`.** Plain `http://` is allowed on loopback only, which
  is what CI uses: `attacks/oidc_issuer.py` is a local issuer that mints tokens with
  any claims.

## Alternatives

- *An authenticating reverse proxy in front* (oauth2-proxy, Azure API Management, Easy
  Auth). It still works and stays an option. But the principal would reach gatehouse
  only as a header that it would have to trust, and the MCP-specific 401 and metadata
  behaviour would be someone else's to get right.
- *Token introspection* (RFC 7662). Entra ID doesn't offer it for access tokens, and it
  adds a network round trip to every call.
- *Exchanging the token on behalf of the user for an upstream token* (OBO). It's useful,
  but it is a different feature: it gives the upstream an identity, rather than
  authorizing the caller to gatehouse. Left for later.

## Consequences

- Entra apps must issue v2.0 access tokens (`"accessTokenAcceptedVersion": 2` in the app
  manifest). Otherwise the issuer is `https://sts.windows.net/<tid>/` and doesn't match
  `https://login.microsoftonline.com/<tid>/v2.0`. `docs/sentinel-setup.md` covers this.
- Multi-tenant (`common`) issuers aren't supported. The issuer must be one tenant.
