"""OAuth 2.1 / OIDC bearer-token validation for ``gatehouse serve`` (M7, ADR-0008).

gatehouse is the MCP *resource server* here. Following the MCP authorization spec:

- every request needs ``Authorization: Bearer <JWT>``; without one the answer is 401 with
  ``WWW-Authenticate: Bearer resource_metadata="<url>"`` pointing at the RFC 9728
  Protected Resource Metadata that gatehouse serves;
- the token must be signed by a key in the issuer's JWKS (asymmetric algorithms only),
  carry ``iss`` = the configured issuer, ``aud`` = the configured audience (this
  server), and be within ``exp`` / ``nbf`` (60 s leeway);
- optionally the token must carry one of the required roles (``roles`` claim, Entra
  app roles) or scopes (``scp`` claim);
- the token is never forwarded upstream (no token passthrough; ``http.py`` rebuilds the
  upstream headers from gatehouse's own configuration).

The principal is ``<tid>/<oid>`` for Entra ID tokens and ``<iss>#<sub>`` otherwise.
It reaches the policy engine (the Cedar ``Principal`` entity) and the events
(``Details.Principal``). No token or claim other than these identifiers is logged.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import urlsplit

import anyio
import httpx2
import jwt

ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384")
LEEWAY_S = 60
JWKS_MIN_REFRESH_S = 60.0  # an unknown kid refreshes the keys at most once a minute
MAX_DOC_BYTES = 256 * 1024
MAX_TOKEN_CHARS = 16 * 1024
LOOPBACK = ("127.0.0.1", "localhost", "::1")


class AuthError(Exception):
    """A request that must be refused. ``status`` is 401 (no or bad token) or 403."""

    def __init__(self, reason: str, status: int = 401, error: str = "invalid_token") -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.error = error


@dataclass(frozen=True)
class Principal:
    id: str
    subject: str
    tenant: str | None = None
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()


@dataclass
class OidcConfig:
    issuer: str
    audience: str
    jwks_url: str | None = None  # None: from the issuer's discovery document
    required_roles: frozenset[str] = frozenset()
    required_scopes: frozenset[str] = frozenset()
    resource: str | None = None  # this server's public URL, for the metadata document


def require_secure(url: str, what: str) -> None:
    """https, or http on loopback only (a local issuer in tests and CI)."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and (parts.hostname or "") in LOOPBACK:
        return
    raise ValueError(f"{what} must be https:// (or http:// on loopback): {url}")


def principal_from_claims(claims: dict[str, Any]) -> Principal:
    sub = str(claims.get("sub") or "")
    tid = claims.get("tid")
    oid = claims.get("oid")
    roles = tuple(str(r) for r in cast(list[Any], claims.get("roles") or [])[:64])
    scp = claims.get("scp")
    scopes = tuple(str(scp).split()[:64]) if isinstance(scp, str) else ()
    if isinstance(tid, str) and isinstance(oid, str):
        return Principal(f"{tid}/{oid}", sub, tid, roles, scopes)
    return Principal(f"{claims.get('iss')}#{sub}", sub, None, roles, scopes)


@dataclass
class TokenValidator:
    config: OidcConfig
    client: httpx2.AsyncClient
    _keys: dict[str, Any] = field(default_factory=dict[str, Any])
    _jwks_url: str | None = None
    _fetched_at: float = 0.0
    _lock: anyio.Lock = field(default_factory=anyio.Lock)

    def __post_init__(self) -> None:
        require_secure(self.config.issuer, "OIDC issuer")
        if self.config.jwks_url:
            require_secure(self.config.jwks_url, "JWKS URL")

    async def _get_json(self, url: str) -> dict[str, Any]:
        try:
            resp = await self.client.get(url, headers={"Accept": "application/json"})
        except httpx2.HTTPError as exc:
            raise AuthError(f"identity provider unreachable ({type(exc).__name__})") from None
        if resp.status_code != 200 or len(resp.content) > MAX_DOC_BYTES:
            raise AuthError(f"identity provider answered HTTP {resp.status_code}")
        try:
            return cast(dict[str, Any], json.loads(resp.content))
        except ValueError:
            raise AuthError("identity provider sent invalid JSON") from None

    async def _discover(self) -> str:
        if self._jwks_url is None:
            if self.config.jwks_url:
                self._jwks_url = self.config.jwks_url
            else:
                base = self.config.issuer.rstrip("/")
                doc = await self._get_json(f"{base}/.well-known/openid-configuration")
                if doc.get("issuer") != self.config.issuer:
                    raise AuthError("discovery document issuer does not match")
                uri = doc.get("jwks_uri")
                if not isinstance(uri, str):
                    raise AuthError("discovery document has no jwks_uri")
                try:
                    require_secure(uri, "jwks_uri")
                except ValueError as exc:
                    raise AuthError(str(exc)) from None
                self._jwks_url = uri
        return self._jwks_url

    async def _refresh(self) -> None:
        url = await self._discover()
        jwks = await self._get_json(url)
        keys: dict[str, Any] = {}
        for raw in cast(list[Any], jwks.get("keys") or [])[:64]:
            if not isinstance(raw, dict):
                continue
            jwk = cast(dict[str, Any], raw)
            if jwk.get("use", "sig") != "sig" or jwk.get("kty") not in ("RSA", "EC"):
                continue
            try:
                keys[str(jwk.get("kid", ""))] = jwt.PyJWK(jwk)
            except jwt.PyJWTError:
                continue
        self._keys = keys
        self._fetched_at = time.monotonic()

    async def _key(self, kid: str) -> Any:
        async with self._lock:
            if kid not in self._keys and (
                not self._fetched_at or time.monotonic() - self._fetched_at >= JWKS_MIN_REFRESH_S
            ):
                await self._refresh()
        key = self._keys.get(kid)
        if key is None:
            raise AuthError("token signed by an unknown key")
        return key

    async def validate(self, authorization: str | None) -> Principal:
        if not authorization:
            raise AuthError("no bearer token", error="invalid_request")
        scheme, _, token = authorization.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise AuthError("authorization is not a bearer token", error="invalid_request")
        if len(token) > MAX_TOKEN_CHARS:
            raise AuthError("token too large")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise AuthError("token is not a JWT") from None
        alg = header.get("alg")
        if alg not in ALGORITHMS:
            raise AuthError(f"token algorithm not allowed ({str(alg)[:16]})")
        key = await self._key(str(header.get("kid", "")))
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=[str(alg)],
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=LEEWAY_S,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            raise AuthError("token expired") from None
        except jwt.InvalidAudienceError:
            raise AuthError("token audience is not this server") from None
        except jwt.InvalidIssuerError:
            raise AuthError("token issuer not trusted") from None
        except jwt.PyJWTError as exc:
            raise AuthError(f"token rejected ({type(exc).__name__})") from None
        principal = principal_from_claims(claims)
        cfg = self.config
        if cfg.required_roles and not cfg.required_roles & set(principal.roles):
            raise AuthError("token lacks a required role", 403, "insufficient_scope")
        if cfg.required_scopes and not cfg.required_scopes & set(principal.scopes):
            raise AuthError("token lacks a required scope", 403, "insufficient_scope")
        return principal

    def metadata(self, resource: str) -> dict[str, Any]:
        """RFC 9728 Protected Resource Metadata."""
        return {
            "resource": self.config.resource or resource,
            "authorization_servers": [self.config.issuer],
            "bearer_methods_supported": ["header"],
            **(
                {"scopes_supported": sorted(self.config.required_scopes)}
                if self.config.required_scopes
                else {}
            ),
        }
