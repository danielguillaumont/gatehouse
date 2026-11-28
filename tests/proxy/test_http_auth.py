"""Bearer-token validation in ``gatehouse serve`` (ADR-0008), against a local issuer."""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx2
import pytest
from helpers import ALLOW_ALL_TOFU, FINGERPRINT_KEY
from test_http import UPSTREAM, Rig, modern_body, modern_headers

from attacks.http_mock import Recorder
from attacks.oidc_issuer import Issuer
from gatehouse.events.emitter import Emitter, EventContext
from gatehouse.events.fingerprint import Fingerprinter
from gatehouse.events.sinks import MemorySink
from gatehouse.inspect.pipeline import ScanConfig
from gatehouse.policy.loader import load_policy
from gatehouse.proxy.auth import OidcConfig, principal_from_claims, require_secure
from gatehouse.proxy.http import HttpProxy, HttpProxyConfig
from gatehouse.proxy.modern import StateSigner
from gatehouse.proxy.router import RouterConfig

pytestmark = pytest.mark.anyio

ISSUER = "http://127.0.0.1:9999"
AUD = "api://gatehouse-test"


def _idp(issuer: Issuer) -> tuple[httpx2.AsyncClient, list[str]]:
    fetched: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        fetched.append(request.url.path)
        if request.url.path == "/.well-known/openid-configuration":
            return httpx2.Response(200, json=issuer.discovery())
        if request.url.path == "/jwks":
            return httpx2.Response(200, json=issuer.jwks())
        return httpx2.Response(404)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler)), fetched


@asynccontextmanager
async def auth_rig(
    tmp_path: Path, issuer: Issuer, **oidc: Any
) -> AsyncGenerator[tuple[Rig, Recorder, list[str]]]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(ALLOW_ALL_TOFU, encoding="utf-8")
    load = load_policy(policy_path)
    sink = MemorySink()
    emitter = Emitter(
        EventContext(agent_session_id="a", server_name="srv", policy_sha256=load.sha256), [sink]
    )
    fp = Fingerprinter(FINGERPRINT_KEY)
    rcfg = RouterConfig(
        server_name="srv",
        policy=load,
        pins_path=tmp_path / "pins.json",
        scan=ScanConfig(fingerprint=fp),
        fingerprinter=fp,
        state_signer=StateSigner(FINGERPRINT_KEY),
        http=True,
    )
    tool = {"name": "a", "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}}}
    up = Recorder(tools=[tool])
    upstream_client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=up))
    idp, fetched = _idp(issuer)
    cfg = OidcConfig(issuer=ISSUER, audience=AUD, **oidc)
    proxy = HttpProxy(
        HttpProxyConfig(upstream=UPSTREAM, oidc=cfg), rcfg, emitter, upstream_client, idp
    )
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=proxy), base_url="http://127.0.0.1:8848"
    ) as client:
        yield Rig(proxy, client, sink), up, fetched
    await upstream_client.aclose()
    await idp.aclose()


async def _call(r: Rig, token: str | None) -> httpx2.Response:
    body = modern_body(1, "tools/list")
    extra = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return await r.post(body, modern_headers(body, **extra))


ENTRA = {"aud": AUD, "tid": "tenant-1", "oid": "object-1", "roles": ["mcp.user"]}


async def test_valid_token_is_accepted_and_never_forwarded(tmp_path: Path) -> None:
    issuer = Issuer(ISSUER)
    async with auth_rig(tmp_path, issuer) as (r, up, _):
        resp = await _call(r, issuer.token(dict(ENTRA)))
        assert resp.status_code == 200
        body = modern_body(2, "tools/call", {"name": "a", "arguments": {"x": "1"}})
        tok = issuer.token(dict(ENTRA))
        called = await r.post(body, modern_headers(body, Authorization=f"Bearer {tok}"))
        assert called.status_code == 200
        (call,) = r.events("tool.call")
        assert call["Details"]["Principal"] == "tenant-1/object-1"
    assert all("authorization" not in h for h, _ in up.requests)  # no token passthrough


async def test_missing_token_gets_a_challenge_with_resource_metadata(tmp_path: Path) -> None:
    issuer = Issuer(ISSUER)
    async with auth_rig(tmp_path, issuer) as (r, up, _):
        resp = await _call(r, None)
        assert resp.status_code == 401
        challenge = resp.headers["www-authenticate"]
        assert challenge.startswith("Bearer ")
        assert (
            'resource_metadata="http://127.0.0.1:8848/.well-known/oauth-protected-resource/mcp"'
            in challenge
        )
        meta = await r.client.get("/.well-known/oauth-protected-resource/mcp")
        assert meta.json()["authorization_servers"] == [ISSUER]
        assert meta.json()["resource"] == "http://127.0.0.1:8848/mcp"
        (denied,) = r.events("auth.denied")
        assert denied["Action"] == "blocked" and denied["Reason"] == "no bearer token"
    assert up.requests == []  # nothing reached the upstream


def _forged_hs256(issuer: Issuer) -> str:
    """Algorithm confusion: HS256 'signed' with the public key's JSON as the secret."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": "k1"}).encode())
    claims = {**ENTRA, "iss": ISSUER, "sub": "x", "exp": 9999999999}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode())
    return f"{header.decode().rstrip('=')}.{payload.decode().rstrip('=')}.c2ln"


def _b64(obj: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _unsigned(issuer: Issuer) -> str:
    claims = {**ENTRA, "iss": ISSUER, "sub": "x", "exp": 9999999999}
    return f"{_b64({'alg': 'none'})}.{_b64(claims)}."


def _expired(i: Issuer) -> str:
    return i.token({**ENTRA, "ttl": -3600})


def _wrong_aud(i: Issuer) -> str:
    return i.token({**ENTRA, "aud": "api://other"})


def _wrong_iss(i: Issuer) -> str:
    return i.token({**ENTRA, "iss": "http://127.0.0.1:1"})


def _other_key(i: Issuer) -> str:
    return Issuer(ISSUER).token(dict(ENTRA))  # same kid, different key


def _unknown_kid(i: Issuer) -> str:
    return i.token(dict(ENTRA), kid="k2")


def _garbage(i: Issuer) -> str:
    return "not-a-jwt"


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        (_expired, "token expired"),
        (_wrong_aud, "token audience is not this server"),
        (_wrong_iss, "token issuer not trusted"),
        (_other_key, "token rejected (InvalidSignatureError)"),
        (_unknown_kid, "token signed by an unknown key"),
        (_forged_hs256, "token algorithm not allowed (HS256)"),
        (_unsigned, "token algorithm not allowed (none)"),
        (_garbage, "token is not a JWT"),
    ],
)
async def test_bad_tokens_are_refused(
    tmp_path: Path, make: Callable[[Issuer], str], reason: str
) -> None:
    issuer = Issuer(ISSUER)
    async with auth_rig(tmp_path, issuer) as (r, up, _):
        resp = await _call(r, make(issuer))
        assert resp.status_code == 401
        assert 'error="invalid_token"' in resp.headers["www-authenticate"]
        (denied,) = r.events("auth.denied")
        assert denied["Reason"] == reason
    assert up.requests == []


async def test_required_role_gives_403(tmp_path: Path) -> None:
    issuer = Issuer(ISSUER)
    async with auth_rig(tmp_path, issuer, required_roles=frozenset({"mcp.admin"})) as (r, *_):
        resp = await _call(r, issuer.token(dict(ENTRA)))
        assert resp.status_code == 403
        assert 'error="insufficient_scope"' in resp.headers["www-authenticate"]
        ok = await _call(r, issuer.token({**ENTRA, "roles": ["mcp.admin"]}))
        assert ok.status_code == 200


async def test_jwks_refresh_is_rate_limited(tmp_path: Path) -> None:
    issuer = Issuer(ISSUER)
    async with auth_rig(tmp_path, issuer) as (r, _, fetched):
        for _ in range(5):
            await _call(r, issuer.token(dict(ENTRA), kid="unknown"))
    # discovery once, JWKS once: an attacker can't make gatehouse hammer the IdP
    assert fetched == ["/.well-known/openid-configuration", "/jwks"]


def test_principal_ids() -> None:
    assert principal_from_claims({"tid": "t", "oid": "o", "sub": "s"}).id == "t/o"
    p = principal_from_claims({"iss": "https://idp", "sub": "s", "scp": "a b"})
    assert p.id == "https://idp#s" and p.scopes == ("a", "b")


@pytest.mark.parametrize(
    "url", ["http://idp.example.com", "ftp://127.0.0.1", "http://127.0.0.1.evil.example"]
)
def test_issuer_must_be_https_unless_loopback(url: str) -> None:
    with pytest.raises(ValueError):
        require_secure(url, "OIDC issuer")
