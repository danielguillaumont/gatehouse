"""A local OIDC issuer for tests and CI (never for real use).

    python -m attacks.oidc_issuer PORT

Serves, on 127.0.0.1 only:

- ``/.well-known/openid-configuration`` and ``/jwks`` (one RS256 key, generated at
  start, ``kid`` = ``k1``);
- ``POST /token`` with a JSON body ``{"sub", "aud", "roles", "scp", "tid", "oid",
  "ttl", "iss"}``: returns ``{"access_token": <JWT>}``. Any claim can be set, so tests
  can mint expired, wrong-audience or wrong-issuer tokens.

``Issuer`` is the same logic without a socket, for in-process tests.
"""

from __future__ import annotations

import base64
import json
import sys
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64int(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class Issuer:
    url: str
    kid: str = "k1"
    key: rsa.RSAPrivateKey = field(default_factory=_new_key)

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.url,
            "jwks_uri": f"{self.url}/jwks",
            "token_endpoint": f"{self.url}/token",
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def jwks(self) -> dict[str, Any]:
        nums = self.key.public_key().public_numbers()
        jwk = {"kty": "RSA", "n": _b64int(nums.n), "e": _b64int(nums.e)}
        return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}

    def token(self, claims: dict[str, Any], *, kid: str | None = None) -> str:
        now = int(time.time())
        ttl = int(claims.pop("ttl", 300))
        body = {"iss": self.url, "sub": "user-1", "iat": now, "nbf": now, "exp": now + ttl}
        body.update(claims)
        return jwt.encode(body, self.key, algorithm="RS256", headers={"kid": kid or self.kid})


def serve(port: int) -> None:
    issuer = Issuer(f"http://127.0.0.1:{port}")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == "/.well-known/openid-configuration":
                self._send(200, issuer.discovery())
            elif self.path == "/jwks":
                self._send(200, issuer.jwks())
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/token":
                self._send(404, {"error": "not found"})
                return
            n = min(int(self.headers.get("Content-Length") or 0), 64 * 1024)
            claims = cast(dict[str, Any], json.loads(self.rfile.read(n) or b"{}"))
            self._send(200, {"access_token": issuer.token(claims), "token_type": "Bearer"})

        def log_message(self, format: str, *args: Any) -> None:
            return  # quiet: stdout and stderr stay clean in tests

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    serve(int(sys.argv[1]))
