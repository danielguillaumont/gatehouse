"""Helpers for the modern (2026-07-28) request envelope and for gatehouse's own MRTR
approval prompt.

Approval through MRTR (D-036): when a ``tools/call`` needs approval and the request
declares the ``elicitation`` capability, gatehouse answers it itself with an
``InputRequiredResult`` that asks the *user* to approve. The client retries the same call
with ``inputResponses`` and the ``requestState`` gatehouse issued. gatehouse treats that
state as attacker-controlled input, as the spec requires of any server: it is
HMAC-protected and bound to the exact call (method, tool, argument fingerprint), expires,
and is redeemed at most once. gatehouse strips its own entries before forwarding, so the
upstream server sees an ordinary first request.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from gatehouse.jsonutil import as_obj, as_str
from gatehouse.protocol import (
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
    RESULT_INPUT_REQUIRED,
)

STATE_PREFIX = "gatehouse.v1."
APPROVAL_KEY = "gatehouse.approval"
STATE_TTL_S = 600.0
MAX_STATE_CHARS = 4096


@dataclass(frozen=True)
class RequestMeta:
    """The per-request protocol fields of a client request."""

    present: bool  # the request carries io.modelcontextprotocol/protocolVersion
    version: str | None
    capabilities: dict[str, Any] | None
    client_info: dict[str, Any] | None

    def problem(self) -> str | None:
        """Why a modern request is malformed (-32602), or None."""
        if not self.present:
            return f"missing _meta {META_PROTOCOL_VERSION}"
        if self.version is None:
            return f"_meta {META_PROTOCOL_VERSION} must be a string"
        if self.capabilities is None:
            return f"missing or invalid _meta {META_CLIENT_CAPABILITIES}"
        return None

    def supports_elicitation_form(self) -> bool:
        elicitation = (self.capabilities or {}).get("elicitation")
        if not isinstance(elicitation, dict):
            return False
        # 2025-11-25+: an empty object means form mode; otherwise `form` must be declared
        return not elicitation or "form" in elicitation


def request_meta(params: Mapping[str, Any]) -> RequestMeta:
    meta = as_obj(params.get("_meta")) or {}
    return RequestMeta(
        present=META_PROTOCOL_VERSION in meta,
        version=as_str(meta.get(META_PROTOCOL_VERSION)),
        capabilities=as_obj(meta.get(META_CLIENT_CAPABILITIES)),
        client_info=as_obj(meta.get(META_CLIENT_INFO)),
    )


def internal_meta(version: str, capabilities: Mapping[str, Any] | None) -> dict[str, Any]:
    """_meta for a request gatehouse itself sends upstream (e.g. its own tools/list)."""
    from gatehouse import __version__

    return {
        META_PROTOCOL_VERSION: version,
        META_CLIENT_CAPABILITIES: dict(capabilities or {}),
        META_CLIENT_INFO: {"name": "gatehouse", "version": __version__},
    }


# ---------------------------------------------------------------------- approval state


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def call_binding(server: str, method: str, tool: str, args_fingerprint: str) -> str:
    """What an approval state is bound to. The install key is shared by every gatehouse
    process on the machine, so the server name is part of the binding: a state issued
    for one server's tool must not approve the same call on another server."""
    parts = (server, method, tool, args_fingerprint)
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


@dataclass(frozen=True)
class VerifiedState:
    nonce: str
    binding: str


class StateSigner:
    """Issues and verifies gatehouse's approval ``requestState`` tokens."""

    def __init__(self, key: bytes, ttl_s: float = STATE_TTL_S) -> None:
        # Derived key: the install key also fingerprints arguments; keep the uses apart.
        self._key = hmac.new(key, b"gatehouse/requestState/v1", hashlib.sha256).digest()
        self.ttl_s = ttl_s

    def issue(self, binding: str, now: float | None = None) -> str:
        payload = {
            "b": binding,
            "e": int((now if now is not None else time.time()) + self.ttl_s),
            "n": secrets.token_hex(12),
        }
        body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        mac = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        return f"{STATE_PREFIX}{body}.{mac}"

    def verify(self, token: str, binding: str, now: float | None = None) -> VerifiedState | None:
        """The token's nonce if it is genuine, unexpired and bound to ``binding``."""
        if not token.startswith(STATE_PREFIX) or len(token) > MAX_STATE_CHARS:
            return None
        try:
            body, mac = token[len(STATE_PREFIX) :].split(".", 1)
            expected = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(mac, expected):
                return None
            payload = json.loads(_unb64(body))
        except (ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        fields: dict[str, Any] = payload  # type: ignore[assignment]
        expires, nonce, bound = fields.get("e"), fields.get("n"), fields.get("b")
        if not isinstance(expires, int) or not isinstance(nonce, str) or bound != binding:
            return None
        if (now if now is not None else time.time()) > expires:
            return None
        return VerifiedState(nonce=nonce, binding=binding)


def is_gatehouse_state(value: object) -> bool:
    return isinstance(value, str) and value.startswith(STATE_PREFIX)


def approval_input_required(elicitation_params: Mapping[str, Any], state: str) -> dict[str, Any]:
    """The InputRequiredResult gatehouse returns to ask the user for approval."""
    return {
        "resultType": RESULT_INPUT_REQUIRED,
        "inputRequests": {
            APPROVAL_KEY: {
                "method": "elicitation/create",
                "params": {"mode": "form", **elicitation_params},
            }
        },
        "requestState": state,
    }
