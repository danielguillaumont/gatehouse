"""End-to-end: ``gatehouse serve --oidc-issuer`` (uvicorn, real TCP) with the local OIDC
issuer (``attacks/oidc_issuer.py``) as a separate process, in front of the SDK weather
server. Tokens are minted by the issuer's ``/token`` endpoint."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
from test_http_serve import ROOT, TOFU, _events, _free_port, _wait_for  # pyright: ignore[reportPrivateUsage]

pytestmark = [pytest.mark.integration]

AUD = "api://gatehouse-ci"
MODERN = "2026-07-28"


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[tuple[str, str, Path]]:
    up_port, gh_port, idp_port = _free_port(), _free_port(), _free_port()
    issuer = f"http://127.0.0.1:{idp_port}"
    policy = tmp_path / "policy.yaml"
    policy.write_text(TOFU, encoding="utf-8")
    procs = [
        subprocess.Popen([sys.executable, "-m", "attacks.oidc_issuer", str(idp_port)], cwd=ROOT),
        subprocess.Popen(
            [sys.executable, str(ROOT / "demo" / "weather_http.py"), str(up_port)],
            cwd=ROOT / "demo",
        ),
    ]
    gatehouse = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "gatehouse",
            "serve",
            "--name",
            "weather",
            "--policy",
            str(policy),
            "--pins",
            str(tmp_path / "pins.json"),
            "--events-dir",
            str(tmp_path / "events"),
            "--quiet",
            "--upstream",
            f"http://127.0.0.1:{up_port}/mcp",
            "--port",
            str(gh_port),
            "--oidc-issuer",
            issuer,
            "--oidc-audience",
            AUD,
            "--oidc-require-role",
            "mcp.user",
        ],
        stdout=subprocess.PIPE,
    )
    procs.append(gatehouse)
    try:
        _wait_for(idp_port, procs[0])
        _wait_for(up_port, procs[1])
        _wait_for(gh_port, gatehouse)
        yield f"http://127.0.0.1:{gh_port}/mcp", issuer, tmp_path
    finally:
        for proc in reversed(procs):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        assert gatehouse.stdout is not None
        assert gatehouse.stdout.read() == b""


def _list(rid: int) -> tuple[dict[str, Any], dict[str, str]]:
    body: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    headers = {
        "MCP-Protocol-Version": MODERN,
        "Mcp-Method": "tools/list",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    return body, headers


def _token(issuer: str, **claims: Any) -> str:
    resp = httpx2.post(f"{issuer}/token", json={"aud": AUD, **claims}, timeout=10)
    return str(resp.json()["access_token"])


def test_oidc_tokens_end_to_end(stack: tuple[str, str, Path]) -> None:
    url, issuer, tmp_path = stack
    body, headers = _list(1)
    with httpx2.Client(timeout=30) as http:
        missing = http.post(url, json=body, headers=headers)
        assert missing.status_code == 401
        assert "resource_metadata=" in missing.headers["www-authenticate"]
        meta_url = missing.headers["www-authenticate"].split('resource_metadata="')[1].rstrip('"')
        assert http.get(meta_url).json()["authorization_servers"] == [issuer]

        good = _token(issuer, tid="t1", oid="o1", roles=["mcp.user"])
        ok = http.post(url, json=body, headers={**headers, "Authorization": f"Bearer {good}"})
        assert ok.status_code == 200, ok.text
        names = sorted(t["name"] for t in ok.json()["result"]["tools"])
        assert names == ["get_forecast", "list_cities"]

        no_role = _token(issuer, tid="t1", oid="o2", roles=[])
        hdr = {**headers, "Authorization": f"Bearer {no_role}"}
        assert http.post(url, json=body, headers=hdr).status_code == 403
        expired = _token(issuer, tid="t1", oid="o1", roles=["mcp.user"], ttl=-3600)
        hdr = {**headers, "Authorization": f"Bearer {expired}"}
        assert http.post(url, json=body, headers=hdr).status_code == 401
    denied = [e for e in _events(tmp_path) if e["EventType"] == "auth.denied"]
    assert [e["Reason"] for e in denied] == [
        "no bearer token",
        "token lacks a required role",
        "token expired",
    ]
    assert good not in json.dumps(_events(tmp_path))  # tokens never reach the event log
