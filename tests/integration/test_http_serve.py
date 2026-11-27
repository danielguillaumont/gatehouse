"""End-to-end: ``gatehouse serve`` (uvicorn, real TCP) in front of the SDK weather server
over Streamable HTTP, driven by the official SDK client in both protocol eras."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

ROOT = Path(__file__).resolve().parents[2]
TOFU = "version: 1\ndefault_action: allow\npinning: tofu\n"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for(port: int, proc: subprocess.Popen[bytes], timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited with {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"port {port} never opened")


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    up_port, gh_port = _free_port(), _free_port()
    policy = tmp_path / "policy.yaml"
    policy.write_text(TOFU, encoding="utf-8")
    upstream = subprocess.Popen(
        [sys.executable, str(ROOT / "demo" / "weather_http.py"), str(up_port)],
        cwd=ROOT / "demo",
    )
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
        ],
        stdout=subprocess.PIPE,
    )
    try:
        _wait_for(up_port, upstream)
        _wait_for(gh_port, gatehouse)
        yield f"http://127.0.0.1:{gh_port}/mcp", tmp_path
    finally:
        for proc in (gatehouse, upstream):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        assert gatehouse.stdout is not None
        # gatehouse serve never writes to stdout (no access log, no prints)
        assert gatehouse.stdout.read() == b""


def _events(tmp_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in sorted((tmp_path / "events").glob("*.jsonl")):
        out += [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines()]
    return out


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_sdk_client_through_gatehouse_serve(stack: tuple[str, Path], mode: str) -> None:
    from mcp import Client

    url, tmp_path = stack
    with anyio.fail_after(60):
        async with Client(url, mode=mode, cache=None) as c:
            assert c.protocol_version == ("2026-07-28" if mode == "auto" else "2025-11-25")
            names = sorted(t.name for t in (await c.list_tools()).tools)
            assert names == ["get_forecast", "list_cities"]
            result = await c.call_tool("get_forecast", {"city": "Paris"})
            assert "Sunny in Paris" in json.dumps(result.model_dump(mode="json"))
    calls = [e for e in _events(tmp_path) if e["EventType"] == "tool.call"]
    assert calls and calls[-1]["Action"] == "allowed"
