"""End-to-end: real gatehouse process in front of a real MCP SDK server."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from gatehouse.client import StdioClient
from gatehouse.protocol import SUPPORTED_VERSIONS

pytestmark = pytest.mark.integration

SERVER = Path(__file__).resolve().parents[2] / "demo" / "weather_server.py"


def _gatehouse(tmp_path: Path, policy: str, *extra: str) -> list[str]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy, encoding="utf-8")
    return [
        sys.executable, "-m", "gatehouse", "run", "--name", "weather",
        "--policy", str(policy_path), "--pins", str(tmp_path / "pins.json"),
        "--events-dir", str(tmp_path / "events"), *extra, "--", sys.executable, str(SERVER),
    ]  # fmt: skip


def _events(tmp_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in sorted((tmp_path / "events").glob("*.jsonl")):
        out += [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines()]
    return out


def test_sdk_pins_every_version_gatehouse_supports() -> None:
    from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS

    assert set(SUPPORTED_VERSIONS) <= set(HANDSHAKE_PROTOCOL_VERSIONS)


def test_proxy_round_trip_tofu_then_rug_pull(tmp_path: Path) -> None:
    policy = "version: 1\ndefault_action: allow\npinning: tofu\n"
    with StdioClient(_gatehouse(tmp_path, policy), timeout=30) as c:
        info = c.initialize()
        assert info["protocolVersion"] in SUPPORTED_VERSIONS
        names = sorted(t["name"] for t in c.list_tools())
        assert names == ["get_forecast", "list_cities"]
        reply = c.call_tool("get_forecast", {"city": "Paris"})
        assert reply["result"]["isError"] is False
        assert "Sunny in Paris" in json.dumps(reply)

    # Restart the server with a poisoned get_forecast: gatehouse must hide it.
    env = {"WEATHER_POISONED": "1"}
    with StdioClient(_gatehouse(tmp_path, policy), env=env, timeout=30) as c:
        c.initialize()
        names = [t["name"] for t in c.list_tools()]
        assert names == ["list_cities"]
        blocked = c.call_tool("get_forecast", {"city": "x"})
        assert blocked["result"]["isError"] is True
    stderr = "".join(c.stderr_lines)
    assert "listing.pin_mismatch" in stderr

    mismatch = [e for e in _events(tmp_path) if e.get("DetectorId") == "listing.pin_mismatch"]
    assert mismatch and mismatch[0]["ToolName"] == "get_forecast"


def test_discover_probe_falls_back_to_initialize(tmp_path: Path) -> None:
    with StdioClient(
        _gatehouse(tmp_path, "version: 1\ndefault_action: allow\npinning: tofu\n"), timeout=30
    ) as c:
        probe = c.request("server/discover", {})
        assert probe["error"]["code"] == -32601
        assert c.initialize()["protocolVersion"]


def test_invalid_policy_fails_closed_end_to_end(tmp_path: Path) -> None:
    with StdioClient(_gatehouse(tmp_path, "version: 1\ndefault_action: maybe\n"), timeout=30) as c:
        c.initialize()
        c.list_tools()
        reply = c.call_tool("list_cities", {})
        assert reply["result"]["isError"] is True
    kinds = [e["EventType"] for e in _events(tmp_path)]
    assert "policy.load_failed" in kinds


def test_expected_policy_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    cmd = _gatehouse(
        tmp_path,
        "version: 1\ndefault_action: allow\npinning: tofu\n",
        "--expect-policy-sha256",
        "0" * 64,
    )
    with StdioClient(cmd, timeout=30) as c:
        c.initialize()
        c.list_tools()
        assert c.call_tool("list_cities", {})["result"]["isError"] is True
    failed = [e for e in _events(tmp_path) if e["EventType"] == "policy.load_failed"]
    assert failed and failed[0]["Details"]["ErrorKind"] == "integrity"


def test_stdout_carries_only_protocol_frames(tmp_path: Path) -> None:
    with StdioClient(
        _gatehouse(tmp_path, "version: 1\ndefault_action: allow\npinning: tofu\n"), timeout=30
    ) as c:
        c.initialize()
        c.list_tools()
        c.call_tool("get_forecast", {"city": "AKIAIOSFODNN7EXAMPLE"})
    assert c.unparsed == []


def test_upstream_crash_is_reported(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("version: 1\ndefault_action: allow\n", encoding="utf-8")
    cmd = [
        sys.executable, "-m", "gatehouse", "run", "--name", "dead", "--policy", str(policy_path),
        "--events-dir", str(tmp_path / "events"), "--",
        sys.executable, "-c", "import sys; sys.exit(3)",
    ]  # fmt: skip
    with StdioClient(cmd, timeout=30) as c:
        pass
    assert c.proc.returncode == 3
    assert any(e["EventType"] == "upstream.exited" for e in _events(tmp_path))
