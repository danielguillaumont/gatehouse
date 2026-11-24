from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from gatehouse.cli import main

pytestmark = pytest.mark.integration

SERVER = Path(__file__).resolve().parents[1] / "servers" / "weather_server.py"
EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


def test_validate_policy(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate-policy", str(EXAMPLES / "policy-filesystem.yaml")]) == 0
    assert "OK" in capsys.readouterr().out


def test_validate_policy_rejects_bad_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("version: 1\n", encoding="utf-8")
    assert main(["validate-policy", str(bad)]) == 1
    assert "INVALID (schema)" in capsys.readouterr().err


def test_policy_hash(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["policy-hash", str(EXAMPLES / "policy-filesystem.yaml")]) == 0
    assert len(capsys.readouterr().out.strip()) == 64


def test_table_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["table-schema"]) == 0
    cols = json.loads(capsys.readouterr().out)
    assert cols[0] == {"name": "TimeGenerated", "type": "datetime"}


def test_pin_then_diff(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    pins = tmp_path / "pins.json"
    cmd = ["--", sys.executable, str(SERVER)]
    assert main(["pin", "--name", "weather", "--pins", str(pins), *cmd]) == 0
    assert "2 tool(s) pinned" in capsys.readouterr().out
    assert main(["diff", "--name", "weather", "--pins", str(pins), *cmd]) == 0
    capsys.readouterr()
    monkeypatch.setenv("WEATHER_POISONED", "1")
    assert main(["diff", "--name", "weather", "--pins", str(pins), *cmd]) == 1
    out = capsys.readouterr().out
    assert "~ changed  get_forecast  fields: description" in out
    assert "id_rsa" in out


def test_pin_selected_tool(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pins = tmp_path / "pins.json"
    rc = main(
        [
            "pin",
            "--name",
            "weather",
            "--pins",
            str(pins),
            "--tool",
            "list_cities",
            "--",
            sys.executable,
            str(SERVER),
        ]
    )
    assert rc == 0
    assert "1 tool(s) pinned" in capsys.readouterr().out
