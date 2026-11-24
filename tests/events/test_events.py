from __future__ import annotations

import json
from pathlib import Path

import pytest

from gatehouse.events.emitter import Emitter, EventContext
from gatehouse.events.fingerprint import Fingerprinter, load_or_create_key
from gatehouse.events.redact import redact_str, redact_value
from gatehouse.events.schema import EventType, SecurityEvent, sentinel_columns
from gatehouse.events.sinks import JsonlFileSink, MemorySink, StderrSink

ROOT = Path(__file__).resolve().parents[2]
SECRET = "ghp_" + "Z" * 36


def _emitter() -> tuple[Emitter, MemorySink]:
    sink = MemorySink()
    return Emitter(EventContext(agent_session_id="a", server_name="s"), [sink]), sink


def test_free_text_fields_are_redacted() -> None:
    emitter, sink = _emitter()
    emitter.emit(
        EventType.TOOL_CALL,
        tool_name=f"tool_{SECRET}",
        reason=f"saw {SECRET}",
        details={"nested": [f"x {SECRET}"], SECRET: 1},
    )
    assert SECRET not in json.dumps(sink.records)


def test_invisible_characters_are_made_visible() -> None:
    assert redact_str("read​_file‮") == "read\\u200b_file\\u202e"


def test_long_values_are_truncated() -> None:
    assert len(redact_str("x" * 5000)) <= 512
    deep = redact_value({"a": {"b": {"c": {"d": {"e": 1}}}}})
    assert "<truncated>" in json.dumps(deep)


def test_records_use_pascal_case_columns() -> None:
    emitter, sink = _emitter()
    emitter.emit(EventType.SESSION_STARTED)
    record = sink.records[0]
    assert {"TimeGenerated", "EventType", "AgentSessionId", "ServerName", "SchemaVersion"} <= set(
        record
    )
    assert set(record) == {c["name"] for c in sentinel_columns()}


def test_checked_in_table_schema_matches_model() -> None:
    schema = json.loads(
        (ROOT / "detections" / "schema" / "GatehouseEvents_CL.json").read_text(encoding="utf-8")
    )
    assert schema["columns"] == sentinel_columns(), (
        "run: uv run gatehouse table-schema (and update the file)"
    )


def test_sentinel_types() -> None:
    types = {c["name"]: c["type"] for c in sentinel_columns()}
    assert types["TimeGenerated"] == "datetime"
    assert types["Details"] == "dynamic"
    assert types["Mitre"] == "dynamic"
    assert types["LatencyMs"] == "real"
    assert types["ProcessId"] == "int"


def test_broken_sink_does_not_raise() -> None:
    class Broken:
        def write(self, record: dict[str, object]) -> None:
            raise OSError("disk full")

        def close(self) -> None:
            pass

    sink = MemorySink()
    emitter = Emitter(EventContext(agent_session_id="a", server_name="s"), [Broken(), sink])
    emitter.emit(EventType.SESSION_STARTED)
    # the broken sink fails twice: the event itself and the fail_open report
    assert emitter.sink_errors == 2
    assert [r["EventType"] for r in sink.records] == ["session.started", "gatehouse.fail_open"]
    fail_open = sink.records[1]
    assert fail_open["Action"] == "fail_open" and fail_open["Severity"] == "high"
    # reported once per broken sink, not on every event
    emitter.emit(EventType.SESSION_ENDED)
    assert [r["EventType"] for r in sink.records][-1] == "session.ended"
    assert len(sink.records) == 3


def test_unwritable_event_dir_reports_fail_open(tmp_path: Path) -> None:
    from gatehouse.proxy.app import RunOptions, build_emitter

    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    mem = MemorySink()
    opts = RunOptions(
        server_name="s",
        policy_path=tmp_path / "p.yaml",
        command=["x"],
        events_dir=blocker / "events",
        stderr_events=False,
        extra_sinks=[mem],
    )
    build_emitter(opts, EventContext(agent_session_id="a", server_name="s"))
    assert [r["EventType"] for r in mem.records] == ["gatehouse.fail_open"]


def test_jsonl_sink(tmp_path: Path) -> None:
    path = tmp_path / "e" / "events.jsonl"
    sink = JsonlFileSink(path)
    sink.write({"A": "é"})
    sink.write({"B": 2})
    sink.close()
    lines = path.read_bytes().split(b"\n")
    assert lines[-1] == b"" and len(lines) == 3
    assert json.loads(lines[0]) == {"A": "é"}


def test_stderr_sink_only_prints_notable_events(capsys: pytest.CaptureFixture[str]) -> None:
    sink = StderrSink()
    sink.write({"Severity": "informational", "Action": "allowed", "EventType": "tool.call"})
    sink.write(
        {
            "Severity": "high",
            "Action": "blocked",
            "EventType": "tool.call",
            "ServerName": "s",
            "ToolName": "t",
        }
    )
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "BLOCKED" in err


def test_hmac_key_is_stable_and_private(tmp_path: Path) -> None:
    path = tmp_path / "k" / "hmac.key"
    a = load_or_create_key(path)
    b = load_or_create_key(path)
    assert a == b and len(a) == 32
    fp = Fingerprinter(a)
    assert fp.text("x") == fp.text("x") != Fingerprinter(b"o" * 32).text("x")
    assert fp.json({"b": 1, "a": 2}) == fp.json({"a": 2, "b": 1})


def test_event_model_forbids_unknown_fields() -> None:
    with pytest.raises(ValueError):
        SecurityEvent.model_validate({"bogus": 1})
