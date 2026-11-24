"""Sentinel (Logs Ingestion) sink: batching, failure reporting, configuration."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

from gatehouse.cli import main
from gatehouse.events.emitter import Emitter, EventContext
from gatehouse.events.schema import EventType
from gatehouse.events.sentinel import (
    DEFAULT_STREAM,
    SentinelConfig,
    SentinelSink,
    SentinelSinkError,
)
from gatehouse.events.sinks import MemorySink
from gatehouse.proxy import app
from gatehouse.proxy.app import RunOptions, build_emitter


class FakeUpload:
    def __init__(self, fail: int = 0) -> None:
        self.batches: list[list[dict[str, Any]]] = []
        self.fail = fail
        self.calls = 0
        self.lock = threading.Lock()

    def __call__(self, batch: list[dict[str, Any]]) -> None:
        with self.lock:
            self.calls += 1
            if self.fail:
                self.fail -= 1
                raise ConnectionError("HTTP 503 from ingestion endpoint")
            self.batches.append(list(batch))

    @property
    def records(self) -> list[dict[str, Any]]:
        return [r for b in self.batches for r in b]


def _wait(cond: Any, timeout: float = 3.0) -> None:
    end = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < end, "timed out"
        time.sleep(0.01)


def test_batches_by_size_and_flushes_on_close() -> None:
    up = FakeUpload()
    sink = SentinelSink(up, batch_max=3, flush_interval=60, backoff=0)
    for i in range(7):
        sink.write({"n": i})
    _wait(lambda: len(up.batches) == 2)
    sink.close()
    assert [len(b) for b in up.batches] == [3, 3, 1]
    assert [r["n"] for r in up.records] == list(range(7))
    assert sink.uploaded == 7


def test_flushes_on_interval() -> None:
    up = FakeUpload()
    sink = SentinelSink(up, batch_max=100, flush_interval=0.05, backoff=0)
    sink.write({"n": 1})
    _wait(lambda: up.records == [{"n": 1}])
    sink.close()


def test_transient_failure_is_retried() -> None:
    up = FakeUpload(fail=2)
    sink = SentinelSink(up, batch_max=1, flush_interval=60, retries=3, backoff=0)
    sink.write({"n": 1})
    sink.close()
    assert up.records == [{"n": 1}] and sink.dropped == 0


def test_persistent_failure_is_reported_on_the_next_write() -> None:
    up = FakeUpload(fail=99)
    sink = SentinelSink(up, batch_max=1, flush_interval=60, retries=2, backoff=0)
    sink.write({"n": 1})
    _wait(lambda: sink.dropped == 1)
    with pytest.raises(SentinelSinkError, match="503"):
        sink.write({"n": 2})
    sink.close()


def test_emitter_turns_sentinel_loss_into_fail_open() -> None:
    up = FakeUpload(fail=99)
    sentinel = SentinelSink(up, batch_max=1, flush_interval=60, retries=1, backoff=0)
    local = MemorySink()
    emitter = Emitter(EventContext(agent_session_id="a", server_name="s"), [local, sentinel])
    emitter.emit(EventType.SESSION_STARTED)
    _wait(lambda: sentinel.dropped >= 1)
    emitter.emit(EventType.SESSION_ENDED)
    fail_open = [r for r in local.records if r["EventType"] == "gatehouse.fail_open"]
    assert len(fail_open) == 1
    assert "SentinelSink" in fail_open[0]["Reason"]
    emitter.close()


def test_full_queue_drops_and_reports() -> None:
    gate = threading.Event()

    def slow(batch: list[dict[str, Any]]) -> None:
        gate.wait(5)

    sink = SentinelSink(slow, batch_max=1, flush_interval=60, queue_max=2, backoff=0)
    with pytest.raises(SentinelSinkError, match="queue full"):
        for i in range(10):
            sink.write({"n": i})
    assert sink.dropped >= 1
    gate.set()
    sink.close()


def test_config_from_env() -> None:
    assert SentinelConfig.from_env({}) is None
    assert SentinelConfig.from_env({"GATEHOUSE_SENTINEL_ENDPOINT": "https://x"}) is None
    cfg = SentinelConfig.from_env(
        {"GATEHOUSE_SENTINEL_ENDPOINT": "https://x", "GATEHOUSE_SENTINEL_DCR_ID": "dcr-1"}
    )
    assert cfg == SentinelConfig("https://x", "dcr-1", DEFAULT_STREAM)


def test_half_configured_sentinel_refuses_to_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GATEHOUSE_SENTINEL_ENDPOINT", raising=False)
    monkeypatch.delenv("GATEHOUSE_SENTINEL_DCR_ID", raising=False)
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\ndefault_action: allow\n", encoding="utf-8")
    rc = main(
        ["run", "--name", "s", "--policy", str(policy), "--sentinel-endpoint", "https://x",
         "--", "python", "-c", "pass"]
    )  # fmt: skip
    assert rc == 2
    assert "DCR id" in capsys.readouterr().err


def test_unavailable_sentinel_sink_is_reported_as_fail_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(cfg: SentinelConfig) -> Any:
        raise ImportError("No module named 'azure'")

    monkeypatch.setattr(app, "azure_uploader", missing)
    local = MemorySink()
    opts = RunOptions(
        server_name="s",
        policy_path=tmp_path / "p.yaml",
        command=["x"],
        events_dir=None,
        stderr_events=False,
        sentinel=SentinelConfig("https://x", "dcr-1"),
        extra_sinks=[local],
    )
    build_emitter(opts, EventContext(agent_session_id="a", server_name="s"))
    (event,) = [r for r in local.records if r["EventType"] == "gatehouse.fail_open"]
    assert "gatehouse[sentinel]" in event["Reason"]
