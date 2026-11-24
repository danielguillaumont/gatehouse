"""Event sinks. Every sink receives already-redacted records (PascalCase dicts)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Protocol, TextIO


class Sink(Protocol):
    def write(self, record: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


class JsonlFileSink:
    """Append one JSON object per line. One file per gatehouse process.

    Separate files per process avoid interleaved writes when several wrappers (one per MCP
    server) run at once; Windows has no atomic O_APPEND across processes.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._fh: TextIO = open(path, "a", encoding="utf-8", newline="\n")

    def write(self, record: dict[str, Any]) -> None:
        self._fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class MemorySink:
    """Collects records in memory (tests, `gatehouse pin`)."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def write(self, record: dict[str, Any]) -> None:
        self.records.append(record)

    def close(self) -> None:
        pass


_LOUD_ACTIONS = {"blocked", "filtered", "approval_required", "denied", "fail_closed", "fail_open"}


class StderrSink:
    """Short human-readable lines on stderr for notable events.

    stderr is safe: MCP clients treat a stdio server's stderr as logs, never protocol.
    """

    def __init__(self, stream: TextIO | None = None, min_rank: int = 2) -> None:
        self._stream = stream or sys.stderr
        self._min_rank = min_rank

    def write(self, record: dict[str, Any]) -> None:
        rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            str(record.get("Severity")), 0
        )
        action = str(record.get("Action", "none"))
        if rank < self._min_rank and action not in _LOUD_ACTIONS:
            return
        parts = [
            f"gatehouse[{record.get('ServerName')}]",
            action.upper() if action != "none" else str(record.get("Severity", "")).upper(),
            str(record.get("EventType")),
        ]
        if record.get("ToolName"):
            parts.append(str(record["ToolName"]))
        if record.get("DetectorId"):
            parts.append(f"{record['DetectorId']}/{record.get('RuleId')}")
        if record.get("Reason"):
            parts.append(f"- {record['Reason']}")
        try:
            self._stream.write(" ".join(parts) + "\n")
            self._stream.flush()
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        pass
