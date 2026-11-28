"""The evaluation-v2 collation counts what the reports say (D-048)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attacks.evaluate import collate, render


def _r(
    sid: str, outcome: str, *, category: str = "x", milestone: str = "m6", approvals: int = 0
) -> dict[str, Any]:
    expect = "benign" if sid.startswith("benign.") else "attack"
    return {
        "id": sid,
        "category": category,
        "milestone": milestone,
        "expect": expect,
        "outcome": outcome,
        "approvals": approvals,
    }


def _write(root: Path, name: str, results: list[dict[str, Any]]) -> None:
    d = root / name
    d.mkdir(parents=True)
    meta = {"git_commit": "abc1234", "gatehouse_version": "0.3.0", "python": "3.12"}
    (d / "report.json").write_text(json.dumps({"meta": meta, "results": results}), encoding="utf-8")


def test_collate_ablation_and_comparison(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "gatehouse__full__suite",
        [
            _r("flow.a", "prevented", category="flow"),
            _r("flow.b", "missed", category="flow"),
            _r("x.bypass", "missed", milestone="bypass"),
            _r("benign.flow.t", "pass", approvals=1),
            _r("benign.y", "false_positive"),
        ],
    )
    _write(tmp_path, "gateward__-__suite", [_r("flow.a", "detected", category="flow")])
    data = collate(tmp_path)
    full = data["summary"]["gatehouse:full"]["suite"]
    assert (full["attacks"], full["prevented"], full["missed"]) == (2, 1, 1)  # bypass excluded
    assert (full["chains"], full["chains_completed"]) == (2, 1)
    assert (full["flow_benign"], full["flow_benign_approvals"], full["approvals"]) == (1, 1, 1)
    assert full["false_positives"] == 1
    md = render(data)
    assert "| `full` | 1 / 2 |" in md
    assert "| gateward | 0 / 1 / 0 |" in md
    assert "commit `abc1234`" in md
