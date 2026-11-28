"""Evaluation plumbing: shards, shard merging and schema equivalence (D-048, D-051)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attacks.__main__ import _shard  # pyright: ignore[reportPrivateUsage]
from attacks.evaluate import load_reports
from attacks.harness import _listing  # pyright: ignore[reportPrivateUsage]
from attacks.layers import LAYERS, NEEDS_OLLAMA, apply
from gatehouse.policy.loader import parse_policy

SCHEMA: dict[str, Any] = {"type": "object", "properties": {"url": {"type": "string"}}}
TOOL: dict[str, Any] = {
    "name": "fetch",
    "description": "Fetch a page.",
    "inputSchema": SCHEMA,
}


def test_rebuilt_schema_with_no_op_keywords_is_equivalent() -> None:
    rebuilt: dict[str, Any] = {
        **TOOL,
        "inputSchema": {
            "type": "object",
            "required": [],
            "properties": {"url": {"type": "string", "description": ""}},
        },
    }
    assert _listing([rebuilt]) == _listing([TOOL])


@pytest.mark.parametrize(
    "changed",
    [
        {**TOOL, "description": ""},  # the tool's own description is content
        {**TOOL, "inputSchema": {**SCHEMA, "required": ["url"]}},
        {**TOOL, "inputSchema": {"type": "object", "properties": {"url": {"type": "number"}}}},
        {**TOOL, "annotations": {"readOnlyHint": True}},
    ],
)
def test_real_changes_still_count(changed: dict[str, Any]) -> None:
    assert _listing([changed]) != _listing([TOOL])


def test_shard_spec() -> None:
    assert _shard(None) == (0, 1)
    assert _shard("2/4") == (2, 4)
    with pytest.raises(SystemExit):
        _shard("4/4")


def _report(root: Path, name: str, ids: list[str]) -> None:
    d = root / name
    d.mkdir()
    rows = [{"id": i, "expect": "attack", "outcome": "prevented"} for i in ids]
    (d / "report.json").write_text(json.dumps({"meta": {}, "results": rows}), "utf-8")


def test_shards_merge_into_one_set(tmp_path: Path) -> None:
    _report(tmp_path, "gatehouse__judge__heldout2.0", ["a", "c"])
    _report(tmp_path, "gatehouse__judge__heldout2.1", ["b"])
    _report(tmp_path, "gatehouse__full__heldout2", ["a", "b", "c"])
    reports = load_reports(tmp_path)
    assert set(reports) == {("gatehouse", "judge", "heldout2"), ("gatehouse", "full", "heldout2")}
    merged = reports[("gatehouse", "judge", "heldout2")]["results"]
    assert sorted(r["id"] for r in merged) == ["a", "b", "c"]


def test_judge_layer_is_a_valid_policy() -> None:
    assert NEEDS_OLLAMA <= set(LAYERS)
    text = apply(Path("attacks/policy-eval.yaml").read_text("utf-8"), "judge")
    (judge,) = parse_policy(text).classifiers
    assert judge.mode.value == "enforce" and judge.kind.value == "ollama"
