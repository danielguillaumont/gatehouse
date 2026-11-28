"""The attack suite itself: scenarios load, the judge is correct, and a smoke run works."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attacks.__main__ import main as attacks_main
from attacks.harness import (
    Observation,
    ScenarioError,
    _scenario,  # pyright: ignore[reportPrivateUsage]
    approvals_asked,
    attack_succeeded,
    benign_interference,
    load_scenarios,
    run_scenario,
)
from attacks.report import build_report, judge, render_markdown
from attacks.targets import TARGETS


def test_all_scenarios_load_with_unique_ids() -> None:
    scenarios = load_scenarios()
    assert len(scenarios) >= 60
    assert len({s.id for s in scenarios}) == len(scenarios)
    assert sum(s.benign for s in scenarios) >= 10


def test_unknown_predicate_is_rejected() -> None:
    raw: dict[str, Any] = {
        "id": "x",
        "category": "c",
        "milestone": "mvp",
        "title": "t",
        "server": {"tools": []},
        "success_if": {"bogus": {}},
    }
    with pytest.raises(ScenarioError):
        _scenario(raw, "inline")


def test_unicode_tags_predicate_matches_decoded_characters() -> None:
    (sc,) = load_scenarios(only=["poison.unicode-tags"])
    tool = sc.phases[0].server["tools"][0]
    obs = Observation(sc.id, "direct", lists=[[tool]])
    assert attack_succeeded(sc, obs)
    clean = {**tool, "description": "Summarize a document."}
    assert not attack_succeeded(sc, Observation(sc.id, "direct", lists=[[clean]]))


def test_benign_judge_flags_hidden_tools_and_blocked_calls() -> None:
    (sc,) = load_scenarios(only=["benign.password-reset-tool"])
    obs = Observation(
        sc.id,
        "gatehouse",
        lists=[[]],
        calls=[{"tool": "send_password_reset", "response": {"error": {"message": "no"}}}],
    )
    problems = benign_interference(sc, obs)
    assert len(problems) == 2


@pytest.mark.integration
@pytest.mark.parametrize("target", ["direct", "gatehouse"])
def test_smoke_run(target: str) -> None:
    ids = ["rugpull.in-session", "secrets.aws-access-key", "benign.dev-commands"]
    results = [judge(sc, run_scenario(sc, TARGETS[target])) for sc in load_scenarios(only=ids)]
    outcomes = {r.id: r.outcome for r in results}
    if target == "direct":
        assert outcomes["rugpull.in-session"] == "missed"
        assert outcomes["secrets.aws-access-key"] == "missed"
    else:
        assert outcomes["rugpull.in-session"] == "prevented"
        assert outcomes["secrets.aws-access-key"] == "prevented"
    assert outcomes["benign.dev-commands"] == "pass"
    md = render_markdown(build_report(target, results))
    assert "| mvp |" in md


@pytest.mark.integration
def test_cli_run_and_canary_check(tmp_path: Path) -> None:
    out = tmp_path / "r"
    rc = attacks_main(["run", "--target", "gatehouse", "--out", str(out), "--only", "secrets.jwt"])
    assert rc == 0
    assert (out / "report.md").exists()
    assert attacks_main(["canary-check", str(out)]) == 0
    # a planted leak is found
    leak = out / "evidence" / "secrets.jwt" / "stderr.txt"
    leak.write_text("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUllKV1QifQ.Q0FOQVJZc2lnbmF0dXJlQ0FOQVJZ")
    assert attacks_main(["canary-check", str(out)]) == 1


def test_target_result_marker_is_stripped_and_counted() -> None:
    from attacks.harness import strip_result_marker

    calls: list[dict[str, Any]] = [
        {"response": {"result": {"content": [{"type": "text", "text": "ok<!-- gw:0a1b2c3d -->"}]}}},
        {"response": {"error": {"code": 1}}},
    ]
    assert strip_result_marker(calls, r"<!-- gw:[0-9a-f]{8} -->") == 1
    assert calls[0]["response"]["result"]["content"][0]["text"] == "ok"


def test_competitor_patterns_are_clean_and_match() -> None:
    import re

    from attacks.targets import TARGETS

    for target in TARGETS.values():
        for pattern in (target.result_marker, target.stderr_alert):
            if pattern is not None:
                assert not any(ord(c) < 32 for c in pattern), target.name
    alert = TARGETS["mcp-watchdog"].stderr_alert
    assert alert is not None
    panel = "| CRITICAL [CMD-INJECT] upstream | LOW [ENTROPY] Unusual JSON nesting depth"
    assert re.findall(alert, panel) == ["CRITICAL [CMD-INJECT]"]


@pytest.mark.parametrize("target", ["direct", "gatehouse"])
def test_http_scenarios(tmp_path: Path, target: str) -> None:
    """Every HTTP attack works without a proxy and is prevented by gatehouse (D-039)."""
    assert attacks_main(["http", "--target", target, "--out", str(tmp_path)]) == 0
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    outcomes = {r["id"]: r["outcome"] for r in report["results"]}
    attacks = [k for k in outcomes if ".benign." not in k]
    expected = "missed" if target == "direct" else "prevented"
    assert attacks and all(outcomes[k] == expected for k in attacks)
    assert all(v == "pass" for k, v in outcomes.items() if ".benign." in k)


@pytest.mark.integration
@pytest.mark.parametrize("target", ["direct", "gatehouse"])
def test_multi_server_flow_scenario(target: str) -> None:
    # Three gatehouse processes share one agent session through the flow store: the chain
    # works without a proxy and is stopped by structure (not detection) through gatehouse.
    (sc,) = load_scenarios(only=["flow.paraphrased-exfil"])
    assert set(sc.servers) == {"notes", "web", "mail"} and not sc.phases
    obs = run_scenario(sc, TARGETS[target], flow_mode="approve")
    res = judge(sc, obs)
    if target == "direct":
        assert res.outcome == "missed"
    else:
        assert res.outcome == "prevented"
        assert res.detections == ["tool.call/flow"]


@pytest.mark.integration
def test_benign_flow_task_counts_approvals() -> None:
    (sc,) = load_scenarios(only=["benign.flow.inbox-reply"])
    obs = run_scenario(sc, TARGETS["gatehouse"], flow_mode="approve")
    assert judge(sc, obs).outcome == "pass"
    assert approvals_asked(obs) == 1


def test_flow_scenarios_need_a_known_policy() -> None:
    with pytest.raises(ScenarioError, match="policy"):
        _scenario(
            {
                "id": "x",
                "category": "flow",
                "milestone": "m5",
                "title": "t",
                "policy": "other",
                "servers": {"a": {"tools": []}},
                "steps": [],
                "success_if": {"server_received": {"tool": "t"}},
            },
            "test",
        )
