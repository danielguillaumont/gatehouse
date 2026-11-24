"""The attack suite itself: scenarios load, the judge is correct, and a smoke run works."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from attacks.__main__ import main as attacks_main
from attacks.harness import (
    Observation,
    ScenarioError,
    _scenario,  # pyright: ignore[reportPrivateUsage]
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
