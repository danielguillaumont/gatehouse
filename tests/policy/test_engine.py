"""Decision precedence, glob matching, defaults and name normalization."""

from __future__ import annotations

import itertools
from collections.abc import Callable

import pytest

from gatehouse.policy import Action, DecisionBasis, Policy, evaluate

PolicyFrom = Callable[[str], Policy]

A, B, R = Action.ALLOW, Action.BLOCK, Action.REQUIRE_APPROVAL


# --- defaults ---------------------------------------------------------------------------


@pytest.mark.parametrize("default", [A, B, R])
def test_no_match_uses_default(policy_from: PolicyFrom, default: Action) -> None:
    policy = policy_from(
        f"""
        version: 1
        default_action: {default.value}
        servers:
          fs:
            tools:
              read_file: allow
        """
    )
    decision = evaluate(policy, "github", "create_issue")
    assert decision.action is default
    assert decision.basis is DecisionBasis.DEFAULT
    assert decision.matched_rules == ()


def test_rule_beats_default(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          fs:
            tools:
              read_file: allow
        """
    )
    decision = evaluate(policy, "fs", "read_file")
    assert decision.action is A
    assert decision.basis is DecisionBasis.MOST_SPECIFIC


# --- explicit block wins ----------------------------------------------------------------


def test_explicit_block_beats_more_specific_allow(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: allow
        servers:
          fs:
            tools:
              "*": block
              read_file: allow
        """
    )
    decision = evaluate(policy, "fs", "read_file")
    assert decision.action is B
    assert decision.basis is DecisionBasis.EXPLICIT_BLOCK


def test_global_block_beats_server_specific_allow(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          "*":
            tools:
              "delete_*": block
          github:
            tools:
              delete_repo: allow
        """
    )
    decision = evaluate(policy, "github", "delete_repo")
    assert decision.action is B
    assert [r.server_pattern for r in decision.matched_rules] == ["*"]


def test_block_reason_is_reported(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: allow
        servers:
          "*":
            tools:
              "delete_*":
                action: block
                reason: Destructive operations are never automated
        """
    )
    decision = evaluate(policy, "fs", "delete_file")
    assert "Destructive operations are never automated" in decision.reason
    assert "delete_*" in decision.reason


def test_block_beats_require_approval(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: allow
        servers:
          fs:
            tools:
              write_file: require_approval
              "*_file": block
        """
    )
    assert evaluate(policy, "fs", "write_file").action is B


# --- most specific wins -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("specific", "broad", "expected"),
    [(A, R, A), (R, A, R)],
)
def test_exact_tool_beats_wildcard(
    policy_from: PolicyFrom, specific: Action, broad: Action, expected: Action
) -> None:
    policy = policy_from(
        f"""
        version: 1
        default_action: block
        servers:
          fs:
            tools:
              "*": {broad.value}
              read_file: {specific.value}
        """
    )
    decision = evaluate(policy, "fs", "read_file")
    assert decision.action is expected
    assert decision.basis is DecisionBasis.MOST_SPECIFIC
    assert [r.tool_pattern for r in decision.matched_rules] == ["read_file"]


def test_partial_glob_beats_wildcard(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          prod-db:
            tools:
              "*": require_approval
              "describe_*": allow
        """
    )
    assert evaluate(policy, "prod-db", "describe_table").action is A
    assert evaluate(policy, "prod-db", "query").action is R


def test_exact_beats_partial_glob(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          fs:
            tools:
              "read_*": require_approval
              read_file: allow
        """
    )
    assert evaluate(policy, "fs", "read_file").action is A
    assert evaluate(policy, "fs", "read_dir").action is R


def test_specific_server_beats_wildcard_server(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          "*":
            tools:
              "*": require_approval
          github:
            tools:
              "*": allow
        """
    )
    assert evaluate(policy, "github", "anything").action is A
    assert evaluate(policy, "notes", "anything").action is R


def test_server_glob_beats_server_wildcard(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          "*":
            tools:
              query: allow
          "prod-*":
            tools:
              query: require_approval
        """
    )
    assert evaluate(policy, "prod-db", "query").action is R
    assert evaluate(policy, "dev-db", "query").action is A


# --- incomparable ties ------------------------------------------------------------------


def test_incomparable_disagreement_requires_approval(policy_from: PolicyFrom) -> None:
    # github/* is more specific on server; */merge_* is more specific on tool.
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          github:
            tools:
              "*": allow
          "*":
            tools:
              "merge_*": require_approval
        """
    )
    decision = evaluate(policy, "github", "merge_pull_request")
    assert decision.action is R
    assert decision.basis is DecisionBasis.TIE
    assert len(decision.matched_rules) == 2


def test_equal_rank_disagreement_requires_approval(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          "*":
            tools:
              "close_*": allow
              "*_issue": require_approval
        """
    )
    decision = evaluate(policy, "github", "close_issue")
    assert decision.action is R
    assert decision.basis is DecisionBasis.TIE


def test_incomparable_agreement_keeps_action(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          github:
            tools:
              "*": allow
          "*":
            tools:
              "get_*": allow
        """
    )
    decision = evaluate(policy, "github", "get_issue")
    assert decision.action is A
    assert decision.basis is DecisionBasis.MOST_SPECIFIC
    assert len(decision.matched_rules) == 2


def test_dominated_rules_do_not_cause_a_tie(policy_from: PolicyFrom) -> None:
    # Three matching rules; github/get_issue dominates both others.
    policy = policy_from(
        """
        version: 1
        default_action: block
        servers:
          github:
            tools:
              get_issue: allow
              "*": require_approval
          "*":
            tools:
              "get_*": require_approval
        """
    )
    decision = evaluate(policy, "github", "get_issue")
    assert decision.action is A
    assert [r.tool_pattern for r in decision.matched_rules] == ["get_issue"]


# --- globs ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "name", "hit"),
    [
        ("delete_*", "delete_repo", True),
        ("delete_*", "delete_", True),
        ("delete_*", "undelete_repo", False),
        ("*_exec*", "shell_exec", True),
        ("*_exec*", "run_exec_job", True),
        ("*_exec*", "execute", False),
        ("get_?", "get_x", True),
        ("get_?", "get_xy", False),
        ("v[12]_*", "v1_list", True),
        ("v[12]_*", "v3_list", False),
        ("v[!12]_*", "v3_list", True),
        ("*", "", True),
    ],
)
def test_glob_matching(policy_from: PolicyFrom, pattern: str, name: str, hit: bool) -> None:
    policy = policy_from(
        f"""
        version: 1
        default_action: allow
        servers:
          s:
            tools:
              "{pattern}": block
        """
    )
    assert (evaluate(policy, "s", name).action is B) is hit


def test_glob_is_not_a_regex_or_path(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: allow
        servers:
          s:
            tools:
              "a.b": block
        """
    )
    assert evaluate(policy, "s", "a.b").action is B
    assert evaluate(policy, "s", "axb").action is A  # '.' is literal, not regex


# --- normalization: names are attacker-controlled ---------------------------------------

DELETE_GUARD = """
version: 1
default_action: allow
servers:
  "*":
    tools:
      "delete_*": block
      "kill_*": block
"""


@pytest.mark.parametrize(
    "tool",
    [
        pytest.param("Delete_Repo", id="mixed-case"),
        pytest.param("DELETE_REPO", id="upper-case"),
        pytest.param("ｄｅｌｅｔｅ＿repo", id="fullwidth"),
        pytest.param(
            "\U0001d41d\U0001d41e\U0001d425\U0001d41e\U0001d42d\U0001d41e_repo", id="math-bold"
        ),
        pytest.param("dele​te_repo", id="zero-width-space"),
        pytest.param("d­elete_repo", id="soft-hyphen"),
        pytest.param("‮delete_repo", id="bidi-override"),
        pytest.param("delete\U000e0041_repo", id="tag-character"),
        pytest.param("Kill_process", id="kelvin-sign"),
    ],
)
def test_lookalike_names_still_match(policy_from: PolicyFrom, tool: str) -> None:
    decision = evaluate(policy_from(DELETE_GUARD), "github", tool)
    assert decision.action is B, f"{tool!r} normalized to {decision.tool!r}"


@pytest.mark.xfail(
    reason="Known gap: NFKC does not fold cross-script confusables (Cyrillic U+0435). "
    "Covered by pinning and M2 detectors; see docs/policy.md.",
    strict=True,
)
def test_cyrillic_confusable_is_a_known_gap(policy_from: PolicyFrom) -> None:
    assert evaluate(policy_from(DELETE_GUARD), "github", "dеlete_repo").action is B


def test_server_names_are_normalized(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: allow
        servers:
          github:
            tools:
              "*": block
        """
    )
    assert evaluate(policy, "GitHub", "x").action is B
    assert evaluate(policy, "ＧｉｔＨｕｂ", "x").action is B


def test_patterns_are_normalized(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: allow
        servers:
          GitHub:
            tools:
              "Delete_*": block
        """
    )
    assert evaluate(policy, "github", "delete_repo").action is B


def test_decision_reports_normalized_names(policy_from: PolicyFrom) -> None:
    decision = evaluate(policy_from(DELETE_GUARD), "GitHub", "Dele​te_Repo")
    assert decision.server == "github"
    assert decision.tool == "delete_repo"


# --- order independence -----------------------------------------------------------------


def test_rule_order_never_changes_decisions() -> None:
    servers = {
        "*": {"delete_*": "block", "*_exec*": "require_approval", "get_*": "allow"},
        "github": {"*": "allow", "merge_*": "require_approval"},
        "prod-*": {"*": "require_approval", "describe_*": "allow"},
    }
    calls = [
        ("github", "get_issue"),
        ("github", "merge_pr"),
        ("github", "delete_repo"),
        ("github", "run_exec"),
        ("prod-db", "describe_x"),
        ("prod-db", "get_exec_log"),
        ("notes", "get_note"),
        ("notes", "write"),
    ]

    def build(server_order: tuple[str, ...], reverse_tools: bool) -> Policy:
        return Policy.model_validate(
            {
                "version": 1,
                "default_action": "block",
                "servers": {
                    s: {
                        "tools": dict(
                            reversed(servers[s].items()) if reverse_tools else servers[s].items()
                        )
                    }
                    for s in server_order
                },
            }
        )

    baseline = build(tuple(servers), False)
    expected = [evaluate(baseline, s, t).action for s, t in calls]
    for order in itertools.permutations(servers):
        for rev in (False, True):
            policy = build(order, rev)
            assert [evaluate(policy, s, t).action for s, t in calls] == expected
