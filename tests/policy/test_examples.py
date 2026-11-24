"""The shipped example policies must load and behave as documented."""

from __future__ import annotations

from pathlib import Path

import pytest

from gatehouse.policy import Action, DecisionBasis, decide, load_policy

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
A, B, R = Action.ALLOW, Action.BLOCK, Action.REQUIRE_APPROVAL


@pytest.mark.parametrize("name", ["policy-filesystem.yaml", "policy-multi-server.yaml"])
def test_example_loads(name: str) -> None:
    load = load_policy(EXAMPLES / name)
    assert load.ok, load.error


@pytest.mark.parametrize(
    ("server", "tool", "action", "basis"),
    [
        ("filesystem", "read_file", A, DecisionBasis.MOST_SPECIFIC),
        ("filesystem", "search_files", A, DecisionBasis.MOST_SPECIFIC),
        ("filesystem", "write_file", R, DecisionBasis.MOST_SPECIFIC),
        ("filesystem", "move_file", R, DecisionBasis.MOST_SPECIFIC),
        ("filesystem", "delete_file", B, DecisionBasis.EXPLICIT_BLOCK),
        ("filesystem", "create_directory", B, DecisionBasis.DEFAULT),
        ("github", "read_file", B, DecisionBasis.DEFAULT),
    ],
)
def test_filesystem_example(server: str, tool: str, action: Action, basis: DecisionBasis) -> None:
    decision = decide(load_policy(EXAMPLES / "policy-filesystem.yaml"), server, tool)
    assert (decision.action, decision.basis) == (action, basis)


@pytest.mark.parametrize(
    ("server", "tool", "action", "basis"),
    [
        ("github", "get_issue", A, DecisionBasis.MOST_SPECIFIC),
        ("github", "create_issue", A, DecisionBasis.MOST_SPECIFIC),
        ("github", "merge_pull_request", R, DecisionBasis.MOST_SPECIFIC),
        ("github", "update_issue", B, DecisionBasis.DEFAULT),
        ("github", "Delete_Repo", B, DecisionBasis.EXPLICIT_BLOCK),
        # github/list_* (exact server) dominates */*_exec* (wildcard server, same tool rank).
        ("github", "list_exec_jobs", A, DecisionBasis.MOST_SPECIFIC),
        ("prod-db", "query", R, DecisionBasis.MOST_SPECIFIC),
        ("prod-db", "describe_table", A, DecisionBasis.MOST_SPECIFIC),
        ("prod-db", "delete_table", B, DecisionBasis.EXPLICIT_BLOCK),
        # prod-*/* (glob server, wildcard tool) vs */*_exec* (wildcard server, glob tool):
        # incomparable, but both say require_approval.
        ("prod-db", "shell_exec", R, DecisionBasis.MOST_SPECIFIC),
        ("notes", "shell_exec", R, DecisionBasis.MOST_SPECIFIC),
        ("notes", "read_note", B, DecisionBasis.DEFAULT),
    ],
)
def test_multi_server_example(server: str, tool: str, action: Action, basis: DecisionBasis) -> None:
    decision = decide(load_policy(EXAMPLES / "policy-multi-server.yaml"), server, tool)
    assert (decision.action, decision.basis) == (action, basis)
