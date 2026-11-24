"""Loading and validation. Every malformed policy must fail closed."""

from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

import gatehouse.policy.loader as loader_module
from gatehouse.policy import (
    MAX_POLICY_BYTES,
    Action,
    DecisionBasis,
    PolicyError,
    PolicyErrorKind,
    decide,
    load_policy,
    parse_policy,
)

MINIMAL = "version: 1\ndefault_action: block\n"


def _kind_of(text: str | bytes) -> PolicyErrorKind:
    with pytest.raises(PolicyError) as info:
        parse_policy(textwrap.dedent(text) if isinstance(text, str) else text)
    return info.value.kind


# --- valid input -------------------------------------------------------------------------


def test_minimal_policy() -> None:
    policy = parse_policy(MINIMAL)
    assert policy.default_action is Action.BLOCK
    assert policy.rules == ()


def test_shorthand_form() -> None:
    policy = parse_policy(
        MINIMAL + 'servers:\n  fs:\n    tools:\n      "*_exec*": require_approval\n'
    )
    (rule,) = policy.rules
    assert rule.tool_pattern == "*_exec*"
    assert rule.action is Action.REQUIRE_APPROVAL
    assert rule.reason is None


def test_object_form_with_reason() -> None:
    policy = parse_policy(
        MINIMAL
        + 'servers:\n  fs:\n    tools:\n      "*_exec*":\n'
        + "        action: require_approval\n        reason: needs a human\n"
    )
    (rule,) = policy.rules
    assert rule.action is Action.REQUIRE_APPROVAL
    assert rule.reason == "needs a human"


def test_object_form_without_reason() -> None:
    policy = parse_policy(MINIMAL + "servers:\n  fs:\n    tools:\n      x: {action: allow}\n")
    assert policy.rules[0].action is Action.ALLOW


def test_shorthand_and_object_form_are_equivalent() -> None:
    short = parse_policy(MINIMAL + "servers:\n  fs:\n    tools:\n      x: block\n")
    long = parse_policy(MINIMAL + "servers:\n  fs:\n    tools:\n      x: {action: block}\n")
    assert short == long


def test_utf8_bom_is_accepted() -> None:
    assert parse_policy(("﻿" + MINIMAL).encode("utf-8")).version == 1


def test_bytes_and_str_inputs_agree() -> None:
    assert parse_policy(MINIMAL) == parse_policy(MINIMAL.encode())


# --- malformed input: each case must raise with the right kind ---------------------------


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        pytest.param("", PolicyErrorKind.SCHEMA, id="empty-file"),
        pytest.param("# only a comment\n", PolicyErrorKind.SCHEMA, id="comments-only"),
        pytest.param("- version: 1\n", PolicyErrorKind.SCHEMA, id="top-level-list"),
        pytest.param("just a string\n", PolicyErrorKind.SCHEMA, id="top-level-scalar"),
        pytest.param("version: 1\ndefault_action: [block\n", PolicyErrorKind.YAML, id="bad-yaml"),
        pytest.param("default_action: block\n", PolicyErrorKind.SCHEMA, id="missing-version"),
        pytest.param("version: 1\n", PolicyErrorKind.SCHEMA, id="missing-default-action"),
        pytest.param("version: 2\ndefault_action: block\n", PolicyErrorKind.SCHEMA, id="version-2"),
        pytest.param(
            'version: "1"\ndefault_action: block\n', PolicyErrorKind.SCHEMA, id="version-str"
        ),
        pytest.param(
            "version: true\ndefault_action: block\n", PolicyErrorKind.SCHEMA, id="version-bool"
        ),
        pytest.param(
            "version: 1\ndefault_action: deny\n", PolicyErrorKind.SCHEMA, id="action-deny"
        ),
        pytest.param(
            "version: 1\ndefault_action: Block\n", PolicyErrorKind.SCHEMA, id="action-case"
        ),
        pytest.param("version: 1\ndefault_action: yes\n", PolicyErrorKind.SCHEMA, id="action-bool"),
        pytest.param("version: 1\ndefault_action:\n", PolicyErrorKind.SCHEMA, id="action-null"),
        pytest.param(MINIMAL + "rules: []\n", PolicyErrorKind.SCHEMA, id="unknown-top-key"),
        pytest.param(MINIMAL + "servers:\n", PolicyErrorKind.SCHEMA, id="servers-null"),
        pytest.param(
            MINIMAL + "servers:\n  fs: {}\n", PolicyErrorKind.SCHEMA, id="server-missing-tools"
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tool:\n      x: allow\n",
            PolicyErrorKind.SCHEMA,
            id="server-key-typo",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools:\n      x: {acton: allow}\n",
            PolicyErrorKind.SCHEMA,
            id="rule-key-typo",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools:\n      x: {action: allow, why: x}\n",
            PolicyErrorKind.SCHEMA,
            id="rule-unknown-key",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools:\n      x: permit\n",
            PolicyErrorKind.SCHEMA,
            id="shorthand-bad-action",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools:\n      x: {reason: hi}\n",
            PolicyErrorKind.SCHEMA,
            id="object-missing-action",
        ),
        pytest.param(
            MINIMAL + 'servers:\n  fs:\n    tools:\n      x: {action: allow, reason: ""}\n',
            PolicyErrorKind.SCHEMA,
            id="empty-reason",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools:\n      x: 1\n",
            PolicyErrorKind.SCHEMA,
            id="rule-is-int",
        ),
        pytest.param(
            MINIMAL + "servers:\n  on:\n    tools:\n      x: allow\n",
            PolicyErrorKind.SCHEMA,
            id="server-key-yaml-bool",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools:\n      123: allow\n",
            PolicyErrorKind.SCHEMA,
            id="tool-key-int",
        ),
        pytest.param(
            MINIMAL + 'servers:\n  fs:\n    tools:\n      "": allow\n',
            PolicyErrorKind.SCHEMA,
            id="empty-pattern",
        ),
        pytest.param(
            MINIMAL + 'servers:\n  fs:\n    tools:\n      "\\u200b\\u200d": allow\n',
            PolicyErrorKind.SCHEMA,
            id="pattern-empty-after-normalization",
        ),
        pytest.param(
            MINIMAL + 'servers:\n  fs:\n    tools:\n      " read_file": allow\n',
            PolicyErrorKind.SCHEMA,
            id="pattern-whitespace",
        ),
        pytest.param(
            MINIMAL + f"servers:\n  fs:\n    tools:\n      {'a' * 201}: allow\n",
            PolicyErrorKind.SCHEMA,
            id="pattern-too-long",
        ),
        pytest.param(
            MINIMAL
            + 'servers:\n  fs:\n    tools:\n      "Delete_*": block\n      "delete_*": allow\n',
            PolicyErrorKind.SCHEMA,
            id="tool-patterns-collide-after-normalization",
        ),
        pytest.param(
            MINIMAL
            + "servers:\n  GitHub:\n    tools: {x: allow}\n  github:\n    tools: {y: allow}\n",
            PolicyErrorKind.SCHEMA,
            id="server-patterns-collide-after-normalization",
        ),
        pytest.param(
            "version: 1\nversion: 1\ndefault_action: block\n",
            PolicyErrorKind.DUPLICATE_KEY,
            id="duplicate-top-key",
        ),
        pytest.param(
            MINIMAL
            + "servers:\n  fs:\n    tools:\n      delete_repo: block\n      delete_repo: allow\n",
            PolicyErrorKind.DUPLICATE_KEY,
            id="duplicate-tool-key",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools: {x: allow}\n  fs:\n    tools: {y: allow}\n",
            PolicyErrorKind.DUPLICATE_KEY,
            id="duplicate-server-key",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools: &t {x: allow}\n  gh:\n    tools: *t\n",
            PolicyErrorKind.ALIAS,
            id="anchor-and-alias",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs: &base\n    tools: {x: allow}\n  gh:\n    <<: *base\n",
            PolicyErrorKind.ALIAS,
            id="merge-key",
        ),
        pytest.param(
            MINIMAL + "servers:\n  fs:\n    tools:\n      ? [a, b]\n      : allow\n",
            PolicyErrorKind.SCHEMA,
            id="non-scalar-key",
        ),
    ],
)
def test_malformed_policy_is_rejected(text: str, kind: PolicyErrorKind) -> None:
    assert _kind_of(text) is kind


def test_unquoted_leading_star_is_rejected_with_hint() -> None:
    with pytest.raises(PolicyError) as info:
        parse_policy(MINIMAL + "servers:\n  fs:\n    tools:\n      *: allow\n")
    assert info.value.kind in {PolicyErrorKind.YAML, PolicyErrorKind.ALIAS}
    assert "must be quoted" in info.value.message


def test_too_large() -> None:
    assert _kind_of(b"#" * (MAX_POLICY_BYTES + 1)) is PolicyErrorKind.TOO_LARGE


def test_invalid_utf8() -> None:
    assert _kind_of(b"version: 1\ndefault_action: block\n# \xff\xfe\n") is PolicyErrorKind.ENCODING


def test_deeply_nested_yaml_does_not_crash() -> None:
    depth = 5000
    assert _kind_of("a: " + "[" * depth + "]" * depth + "\n") is PolicyErrorKind.YAML


def test_schema_error_message_names_the_location() -> None:
    with pytest.raises(PolicyError) as info:
        parse_policy(MINIMAL + "servers:\n  fs:\n    tools:\n      x: {acton: allow}\n")
    assert "servers.fs.tools.x" in info.value.message


def test_duplicate_key_message_names_both_lines() -> None:
    with pytest.raises(PolicyError) as info:
        parse_policy(MINIMAL + "servers:\n  fs:\n    tools:\n      d: block\n      d: allow\n")
    assert "line 7" in info.value.message
    assert "line 6" in info.value.message


# --- load_policy: never raises, always fails closed ---------------------------------------


def test_load_valid_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_bytes(MINIMAL.encode())
    load = load_policy(path)
    assert load.ok
    assert load.error is None
    assert load.sha256 is not None and len(load.sha256) == 64


def _missing(_p: Path) -> None:
    pass


def _directory(p: Path) -> None:
    p.mkdir()


def _bad_yaml(p: Path) -> None:
    p.write_text("version: [", encoding="utf-8")


def _bad_schema(p: Path) -> None:
    p.write_text("version: 9\ndefault_action: allow\n", encoding="utf-8")


def _too_large(p: Path) -> None:
    p.write_bytes(b"x" * (MAX_POLICY_BYTES + 1))


@pytest.mark.parametrize(
    ("setup", "kind"),
    [
        pytest.param(_missing, PolicyErrorKind.IO, id="missing-file"),
        pytest.param(_directory, PolicyErrorKind.IO, id="directory"),
        pytest.param(_bad_yaml, PolicyErrorKind.YAML, id="bad-yaml"),
        pytest.param(_bad_schema, PolicyErrorKind.SCHEMA, id="bad-schema"),
        pytest.param(_too_large, PolicyErrorKind.TOO_LARGE, id="too-large"),
    ],
)
def test_load_failure_fails_closed(
    tmp_path: Path, setup: Callable[[Path], None], kind: PolicyErrorKind
) -> None:
    path = tmp_path / "policy.yaml"
    setup(path)
    load = load_policy(path)

    assert not load.ok
    assert load.policy is None
    assert load.error is not None
    assert load.error.error_kind is kind

    decision = decide(load, "anything", "anything")
    assert decision.action is Action.BLOCK
    assert decision.basis is DecisionBasis.FAIL_CLOSED


def test_load_failure_even_with_permissive_content(tmp_path: Path) -> None:
    """A broken policy that *would* allow everything must still block everything."""
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\ndefault_action: allow\ndefault_action: allow\n", encoding="utf-8")
    load = load_policy(path)
    assert decide(load, "fs", "read_file").action is Action.BLOCK


def test_load_failure_event(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\ndefault_action: deny\n", encoding="utf-8")
    load = load_policy(path)
    assert load.error is not None

    event = load.error.to_event()
    assert event["EventType"] == "policy.load_failed"
    assert event["Severity"] == "critical"
    assert event["Action"] == "fail_closed"
    assert event["ErrorKind"] == "schema"
    assert event["PolicyPath"] == str(path)
    assert event["PolicySha256"] == load.sha256
    assert "default_action" in str(event["Message"])
    assert "TimeGenerated" in event


def test_internal_error_still_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(MINIMAL, encoding="utf-8")

    def boom(_data: bytes | str) -> None:
        raise RuntimeError("simulated bug")

    monkeypatch.setattr(loader_module, "parse_policy", boom)
    load = load_policy(path)
    assert load.error is not None
    assert load.error.error_kind is PolicyErrorKind.INTERNAL
    assert decide(load, "fs", "read_file").action is Action.BLOCK
