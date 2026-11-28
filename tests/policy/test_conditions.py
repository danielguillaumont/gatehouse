"""Argument conditions (D-040): parsing is strict and every failure is the safe way."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from gatehouse.policy import Action, Policy, PolicyError, evaluate, parse_policy
from gatehouse.policy.conditions import (
    EmailDomains,
    NumberRange,
    OneOf,
    PathUnder,
    UrlHosts,
    holds,
    normalize_path,
    url_host,
)

PolicyFrom = Callable[[str], Policy]


def _email(*domains: str) -> EmailDomains:
    return EmailDomains(email_domains=domains)


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("alice@example.com", True),
        ("Alice <alice@example.com>", True),
        ("a@example.com, b@team.example.com; c@EXAMPLE.com", True),
        (["a@example.com", "b@x.example.com"], True),
        ("a@example.com, b@evil.com", False),
        ("a@example.com.evil.com", False),
        ("a@evilexample.com", False),
        ("not an address", False),
        ("a@", False),
        ("", False),
        ([], False),
        (42, False),
        (["a@example.com", 7], False),
        (["a@example.com"] * 65, False),  # too many values: fail, never truncate
    ],
)
def test_email_domains(value: Any, ok: bool) -> None:
    assert holds(_email("example.com", "*.example.com"), value) is ok


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("https://api.example.com/v1?q=1", True),
        ("https://API.Example.com.:443/", True),
        ("https://user:pw@api.example.com/", True),
        ("http://api.example.com/", False),  # scheme not allowed by default
        ("https://api.example.com@evil.com/", False),
        ("https://evil.com/?next=https://api.example.com", False),
        ("https://api.example.com.evil.com/", False),
        ("https://api.example.com:notaport/", False),
        ("https://api.example.com\\@evil.com/", False),
        ("https://xn--exmple-cua.com/", False),
        ("https://аpi.example.com/", False),  # non-ASCII: fail
        ("//api.example.com/", False),
        ("api.example.com", False),
        ("https://127.0.0.1/", False),
        ("https://[::1]/", False),
        (["https://api.example.com/", "https://evil.com/"], False),
    ],
)
def test_url_hosts(value: Any, ok: bool) -> None:
    assert holds(UrlHosts(url_hosts=("api.example.com",)), value) is ok


def test_url_host_ip_literal_needs_an_explicit_entry() -> None:
    assert url_host("https://127.0.0.1:8080/x", ("https",)) == "127.0.0.1"
    assert holds(UrlHosts(url_hosts=("127.0.0.1",)), "https://127.0.0.1/")


def test_url_hosts_schemes() -> None:
    cond = UrlHosts(url_hosts=("example.com",), schemes=("http", "https"))
    assert holds(cond, "http://example.com/")
    assert not holds(cond, "ftp://example.com/")
    assert not holds(cond, "file:///etc/passwd")


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("/srv/data/a.txt", True),
        ("/srv/data", True),
        ("/srv/data/./sub/../b", True),
        ("/srv/data/../secrets", False),
        ("/srv/database/x", False),  # prefix of a sibling, not under the root
        ("/srv/data/../../etc/passwd", False),
        ("relative/path", False),
        ("~/notes", False),
        ("//server/share/x", False),
        ("/srv/data/a\x00b", False),
        ("C:\\Users\\me\\Docs\\x.txt", True),
        ("c:/users/ME/docs/y", True),
        ("C:\\Users\\me\\Docs\\..\\..\\other", False),
        ("C:Users\\me\\Docs", False),  # drive-relative
        (["/srv/data/a", "/etc/passwd"], False),
    ],
)
def test_path_under(value: Any, ok: bool) -> None:
    cond = PathUnder(path_under=("/srv/data", "C:\\Users\\me\\Docs"))
    assert holds(cond, value) is ok


def test_normalize_path() -> None:
    assert normalize_path("/a/./b/../c//d/") == "/a/c/d"
    assert normalize_path("/") == "/"
    assert normalize_path("/..") is None
    assert normalize_path("D:\\X\\y") == "d:/x/y"


def test_path_root_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="absolute"):
        PathUnder(path_under=("data",))


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        (0, True),
        (100, True),
        (99.5, True),
        (101, False),
        (-1, False),
        ([1, 2, 3], True),
        ([1, 200], False),
        (True, False),
        ("50", False),
        (float("nan"), False),
        (float("inf"), False),
        (None, False),
    ],
)
def test_number_range(value: Any, ok: bool) -> None:
    assert holds(NumberRange(min=0, max=100), value) is ok


def test_number_range_validation() -> None:
    with pytest.raises(ValueError):
        NumberRange()
    with pytest.raises(ValueError):
        NumberRange(min=5, max=1)
    with pytest.raises(ValueError):
        NumberRange(max=float("inf"))


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("main", True),
        (["main", "dev"], True),
        ("Main", False),
        (["main", "prod"], False),
        (1, True),
        (True, False),
        ({"a": 1}, False),
    ],
)
def test_one_of(value: Any, ok: bool) -> None:
    assert holds(OneOf(one_of=("main", "dev", 1)), value) is ok


def test_host_patterns_are_validated() -> None:
    for bad in ("exa mple.com", "*example.com", "example.com/", " example.com", "*.*.com"):
        with pytest.raises(ValueError):
            UrlHosts(url_hosts=(bad,))


# --- conditions in policies ---------------------------------------------------------------

_MAIL = """
version: 1
default_action: block
servers:
  mail:
    tools:
      send_email:
        action: allow
        when:
          to: {email_domains: ["example.com"]}
          attachments_mb: {max: 10}
        otherwise: require_approval
"""


def test_rule_uses_action_when_all_conditions_hold(policy_from: PolicyFrom) -> None:
    policy = policy_from(_MAIL)
    ok = evaluate(policy, "mail", "send_email", {"to": "a@example.com", "attachments_mb": 3})
    assert ok.action is Action.ALLOW
    assert ok.matched_rules[0].action is Action.ALLOW


@pytest.mark.parametrize(
    "arguments",
    [
        {"to": "a@evil.com", "attachments_mb": 3},
        {"to": "a@example.com", "attachments_mb": 30},
        {"to": "a@example.com"},  # missing argument
        {"to": "a@example.com", "attachments_mb": None},
        {},
        None,
    ],
)
def test_rule_uses_otherwise_when_any_condition_fails(
    policy_from: PolicyFrom, arguments: dict[str, Any] | None
) -> None:
    decision = evaluate(policy_from(_MAIL), "mail", "send_email", arguments)
    assert decision.action is Action.REQUIRE_APPROVAL
    assert decision.matched_rules[0].action is Action.REQUIRE_APPROVAL


def test_otherwise_defaults_to_block(policy_from: PolicyFrom) -> None:
    policy = policy_from(
        """
        version: 1
        default_action: allow
        servers:
          fs:
            tools:
              read_file:
                action: allow
                when: {path: {path_under: ["/srv/data"]}}
        """
    )
    assert evaluate(policy, "fs", "read_file", {"path": "/etc/passwd"}).action is Action.BLOCK
    assert evaluate(policy, "fs", "read_file", {"path": "/srv/data/x"}).action is Action.ALLOW


def test_failed_condition_acting_as_block_is_an_explicit_block(policy_from: PolicyFrom) -> None:
    # A failed allow-condition (otherwise: block) must beat a more general allow, just
    # as an explicit block rule does.
    policy = policy_from(
        """
        version: 1
        default_action: allow
        servers:
          "*":
            tools:
              "*": allow
          fs:
            tools:
              write_file:
                action: allow
                when: {path: {path_under: ["/srv/out"]}}
        """
    )
    assert evaluate(policy, "fs", "write_file", {"path": "/etc/x"}).action is Action.BLOCK


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        ("{action: block, when: {x: {max: 1}}}", "unconditional"),
        ("{action: allow, when: {x: {max: 1}}, otherwise: allow}", "stricter"),
        ("{action: require_approval, when: {x: {max: 1}}, otherwise: allow}", "stricter"),
        ("{action: allow, otherwise: block}", "needs `when`"),
        ("{action: allow, when: {x: {nope: 1}}}", None),
        ("{action: allow, when: {}}", None),
    ],
)
def test_invalid_conditions_are_rejected(rule: str, message: str | None) -> None:
    text = f"version: 1\ndefault_action: block\nservers:\n  s:\n    tools:\n      t: {rule}\n"
    with pytest.raises(PolicyError, match=message):
        parse_policy(text)


def test_rule_ids_do_not_depend_on_file_order() -> None:
    head = "version: 1\ndefault_action: block\nservers:\n"
    a = parse_policy(head + "  b: {tools: {x: allow}}\n  a: {tools: {y: block}}\n")
    b = parse_policy(head + "  a: {tools: {y: block}}\n  b: {tools: {x: allow}}\n")
    assert [(r.rule_id, r.server_norm) for r in a.rules] == [
        (r.rule_id, r.server_norm) for r in b.rules
    ]
