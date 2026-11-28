"""The Cedar compilation must decide exactly like the reference evaluator (D-040).

Hypothesis generates random policies (glob patterns of every kind, conditional rules,
defaults, flow modes) and random calls (names that collide with the patterns, arguments
that make conditions hold or fail, session and tool labels) and requires the action
Cedar returns to equal the action ``evaluate`` returns. Cedar is asked directly
(``cedar_action``), not through ``CedarEngine.decide``, which would hide a disagreement
behind the stricter-wins fallback.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gatehouse.policy import (
    Action,
    AuthzRequest,
    DecisionBasis,
    FlowMode,
    Label,
    Policy,
    evaluate,
    parse_policy,
)
from gatehouse.policy.cedar import CedarEngine, compile_policy

# A small alphabet makes patterns and names collide often; the odd characters check
# escaping in Cedar string and `like` literals.
_CHARS = ["a", "b", "_", '"', "\\", "é", "*"]
_NAMES = ["a", "b", "ab", "a_b", "ba", 'a"b', "a\\b", "é", "A", "aé", "a*b"]
_PATTERNS = [
    *_NAMES,
    "*",
    "a*",
    "*b",
    "a*b",
    "**",
    "*_*",
    "?",
    "a?",
    "[ab]",
    "[!a]*",
    "*\\*",
    'a"*',
    "é*",
]

pattern = st.one_of(
    st.sampled_from(_PATTERNS),
    st.text(alphabet=[*_CHARS, "?"], min_size=1, max_size=4).filter(lambda s: s == s.strip()),
)
name = st.one_of(st.sampled_from(_NAMES), st.text(alphabet=_CHARS, min_size=1, max_size=4))
action = st.sampled_from(list(Action))
labels = st.frozensets(st.sampled_from(list(Label)))


@st.composite
def rule(draw: st.DrawFn) -> Any:
    act = draw(action)
    if act is Action.BLOCK or draw(st.booleans()):
        return act.value
    stricter = [a for a in Action if a.strictness > act.strictness]
    return {
        "action": act.value,
        "when": {"k": {"one_of": [1]}},
        "otherwise": draw(st.sampled_from(stricter)).value,
    }


@st.composite
def policy_doc(draw: st.DrawFn) -> dict[str, Any]:
    servers = draw(
        st.dictionaries(
            pattern,
            st.dictionaries(pattern, rule(), min_size=1, max_size=4),
            max_size=4,
        )
    )
    label_rules = draw(
        st.dictionaries(
            pattern,
            st.dictionaries(
                pattern,
                st.lists(st.sampled_from([lbl.value for lbl in Label]), min_size=1, max_size=2),
                min_size=1,
                max_size=2,
            ),
            max_size=2,
        )
    )
    blocks: dict[str, dict[str, Any]] = {s: {"tools": t} for s, t in servers.items()}
    for s, labels in label_rules.items():
        blocks.setdefault(s, {})["labels"] = labels
    return {
        "version": 1,
        "default_action": draw(action).value,
        "flow": {"mode": draw(st.sampled_from(list(FlowMode))).value},
        "servers": blocks,
    }


request = st.builds(
    AuthzRequest,
    server=name,
    tool=name,
    arguments=st.sampled_from([None, {}, {"k": 1}, {"k": 2}, {"k": [1, 1]}]),
    tool_labels=labels,
    session_labels=labels,
)


def _policy(doc: dict[str, Any]) -> Policy | None:
    try:
        return Policy.model_validate(doc)
    except ValueError:
        return None  # e.g. two patterns that normalize to the same name


@settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(doc=policy_doc(), requests=st.lists(request, min_size=1, max_size=6))
def test_cedar_matches_reference(doc: dict[str, Any], requests: list[AuthzRequest]) -> None:
    policy = _policy(doc)
    if policy is None:
        return
    engine = CedarEngine(policy)
    for req in requests:
        reference = evaluate(
            policy,
            req.server,
            req.tool,
            req.arguments,
            tool_labels=req.tool_labels,
            session_labels=req.session_labels,
        )
        cedar, errored = engine.cedar_action(req)
        assert not errored
        assert cedar is reference.action, (
            f"{req!r}: cedar={cedar.value} reference={reference.action.value} "
            f"({reference.basis.value})\n{engine.compiled.text}"
        )
        assert engine.decide(req).basis is not DecisionBasis.ENGINE_DISAGREEMENT


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(doc=policy_doc(), req=request, extra=labels, extra_session=labels)
def test_labels_only_tighten(
    doc: dict[str, Any],
    req: AuthzRequest,
    extra: frozenset[Label],
    extra_session: frozenset[Label],
) -> None:
    # `policy prove` relies on this: adding labels never makes a decision less strict.
    policy = _policy(doc)
    if policy is None:
        return
    engine = CedarEngine(policy)
    more = AuthzRequest(
        req.server,
        req.tool,
        req.arguments,
        req.tool_labels | extra,
        req.session_labels | extra_session,
    )
    before, _ = engine.cedar_action(req)
    after, _ = engine.cedar_action(more)
    assert after.strictness >= before.strictness


def test_disagreement_takes_the_stricter_action(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = parse_policy("version: 1\ndefault_action: allow\n")
    engine = CedarEngine(policy)

    def fake(_req: AuthzRequest) -> tuple[Action, bool]:
        return Action.BLOCK, False

    monkeypatch.setattr(engine, "cedar_action", fake)
    decision = engine.decide(AuthzRequest("s", "t"))
    assert decision.action is Action.BLOCK
    assert decision.basis is DecisionBasis.ENGINE_DISAGREEMENT


def test_evaluation_errors_block(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = parse_policy("version: 1\ndefault_action: allow\n")
    engine = CedarEngine(policy)

    def fake(_req: AuthzRequest) -> tuple[Action, bool]:
        return Action.ALLOW, True

    monkeypatch.setattr(engine, "cedar_action", fake)
    assert engine.decide(AuthzRequest("s", "t")).action is Action.BLOCK


def test_compiled_policy_text_is_deterministic() -> None:
    text = (
        "version: 1\ndefault_action: require_approval\nflow: {mode: enforce}\n"
        "servers:\n  '*': {tools: {'*_?': block, 'read_*': allow}}\n"
        "  fs: {tools: {read_file: allow}}\n"
    )
    assert compile_policy(parse_policy(text)).text == compile_policy(parse_policy(text)).text


def test_names_never_reach_cedar_syntax() -> None:
    # A tool name full of Cedar syntax is data in the request, not policy text.
    policy = parse_policy(
        "version: 1\ndefault_action: block\nservers:\n  s: {tools: {ok: allow}}\n"
    )
    engine = CedarEngine(policy)
    evil = 'ok" || true || "'
    assert engine.cedar_action(AuthzRequest("s", evil)) == (Action.BLOCK, False)
    assert engine.cedar_action(AuthzRequest("s", "ok")) == (Action.ALLOW, False)
