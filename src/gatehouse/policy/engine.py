"""Policy decisions: a pure function from (policy, server, tool) to a Decision.

Precedence (see docs/policy.md):

1. Fail closed: no valid policy  -> block.
2. A rule with ``when:`` conditions acts with ``action`` if they all hold for the call's
   arguments and with ``otherwise`` if not (D-040). Matching itself ignores conditions.
3. Explicit block: any matching rule acting as block -> block (IAM-style explicit deny).
4. Most specific match: among the remaining matches, keep the rules that no other
   matching rule dominates. If they all agree, that action wins.
5. Incomparable tie: if those rules disagree -> require_approval.
6. No match -> default_action.
7. Flow control (``flow.mode``): a call that would give the session all three Rule-of-Two
   properties needs approval (``approve``) or is blocked (``enforce``).

Rule order in the file never affects the result. This module is the reference
semantics; ``gatehouse.policy.cedar`` compiles the same policy to Cedar and is tested
against it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from gatehouse.policy.conditions import all_hold
from gatehouse.policy.loader import PolicyLoad
from gatehouse.policy.models import (
    Action,
    CompiledRule,
    FlowMode,
    Label,
    PinningMode,
    Policy,
)
from gatehouse.policy.names import matches, normalize_name


class DecisionBasis(StrEnum):
    FAIL_CLOSED = "fail_closed"
    EXPLICIT_BLOCK = "explicit_block"
    MOST_SPECIFIC = "most_specific"
    TIE = "tie"
    DEFAULT = "default"
    FLOW = "flow"  # the Rule-of-Two check changed the outcome
    ENGINE_DISAGREEMENT = "engine_disagreement"  # Cedar and the reference differed


TRIFECTA_EGRESS = frozenset({Label.STATE_CHANGE, Label.EGRESS})
ALL_LABELS = frozenset(Label)


@dataclass(frozen=True, slots=True)
class AuthzRequest:
    """Everything a policy decision may depend on. Names are raw (normalized here)."""

    server: str
    tool: str
    arguments: Mapping[str, Any] | None = None
    tool_labels: frozenset[Label] = frozenset()
    session_labels: frozenset[Label] = frozenset()
    principal: str = "local"


class PolicyEngine(Protocol):
    """Decides one call. Implementations must be pure (no I/O) and agree with
    ``evaluate``; see tests/policy/test_cedar_differential.py."""

    def decide(self, request: AuthzRequest) -> Decision: ...


def completes_trifecta(tool: frozenset[Label], session: frozenset[Label]) -> bool:
    """True if calling a tool with ``tool`` labels in a session that already holds
    ``session`` labels gives the session all three Rule-of-Two properties, with the tool
    contributing at least one of them."""
    combined = tool | session
    return (
        Label.UNTRUSTED_INPUT in combined
        and Label.PRIVATE_DATA in combined
        and bool(combined & TRIFECTA_EGRESS)
        and bool(tool & ALL_LABELS)
    )


class RuleRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    server_pattern: str
    tool_pattern: str
    action: Action  # the action this rule took for this call (after its conditions)
    rule_id: str = ""


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: Action
    basis: DecisionBasis
    reason: str
    matched_rules: tuple[RuleRef, ...]  # the rules that determined the outcome
    server: str  # normalized name actually matched
    tool: str
    flow_violation: bool = False  # the call completes the Rule-of-Two trifecta


def _refs(rules: Iterable[CompiledRule], acts: Mapping[str, Action]) -> tuple[RuleRef, ...]:
    ordered = sorted(rules, key=lambda r: (r.server_pattern, r.tool_pattern))
    return tuple(
        RuleRef(
            server_pattern=r.server_pattern,
            tool_pattern=r.tool_pattern,
            action=acts.get(r.rule_id, r.action),
            rule_id=r.rule_id,
        )
        for r in ordered
    )


def acting(rule: CompiledRule, arguments: Mapping[str, Any] | None) -> Action:
    """The action a matching rule takes for these arguments."""
    if not rule.conditions:
        return rule.action
    if all_hold(dict(rule.conditions), arguments):
        return rule.action
    return rule.otherwise or Action.BLOCK


def matching_rules(policy: Policy, server: str, tool: str) -> list[CompiledRule]:
    """Rules whose patterns match the (raw) names, in rule-id order."""
    server_n = normalize_name(server)
    tool_n = normalize_name(tool)
    return [
        r for r in policy.rules if matches(r.server_norm, server_n) and matches(r.tool_norm, tool_n)
    ]


def _explain(rules: list[CompiledRule], prefix: str) -> str:
    ordered = sorted(rules, key=lambda r: (r.server_pattern, r.tool_pattern))
    custom = next((r.reason for r in ordered if r.reason), None)
    labels = ", ".join(r.label for r in ordered)
    return f"{custom} ({prefix}: {labels})" if custom else f"{prefix}: {labels}"


def evaluate(
    policy: Policy,
    server: str,
    tool: str,
    arguments: Mapping[str, Any] | None = None,
    *,
    tool_labels: frozenset[Label] = frozenset(),
    session_labels: frozenset[Label] = frozenset(),
) -> Decision:
    """The reference decision. Without ``arguments``, every condition fails.

    ``tool_labels`` are extra labels (hints); the policy's own labels for the tool always
    apply, so a caller can't leave them out."""
    tool_labels = tool_labels | policy.labels_for(server, tool)
    base = _rules_decision(policy, server, tool, arguments)
    violation = completes_trifecta(tool_labels, session_labels)
    mode = policy.flow.mode
    if not violation or mode is FlowMode.OFF:
        return base
    flagged = base.model_copy(update={"flow_violation": True})
    target = {FlowMode.APPROVE: Action.REQUIRE_APPROVAL, FlowMode.ENFORCE: Action.BLOCK}.get(mode)
    if target is None or base.action.strictness >= target.strictness:
        return flagged
    have = ", ".join(sorted(label.value for label in session_labels)) or "none"
    adds = ", ".join(sorted(label.value for label in tool_labels))
    return flagged.model_copy(
        update={
            "action": target,
            "basis": DecisionBasis.FLOW,
            "reason": (
                f"Rule of Two: the session holds [{have}] and this tool adds [{adds}]; "
                f"flow mode is {mode.value} (rules alone: {base.action.value})"
            ),
        }
    )


def _rules_decision(
    policy: Policy, server: str, tool: str, arguments: Mapping[str, Any] | None
) -> Decision:
    server_n = normalize_name(server)
    tool_n = normalize_name(tool)
    hits = matching_rules(policy, server, tool)
    acts = {r.rule_id: acting(r, arguments) for r in hits}

    def decision(
        action: Action, basis: DecisionBasis, reason: str, rules: list[CompiledRule]
    ) -> Decision:
        return Decision(
            action=action,
            basis=basis,
            reason=reason,
            matched_rules=_refs(rules, acts),
            server=server_n,
            tool=tool_n,
        )

    if not hits:
        return decision(
            policy.default_action,
            DecisionBasis.DEFAULT,
            f"no rule matched; default_action is {policy.default_action.value}",
            [],
        )

    blocks = [r for r in hits if acts[r.rule_id] is Action.BLOCK]
    if blocks:
        return decision(
            Action.BLOCK, DecisionBasis.EXPLICIT_BLOCK, _explain(blocks, "blocked by"), blocks
        )

    winners = [r for r in hits if not any(o.dominates(r) for o in hits)]
    actions = {acts[r.rule_id] for r in winners}
    if len(actions) == 1:
        (action,) = actions
        return decision(action, DecisionBasis.MOST_SPECIFIC, _explain(winners, "matched"), winners)
    return decision(
        Action.REQUIRE_APPROVAL,
        DecisionBasis.TIE,
        _explain(winners, "equally specific rules disagree"),
        winners,
    )


def pinning_mode(policy: Policy, server: str) -> PinningMode:
    """Pinning mode for a server: most specific matching server block, else the global.

    Ties between equally specific server patterns resolve to the strictest mode.
    """
    server_n = normalize_name(server)
    hits = [(spec, mode) for pat, spec, mode in policy.pinning_overrides if matches(pat, server_n)]
    if not hits:
        return policy.pinning
    best = max(spec for spec, _ in hits)
    return max((mode for spec, mode in hits if spec == best), key=lambda m: m.strictness)


class NativeEngine:
    """The reference engine (``engine: native``)."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def decide(self, request: AuthzRequest) -> Decision:
        return evaluate(
            self.policy,
            request.server,
            request.tool,
            request.arguments,
            tool_labels=request.tool_labels,
            session_labels=request.session_labels,
        )


def decide(
    load: PolicyLoad,
    server: str,
    tool: str,
    arguments: Mapping[str, Any] | None = None,
    *,
    tool_labels: frozenset[Label] = frozenset(),
    session_labels: frozenset[Label] = frozenset(),
) -> Decision:
    """Evaluate against a loaded policy, blocking everything if the load failed."""
    if load.policy is None:
        kind = load.error.error_kind.value if load.error else "unknown"
        return Decision(
            action=Action.BLOCK,
            basis=DecisionBasis.FAIL_CLOSED,
            reason=f"policy failed to load ({kind}); blocking all tool calls",
            matched_rules=(),
            server=normalize_name(server),
            tool=normalize_name(tool),
        )
    request = AuthzRequest(server, tool, arguments, tool_labels, session_labels)
    engine: PolicyEngine = load.engine if load.engine is not None else NativeEngine(load.policy)
    return engine.decide(request)
