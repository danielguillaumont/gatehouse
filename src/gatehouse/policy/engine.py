"""Policy decisions: a pure function from (policy, server, tool) to a Decision.

Precedence (see docs/policy.md):

1. Fail closed: no valid policy  -> block.
2. Explicit block: any matching block rule -> block (IAM-style explicit deny).
3. Most specific match: among the remaining matches, keep the rules that no other
   matching rule dominates. If they all agree, that action wins.
4. Incomparable tie: if those rules disagree -> require_approval.
5. No match -> default_action.

Rule order in the file never affects the result.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from gatehouse.policy.loader import PolicyLoad
from gatehouse.policy.models import Action, CompiledRule, Policy
from gatehouse.policy.names import matches, normalize_name


class DecisionBasis(StrEnum):
    FAIL_CLOSED = "fail_closed"
    EXPLICIT_BLOCK = "explicit_block"
    MOST_SPECIFIC = "most_specific"
    TIE = "tie"
    DEFAULT = "default"


class RuleRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    server_pattern: str
    tool_pattern: str
    action: Action


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: Action
    basis: DecisionBasis
    reason: str
    matched_rules: tuple[RuleRef, ...]  # the rules that determined the outcome
    server: str  # normalized name actually matched
    tool: str


def _refs(rules: Iterable[CompiledRule]) -> tuple[RuleRef, ...]:
    ordered = sorted(rules, key=lambda r: (r.server_pattern, r.tool_pattern))
    return tuple(
        RuleRef(server_pattern=r.server_pattern, tool_pattern=r.tool_pattern, action=r.action)
        for r in ordered
    )


def _explain(rules: list[CompiledRule], prefix: str) -> str:
    ordered = sorted(rules, key=lambda r: (r.server_pattern, r.tool_pattern))
    custom = next((r.reason for r in ordered if r.reason), None)
    labels = ", ".join(r.label for r in ordered)
    return f"{custom} ({prefix}: {labels})" if custom else f"{prefix}: {labels}"


def evaluate(policy: Policy, server: str, tool: str) -> Decision:
    server_n = normalize_name(server)
    tool_n = normalize_name(tool)
    hits = [
        r for r in policy.rules if matches(r.server_norm, server_n) and matches(r.tool_norm, tool_n)
    ]

    def decision(
        action: Action, basis: DecisionBasis, reason: str, rules: list[CompiledRule]
    ) -> Decision:
        return Decision(
            action=action,
            basis=basis,
            reason=reason,
            matched_rules=_refs(rules),
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

    blocks = [r for r in hits if r.action is Action.BLOCK]
    if blocks:
        return decision(
            Action.BLOCK, DecisionBasis.EXPLICIT_BLOCK, _explain(blocks, "blocked by"), blocks
        )

    winners = [r for r in hits if not any(o.dominates(r) for o in hits)]
    actions = {r.action for r in winners}
    if len(actions) == 1:
        (action,) = actions
        return decision(action, DecisionBasis.MOST_SPECIFIC, _explain(winners, "matched"), winners)
    return decision(
        Action.REQUIRE_APPROVAL,
        DecisionBasis.TIE,
        _explain(winners, "equally specific rules disagree"),
        winners,
    )


def decide(load: PolicyLoad, server: str, tool: str) -> Decision:
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
    return evaluate(load.policy, server, tool)
