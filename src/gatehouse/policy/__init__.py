"""Policy engine: YAML policy -> allow / block / require_approval decisions."""

from gatehouse.policy.engine import Decision, DecisionBasis, RuleRef, decide, evaluate
from gatehouse.policy.errors import PolicyError, PolicyErrorKind, PolicyLoadFailed
from gatehouse.policy.loader import MAX_POLICY_BYTES, PolicyLoad, load_policy, parse_policy
from gatehouse.policy.models import Action, Policy, ServerBlock, ToolRule
from gatehouse.policy.names import normalize_name

__all__ = [
    "MAX_POLICY_BYTES",
    "Action",
    "Decision",
    "DecisionBasis",
    "Policy",
    "PolicyError",
    "PolicyErrorKind",
    "PolicyLoad",
    "PolicyLoadFailed",
    "RuleRef",
    "ServerBlock",
    "ToolRule",
    "decide",
    "evaluate",
    "load_policy",
    "normalize_name",
    "parse_policy",
]
