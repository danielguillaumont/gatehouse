"""Pydantic models for the policy file (schema v1). See docs/policy.md."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from gatehouse.policy.conditions import Condition
from gatehouse.policy.names import Specificity, matches, normalize_name, specificity

MAX_PATTERN_LEN = 200
MAX_REASON_LEN = 500
SUPPORTED_VERSIONS = frozenset({1})


class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"

    @property
    def strictness(self) -> int:
        return {"allow": 0, "require_approval": 1, "block": 2}[self.value]


class Label(StrEnum):
    """Capability labels for session flow control (D-040, Meta's Rule of Two)."""

    UNTRUSTED_INPUT = "untrusted_input"  # results may carry attacker-controlled text
    PRIVATE_DATA = "private_data"  # results may carry the user's private data
    STATE_CHANGE = "state_change"  # changes something outside the conversation
    EGRESS = "egress"  # sends data outside (messages, uploads, outbound requests)


class FlowMode(StrEnum):
    OFF = "off"  # no flow control (v0.1 behaviour)
    MONITOR = "monitor"  # log Rule-of-Two violations
    APPROVE = "approve"  # a call that completes the trifecta needs approval
    ENFORCE = "enforce"  # a call that completes the trifecta is blocked


# StrictStr: YAML turns unquoted `on`, `yes`, `123` into bool/int. Those must be rejected,
# not coerced, so a key always means exactly what was typed.
Pattern = Annotated[StrictStr, Field(min_length=1, max_length=MAX_PATTERN_LEN)]


class _Strict(BaseModel):
    # extra="forbid": a typo such as `acton:` must fail loudly, never become "no rule".
    model_config = ConfigDict(extra="forbid", frozen=True)


ArgName = Annotated[StrictStr, Field(min_length=1, max_length=MAX_PATTERN_LEN)]


class ToolRule(_Strict):
    action: Action
    reason: Annotated[StrictStr, Field(min_length=1, max_length=MAX_REASON_LEN)] | None = None
    # Argument conditions (D-040): `action` applies if all hold, `otherwise` if not.
    when: Annotated[dict[ArgName, Condition], Field(min_length=1, max_length=32)] | None = None
    otherwise: Action | None = None

    @model_validator(mode="after")
    def _conditions(self) -> ToolRule:
        if self.when is None:
            if self.otherwise is not None:
                raise ValueError("`otherwise` needs `when` conditions")
            return self
        if self.action is Action.BLOCK:
            raise ValueError("a `block` rule cannot have conditions: block is unconditional")
        otherwise = self.otherwise if self.otherwise is not None else Action.BLOCK
        if otherwise.strictness <= self.action.strictness:
            raise ValueError(
                f"`otherwise: {otherwise.value}` must be stricter than `action: "
                f"{self.action.value}`, so a condition that fails or cannot be checked "
                "never loosens the decision"
            )
        object.__setattr__(self, "otherwise", otherwise)
        return self


def _expand_shorthand(value: Any) -> Any:
    """Accept `tool: allow` as shorthand for `tool: {action: allow}`."""
    if isinstance(value, str):
        return {"action": value}
    return value


RuleSpec = Annotated[ToolRule, BeforeValidator(_expand_shorthand)]


class PinningMode(StrEnum):
    """How tool definitions are trusted (see docs/policy.md#pinning)."""

    STRICT = "strict"  # only tools pinned with `gatehouse pin` are visible/callable
    TOFU = "tofu"  # trust on first use: new tools are pinned automatically
    OFF = "off"  # no pinning (not recommended)

    @property
    def strictness(self) -> int:
        return {"off": 0, "tofu": 1, "strict": 2}[self.value]


class FindingAction(StrEnum):
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    LOG = "log"  # allow, but record the detection


class FindingActions(_Strict):
    """What to do when a detector reports a finding of a given severity."""

    critical: FindingAction = FindingAction.BLOCK
    high: FindingAction = FindingAction.BLOCK
    medium: FindingAction = FindingAction.LOG
    low: FindingAction = FindingAction.LOG
    informational: FindingAction = FindingAction.LOG

    def for_severity(self, severity: str) -> FindingAction:
        return FindingAction(getattr(self, severity))


class SamplingMode(StrEnum):
    INSPECT = "inspect"  # scan server sampling requests like tool results
    BLOCK = "block"  # refuse every server sampling request (deprecated feature, SEP-2577)


DEFAULT_MAX_TTL_MS = 300_000


class ProtocolSettings(_Strict):
    """Protocol-level controls (MCP 2026-07-28). See docs/policy.md#protocol."""

    # Cache hints (`ttlMs`) above this are lowered, so a client re-lists (and gatehouse
    # re-checks pins) at least this often. 0 disables client caching of inspected results.
    max_ttl_ms: Annotated[StrictInt, Field(ge=0, le=86_400_000)] = DEFAULT_MAX_TTL_MS
    # A server that was seen speaking a newer protocol revision and now answers with an
    # older one (e.g. fails `server/discover` so the client falls back to `initialize`)
    # is a downgrade. False: the downgraded session is refused.
    allow_downgrade: bool = False
    sampling: SamplingMode = SamplingMode.INSPECT


class FlowSettings(_Strict):
    """Session flow control (D-040). See docs/policy.md#flow."""

    mode: FlowMode = FlowMode.OFF
    # Server annotations and the tool-name heuristic may *add* labels to a tool (never
    # remove them): a server choosing its own labels could otherwise hide an egress tool.
    annotation_hints: bool = True
    name_hints: bool = True
    # An egress call whose arguments copy private data the session read (D-043): what to
    # do when the session also holds untrusted input. Without untrusted input it is
    # logged (sending your own notes to a colleague is a normal task).
    provenance: FindingAction = FindingAction.REQUIRE_APPROVAL


class ApprovalBudget(_Strict):
    """Approval prompts per agent session per window; 0 prompts means unlimited (D-044)."""

    prompts: int = Field(default=20, ge=0, le=10_000)
    minutes: int = Field(default=60, ge=1, le=24 * 60)


class ControlSettings(_Strict):
    """Response controls (ADR-0006, D-044). See docs/policy.md#response-controls."""

    # Keep withheld results for review with `gatehouse review` (raw output, owner-only file).
    quarantine: bool = True
    # Lock the agent session after this many calls or results with a high or critical
    # finding, until `gatehouse unlock`. 0 turns the breaker off.
    circuit_breaker: int = Field(default=5, ge=0, le=10_000)
    approval_budget: ApprovalBudget = Field(default_factory=ApprovalBudget)


class ServerBlock(_Strict):
    tools: dict[Pattern, RuleSpec] = Field(default_factory=dict[str, ToolRule])
    pinning: PinningMode | None = None
    labels: dict[Pattern, Annotated[tuple[Label, ...], Field(min_length=1)]] = Field(
        default_factory=dict[str, tuple[Label, ...]]
    )

    @model_validator(mode="after")
    def _not_empty(self) -> ServerBlock:
        if not self.tools and self.pinning is None and not self.labels:
            raise ValueError("server block must set `tools`, `pinning` and/or `labels`")
        return self


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A (server pattern, tool pattern) rule, normalized and ranked for evaluation."""

    server_pattern: str  # as written in the file (for explanations and events)
    tool_pattern: str
    server_norm: str
    tool_norm: str
    server_spec: Specificity
    tool_spec: Specificity
    action: Action
    reason: str | None
    rule_id: str = ""  # stable id, independent of file order (see Policy._compile)
    conditions: tuple[tuple[str, Condition], ...] = ()
    otherwise: Action | None = None

    def dominates(self, other: CompiledRule) -> bool:
        """True if self is at least as specific in both dimensions and strictly in one."""
        return (
            self.server_spec >= other.server_spec
            and self.tool_spec >= other.tool_spec
            and (self.server_spec > other.server_spec or self.tool_spec > other.tool_spec)
        )

    @property
    def label(self) -> str:
        return f"servers[{self.server_pattern!r}].tools[{self.tool_pattern!r}]"


def _check_pattern(pattern: str, where: str) -> str:
    if pattern != pattern.strip():
        raise ValueError(f"{where} pattern {pattern!r} has leading/trailing whitespace")
    normalized = normalize_name(pattern)
    if not normalized:
        raise ValueError(f"{where} pattern {pattern!r} is empty after normalization")
    return normalized


class Policy(_Strict):
    version: StrictInt
    default_action: Action
    pinning: PinningMode = PinningMode.STRICT
    findings: FindingActions = Field(default_factory=FindingActions)
    protocol: ProtocolSettings = Field(default_factory=ProtocolSettings)
    flow: FlowSettings = Field(default_factory=FlowSettings)
    controls: ControlSettings = Field(default_factory=ControlSettings)
    # Which engine decides (D-040). Both implement the same semantics; native is the
    # reference the Cedar compiler is tested against.
    engine: Literal["cedar", "native"] = "cedar"
    servers: dict[Pattern, ServerBlock] = Field(default_factory=dict[str, ServerBlock])

    _rules: tuple[CompiledRule, ...] = PrivateAttr(default=())
    _pinning: tuple[tuple[str, Specificity, PinningMode], ...] = PrivateAttr(default=())
    _labels: tuple[tuple[str, str, frozenset[Label]], ...] = PrivateAttr(default=())

    @field_validator("version")
    @classmethod
    def _supported_version(cls, v: int) -> int:
        if v not in SUPPORTED_VERSIONS:
            raise ValueError(
                f"unsupported policy version {v}; supported: {sorted(SUPPORTED_VERSIONS)}"
            )
        return v

    @model_validator(mode="after")
    def _compile(self) -> Policy:
        rules: list[CompiledRule] = []
        pinning: list[tuple[str, Specificity, PinningMode]] = []
        labels: list[tuple[str, str, frozenset[Label]]] = []
        seen_servers: dict[str, str] = {}
        for server_pattern, block in self.servers.items():
            server_norm = _check_pattern(server_pattern, "server")
            if server_norm in seen_servers:
                raise ValueError(
                    f"server patterns {seen_servers[server_norm]!r} and {server_pattern!r} "
                    "are identical after normalization"
                )
            seen_servers[server_norm] = server_pattern
            if block.pinning is not None:
                pinning.append((server_norm, specificity(server_norm), block.pinning))
            for tool_pattern, tool_labels in block.labels.items():
                tool_norm = _check_pattern(tool_pattern, f"server {server_pattern!r} label")
                labels.append((server_norm, tool_norm, frozenset(tool_labels)))

            seen_tools: dict[str, str] = {}
            for tool_pattern, rule in block.tools.items():
                tool_norm = _check_pattern(tool_pattern, f"server {server_pattern!r} tool")
                if tool_norm in seen_tools:
                    raise ValueError(
                        f"tool patterns {seen_tools[tool_norm]!r} and {tool_pattern!r} under "
                        f"server {server_pattern!r} are identical after normalization"
                    )
                seen_tools[tool_norm] = tool_pattern
                rules.append(
                    CompiledRule(
                        server_pattern=server_pattern,
                        tool_pattern=tool_pattern,
                        server_norm=server_norm,
                        tool_norm=tool_norm,
                        server_spec=specificity(server_norm),
                        tool_spec=specificity(tool_norm),
                        action=rule.action,
                        reason=rule.reason,
                        conditions=tuple(sorted((rule.when or {}).items())),
                        otherwise=rule.otherwise,
                    )
                )
        # Rule ids follow the normalized patterns, not file order, so reordering a policy
        # changes neither decisions nor ids (they appear in events and Cedar output).
        rules.sort(key=lambda r: (r.server_norm, r.tool_norm))
        self._rules = tuple(replace(r, rule_id=f"r{i}") for i, r in enumerate(rules))
        self._pinning = tuple(pinning)
        self._labels = tuple(labels)
        return self

    @property
    def rules(self) -> tuple[CompiledRule, ...]:
        return self._rules

    @property
    def label_rules(self) -> tuple[tuple[str, str, frozenset[Label]], ...]:
        """(server pattern, tool pattern, labels), normalized. Every match applies."""
        return self._labels

    def labels_for(self, server: str, tool: str) -> frozenset[Label]:
        """Labels the policy itself gives a tool (every matching entry applies)."""
        server_n, tool_n = normalize_name(server), normalize_name(tool)
        out: set[Label] = set()
        for server_pat, tool_pat, labels in self._labels:
            if matches(server_pat, server_n) and matches(tool_pat, tool_n):
                out |= labels
        return frozenset(out)

    @property
    def pinning_overrides(self) -> tuple[tuple[str, Specificity, PinningMode], ...]:
        return self._pinning
