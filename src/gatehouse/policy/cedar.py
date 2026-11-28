"""Compile a gatehouse policy to Cedar and decide calls with cedarpy (D-040).

The YAML policy is the source of truth; this module produces an equivalent Cedar policy
set so that (a) an industry-standard engine makes the runtime decision and (b) Cedar's
analysis tools can prove invariants about it (``gatehouse policy prove``). The native
evaluator in ``engine.py`` is the reference semantics, and property-based tests require
the two to agree on random policies.

Encoding (entity types live in the ``Gatehouse`` namespace):

- principal ``Principal::"local"`` (an OIDC subject in HTTP mode, later);
- resource ``Tool`` with attributes ``server`` and ``name`` (normalized names) and
  ``labels`` (the tool's capability labels), member of ``NamePattern`` groups for the
  patterns Cedar can't express (those containing ``?`` or ``[``);
- context ``session`` (labels the session already holds) and ``when`` (ids of the
  rules whose argument conditions hold for this call);
- two actions: ``call`` permitted means allow; otherwise ``call_with_approval``
  permitted means require approval; otherwise block.

"Most specific rule wins" is not a Cedar concept, so the compiler spells it out: a rule
variant permits ``call`` only if no matching rule dominates it and no approval variant
it doesn't dominate is also a winner. See D-040 for the derivation.

Every string that reaches the policy text is a pattern from the policy file (validated,
bounded) or a fixed identifier, and is escaped with ``cedar_string``; entity ids for groups are
generated (``s0``, ``t3``), never taken from names. Requests use the structured
(``{"type", "id"}``) form, so names from servers never pass through Cedar's parser.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from gatehouse.policy.conditions import all_hold
from gatehouse.policy.engine import (
    ALL_LABELS,
    TRIFECTA_EGRESS,
    AuthzRequest,
    Decision,
    DecisionBasis,
    evaluate,
)
from gatehouse.policy.models import Action, CompiledRule, FlowMode, Label, Policy
from gatehouse.policy.names import matches, normalize_name

NAMESPACE = "Gatehouse"
CALL = "call"
CALL_WITH_APPROVAL = "call_with_approval"
_GLOB_ONLY_STAR = frozenset("?[")


class CedarUnavailable(RuntimeError):
    """cedarpy is missing or the compiled policy did not parse."""


def cedar_string(text: str) -> str:
    """A Cedar string literal. Printable ASCII passes through (except ``"`` and ``\\``);
    everything else becomes a ``\\u{...}`` escape."""
    out: list[str] = ['"']
    for ch in text:
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            out.append(f"\\u{{{ord(ch):x}}}")
    out.append('"')
    return "".join(out)


def _like(pattern: str) -> str:
    """A ``like`` pattern for a glob that only uses ``*``. ``like`` gives ``*`` the same
    meaning as fnmatch; every other character must match literally."""
    return cedar_string(pattern)


@dataclass(frozen=True, slots=True)
class _Variant:
    rule: CompiledRule
    holds: bool  # conditions hold (True) or fail (False); rules without conditions: True

    @property
    def action(self) -> Action:
        if self.holds:
            return self.rule.action
        return self.rule.otherwise or Action.BLOCK


@dataclass(frozen=True, slots=True)
class CompiledCedar:
    """A policy compiled to Cedar, plus what's needed to build requests for it."""

    text: str  # the policy set, in Cedar syntax
    schema: dict[str, Any]  # Cedar JSON schema
    policy_ids: tuple[str, ...]  # gatehouse id of each Cedar policy, in order
    server_groups: tuple[tuple[str, str], ...]  # (group id, normalized pattern)
    tool_groups: tuple[tuple[str, str], ...]
    conditional: tuple[CompiledRule, ...] = field(default=())
    # Cedar expression for "the tool carries this label": a label in the request (hints)
    # or a matching `labels:` entry in the policy. Invariant scopes reuse them.
    label_exprs: tuple[tuple[Label, str], ...] = field(default=())


def _needs_group(pattern: str) -> bool:
    return any(c in _GLOB_ONLY_STAR for c in pattern)


def compile_policy(policy: Policy) -> CompiledCedar:
    rules = policy.rules
    label_rules = policy.label_rules
    all_servers = {r.server_norm for r in rules} | {s for s, _, _ in label_rules}
    all_tools = {r.tool_norm for r in rules} | {t for _, t, _ in label_rules}
    server_pats = sorted(p for p in all_servers if _needs_group(p))
    tool_pats = sorted(p for p in all_tools if _needs_group(p))
    server_group = {p: f"s{i}" for i, p in enumerate(server_pats)}
    tool_group = {p: f"t{i}" for i, p in enumerate(tool_pats)}

    def name_expr(attr: str, pattern: str, groups: Mapping[str, str]) -> str:
        if pattern in groups:
            return f"resource in {NAMESPACE}::NamePattern::{cedar_string(groups[pattern])}"
        if set(pattern) == {"*"}:
            return "true"
        if "*" in pattern:
            return f"resource.{attr} like {_like(pattern)}"
        return f"resource.{attr} == {cedar_string(pattern)}"

    def names(server_pattern: str, tool_pattern: str) -> str:
        s = name_expr("server", server_pattern, server_group)
        t = name_expr("name", tool_pattern, tool_group)
        return f"({s} && {t})"

    def m(rule: CompiledRule) -> str:
        return names(rule.server_norm, rule.tool_norm)

    def carries(label: Label) -> str:
        lit = cedar_string(label.value)
        by_policy = [names(s, t) for s, t, labels in label_rules if label in labels]
        return "(" + " || ".join([f"resource.labels.contains({lit})", *by_policy]) + ")"

    label_exprs = tuple((lbl, carries(lbl)) for lbl in sorted(ALL_LABELS))

    def cond(v: _Variant) -> str:
        if not v.rule.conditions:
            return "true"
        test = f"context.when.contains({cedar_string(v.rule.rule_id)})"
        return test if v.holds else f"!{test}"

    def match(v: _Variant) -> str:
        return f"({m(v.rule)} && {cond(v)})"

    def any_of(exprs: Sequence[str]) -> str:
        return "(" + " || ".join(exprs) + ")" if exprs else "false"

    def winner(v: _Variant) -> str:
        dominating = [m(o) for o in rules if o.dominates(v.rule)]
        return f"({match(v)} && !{any_of(dominating)})"

    variants: list[_Variant] = []
    for r in rules:
        variants.append(_Variant(r, True))
        if r.conditions:
            variants.append(_Variant(r, False))

    statements: list[str] = []
    ids: list[str] = []

    def add(gid: str, text: str) -> None:
        ids.append(gid)
        statements.append(f"@id({cedar_string(gid)})\n{text};")

    act = f"{NAMESPACE}::Action"
    both = f"action in [{act}::{cedar_string(CALL)}, {act}::{cedar_string(CALL_WITH_APPROVAL)}]"
    only_call = f"action == {act}::{cedar_string(CALL)}"
    only_cwa = f"action == {act}::{cedar_string(CALL_WITH_APPROVAL)}"

    for v in variants:
        suffix = "" if not v.rule.conditions else (".when" if v.holds else ".otherwise")
        gid = f"{v.rule.rule_id}{suffix}"
        if v.action is Action.BLOCK:
            add(gid, f"forbid (principal, action, resource)\nwhen {{ {match(v)} }}")
            continue
        # Every non-block winner makes approval possible...
        add(gid + ".approval", f"permit (principal, {only_cwa}, resource)\nwhen {{ {winner(v)} }}")
        if v.action is Action.ALLOW:
            # ...and an allow winner allows outright unless an approval winner it does not
            # dominate ties with it.
            rivals = [
                winner(w)
                for w in variants
                if w.action is Action.REQUIRE_APPROVAL and not v.rule.dominates(w.rule)
            ]
            add(
                gid,
                f"permit (principal, {only_call}, resource)\n"
                f"when {{ {winner(v)} && !{any_of(rivals)} }}",
            )

    no_match = f"!{any_of([m(r) for r in rules])}"
    if policy.default_action is Action.ALLOW:
        add("default", f"permit (principal, {both}, resource)\nwhen {{ {no_match} }}")
    elif policy.default_action is Action.REQUIRE_APPROVAL:
        add("default.approval", f"permit (principal, {only_cwa}, resource)\nwhen {{ {no_match} }}")

    mode = policy.flow.mode
    if mode in (FlowMode.APPROVE, FlowMode.ENFORCE):

        def has(label: Label) -> str:
            lit = cedar_string(label.value)
            return f"(context.session.contains({lit}) || {carries(label)})"

        egress = " || ".join(has(lbl) for lbl in sorted(TRIFECTA_EGRESS))
        contributes = " || ".join(expr for _, expr in label_exprs)
        trifecta = (
            f"{has(Label.UNTRUSTED_INPUT)} && {has(Label.PRIVATE_DATA)} && ({egress}) "
            f"&& ({contributes})"
        )
        scope = "action" if mode is FlowMode.ENFORCE else only_call
        add(f"flow.{mode.value}", f"forbid (principal, {scope}, resource)\nwhen {{ {trifecta} }}")

    return CompiledCedar(
        text="\n\n".join(statements) + "\n",
        schema=schema(),
        policy_ids=tuple(ids),
        server_groups=tuple((g, p) for p, g in server_group.items()),
        tool_groups=tuple((g, p) for p, g in tool_group.items()),
        conditional=tuple(r for r in rules if r.conditions),
        label_exprs=label_exprs,
    )


def schema() -> dict[str, Any]:
    """The Cedar JSON schema every compiled policy is written against."""
    strings = {"type": "Set", "element": {"type": "String"}}
    context = {
        "type": "Record",
        "attributes": {"session": strings, "when": strings},
    }
    applies = {
        "principalTypes": ["Principal"],
        "resourceTypes": ["Tool"],
        "context": context,
    }
    return {
        NAMESPACE: {
            "entityTypes": {
                "Principal": {},
                "NamePattern": {},
                "Tool": {
                    "memberOfTypes": ["NamePattern"],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "server": {"type": "String"},
                            "name": {"type": "String"},
                            "labels": strings,
                        },
                    },
                },
            },
            "actions": {CALL: {"appliesTo": applies}, CALL_WITH_APPROVAL: {"appliesTo": applies}},
        }
    }


# ---------------------------------------------------------------------- requests


def request_facts(
    compiled: CompiledCedar, request: AuthzRequest, when: Iterable[str] | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Entities and context for one call. ``when`` overrides the ids of the rules whose
    conditions hold (``policy prove`` enumerates them instead of evaluating arguments)."""
    server_n = normalize_name(request.server)
    tool_n = normalize_name(request.tool)
    groups = [g for g, p in compiled.server_groups if matches(p, server_n)]
    groups += [g for g, p in compiled.tool_groups if matches(p, tool_n)]
    tool_uid = {"type": f"{NAMESPACE}::Tool", "id": "call"}
    entities: list[dict[str, Any]] = [
        {
            "uid": tool_uid,
            "attrs": {
                "server": server_n,
                "name": tool_n,
                "labels": sorted(label.value for label in request.tool_labels),
            },
            "parents": [{"type": f"{NAMESPACE}::NamePattern", "id": g} for g in groups],
        },
        *(
            {"uid": {"type": f"{NAMESPACE}::NamePattern", "id": g}, "attrs": {}, "parents": []}
            for g in groups
        ),
        {
            "uid": {"type": f"{NAMESPACE}::Principal", "id": request.principal},
            "attrs": {},
            "parents": [],
        },
    ]
    if when is None:
        when = (
            r.rule_id
            for r in compiled.conditional
            if all_hold(dict(r.conditions), request.arguments)
        )
    context = {
        "session": sorted(label.value for label in request.session_labels),
        "when": sorted(when),
    }
    return entities, context


class CedarEngine:
    """``engine: cedar``: Cedar decides; the reference explains and cross-checks."""

    def __init__(self, policy: Policy) -> None:
        try:
            import cedarpy
        except ImportError as exc:  # pragma: no cover - a hard dependency
            raise CedarUnavailable(f"cedarpy is not installed: {exc}") from exc
        self.policy = policy
        self.compiled = compile_policy(policy)
        self._cedar: Any = cedarpy  # loosely typed upstream
        try:
            self._policies = cedarpy.PolicySet.from_str(self.compiled.text)
            schema_obj = cedarpy.Schema.from_json_str(json.dumps(self.compiled.schema))
            # Type-check the compiled policy once: a policy that fails validation could
            # error at evaluation time, and an erroring forbid is skipped by Cedar.
            check: Any = cedarpy.validate_policies(  # pyright: ignore[reportUnknownMemberType]
                self.compiled.text, schema_obj
            )
        except Exception as exc:  # cedarpy raises plain exceptions on parse errors
            raise CedarUnavailable(f"compiled Cedar policy did not parse: {exc}") from exc
        if not check.validation_passed:
            errors = "; ".join(str(e) for e in check.errors)[:500]
            raise CedarUnavailable(f"compiled Cedar policy failed validation: {errors}")

    def cedar_action(
        self, request: AuthzRequest, when: Iterable[str] | None = None
    ) -> tuple[Action, bool]:
        """The action Cedar decides, and whether evaluation reported errors."""
        entities, context = request_facts(self.compiled, request, when)
        principal = {"type": f"{NAMESPACE}::Principal", "id": request.principal}
        resource = {"type": f"{NAMESPACE}::Tool", "id": "call"}
        requests = [
            {
                "principal": principal,
                "action": {"type": f"{NAMESPACE}::Action", "id": action_id},
                "resource": resource,
                "context": context,
            }
            for action_id in (CALL, CALL_WITH_APPROVAL)
        ]
        results: list[Any] = self._cedar.is_authorized_batch(requests, self._policies, entities)
        errored = any(bool(getattr(r.diagnostics, "errors", None)) for r in results)
        if results[0].allowed:
            return Action.ALLOW, errored
        if results[1].allowed:
            return Action.REQUIRE_APPROVAL, errored
        return Action.BLOCK, errored

    def cedar_actions(
        self,
        server: str,
        tool: str,
        cases: Sequence[tuple[frozenset[Label], frozenset[Label], Iterable[str]]],
    ) -> list[Action]:
        """Cedar's action for many (tool labels, session labels, conditions that hold)
        cases of one name pair, in one batch call. Used by ``policy prove``; an evaluation
        error counts as block, as at runtime."""
        server_n, tool_n = normalize_name(server), normalize_name(tool)
        groups = [g for g, p in self.compiled.server_groups if matches(p, server_n)]
        groups += [g for g, p in self.compiled.tool_groups if matches(p, tool_n)]
        parents = [{"type": f"{NAMESPACE}::NamePattern", "id": g} for g in groups]
        label_ids: dict[frozenset[Label], str] = {}
        for tl, _, _ in cases:
            label_ids.setdefault(tl, f"call{len(label_ids)}")
        entities: list[dict[str, Any]] = [
            {
                "uid": {"type": f"{NAMESPACE}::Tool", "id": uid},
                "attrs": {
                    "server": server_n,
                    "name": tool_n,
                    "labels": sorted(label.value for label in tl),
                },
                "parents": parents,
            }
            for tl, uid in label_ids.items()
        ]
        entities += [
            {"uid": {"type": f"{NAMESPACE}::NamePattern", "id": g}, "attrs": {}, "parents": []}
            for g in groups
        ]
        entities.append(
            {"uid": {"type": f"{NAMESPACE}::Principal", "id": "local"}, "attrs": {}, "parents": []}
        )
        principal = {"type": f"{NAMESPACE}::Principal", "id": "local"}
        requests: list[dict[str, Any]] = []
        for tl, sl, when in cases:
            context = {"session": sorted(label.value for label in sl), "when": sorted(when)}
            for action_id in (CALL, CALL_WITH_APPROVAL):
                requests.append(
                    {
                        "principal": principal,
                        "action": {"type": f"{NAMESPACE}::Action", "id": action_id},
                        "resource": {"type": f"{NAMESPACE}::Tool", "id": label_ids[tl]},
                        "context": context,
                    }
                )
        results: list[Any] = self._cedar.is_authorized_batch(requests, self._policies, entities)
        actions: list[Action] = []
        for i in range(0, len(results), 2):
            call, cwa = results[i], results[i + 1]
            if getattr(call.diagnostics, "errors", None) or getattr(
                cwa.diagnostics, "errors", None
            ):
                actions.append(Action.BLOCK)
            elif call.allowed:
                actions.append(Action.ALLOW)
            elif cwa.allowed:
                actions.append(Action.REQUIRE_APPROVAL)
            else:
                actions.append(Action.BLOCK)
        return actions

    def decide(self, request: AuthzRequest) -> Decision:
        reference = evaluate(
            self.policy,
            request.server,
            request.tool,
            request.arguments,
            tool_labels=request.tool_labels,
            session_labels=request.session_labels,
        )
        action, errored = self.cedar_action(request)
        if action is reference.action and not errored:
            return reference
        # The two engines must never disagree (tests generate thousands of policies to
        # check it). If they do, take the stricter answer: never fail open on a bug.
        strict = max(action, reference.action, key=lambda a: a.strictness)
        if errored:
            strict = Action.BLOCK
        return reference.model_copy(
            update={
                "action": strict,
                "basis": DecisionBasis.ENGINE_DISAGREEMENT,
                "reason": (
                    f"policy engines disagree (cedar: {action.value}"
                    f"{', with evaluation errors' if errored else ''}; reference: "
                    f"{reference.action.value}); using {strict.value}"
                ),
            }
        )


def engine_for(policy: Policy) -> Any:
    """The engine the policy asks for. Raises CedarUnavailable if Cedar can't be used."""
    from gatehouse.policy.engine import NativeEngine

    if policy.engine == "native":
        return NativeEngine(policy)
    return CedarEngine(policy)
