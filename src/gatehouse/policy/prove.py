"""``gatehouse policy prove``: check invariants against the compiled Cedar policy (D-041).

An invariant names a scope of calls and what must never happen to them::

    version: 1
    invariants:
      - name: deletes always need a human
        tools: "*delete*"
        never: allow                 # never allowed without approval
      - name: no egress once the session is tainted
        tool_labels: [egress]
        session_labels: [untrusted_input, private_data]
        never: allow_or_approve      # always blocked

``never: allow`` means the ``call`` action is never permitted in scope;
``never: allow_or_approve`` means neither action is (the call is always blocked).
Each becomes an implication between policy sets, ``P => Q``, where ``P`` is the compiled
policy and ``Q`` permits everything except the forbidden action in scope.

Two provers:

- **symcc** (Cedar's symbolic compiler, via ``cedar symcc implies`` from
  cedar-policy-cli built with ``analyze``, plus cvc5): a proof over every request the
  schema allows, so every server name, tool name, label set and condition outcome.
  Patterns that Cedar can't express (``?``, ``[...]``) are free group memberships there,
  so a proof is sound and a counterexample may be spurious; gatehouse says which.
- **bounded**: enumerates requests built from the policy's own patterns (plus pinned
  tools, if given): names that match and just miss each pattern, every combination of
  labels that can matter and every outcome of the matching rules' conditions. It finds
  real counterexamples but can't prove absence beyond what it enumerated, and says so.

The CLI exits 0 even when a property does not hold (it prints "DOES NOT HOLD"), so the
result is read from its output, never from its exit code.
"""

from __future__ import annotations

import itertools
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from gatehouse.policy.cedar import (
    CALL,
    CALL_WITH_APPROVAL,
    NAMESPACE,
    CedarEngine,
    CompiledCedar,
    cedar_string,
)
from gatehouse.policy.errors import PolicyError, PolicyErrorKind
from gatehouse.policy.loader import strict_yaml
from gatehouse.policy.models import Action, Label
from gatehouse.policy.names import matches, normalize_name

MAX_PAIRS = 4000  # (server, tool) name pairs in a bounded check
MAX_CONDITIONAL = 6  # conditional rules per name pair whose outcomes are enumerated
SYMCC_TIMEOUT_S = 300.0


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


StarPattern = Annotated[StrictStr, Field(min_length=1, max_length=256, pattern=r"^[^?\[]*$")]


class Invariant(_Strict):
    name: Annotated[StrictStr, Field(min_length=1, max_length=200)]
    never: Literal["allow", "allow_or_approve"]
    servers: StarPattern = "*"
    tools: StarPattern = "*"
    tool_labels: tuple[Label, ...] = ()  # in scope: tools carrying all of these
    session_labels: tuple[Label, ...] = ()  # in scope: sessions holding all of these


class InvariantFile(_Strict):
    version: StrictInt = Field(ge=1, le=1)
    invariants: Annotated[tuple[Invariant, ...], Field(min_length=1, max_length=200)]


def parse_invariants(data: bytes | str) -> InvariantFile:
    document = strict_yaml(data, "invariants")
    try:
        return InvariantFile.model_validate(document)
    except ValidationError as exc:
        msgs = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
            for e in exc.errors(include_input=False, include_url=False)
        )
        raise PolicyError(PolicyErrorKind.SCHEMA, msgs) from None


# ---------------------------------------------------------------------- scope


def _scope_expr(inv: Invariant, label_exprs: Mapping[Label, str]) -> str:
    parts: list[str] = []
    for attr, pattern in (("server", inv.servers), ("name", inv.tools)):
        norm = normalize_name(pattern)
        if set(norm) != {"*"}:
            op = "like" if "*" in norm else "=="
            parts.append(f"resource.{attr} {op} {cedar_string(norm)}")
    # A tool carries a label if the request says so (hints) or the policy gives it one.
    parts += [label_exprs[lbl] for lbl in sorted(set(inv.tool_labels))]
    if inv.session_labels:
        items = ", ".join(cedar_string(lbl.value) for lbl in sorted(set(inv.session_labels)))
        parts.append(f"context.session.containsAll([{items}])")
    return " && ".join(parts) if parts else "true"


def _forbidden_actions(inv: Invariant) -> tuple[str, ...]:
    return (CALL,) if inv.never == "allow" else (CALL, CALL_WITH_APPROVAL)


def bound_policy(inv: Invariant, compiled: CompiledCedar) -> str:
    """``Q``: permits every request except the invariant's forbidden ones."""
    scope = _scope_expr(inv, dict(compiled.label_exprs))
    return f"permit (principal, action, resource)\nunless {{ {scope} }};\n"


def _in_scope(
    inv: Invariant, server: str, tool: str, tl: frozenset[Label], sl: frozenset[Label]
) -> bool:
    return (
        matches(normalize_name(inv.servers), server)
        and matches(normalize_name(inv.tools), tool)
        and set(inv.tool_labels) <= tl
        and set(inv.session_labels) <= sl
    )


# ---------------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class Counterexample:
    server: str
    tool: str
    tool_labels: tuple[str, ...]
    session_labels: tuple[str, ...]
    conditions_hold: tuple[str, ...]
    decision: str

    def render(self) -> str:
        return (
            f"server={self.server!r} tool={self.tool!r} tool_labels={list(self.tool_labels)} "
            f"session_labels={list(self.session_labels)} "
            f"conditions_hold={list(self.conditions_hold)} -> {self.decision}"
        )


@dataclass(frozen=True, slots=True)
class Result:
    invariant: str
    holds: bool | None  # None: the prover could not decide (error)
    prover: Literal["symcc", "bounded"]
    detail: str = ""  # requests checked, counterexample, or error
    counterexample: Counterexample | None = None
    maybe_spurious: bool = False


# ---------------------------------------------------------------------- bounded


def _witnesses(pattern: str) -> set[str]:
    """Names that match the glob, and names that just miss it."""
    pieces: list[list[str]] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            pieces.append(["", "q"])
        elif c == "?":
            pieces.append(["q"])
        elif c == "[":
            j = i + 1
            if j < n and pattern[j] == "!":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                pieces.append(["["])
            else:
                body = pattern[i + 1 : j]
                if body.startswith("!"):
                    choice = next((ch for ch in "qzx0_" if ch not in body), "q")
                    pieces.append([choice, body[1:2] or "q"])
                else:
                    pieces.append([body[:1] or "q", "q"])
                i = j
        else:
            pieces.append([c])
        i += 1
        if len(pieces) > 24:
            break
    out: set[str] = set()
    for combo in itertools.islice(itertools.product(*pieces), 32):
        name = "".join(combo)
        if name:
            out |= {name, name + "q", name[:-1] or "q", "q" + name}
    return out or {"q"}


def bounded_check(
    engine: CedarEngine,
    invariants: Sequence[Invariant],
    extra_names: Iterable[tuple[str, str]] = (),
) -> list[Result]:
    policy = engine.policy
    servers: set[str] = {"q"}
    tools: set[str] = {"q"}
    for r in policy.rules:
        servers |= _witnesses(r.server_norm)
        tools |= _witnesses(r.tool_norm)
    for s, t, _ in policy.label_rules:
        servers |= _witnesses(s)
        tools |= _witnesses(t)
    for inv in invariants:
        servers |= _witnesses(normalize_name(inv.servers))
        tools |= _witnesses(normalize_name(inv.tools))
    pairs = set(itertools.islice(itertools.product(sorted(servers), sorted(tools)), MAX_PAIRS))
    pairs |= {(normalize_name(s), normalize_name(t)) for s, t in extra_names}

    # Labels only appear in `forbid` policies, and only through `contains`, so adding a
    # label can only make a decision stricter (tests/policy/test_cedar_differential.py
    # checks this). The most permissive request in an invariant's scope therefore carries
    # exactly the invariant's labels, and checking that one is exact, not a sample.
    found: dict[str, Counterexample] = {}
    checked = 0
    for server, tool in sorted(pairs):
        conditional = [
            r.rule_id
            for r in policy.rules
            if r.conditions and matches(r.server_norm, server) and matches(r.tool_norm, tool)
        ][:MAX_CONDITIONAL]
        outcomes = [
            frozenset(c)
            for k in range(len(conditional) + 1)
            for c in itertools.combinations(conditional, k)
        ]
        cases: list[tuple[frozenset[Label], frozenset[Label], frozenset[str]]] = []
        scopes: list[list[Invariant]] = []
        by_labels: dict[tuple[frozenset[Label], frozenset[Label]], list[Invariant]] = {}
        for inv in invariants:
            tl, sl = frozenset(inv.tool_labels), frozenset(inv.session_labels)
            if inv.name not in found and _in_scope(inv, server, tool, tl, sl):
                by_labels.setdefault((tl, sl), []).append(inv)
        for (tl, sl), live in by_labels.items():
            for when in outcomes:
                cases.append((tl, sl, when))
                scopes.append(live)
        if not cases:
            continue
        checked += len(cases)
        actions = engine.cedar_actions(server, tool, cases)
        for (tl, sl, when), live, action in zip(cases, scopes, actions, strict=True):
            for inv in live:
                bad = action is Action.ALLOW or (
                    inv.never == "allow_or_approve" and action is Action.REQUIRE_APPROVAL
                )
                if bad and inv.name not in found:
                    found[inv.name] = Counterexample(
                        server,
                        tool,
                        tuple(sorted(lbl.value for lbl in tl | policy.labels_for(server, tool))),
                        tuple(sorted(lbl.value for lbl in sl)),
                        tuple(sorted(when)),
                        action.value,
                    )
    results: list[Result] = []
    for inv in invariants:
        cex = found.get(inv.name)
        if cex is not None:
            results.append(Result(inv.name, False, "bounded", cex.render(), cex))
        else:
            results.append(
                Result(
                    inv.name,
                    True,
                    "bounded",
                    f"no counterexample in {checked} enumerated requests "
                    f"({len(pairs)} name pairs); not a proof",
                )
            )
    return results


# ---------------------------------------------------------------------- symcc


def find_cedar(explicit: str | None = None) -> str | None:
    """The cedar CLI to use: --cedar, $GATEHOUSE_CEDAR_CLI, or `cedar` on PATH."""
    for candidate in (explicit, os.environ.get("GATEHOUSE_CEDAR_CLI")):
        if candidate:
            return candidate
    return shutil.which("cedar")


_VERDICT = re.compile(
    r"^\S+ Policy set 1 implies policy set 2: (?P<verdict>VERIFIED|DOES NOT HOLD)\r?$", re.M
)


def _run_symcc(
    cedar: str, workdir: Path, action: str, policy_file: Path, bound_file: Path
) -> tuple[bool | None, str]:
    cmd = [
        cedar,
        "symcc",
        "--principal-type",
        f"{NAMESPACE}::Principal",
        "--action",
        f'{NAMESPACE}::Action::"{action}"',
        "--resource-type",
        f"{NAMESPACE}::Tool",
        "--schema",
        str(workdir / "schema.cedarschema.json"),
        "--schema-format",
        "json",
        "implies",
        "--policies1",
        str(policy_file),
        "--policies2",
        str(bound_file),
    ]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, capture_output=True, timeout=SYMCC_TIMEOUT_S, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"could not run {cedar}: {exc}"
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    m = _VERDICT.search(out)
    if m is None:
        text = err.strip() or out.strip() or f"exit {proc.returncode}"
        # drop the CLI's box-drawing decoration (and anything else a console may not print)
        text = "".join(ch if ch.isascii() else " " for ch in text)
        return None, " ".join(text.split())[:2000]
    if m.group("verdict") == "VERIFIED":
        return True, "proved for every request the schema allows"
    return False, out[m.end() :].strip()[:4000]


def symcc_check(cedar: str, engine: CedarEngine, invariants: Sequence[Invariant]) -> list[Result]:
    import json

    spurious_possible = bool(engine.compiled.server_groups or engine.compiled.tool_groups)
    results: list[Result] = []
    with tempfile.TemporaryDirectory(prefix="gatehouse-prove-") as tmp:
        workdir = Path(tmp)
        (workdir / "schema.cedarschema.json").write_text(
            json.dumps(engine.compiled.schema, indent=2), encoding="utf-8"
        )
        policy_file = workdir / "policy.cedar"
        policy_file.write_text(engine.compiled.text, encoding="utf-8")
        for i, inv in enumerate(invariants):
            bound_file = workdir / f"invariant{i}.cedar"
            bound_file.write_text(bound_policy(inv, engine.compiled), encoding="utf-8")
            verdict: bool | None = True
            detail = "proved for every request the schema allows"
            for action in _forbidden_actions(inv):
                holds, text = _run_symcc(cedar, workdir, action, policy_file, bound_file)
                if holds is not True:
                    verdict, detail = holds, f"[{action}] {text}"
                    break
            results.append(
                Result(
                    inv.name,
                    verdict,
                    "symcc",
                    detail,
                    maybe_spurious=verdict is False and spurious_possible,
                )
            )
    return results


def symcc_available(cedar: str) -> tuple[bool, str]:
    """True if this cedar CLI was built with the `analyze` feature."""
    try:
        proc = subprocess.run(  # noqa: S603
            [cedar, "symcc", "--help"], capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    text = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    if proc.returncode != 0 or "implies" not in text:
        return False, text.strip().splitlines()[0] if text.strip() else f"exit {proc.returncode}"
    return True, ""


def prove(
    engine: CedarEngine,
    invariants: Sequence[Invariant],
    *,
    cedar: str | None,
    extra_names: Iterable[tuple[str, str]] = (),
) -> Iterator[Result]:
    """symcc if available, else bounded. A bounded counterexample is always real, so the
    bounded check also runs first when symcc is used: it gives concrete names."""
    bounded = bounded_check(engine, invariants, extra_names)
    if cedar is None:
        yield from bounded
        return
    for b, s in zip(bounded, symcc_check(cedar, engine, invariants), strict=True):
        if b.holds is False:
            yield Result(s.invariant, False, "symcc", b.detail, b.counterexample)
        else:
            yield s
