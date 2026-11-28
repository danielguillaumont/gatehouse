"""``gatehouse policy compile`` and ``gatehouse policy prove``. Human output on stdout."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

from gatehouse.policy.cedar import NAMESPACE, CedarEngine, CompiledCedar
from gatehouse.policy.errors import PolicyError
from gatehouse.policy.labels import tool_labels
from gatehouse.policy.loader import parse_policy
from gatehouse.policy.models import Policy
from gatehouse.policy.names import matches, normalize_name


def _safe(text: str, stream: object) -> str:
    # The Cedar CLI's messages use box-drawing characters that a Windows console code
    # page can't encode; replace what the stream can't print instead of crashing.
    encoding = getattr(stream, "encoding", None) or "utf-8"
    return text.encode(encoding, "replace").decode(encoding, "replace")


def _out(text: str) -> None:
    sys.stdout.write(_safe(text, sys.stdout) + "\n")


def _err(text: str) -> None:
    sys.stderr.write(_safe(text, sys.stderr) + "\n")


def _load(path: Path) -> CedarEngine | None:
    try:
        policy = parse_policy(path.read_bytes())
        return CedarEngine(policy)
    except OSError as exc:
        _err(f"cannot read {path}: {exc.strerror or exc}")
    except PolicyError as exc:
        _err(f"INVALID ({exc.kind.value}): {exc.message}")
    except Exception as exc:  # CedarUnavailable and friends
        _err(f"cannot compile {path}: {exc}")
    return None


def _pinned(path: Path | None) -> list[tuple[str, str, dict[str, Any]]]:
    if path is None:
        return []
    from gatehouse.state.pinstore import load_pins

    store = load_pins(path)
    return [
        (server, tool, pin.definition)
        for server, pins in sorted(store.servers.items())
        for tool, pin in sorted(pins.tools.items())
    ]


def pinned_entities(
    policy: Policy, compiled: CompiledCedar, pins: list[tuple[str, str, dict[str, Any]]]
) -> list[dict[str, Any]]:
    """One ``Tool`` entity per pinned tool, with the labels gatehouse would give it."""
    entities: list[dict[str, Any]] = []
    for server, tool, definition in pins:
        server_n, tool_n = normalize_name(server), normalize_name(tool)
        raw = definition.get("annotations")
        annotations = cast(dict[str, Any], raw) if isinstance(raw, dict) else None
        labels = tool_labels(policy, server, tool, annotations)
        groups = [g for g, p in compiled.server_groups if matches(p, server_n)]
        groups += [g for g, p in compiled.tool_groups if matches(p, tool_n)]
        entities.append(
            {
                "uid": {"type": f"{NAMESPACE}::Tool", "id": f"{server}/{tool}"},
                "attrs": {
                    "server": server_n,
                    "name": tool_n,
                    "labels": sorted(label.value for label in labels),
                },
                "parents": [{"type": f"{NAMESPACE}::NamePattern", "id": g} for g in groups],
            }
        )
    return entities


def cmd_compile(args: argparse.Namespace) -> int:
    engine = _load(args.policy)
    if engine is None:
        return 1
    compiled = engine.compiled
    if args.out is None:
        sys.stdout.write(compiled.text)
        return 0
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "policy.cedar").write_text(compiled.text, encoding="utf-8")
    (out / "schema.cedarschema.json").write_text(
        json.dumps(compiled.schema, indent=2) + "\n", encoding="utf-8"
    )
    written = ["policy.cedar", "schema.cedarschema.json"]
    pins = _pinned(args.pins)
    if pins:
        entities = pinned_entities(engine.policy, compiled, pins)
        (out / "entities.json").write_text(json.dumps(entities, indent=2) + "\n", "utf-8")
        written.append(f"entities.json ({len(entities)} pinned tools)")
    _out(f"wrote {', '.join(written)} to {out}")
    return 0


def cmd_prove(args: argparse.Namespace) -> int:
    from gatehouse.policy.prove import find_cedar, parse_invariants, prove, symcc_available

    engine = _load(args.policy)
    if engine is None:
        return 2
    try:
        invariants = parse_invariants(args.invariants.read_bytes()).invariants
    except OSError as exc:
        _err(f"cannot read {args.invariants}: {exc.strerror or exc}")
        return 2
    except PolicyError as exc:
        _err(f"INVALID invariants ({exc.kind.value}): {exc.message}")
        return 2

    cedar = find_cedar(args.cedar)
    if cedar is not None:
        ok, why = symcc_available(cedar)
        if not ok:
            _err(f"note: {cedar} cannot run symcc ({why}); using the bounded check")
            cedar = None
    if cedar is None:
        if args.require_symcc:
            _err("gatehouse policy prove: --require-symcc but no cedar CLI with symcc found")
            return 2
        _out("prover: bounded (install cedar-policy-cli with `analyze` and cvc5 for proofs)")
    else:
        _out(f"prover: symcc ({cedar})")

    pins = [(s, t) for s, t, _ in _pinned(args.pins)]
    failed = errored = 0
    for r in prove(engine, invariants, cedar=cedar, extra_names=pins):
        if r.holds is True:
            mark = "PROVED" if r.prover == "symcc" else "HOLDS "
        elif r.holds is False:
            mark = "FAILED"
            failed += 1
        else:
            mark = "ERROR "
            errored += 1
        _out(f"{mark}  {r.invariant}")
        if (r.detail and r.holds is not True) or r.prover == "bounded":
            for line in r.detail.splitlines():
                _out(f"        {line}")
        if r.maybe_spurious:
            _out(
                "        (the policy uses ?/[...] patterns, which symcc treats as unconstrained;"
                " this counterexample may not be reachable)"
            )
    total = len(invariants)
    _out(f"{total - failed - errored}/{total} invariants hold")
    if errored:
        return 2
    return 1 if failed else 0
