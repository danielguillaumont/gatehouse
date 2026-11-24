"""Load scenarios, run them against a target, and record what each side observed.

A scenario has one or more *phases*; each phase is a fresh client + target process
(a server "restart"), sharing that scenario's isolated home, pin store and server log.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import yaml

from attacks.targets import EVAL_POLICY, RunPaths, Target, server_command
from gatehouse.client import ClientError, StdioClient

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
MILESTONES = ("mvp", "m2", "m3", "bypass")
PREDICATES = ("client_saw_tool", "client_saw_result", "server_received", "server_received_raw")


class ScenarioError(ValueError):
    pass


@dataclass(frozen=True)
class Phase:
    server: dict[str, Any]
    steps: list[Any]


@dataclass(frozen=True)
class Scenario:
    id: str
    category: str
    milestone: str
    title: str
    phases: list[Phase]
    expect: str = "attack"  # "attack" | "benign"
    success_if: dict[str, Any] = field(default_factory=dict[str, Any])
    canaries: list[str] = field(default_factory=list[str])
    targets: list[str] | None = None
    owasp: list[str] = field(default_factory=list[str])
    atlas: list[str] = field(default_factory=list[str])
    source: str = ""

    @property
    def benign(self) -> bool:
        return self.expect == "benign"

    def applies_to(self, target: str) -> bool:
        return self.targets is None or target in self.targets or target == "direct"


def _strs(value: object) -> list[str]:
    return [str(v) for v in cast(list[object], value or [])]


def _scenario(raw: Mapping[str, Any], source: str) -> Scenario:
    sid = str(raw.get("id", "?"))
    try:
        if "phases" in raw:
            phases = [
                Phase(dict(p["server"]), list(p.get("steps", [])))
                for p in cast(list[dict[str, Any]], raw["phases"])
            ]
        else:
            phases = [Phase(dict(raw["server"]), list(raw.get("steps", [])))]
        sc = Scenario(
            id=sid,
            category=str(raw["category"]),
            milestone=str(raw["milestone"]),
            title=str(raw["title"]),
            phases=phases,
            expect=str(raw.get("expect", "attack")),
            success_if=dict(raw.get("success_if") or {}),
            canaries=_strs(raw.get("canaries")),
            targets=_strs(raw["targets"]) if "targets" in raw else None,
            owasp=_strs(raw.get("owasp")),
            atlas=_strs(raw.get("atlas")),
            source=source,
        )
    except (KeyError, TypeError) as exc:
        raise ScenarioError(f"{source}: scenario {sid}: missing/invalid field {exc}") from None
    if sc.milestone not in MILESTONES:
        raise ScenarioError(f"{source}: {sid}: unknown milestone {sc.milestone!r}")
    if sc.expect not in ("attack", "benign"):
        raise ScenarioError(f"{source}: {sid}: expect must be attack or benign")
    if not sc.benign:
        if len(sc.success_if) != 1 or next(iter(sc.success_if)) not in PREDICATES:
            raise ScenarioError(f"{source}: {sid}: success_if needs exactly one of {PREDICATES}")
    return sc


def load_scenarios(directory: Path = SCENARIO_DIR, only: Iterable[str] = ()) -> list[Scenario]:
    wanted = set(only)
    out: list[Scenario] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        docs: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for raw in cast(list[dict[str, Any]], docs):
            sc = _scenario(raw, path.name)
            if sc.id in seen:
                raise ScenarioError(f"duplicate scenario id {sc.id}")
            seen.add(sc.id)
            if not wanted or sc.id in wanted or any(sc.id.startswith(w) for w in wanted):
                out.append(sc)
    return out


# ---------------------------------------------------------------------- observation


@dataclass
class Observation:
    scenario: str
    target: str
    lists: list[list[dict[str, Any]]] = field(default_factory=list[list[dict[str, Any]]])
    calls: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    server_frames: list[str] = field(default_factory=list[str])
    events: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    stderr: list[str] = field(default_factory=list[str])
    errors: list[str] = field(default_factory=list[str])
    duration_s: float = 0.0


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _substitute(value: Any, mapping: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        for k, v in mapping.items():
            value = value.replace("{" + k + "}", v)
        return value
    if isinstance(value, dict):
        return {k: _substitute(v, mapping) for k, v in cast(dict[str, Any], value).items()}
    if isinstance(value, list):
        return [_substitute(v, mapping) for v in cast(list[Any], value)]
    return value


def _run_steps(
    client: StdioClient, steps: list[Any], obs: Observation, subst: Mapping[str, str]
) -> None:
    for step in steps:
        if step == "list":
            try:
                obs.lists.append(client.list_tools())
            except ClientError as exc:
                obs.lists.append([])
                obs.errors.append(f"list: {exc}")
            continue
        s = cast(dict[str, Any], step)
        if "call" in s:
            call = cast(dict[str, Any], s["call"])
            tool = str(call["tool"])
            args = _substitute(call.get("arguments") or {}, subst)
            try:
                resp = client.call_tool(tool, args)
            except ClientError as exc:
                resp = {"error": {"code": None, "message": str(exc)}}
            obs.calls.append({"tool": tool, "arguments": args, "response": resp})
        elif "raw" in s:
            client.send_raw(str(_substitute(s["raw"], subst)).encode("utf-8") + b"\n")
            # Resync: once the ping answer arrives, everything sent before it was handled.
            try:
                client.request("ping", {}, timeout=10)
            except ClientError as exc:
                obs.errors.append(f"ping after raw: {exc}")
        else:
            raise ScenarioError(f"unknown step {step!r}")


def run_scenario(sc: Scenario, target: Target, *, keep_dir: Path | None = None) -> Observation:
    obs = Observation(sc.id, target.name)
    started = time.monotonic()
    tmp = Path(tempfile.mkdtemp(prefix="gh-attack-"))
    try:
        home = tmp / "home"
        state = home / ".gatehouse"
        state.mkdir(parents=True)
        rp = RunPaths(policy=tmp / "policy.yaml", pins=state / "pins.json", events_dir=tmp / "ev")
        shutil.copyfile(EVAL_POLICY, rp.policy)
        log = tmp / "server-frames.jsonl"
        env = {
            "GATEHOUSE_HOME": str(state),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "GATEHOUSE_AGENT_SESSION_ID": f"eval-{sc.id}",
            "ATTACK_LOG": str(log),
            "PYTHONIOENCODING": "utf-8",
        }
        subst = {"policy_path": str(rp.policy), "pins_path": str(rp.pins)}
        for index, phase in enumerate(sc.phases):
            spec_path = tmp / f"spec-{index}.json"
            spec = {"name": sc.id.split(".")[0], **phase.server}
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            argv = target.argv("srv", server_command(), rp)
            client = StdioClient(argv, env={**env, "ATTACK_SPEC": str(spec_path)}, timeout=20)
            try:
                client.initialize(client_name="gatehouse-attack-suite")
                _run_steps(client, phase.steps, obs, subst)
            except ClientError as exc:
                obs.errors.append(f"phase {index}: {exc}")
            finally:
                client.close()
                obs.stderr.extend(client.stderr_lines)
        if log.exists():
            obs.server_frames = log.read_text(encoding="utf-8").splitlines()
        if rp.events_dir.exists():
            for f in sorted(rp.events_dir.glob("*.jsonl")):
                for line in f.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        obs.events.append(json.loads(line))
        if keep_dir is not None:
            shutil.copytree(tmp, keep_dir / sc.id, dirs_exist_ok=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        obs.duration_s = round(time.monotonic() - started, 3)
    return obs


# ---------------------------------------------------------------------- judging


def _server_calls(obs: Observation) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for line in obs.server_frames:
        try:
            frame: Any = json.loads(line)
        except ValueError:
            continue
        if isinstance(frame, dict) and cast(dict[str, Any], frame).get("method") == "tools/call":
            f = cast(dict[str, Any], frame)
            out.append((line, f))
    return out


def attack_succeeded(sc: Scenario, obs: Observation) -> bool:
    ((kind, raw_cond),) = sc.success_if.items()
    cond = cast(dict[str, Any], raw_cond)
    needle = str(cond["contains"]) if "contains" in cond else None
    tool = str(cond["tool"]) if "tool" in cond else None
    if kind == "client_saw_tool":
        for listing in obs.lists:
            for t in listing:
                if t.get("name") == tool and (needle is None or needle in _dump(t)):
                    return True
        return False
    if kind == "client_saw_result":
        for c in obs.calls:
            result = c["response"].get("result")
            if c["tool"] == tool and result is not None and not result.get("isError"):
                if needle is None or needle in _dump(result):
                    return True
        return False
    if kind == "server_received":
        for line, frame in _server_calls(obs):
            params = cast(dict[str, Any], frame.get("params") or {})
            if params.get("name") != tool:
                continue
            if needle is None or needle in line or needle in _dump(frame):
                return True
        return False
    if kind == "server_received_raw":
        assert needle is not None
        return any(needle in line for line in obs.server_frames)
    raise ScenarioError(f"unknown predicate {kind}")


def _expected_result(server: Mapping[str, Any], tool: str) -> dict[str, Any]:
    """What attacks/mockserver.py answers for a call (keep in sync with it)."""
    results = cast(dict[str, Any], server.get("results") or {})
    value: Any = results.get(tool, f"{tool}: ok")
    body = (
        cast(dict[str, Any], value)
        if isinstance(value, dict)
        else {"content": [{"type": "text", "text": value}]}
    )
    return {"isError": False, **body}


def benign_interference(sc: Scenario, obs: Observation) -> list[str]:
    """Ways the target changed benign traffic (each one is a false positive)."""
    problems: list[str] = list(obs.errors)
    lists = iter(obs.lists)
    calls = iter(obs.calls)
    for phase in sc.phases:
        offered = cast(list[dict[str, Any]], phase.server.get("tools") or [])
        for step in phase.steps:
            if step == "list":
                seen: list[dict[str, Any]] = next(lists, cast(list[dict[str, Any]], []))
                if _dump(seen) != _dump(offered):
                    names = {t.get("name") for t in seen}
                    hidden = [t.get("name") for t in offered if t.get("name") not in names]
                    problems.append(f"tools/list altered (hidden: {hidden})")
            elif isinstance(step, dict) and "call" in cast(dict[str, Any], step):
                c = next(calls, None)
                if c is None:
                    problems.append("call missing")
                    continue
                expected = _expected_result(phase.server, c["tool"])
                got = c["response"].get("result")
                if got != expected:
                    err = cast(dict[str, Any], c["response"].get("error") or {})
                    problems.append(f"call {c['tool']} altered/blocked: {err.get('message', '')}")
    return problems


_ENFORCED = ("blocked", "filtered", "fail_closed", "denied")
# Protocol events that are alerts in themselves (no DetectorId: the framing layer decides).
_ALERT_EVENTS = (
    "protocol.invalid_frame",
    "protocol.batch_rejected",
    "protocol.oversized_frame",
    "protocol.unsolicited_response",
    "policy.tampered",
    "policy.load_failed",
)


def _event_key(e: Mapping[str, Any]) -> str | None:
    if e.get("DetectorId"):
        return f"{e['DetectorId']}/{e.get('RuleId')}"
    etype = str(e.get("EventType", ""))
    if etype in _ALERT_EVENTS:
        return etype
    if etype == "tool.call" and e.get("Action") in _ENFORCED:
        return f"tool.call/{e.get('DecisionBasis') or 'blocked'}"
    return None


def detections(obs: Observation) -> list[str]:
    """What gatehouse reported about this scenario (detector rules and alert events)."""
    found: list[str] = []
    for e in obs.events:
        key = _event_key(e)
        if key and key not in found:
            found.append(key)
    return found


def prevented_by(obs: Observation) -> list[str]:
    """The subset of detections that came with an enforcement action."""
    found: list[str] = []
    for e in obs.events:
        key = _event_key(e)
        enforced = e.get("Action") in _ENFORCED or str(e.get("EventType", "")).startswith(
            "protocol."
        )
        if key and enforced and key not in found:
            found.append(key)
    return found


def main_debug(argv: list[str]) -> int:  # pragma: no cover - manual debugging aid
    from attacks.targets import TARGETS

    target = TARGETS[argv[0]]
    for sc in load_scenarios(only=argv[1:]):
        obs = run_scenario(sc, target)
        ok = (not benign_interference(sc, obs)) if sc.benign else attack_succeeded(sc, obs)
        sys.stderr.write(f"{sc.id}: {'ok' if ok else 'no'} {detections(obs)} {obs.errors}\n")
    return 0
