"""Load scenarios, run them against a target, and record what each side observed.

A scenario has one or more *phases*; each phase is a fresh client + target process
(a server "restart"), sharing that scenario's isolated home, pin store and server log.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

import yaml

from attacks import layers as _layers
from attacks.targets import EVAL_POLICY, FLOW_POLICY, RunPaths, Target, server_command
from gatehouse.client import ClientError, StdioClient
from gatehouse.jsonutil import as_obj

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
MILESTONES = ("mvp", "m2", "m3", "m4", "m5", "m6", "m6-rules", "external", "bypass")
# Held-out sets and external corpora: measured, never a regression gate and never a
# tuning target (D-032, D-046, D-047).
HELDOUT = ("m3", "m6", "external")
# Seconds the simulated client waits for each response. The judge layer raises it
# in CI: a CPU-only model needs seconds per verdict (attacks/layers.py).
CLIENT_TIMEOUT = float(os.environ.get("ATTACK_CLIENT_TIMEOUT") or 20)
PREDICATES = (
    "client_saw_tool",
    "client_saw_result",
    "server_received",
    "server_received_raw",
    "client_saw_input_request",
    "client_fell_back",
    "client_saw_discover",
)
ERAS = ("legacy", "modern", "auto")
FLOW_MODES = ("monitor", "approve", "enforce")


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
    # Protocol era the scenario's client speaks: legacy (initialize), modern (2026-07-28
    # _meta on every request) or auto (probe server/discover, fall back to initialize).
    era: str = "legacy"
    client_capabilities: dict[str, Any] = field(default_factory=dict[str, Any])
    # What the simulated user types into any form a server shows: every string field gets
    # this value (booleans stay false, so gatehouse's own approval prompts are declined).
    user_answer: str | None = None
    # Multi-server scenarios (flow.*, milestone m5): every server runs at once, each behind
    # its own target process, sharing one state directory and agent session. Steps name
    # the server they act on. ``phases`` is empty for these.
    servers: dict[str, dict[str, Any]] = field(default_factory=dict[str, dict[str, Any]])
    steps: list[Any] = field(default_factory=list[Any])
    # "flow": run with attacks/policy-flow.yaml instead of the eval policy.
    policy: str | None = None
    # The simulated user approves gatehouse's approval prompts (benign flow tasks), so the
    # task completes and the prompts can be counted. Attack scenarios decline.
    user_approves: bool = False

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
        servers: dict[str, dict[str, Any]] = {}
        if "servers" in raw:
            servers = {
                str(k): dict(v) for k, v in cast(dict[str, dict[str, Any]], raw["servers"]).items()
            }
            phases: list[Phase] = []
        elif "phases" in raw:
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
            era=str(raw.get("era", "legacy")),
            client_capabilities=dict(raw.get("client_capabilities") or {}),
            user_answer=str(raw["user_answer"]) if "user_answer" in raw else None,
            servers=servers,
            steps=list(raw.get("steps", [])) if servers else [],
            policy=str(raw["policy"]) if "policy" in raw else None,
            user_approves=bool(raw.get("user_approves", False)),
        )
    except (KeyError, TypeError) as exc:
        raise ScenarioError(f"{source}: scenario {sid}: missing/invalid field {exc}") from None
    if sc.milestone not in MILESTONES:
        raise ScenarioError(f"{source}: {sid}: unknown milestone {sc.milestone!r}")
    if sc.era not in ERAS:
        raise ScenarioError(f"{source}: {sid}: era must be one of {ERAS}")
    if sc.policy not in (None, "flow"):
        raise ScenarioError(f"{source}: {sid}: policy must be flow (or absent)")
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
    markers_stripped: int = 0
    stderr_alerts: list[str] = field(default_factory=list[str])
    eras: list[str | None] = field(default_factory=list[str | None])  # per phase
    input_requests: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    discovered: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    frame_servers: list[str] = field(default_factory=list[str])  # server of each frame


def strip_result_marker(calls: list[dict[str, Any]], marker: str) -> int:
    """Remove a target's deliberate per-result marker from text content; return count."""
    pattern = re.compile(marker)
    count = 0
    for call in calls:
        result = cast(dict[str, Any], call.get("response", {})).get("result")
        if not isinstance(result, dict):
            continue
        for item in cast(list[Any], cast(dict[str, Any], result).get("content") or []):
            if isinstance(item, dict) and isinstance(cast(dict[str, Any], item).get("text"), str):
                entry = cast(dict[str, Any], item)
                new, n = pattern.subn("", cast(str, entry["text"]))
                entry["text"], count = new, count + n
    return count


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _schema_equivalent(schema: Any) -> Any:
    """A JSON Schema without the no-op keywords a proxy may add when it rebuilds one: an
    empty ``required`` list and empty ``description`` strings (D-051). Anything else a
    target changes still counts."""
    if isinstance(schema, dict):
        out: dict[str, Any] = {}
        for key, value in cast(dict[str, Any], schema).items():
            if (key == "required" and value == []) or (key == "description" and value == ""):
                continue
            out[key] = _schema_equivalent(value)
        return out
    if isinstance(schema, list):
        return [_schema_equivalent(v) for v in cast(list[Any], schema)]
    return schema


def _listing(tools: list[dict[str, Any]]) -> str:
    """A tool listing for comparison: schemas up to no-op keywords, the rest exact."""
    normalized = [
        {
            k: (_schema_equivalent(v) if k in ("inputSchema", "outputSchema") else v)
            for k, v in t.items()
        }
        for t in tools
    ]
    return _dump(normalized)


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


def _fill_form(
    params: Mapping[str, Any], answer: str | None, approve: bool = False
) -> dict[str, Any]:
    """The simulated user's answer to an elicitation form."""
    if answer is None and not approve:
        return {"action": "decline"}
    schema = cast(dict[str, Any], params.get("requestedSchema") or {})
    props = cast(dict[str, Any], schema.get("properties") or {})
    content: dict[str, Any] = {}
    for key, prop in props.items():
        kind = cast(dict[str, Any], prop).get("type") if isinstance(prop, dict) else None
        content[key] = approve if kind == "boolean" else (answer or "")
    return {"action": "accept", "content": content}


class SimulatedUser:
    """Answers forms the way a user who trusts what the client shows would."""

    def __init__(self, sc: Scenario, obs: Observation) -> None:
        self.answer = sc.user_answer
        self.approve = sc.user_approves
        self.obs = obs

    def server_request(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        if frame.get("method") != "elicitation/create":
            return None
        params = cast(dict[str, Any], frame.get("params") or {})
        self.obs.input_requests.append({"method": "elicitation/create", "params": params})
        return _fill_form(params, self.answer, self.approve)

    def input_required(self, result: dict[str, Any]) -> dict[str, Any] | None:
        requests = cast(dict[str, Any], result.get("inputRequests") or {})
        answers: dict[str, Any] = {}
        for key, req in requests.items():
            r = cast(dict[str, Any], req) if isinstance(req, dict) else {}
            self.obs.input_requests.append(r)
            if r.get("method") == "elicitation/create":
                answers[key] = _fill_form(
                    cast(dict[str, Any], r.get("params") or {}), self.answer, self.approve
                )
            elif r.get("method") == "roots/list":
                answers[key] = {"roots": []}
        return answers if answers else None


def _resync(client: StdioClient) -> None:
    """Once this answer arrives, everything sent before it was handled. 2026-07-28 has no
    ping, so modern clients use server/discover."""
    if client.era == "modern":
        client.request("server/discover", {}, timeout=10)
    else:
        client.request("ping", {}, timeout=10)


def _run_steps(
    client: StdioClient,
    steps: list[Any],
    obs: Observation,
    subst: Mapping[str, str],
    user: SimulatedUser,
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
                resp = client.call_tool(tool, args, on_input=user.input_required)
            except ClientError as exc:
                resp = {"error": {"code": None, "message": str(exc)}}
            obs.calls.append({"tool": tool, "arguments": args, "response": resp})
        elif "raw" in s:
            client.send_raw(str(_substitute(s["raw"], subst)).encode("utf-8") + b"\n")
            try:
                _resync(client)
            except ClientError as exc:
                obs.errors.append(f"resync after raw: {exc}")
        else:
            raise ScenarioError(f"unknown step {step!r}")


def _run_multi(
    sc: Scenario,
    target: Target,
    obs: Observation,
    rp: RunPaths,
    env: dict[str, str],
    subst: Mapping[str, str],
    tmp: Path,
) -> None:
    """Every server at once, each behind its own target process (flow.* scenarios)."""
    user = SimulatedUser(sc, obs)
    clients: dict[str, StdioClient] = {}
    try:
        for name, server in sc.servers.items():
            spec_path = tmp / f"spec-{name}.json"
            spec_path.write_text(json.dumps({"name": name, **server}), encoding="utf-8")
            own = RunPaths(policy=rp.policy, pins=rp.pins, events_dir=rp.events_dir / name)
            client = StdioClient(
                target.argv(name, server_command(), own),
                env={
                    **env,
                    "ATTACK_SPEC": str(spec_path),
                    "ATTACK_LOG": str(tmp / f"log-{name}.jsonl"),
                },
                timeout=CLIENT_TIMEOUT,
                on_server_request=user.server_request,
            )
            clients[name] = client
            client.connect(sc.era, sc.client_capabilities, client_name="gatehouse-attack-suite")
        for step in sc.steps:
            if step == "list":
                for client in clients.values():
                    try:
                        obs.lists.append(client.list_tools())
                    except ClientError as exc:
                        obs.lists.append([])
                        obs.errors.append(f"list: {exc}")
                continue
            call = cast(dict[str, Any], cast(dict[str, Any], step)["call"])
            server, tool = str(call["server"]), str(call["tool"])
            args = _substitute(call.get("arguments") or {}, subst)
            try:
                resp = clients[server].call_tool(tool, args, on_input=user.input_required)
            except ClientError as exc:
                resp = {"error": {"code": None, "message": str(exc)}}
            obs.calls.append({"server": server, "tool": tool, "arguments": args, "response": resp})
    except ClientError as exc:
        obs.errors.append(str(exc))
    finally:
        for client in clients.values():
            client.close()
            obs.stderr.extend(client.stderr_lines)
    for name in sc.servers:
        log = tmp / f"log-{name}.jsonl"
        if log.exists():
            lines = log.read_text(encoding="utf-8").splitlines()
            obs.server_frames.extend(lines)
            obs.frame_servers.extend([name] * len(lines))


def run_scenario(
    sc: Scenario,
    target: Target,
    *,
    keep_dir: Path | None = None,
    flow_mode: str = "approve",
    layers: str | None = None,
) -> Observation:
    """Run one scenario. ``layers`` names an ablation row (attacks/layers.py) whose
    overlay is merged into the policy; ``None`` uses the policy as written.

    In an ablation run the client always offers elicitation, and the simulated user
    approves gatehouse's prompts in benign scenarios (and declines them in attacks), so a
    prompt on a benign task is counted as a prompt, not as a false positive (D-048)."""
    if layers is not None:
        sc = replace(
            sc,
            user_approves=sc.user_approves or sc.benign,
            client_capabilities=sc.client_capabilities or {"elicitation": {}},
        )
    obs = Observation(sc.id, target.name)
    started = time.monotonic()
    tmp = Path(tempfile.mkdtemp(prefix="gh-attack-"))
    try:
        home = tmp / "home"
        state = home / ".gatehouse"
        state.mkdir(parents=True)
        rp = RunPaths(policy=tmp / "policy.yaml", pins=state / "pins.json", events_dir=tmp / "ev")
        if sc.policy == "flow":
            if flow_mode not in FLOW_MODES:
                raise ScenarioError(f"flow mode must be one of {FLOW_MODES}")
            text = FLOW_POLICY.read_text(encoding="utf-8").replace("FLOW_MODE", flow_mode)
            rp.policy.write_text(_layers.apply(text, layers), encoding="utf-8")
        elif layers is not None:
            text = EVAL_POLICY.read_text(encoding="utf-8")
            rp.policy.write_text(_layers.apply(text, layers), encoding="utf-8")
        else:
            shutil.copyfile(EVAL_POLICY, rp.policy)
        log = home / "attack-log.jsonl"  # also the mock server's $HOME fallback (D-051)
        env = {
            "GATEHOUSE_HOME": str(state),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "GATEHOUSE_AGENT_SESSION_ID": f"eval-{sc.id}",
            "ATTACK_LOG": str(log),
            "PYTHONIOENCODING": "utf-8",
        }
        subst = {"policy_path": str(rp.policy), "pins_path": str(rp.pins)}
        if sc.servers:
            _run_multi(sc, target, obs, rp, env, subst, tmp)
        for index, phase in enumerate(sc.phases):
            spec_path = tmp / f"spec-{index}.json"
            spec = {"name": sc.id.split(".")[0], **phase.server}
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            # for targets that clean the server's environment (mockserver.py fallback)
            shutil.copyfile(spec_path, home / "attack-spec.json")
            argv = target.argv("srv", server_command(), rp)
            if index == 0:
                target.prepare(rp, {**env, "ATTACK_SPEC": str(spec_path)})
            user = SimulatedUser(sc, obs)
            client = StdioClient(
                argv,
                env={**env, "ATTACK_SPEC": str(spec_path)},
                timeout=CLIENT_TIMEOUT,
                on_server_request=user.server_request,
            )
            try:
                try:
                    hello = client.connect(
                        sc.era, sc.client_capabilities, client_name="gatehouse-attack-suite"
                    )
                    if client.era == "modern":
                        obs.discovered.append(hello)
                finally:
                    obs.eras.append(client.era)
                _run_steps(client, phase.steps, obs, subst, user)
            except ClientError as exc:
                obs.errors.append(f"phase {index}: {exc}")
            finally:
                client.close()
                obs.stderr.extend(client.stderr_lines)
        if log.exists():
            obs.server_frames = log.read_text(encoding="utf-8").splitlines()
        if rp.events_dir.exists():
            for f in sorted(rp.events_dir.rglob("*.jsonl")):
                for line in f.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        obs.events.append(json.loads(line))
        if target.stderr_alert is not None:
            text = "".join(obs.stderr)
            obs.stderr_alerts = sorted(
                {f"stderr:{m.group(0)}" for m in re.finditer(target.stderr_alert, text)}
            )
        if target.result_marker is not None:
            obs.markers_stripped = strip_result_marker(obs.calls, target.result_marker)
        target.unwrap_results(obs.calls)
        if keep_dir is not None:
            shutil.copytree(tmp, keep_dir / sc.id, dirs_exist_ok=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        obs.duration_s = round(time.monotonic() - started, 3)
    return obs


# ---------------------------------------------------------------------- judging


def _server_calls(obs: Observation) -> list[tuple[str, dict[str, Any], str | None]]:
    out: list[tuple[str, dict[str, Any], str | None]] = []
    for i, line in enumerate(obs.server_frames):
        try:
            frame: Any = json.loads(line)
        except ValueError:
            continue
        if isinstance(frame, dict) and cast(dict[str, Any], frame).get("method") == "tools/call":
            f = cast(dict[str, Any], frame)
            server = obs.frame_servers[i] if i < len(obs.frame_servers) else None
            out.append((line, f, server))
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
        want_server = str(cond["server"]) if "server" in cond else None
        for line, frame, server in _server_calls(obs):
            params = cast(dict[str, Any], frame.get("params") or {})
            if params.get("name") != tool:
                continue
            if want_server is not None and server != want_server:
                continue
            if needle is None or needle in line or needle in _dump(frame):
                return True
        return False
    if kind == "server_received_raw":
        assert needle is not None
        return any(needle in line for line in obs.server_frames)
    if kind == "client_saw_input_request":
        return any(needle is None or needle in _dump(r) for r in obs.input_requests)
    if kind == "client_fell_back":
        # an auto-mode client ended up on the legacy handshake in some phase
        return "legacy" in obs.eras
    if kind == "client_saw_discover":
        return any(needle is None or needle in _dump(d) for d in obs.discovered)
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
    if sc.servers:
        return problems + _multi_interference(sc, obs)
    lists = iter(obs.lists)
    calls = iter(obs.calls)
    for phase in sc.phases:
        offered = cast(list[dict[str, Any]], phase.server.get("tools") or [])
        for step in phase.steps:
            if step == "list":
                seen: list[dict[str, Any]] = next(lists, cast(list[dict[str, Any]], []))
                if _listing(seen) != _listing(offered):
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
                body = as_obj(got)
                if body is not None and body.get("resultType") == "complete":
                    got = {k: v for k, v in body.items() if k != "resultType"}  # modern era
                if got != expected:
                    err = cast(dict[str, Any], c["response"].get("error") or {})
                    problems.append(f"call {c['tool']} altered/blocked: {err.get('message', '')}")
    return problems


def _multi_interference(sc: Scenario, obs: Observation) -> list[str]:
    problems: list[str] = []
    expected_lists = [
        cast(list[dict[str, Any]], s.get("tools") or [])
        for step in sc.steps
        if step == "list"
        for s in sc.servers.values()
    ]
    for seen, offered in zip(obs.lists, expected_lists, strict=False):
        if _listing(seen) != _listing(offered):
            problems.append("tools/list altered")
    for c in obs.calls:
        expected = _expected_result(sc.servers[c["server"]], c["tool"])
        got = c["response"].get("result")
        if got != expected:
            err = cast(dict[str, Any], c["response"].get("error") or {})
            text = ""
            body = as_obj(got)
            if body is not None:
                content = cast(list[Any], body.get("content") or [{}])
                first = cast(dict[str, Any], content[0]) if content else {}
                text = str(first.get("text", ""))[:160]
            problems.append(
                f"call {c['server']}/{c['tool']} altered/blocked: {err.get('message', '')}{text}"
            )
    return problems


def approvals_asked(obs: Observation) -> int:
    """Approval prompts gatehouse showed the user (all servers)."""
    return sum(e.get("EventType") == "approval.requested" for e in obs.events)


_ENFORCED = ("blocked", "filtered", "fail_closed", "denied")
# Protocol events that are alerts in themselves (no DetectorId: the framing layer decides).
_ALERT_EVENTS = (
    "protocol.invalid_frame",
    "protocol.batch_rejected",
    "protocol.oversized_frame",
    "protocol.unsolicited_response",
    "protocol.unsupported_version",
    "protocol.invalid_meta",
    "protocol.era_conflict",
    "protocol.invalid_result",
    "protocol.header_mismatch",
    "protocol.unsolicited_notification",
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
    """What the target reported about this scenario: gatehouse detector rules and alert
    events, or, for competitors that only print alerts, matches of their stderr pattern."""
    found: list[str] = []
    for e in obs.events:
        key = _event_key(e)
        if key and key not in found:
            found.append(key)
    for alert in obs.stderr_alerts:
        if alert not in found:
            found.append(alert)
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
