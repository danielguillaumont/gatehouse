"""Streamable HTTP scenarios (milestone m4): header/body smuggling and x-mcp-header abuse.

    python -m attacks http --target gatehouse --out reports/gatehouse-http
    python -m attacks http --target direct --out reports/direct-http

Everything runs in process over ASGI: the client talks to the target (the recording
upstream itself for ``direct``, gatehouse's ``HttpProxy`` in front of it for
``gatehouse``). The simulated client is a conforming 2026-07-28 client: it builds the
routing and ``Mcp-Param-*`` headers from the tool definitions it was shown. A scenario's
``headers`` then override them, which is what a smuggling attacker (or a compromised
client library) does. Success is judged at the upstream: what an intermediary routing on
headers would have seen, and what the server would act on.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import anyio
import httpx2
import yaml

from attacks.http_mock import MODERN, Recorder
from gatehouse.events.emitter import Emitter, EventContext
from gatehouse.events.fingerprint import Fingerprinter
from gatehouse.events.sinks import MemorySink
from gatehouse.inspect.pipeline import ScanConfig
from gatehouse.policy.loader import load_policy
from gatehouse.proxy.http import HttpProxy, HttpProxyConfig
from gatehouse.proxy.http_headers import upstream_headers
from gatehouse.proxy.modern import StateSigner
from gatehouse.proxy.router import RouterConfig

SCENARIOS = Path(__file__).resolve().parent / "http_scenarios.yaml"
POLICY = Path(__file__).resolve().parent / "policy-eval.yaml"
UPSTREAM = "http://127.0.0.1:9000/mcp"
TARGETS = ("direct", "gatehouse")
PREDICATES = ("upstream_routing_mismatch", "client_saw_tool", "upstream_header_contains")
META: dict[str, Any] = {
    "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientCapabilities": {},
}


@dataclass
class HttpScenario:
    id: str
    title: str
    tools: list[dict[str, Any]]
    steps: list[Any]
    expect: str = "attack"
    success_if: dict[str, Any] = field(default_factory=dict[str, Any])
    canaries: list[str] = field(default_factory=list[str])
    owasp: list[str] = field(default_factory=list[str])
    atlas: list[str] = field(default_factory=list[str])


@dataclass
class HttpObservation:
    lists: list[list[dict[str, Any]]] = field(default_factory=list[list[dict[str, Any]]])
    calls: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    upstream: list[tuple[dict[str, str], dict[str, Any]]] = field(
        default_factory=list[tuple[dict[str, str], dict[str, Any]]]
    )
    events: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    errors: list[str] = field(default_factory=list[str])


def load(path: Path = SCENARIOS) -> list[HttpScenario]:
    raw = cast(list[dict[str, Any]], yaml.safe_load(path.read_text(encoding="utf-8")))
    out: list[HttpScenario] = []
    for r in raw:
        sc = HttpScenario(
            id=str(r["id"]),
            title=str(r["title"]),
            tools=list(r["tools"]),
            steps=list(r["steps"]),
            expect=str(r.get("expect", "attack")),
            success_if=dict(r.get("success_if") or {}),
            canaries=[str(c) for c in r.get("canaries", [])],
            owasp=[str(o) for o in r.get("owasp", [])],
            atlas=[str(a) for a in r.get("atlas", [])],
        )
        if sc.expect == "attack" and (
            len(sc.success_if) != 1 or next(iter(sc.success_if)) not in PREDICATES
        ):
            raise ValueError(f"{sc.id}: success_if needs exactly one of {PREDICATES}")
        out.append(sc)
    return out


def _body(rid: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": {**params, "_meta": META}}


async def _run(sc: HttpScenario, target: str) -> HttpObservation:
    obs = HttpObservation()
    upstream = Recorder(tools=sc.tools)
    sink = MemorySink()
    app: Any = upstream
    upstream_client: httpx2.AsyncClient | None = None
    with tempfile.TemporaryDirectory(prefix="gh-http-") as tmp:
        if target == "gatehouse":
            load_ = load_policy(POLICY)
            emitter = Emitter(
                EventContext(
                    agent_session_id=f"eval-{sc.id}", server_name="srv", policy_sha256=load_.sha256
                ),
                [sink],
            )
            key = b"\x00" * 32
            fp = Fingerprinter(key)
            rcfg = RouterConfig(
                server_name="srv",
                policy=load_,
                pins_path=Path(tmp) / "pins.json",
                scan=ScanConfig(fingerprint=fp),
                fingerprinter=fp,
                state_signer=StateSigner(key),
                http=True,
            )
            upstream_client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=upstream))
            app = HttpProxy(HttpProxyConfig(upstream=UPSTREAM), rcfg, emitter, upstream_client)
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://127.0.0.1:9000") as c:
            seen: dict[str, dict[str, Any]] = {}
            rid = 0
            for step in sc.steps:
                rid += 1
                if step == "list":
                    body = _body(rid, "tools/list", {})
                    resp = await _post(c, body, upstream_headers(body, fallback_version=None))
                    tools = cast(
                        list[dict[str, Any]], (resp.get("result") or {}).get("tools") or []
                    )
                    obs.lists.append(tools)
                    seen = {str(t.get("name")): t for t in tools}
                    continue
                call = cast(dict[str, Any], cast(dict[str, Any], step)["call"])
                tool = str(call["tool"])
                body = _body(
                    rid, "tools/call", {"name": tool, "arguments": call.get("arguments") or {}}
                )
                # a conforming client: headers from the definition it was shown
                headers = upstream_headers(body, fallback_version=None, tool=seen.get(tool))
                overrides = cast(dict[str, Any], call.get("headers") or {})
                headers.update({str(k): str(v) for k, v in overrides.items()})
                resp = await _post(c, body, headers)
                obs.calls.append({"tool": tool, "response": resp})
        if upstream_client is not None:
            await upstream_client.aclose()
    obs.upstream = upstream.requests
    obs.events = sink.records
    return obs


async def _post(
    c: httpx2.AsyncClient, body: Mapping[str, Any], headers: Mapping[str, str]
) -> dict[str, Any]:
    hdrs = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    resp = await c.post("/mcp", content=json.dumps(body).encode(), headers={**hdrs, **headers})
    text = resp.text
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        datas = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        text = datas[-1] if datas else "{}"
    try:
        return cast(dict[str, Any], json.loads(text))
    except ValueError:
        return {"error": {"code": None, "message": f"HTTP {resp.status_code}"}}


def attack_succeeded(sc: HttpScenario, obs: HttpObservation) -> bool:
    ((kind, raw),) = sc.success_if.items()
    cond = cast(dict[str, Any], raw or {})
    if kind == "upstream_routing_mismatch":
        for headers, msg in obs.upstream:
            if msg.get("method") != "tools/call":
                continue
            params = cast(dict[str, Any], msg.get("params") or {})
            name = params.get("name")
            if headers.get("mcp-method") != "tools/call" or headers.get("mcp-name") != name:
                return True
            for key, value in headers.items():
                if key.startswith("mcp-param-") and cond.get("param") == key[10:]:
                    args = cast(dict[str, Any], params.get("arguments") or {})
                    if str(args.get(str(cond.get("argument")))) != value:
                        return True
        return False
    if kind == "client_saw_tool":
        return any(t.get("name") == cond["tool"] for listing in obs.lists for t in listing)
    if kind == "upstream_header_contains":
        needle = str(cond["contains"])
        return any(needle in v for headers, _ in obs.upstream for v in headers.values())
    raise ValueError(kind)


def _failed(response: dict[str, Any]) -> bool:
    result = cast(dict[str, Any], response.get("result") or {})
    return "error" in response or result.get("isError") is True


def judge(sc: HttpScenario, obs: HttpObservation) -> tuple[str, list[str]]:
    detections = sorted(
        {
            f"{e['DetectorId']}/{e.get('RuleId')}" if e.get("DetectorId") else str(e["EventType"])
            for e in obs.events
            if e.get("DetectorId") or str(e["EventType"]) == "protocol.header_mismatch"
        }
    )
    if sc.expect == "benign":
        bad = [c for c in obs.calls if _failed(cast(dict[str, Any], c["response"]))]
        hidden = [
            t["name"]
            for t in sc.tools
            if not any(t["name"] == s.get("name") for listing in obs.lists for s in listing)
        ]
        return ("false_positive" if bad or hidden or obs.errors else "pass"), detections
    return ("missed" if attack_succeeded(sc, obs) else "prevented"), detections


def run(target: str, out: Path) -> int:
    if target not in TARGETS:
        raise ValueError(f"target must be one of {TARGETS}")
    out.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    for sc in load():
        obs = anyio.run(_run, sc, target)
        outcome, detections = judge(sc, obs)
        rows.append(
            {
                "id": sc.id,
                "title": sc.title,
                "expect": sc.expect,
                "outcome": outcome,
                "detections": detections,
            }
        )
        print_line = f"{outcome:15} {sc.id}  {', '.join(detections)}"
        sys.stderr.write(print_line + "\n")
        if outcome == "false_positive" or (target == "gatehouse" and outcome == "missed"):
            failures.append(sc.id)
        if target == "direct" and sc.expect == "attack" and outcome == "prevented":
            failures.append(f"{sc.id} (broken: does not succeed without a proxy)")
        logged = json.dumps(obs.events, ensure_ascii=False)
        for canary in sc.canaries:
            if target == "gatehouse" and canary in logged:
                failures.append(f"{sc.id} (canary leaked into gatehouse events)")
        (out / f"{sc.id}.events.jsonl").write_text(
            "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in obs.events), encoding="utf-8"
        )
    (out / "report.json").write_text(
        json.dumps({"target": f"{target}-http", "results": rows}, indent=1), encoding="utf-8"
    )
    lines = [
        f"# HTTP scenarios: {target}",
        "",
        "| Scenario | Expect | Outcome | Detections |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {r['id']} | {r['expect']} | {r['outcome']} | {', '.join(r['detections'])} |"
        for r in rows
    ]
    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for f in failures:
        sys.stderr.write(f"FAIL {f}\n")
    return 1 if failures else 0
