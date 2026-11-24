"""Scripted, recordable demo: a weather server is pinned, rug-pulled, and blocked.

    uv run python demo/run_demo.py [--pause] [--kusto http://localhost:8080]

The same thing happens with Claude Code (see demo/README.md). This script drives gatehouse
with a raw MCP client so the whole story runs unattended, for example for a screen
recording. ``--pause`` waits for Enter between steps. ``--kusto`` loads the session's
events into a Kusto emulator and runs the rug-pull analytics rule (GH001) on them.

All state goes into a temporary GATEHOUSE_HOME; nothing in your real profile is touched.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gatehouse.client import StdioClient  # noqa: E402

SERVER = [sys.executable, str(ROOT / "demo" / "weather_server.py")]
POLICY = ROOT / "demo" / "policy.yaml"
BOLD, DIM, RED, GREEN, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[0m"


def say(text: str = "") -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def step(n: int, title: str, pause: bool) -> None:
    if pause:
        input(f"{DIM}[Enter]{RESET}")
    say(f"\n{BOLD}== {n}. {title}{RESET}")


def gatehouse(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "gatehouse", *args]
    say(f"{DIM}$ gatehouse {' '.join(args[:3])} ...{RESET}")
    return subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)


def session(env: dict[str, str], pins: Path, events: Path, calls: list[str]) -> None:
    argv = [
        sys.executable,
        "-m",
        "gatehouse",
        "run",
        "--name",
        "weather",
        "--policy",
        str(POLICY),
        "--pins",
        str(pins),
        "--events-dir",
        str(events),
        "--quiet",
        "--",
        *SERVER,
    ]
    with StdioClient(argv, env=env, timeout=60) as client:
        client.initialize(client_name="demo-agent")
        tools = client.list_tools()
        say(f"agent sees tools: {GREEN}{[t['name'] for t in tools]}{RESET}")
        for tool in calls:
            resp = client.call_tool(tool, {"city": "Paris"} if tool == "get_forecast" else {})
            result: dict[str, Any] = resp.get("result") or {}
            text = " ".join(c.get("text", "") for c in result.get("content", []))
            colour = RED if result.get("isError") else GREEN
            say(f"call {tool} -> {colour}{text[:110]}{RESET}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--pause", action="store_true")
    p.add_argument("--kusto", default=None)
    args = p.parse_args(argv)
    flag = ROOT / "demo" / ".poisoned"
    flag.unlink(missing_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="gatehouse-demo-"))
    pins, events = tmp / "pins.json", tmp / "events"
    env = {**__import__("os").environ, "GATEHOUSE_HOME": str(tmp / "state")}
    env["GATEHOUSE_AGENT_SESSION_ID"] = "demo-session"

    try:
        step(1, "Approve (pin) the weather server's tools", args.pause)
        r = gatehouse("pin", "--name", "weather", "--pins", str(pins), "--", *SERVER, env=env)
        say(r.stdout.strip())

        step(2, "Normal use through gatehouse", args.pause)
        session(env, pins, events, ["get_forecast"])

        step(3, "The server is updated with a poisoned description (rug pull)", args.pause)
        flag.write_text("demo\n", encoding="utf-8")
        r = gatehouse("diff", "--name", "weather", "--pins", str(pins), "--", *SERVER, env=env)
        say(r.stdout.strip())

        step(4, "Same agent, next session: the poisoned tool never reaches the model", args.pause)
        session(env, pins, events, ["get_forecast", "list_cities"])

        step(5, "What the SOC sees (JSONL events, redacted)", args.pause)
        rows: list[dict[str, Any]] = []
        for f in sorted(events.glob("*.jsonl")):
            rows += [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x]
        for e in rows:
            if e["EventType"] in ("detection", "tool.call") and e["Action"] != "allowed":
                say(
                    f"{e['TimeGenerated'][11:23]} {RED}{e['EventType']:9}{RESET} "
                    f"{e['Action']:8} {e.get('ToolName')}  "
                    f"{e.get('DetectorId') or e.get('DecisionBasis')}  "
                    f"{dict(e.get('Details') or {}).get('ChangedFields', '')}"
                )

        if args.kusto:
            step(6, "Sentinel rule GH001 (rug pull) on these events, in the Kusto emulator", False)
            from detections.kusto import Kusto, create_table, ingest_sample, load_rules

            k = Kusto(args.kusto)
            k.wait_ready(60)
            create_table(k)
            merged = tmp / "events.jsonl"
            merged.write_text("".join(json.dumps(e) + "\n" for e in rows), encoding="utf-8")
            ingest_sample(k, merged)
            for row in k.query(load_rules()["GH001_rug_pull"]["query"]):
                say(
                    f"{RED}ALERT{RESET} rug pull on {row['ServerName']}/{row['ToolName']} "
                    f"changed={row['ChangedFields']}"
                )
        say(f"\n{DIM}state and events: {tmp}{RESET}")
    finally:
        flag.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
