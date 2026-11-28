"""Run the official MCP conformance suite against an SDK server, directly and through
``gatehouse serve``, and compare the two.

    uv run --with click python scripts/conformance.py --server-dir DIR --out reports/conformance

DIR is ``examples/servers/everything-server`` from the MCP Python SDK at the tag that
matches the dev lock (v2.3.0). Fetch it with::

    gh api repos/modelcontextprotocol/python-sdk/tarball/v2.3.0 > sdk.tar.gz
    tar -xzf sdk.tar.gz --wildcards "*/examples/servers/everything-server/*"

The harness version is the one SDK 2.3.0's own CI pins (``CONFORMANCE_PKG``). The SDK's
expected-failures baseline at that tag is empty for both wires, so a failure in the
"direct" column is a harness or environment issue and a new failure in the "gatehouse"
column is gatehouse's doing. The policy allows everything with pinning off: this
measures protocol fidelity, not security decisions (the attack suite measures those).

Exit code: 0 when gatehouse adds no failures over the direct baseline, else 1.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HARNESS = "@modelcontextprotocol/conformance@0.2.0-alpha.11"
WIRES = ("2025-11-25", "2026-07-28")
POLICY = 'version: 1\ndefault_action: allow\npinning: "off"\n'
_STAMP = re.compile(r"-\d{4}-\d\d-\d\dT[\d-]+Z$")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(port: int, proc: subprocess.Popen[bytes], timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited early ({proc.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.3)
    raise TimeoutError(f"port {port} never opened")


def _stop(proc: subprocess.Popen[bytes]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def _run_harness(url: str, wire: str, out: Path, scenario: str | None) -> dict[str, str]:
    """scenario -> PASS/FAIL (a scenario fails if any of its checks fails)."""
    npx = shutil.which("npx")
    if npx is None:
        raise RuntimeError("npx (Node.js) is required")
    out.mkdir(parents=True, exist_ok=True)
    cmd = [npx, "--yes", HARNESS, "server", "--url", url, "--spec-version", wire]
    cmd += ["-o", str(out / "results")]
    cmd += ["--scenario", scenario] if scenario else ["--suite", "all"]
    with (out / "harness.log").open("wb") as fh:
        subprocess.run(  # noqa: S603 (fixed argv, no shell)
            cmd, cwd=out, stdout=fh, stderr=subprocess.STDOUT, check=False, timeout=1800
        )
    verdicts: dict[str, str] = {}
    for checks in sorted((out / "results").glob("server-*/checks.json")):
        name = _STAMP.sub("", checks.parent.name.removeprefix("server-"))
        items: list[dict[str, Any]] = json.loads(checks.read_text(encoding="utf-8"))
        failed = [c for c in items if str(c.get("status", "")).upper() == "FAILURE"]
        verdicts[name] = "FAIL" if failed else "PASS"
        if failed:
            text = json.dumps(failed, indent=1)
            (out / f"{name}.failures.json").write_text(text, encoding="utf-8")
    return verdicts


def _start(argv: list[str], log: Path, cwd: Path | None = None) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 (fixed argv, no shell)
        argv, cwd=cwd, stdout=subprocess.DEVNULL, stderr=log.open("wb")
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--wire", choices=WIRES, help="only this protocol version")
    ap.add_argument("--scenario", help="only this scenario")
    args = ap.parse_args()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "policy.yaml").write_text(POLICY, encoding="utf-8")
    up_port, gh_port = _free_port(), _free_port()
    up_url = f"http://localhost:{up_port}/mcp"
    gh_url = f"http://localhost:{gh_port}/mcp"
    server = _start(
        [sys.executable, "-m", "mcp_everything_server", "--port", str(up_port)],
        out / "server.log",
        cwd=args.server_dir,
    )
    gatehouse = _start(
        [
            *(sys.executable, "-m", "gatehouse", "serve", "--name", "everything"),
            *("--policy", str(out / "policy.yaml"), "--pins", str(out / "pins.json")),
            *("--events-dir", str(out / "events"), "--quiet", "--approval-timeout", "0"),
            *("--upstream", up_url, "--port", str(gh_port)),
        ],
        out / "gatehouse.log",
    )
    rows: list[dict[str, str]] = []
    try:
        _wait(up_port, server)
        _wait(gh_port, gatehouse)
        for wire in [args.wire] if args.wire else WIRES:
            direct = _run_harness(up_url, wire, out / f"direct-{wire}", args.scenario)
            through = _run_harness(gh_url, wire, out / f"gatehouse-{wire}", args.scenario)
            for name in sorted(set(direct) | set(through)):
                rows.append(
                    {
                        "wire": wire,
                        "scenario": name,
                        "direct": direct.get(name, "-"),
                        "gatehouse": through.get(name, "-"),
                    }
                )
    finally:
        _stop(gatehouse)
        _stop(server)
    added = [r for r in rows if r["gatehouse"] == "FAIL" and r["direct"] != "FAIL"]
    summary = {
        "harness": HARNESS,
        "server": "MCP Python SDK v2.3.0 examples/servers/everything-server",
        "rows": rows,
        "added_failures": added,
    }
    (out / "conformance.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    lines = [
        f"Harness `{HARNESS}`, server: MCP Python SDK v2.3.0 everything-server.",
        "",
        "| Wire | Scenario | Direct | Through gatehouse |",
        "|---|---|---|---|",
    ]
    lines += [f"| {r['wire']} | {r['scenario']} | {r['direct']} | {r['gatehouse']} |" for r in rows]
    (out / "conformance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for wire in WIRES:
        sel = [r for r in rows if r["wire"] == wire]
        if not sel:
            continue
        d = sum(r["direct"] == "PASS" for r in sel)
        g = sum(r["gatehouse"] == "PASS" for r in sel)
        sys.stderr.write(f"{wire}: direct {d}/{len(sel)}, through gatehouse {g}/{len(sel)}\n")
    for r in added:
        sys.stderr.write(f"ADDED FAILURE {r['wire']} {r['scenario']}\n")
    return 1 if added else 0


if __name__ == "__main__":
    raise SystemExit(main())
