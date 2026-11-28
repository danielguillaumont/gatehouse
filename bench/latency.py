"""Latency added by gatehouse: tools/call round trip, direct vs. proxied.

    uv run python -m bench.latency [--iterations 200] [--sizes 1024 102400 1048576]
                                   [--policy allow|cedar-native|flow] [--out reports/bench]

For each payload size S the tool call carries an S-byte text argument and the server
returns an S-byte text result, so both the argument detectors (client -> server) and the
result detectors (server -> client) run on S bytes. Reports p50/p95/p99 in milliseconds
and the overhead (proxied minus direct) per percentile. The numbers depend on the
machine; the report records platform, Python version and commit so they can be
reproduced.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from attacks.layers import LAYERS, NEEDS_OLLAMA
from attacks.layers import apply as apply_layers
from attacks.report import _git_commit  # pyright: ignore[reportPrivateUsage]
from attacks.targets import TARGETS, RunPaths, server_command
from gatehouse import __version__
from gatehouse.client import StdioClient

# What the proxied side runs. "allow" (the default, comparable with earlier runs) is an
# allow-all policy, decided by the Cedar engine checked against the reference. "native"
# uses the reference engine alone, so allow minus native is Cedar's cost. "flow" turns
# session flow control on (approve mode) with the bench tool labelled private_data, so
# every call reads the shared flow store and every result is fingerprinted (D-043).
POLICIES = {
    "allow": "version: 1\ndefault_action: allow\npinning: tofu\n",
    "native": "version: 1\ndefault_action: allow\npinning: tofu\nengine: native\n",
    "flow": (
        "version: 1\ndefault_action: allow\npinning: tofu\nflow: {mode: approve}\n"
        "servers:\n  bench:\n    labels: {echo: [private_data]}\n"
    ),
}

WORDS = "the quick brown fox jumps over a lazy dog while agents call tools ".split()


def _text(size: int) -> str:
    out: list[str] = []
    n = 0
    i = 0
    while n < size:
        w = WORDS[i % len(WORDS)]
        out.append(w)
        n += len(w) + 1
        i += 1
    return " ".join(out)[:size]


def _percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    k = (len(ordered) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def policy_text(policy_name: str, layers: str | None = None) -> str:
    """The bench policy, with an ablation layer overlay (attacks/layers.py) merged in.
    A layer with flow control starts from the flow policy, so the tool is labelled."""
    if layers is None:
        return POLICIES[policy_name]
    flow = LAYERS[layers]["flow"]["mode"] != "off"
    return apply_layers(POLICIES["flow" if flow else policy_name], layers)


def measure(
    target: str,
    size: int,
    iterations: int,
    warmup: int = 5,
    policy_name: str = "allow",
    layers: str | None = None,
) -> dict[str, float]:
    tmp = Path(tempfile.mkdtemp(prefix="gh-bench-"))
    spec = {
        "name": "bench",
        "tools": [
            {
                "name": "echo",
                "description": "Echo text.",
                "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
            }
        ],
        "results": {"echo": _text(size)},
    }
    (tmp / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
    policy = tmp / "policy.yaml"
    policy.write_text(policy_text(policy_name, layers), encoding="utf-8")
    rp = RunPaths(policy=policy, pins=tmp / "pins.json", events_dir=tmp / "ev")
    argv = TARGETS[target].argv("bench", server_command(), rp)
    env = {"ATTACK_SPEC": str(tmp / "spec.json"), "GATEHOUSE_HOME": str(tmp / "state")}
    argument = _text(size)
    samples: list[float] = []
    # A judge layer may withhold the bench's word-salad result. The round trip still
    # includes the verdict, so it is measured and the withheld calls are counted.
    tolerate_blocks = layers in NEEDS_OLLAMA
    blocked = 0
    with StdioClient(argv, env=env, timeout=60) as client:
        client.initialize(client_name="gatehouse-bench")
        client.list_tools()
        for i in range(warmup + iterations):
            start = time.perf_counter()
            resp = client.call_tool("echo", {"text": argument})
            elapsed = (time.perf_counter() - start) * 1000.0
            failed = "result" not in resp or bool(resp["result"].get("isError"))
            if failed and not tolerate_blocks:
                raise RuntimeError(f"{target}: call failed: {resp}")
            if i >= warmup:
                samples.append(elapsed)
                blocked += failed
    return {
        "p50": round(_percentile(samples, 0.50), 3),
        "p95": round(_percentile(samples, 0.95), 3),
        "p99": round(_percentile(samples, 0.99), 3),
        "mean": round(statistics.fmean(samples), 3),
        "n": len(samples),
        "blocked": blocked,
    }


def _fmt_size(size: int) -> str:
    if size >= 1 << 20:
        return f"{size // (1 << 20)} MiB"
    if size >= 1024:
        return f"{size // 1024} KiB"
    return f"{size} B"


def render(report: dict[str, Any]) -> str:
    m = report["meta"]
    lines = [
        "# Latency benchmark",
        "",
        f"gatehouse {m['gatehouse_version']} @ `{m['git_commit']}` · Python {m['python']} · "
        f"{m['platform']} · {m['generated_at']} · {m['iterations']} calls per size · "
        f"policy `{m.get('policy', 'allow')}`"
        + (f" · layers `{m['layers']}`" if m.get("layers") else ""),
        "",
        "Round trip of one `tools/call` (argument and result both of the given size), in ms.",
        "",
        "| Payload | direct p50 | gatehouse p50 | overhead p50 | overhead p95 | overhead p99 |",
        "|---|---|---|---|---|---|",
    ]
    for row in report["results"]:
        d, g = row["direct"], row["gatehouse"]
        lines.append(
            f"| {_fmt_size(row['size'])} | {d['p50']:.2f} | {g['p50']:.2f} | "
            f"{g['p50'] - d['p50']:+.2f} | {g['p95'] - d['p95']:+.2f} | "
            f"{g['p99'] - d['p99']:+.2f} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m bench.latency")
    p.add_argument("--iterations", type=int, default=200)
    p.add_argument("--sizes", type=int, nargs="*", default=[1024, 102400, 1048576])
    p.add_argument("--out", type=Path, default=Path("reports/bench"))
    p.add_argument("--policy", choices=sorted(POLICIES), default="allow")
    p.add_argument("--layers", choices=sorted(LAYERS), help="ablation row (attacks/layers.py)")
    args = p.parse_args(argv)
    results: list[dict[str, Any]] = []
    for size in args.sizes:
        iters = args.iterations if size < (1 << 20) else max(20, args.iterations // 4)
        row: dict[str, Any] = {"size": size}
        for target in ("direct", "gatehouse"):
            row[target] = measure(target, size, iters, policy_name=args.policy, layers=args.layers)
            sys.stderr.write(f"{target:10} {_fmt_size(size):>8}  {row[target]}\n")
        results.append(row)
    report = {
        "meta": {
            "gatehouse_version": __version__,
            "git_commit": _git_commit(),
            "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "iterations": args.iterations,
            "policy": args.policy,
            "layers": args.layers,
        },
        "results": results,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "latency.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = render(report)
    (args.out / "latency.md").write_text(md, encoding="utf-8")
    sys.stderr.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
