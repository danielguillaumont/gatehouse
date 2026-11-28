"""Collate one evaluation-v2 workflow run into its tables (M6, D-048).

    python -m attacks.evaluate collate reports/ --out reports/evaluation

Reads ``reports/<target>__<layers>__<set>/report.json``, where ``<layers>`` is ``-`` for
targets other than gatehouse, and ``reports/bench-<layers>/latency.json``. Writes
``evaluation.md`` and ``evaluation.json`` with:

- the **ablation table**: one row per gatehouse layer combination;
- the **comparison table**: one row per target, using gatehouse's ``full`` row.

Every number in them comes from the reports, and the header names the workflow run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

from attacks.layers import LAYERS

SETS = ("suite", "heldout2", "mcptox", "egress")
SET_TITLES = {
    "suite": "Suite (written with the detectors)",
    "heldout2": "Held-out v2 (frozen)",
    "mcptox": "MCPTox (poisoned tools)",
    "egress": "agent-egress-bench (MCP stdio)",
}
TARGET_ORDER = (
    "gatehouse",
    "pipelock",
    "mcp-context-protector",
    "gateward",
    "mcp-watchdog",
    "direct",
)


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


def load_reports(root: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for path in sorted(root.glob("*__*__*/report.json")):
        target, layers, set_name = path.parent.name.split("__")
        report = _load(path)
        if report is None:
            continue
        # ``<set>.<k>``: one shard of a set run with --shard; shards are merged
        base = set_name.split(".", 1)[0]
        key = (target, layers, base)
        if key in out:
            merged = _results(out[key]) + _results(report)
            out[key] = {**out[key], "results": merged}
        else:
            out[key] = report
    return out


def _results(report: dict[str, Any]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], report.get("results") or [])


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    """Counts used by the tables, from one report."""
    rows = _results(report)
    attacks = [r for r in rows if r["expect"] == "attack"]
    # documented bypasses aren't counted as attacks to prevent
    attacks = [r for r in attacks if r["milestone"] != "bypass"]
    benign = [r for r in rows if r["expect"] == "benign"]
    chains = [r for r in attacks if r["category"] == "flow"]
    flow_benign = [r for r in benign if str(r["id"]).startswith("benign.flow.")]
    return {
        "attacks": len(attacks),
        "prevented": sum(r["outcome"] == "prevented" for r in attacks),
        "detected_only": sum(r["outcome"] == "detected" for r in attacks),
        "missed": sum(r["outcome"] == "missed" for r in attacks),
        "broken": sum(r["outcome"] == "broken" for r in attacks),
        "benign": len(benign),
        "false_positives": sum(r["outcome"] == "false_positive" for r in benign),
        "chains": len(chains),
        "chains_completed": sum(r["outcome"] in ("missed", "detected") for r in chains),
        "flow_benign": len(flow_benign),
        "flow_benign_approvals": sum(int(r.get("approvals", 0)) for r in flow_benign),
        "approvals": sum(int(r.get("approvals", 0)) for r in benign),
    }


def _frac(num: int, den: int) -> str:
    return f"{num} / {den}" if den else "n/a"


def _pct(num: int, den: int) -> str:
    return f"{100 * num / den:.1f}%" if den else "n/a"


def _latency(root: Path, layers: str) -> tuple[str, str]:
    report = _load(root / f"bench-{layers}" / "latency.json")
    if report is None:
        return "n/a", "n/a"
    rows = cast(list[dict[str, Any]], report["results"])
    row = next((r for r in rows if r["size"] == 1024), None)
    if row is None:
        return "n/a", "n/a"
    d, g = row["direct"], row["gatehouse"]
    return f"+{g['p50'] - d['p50']:.2f}", f"+{g['p95'] - d['p95']:.2f}"


def collate(root: Path) -> dict[str, Any]:
    reports = load_reports(root)
    summary: dict[str, dict[str, dict[str, Any]]] = {}
    for (target, layers, set_name), report in reports.items():
        key = target if target != "gatehouse" else f"gatehouse:{layers}"
        summary.setdefault(key, {})[set_name] = summarize(report)
    empty: dict[str, Any] = {}
    any_report = next(iter(reports.values()), empty)
    meta = cast(dict[str, Any], any_report.get("meta") or {})
    run_url = None
    if os.environ.get("GITHUB_RUN_ID"):
        run_url = (
            f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        )
    latency = {layers: _latency(root, layers) for layers in LAYERS}
    return {
        "meta": {
            "run": run_url,
            "commit": meta.get("git_commit"),
            "gatehouse_version": meta.get("gatehouse_version"),
            "python": meta.get("python"),
            "platform": meta.get("platform"),
            "generated_at": meta.get("generated_at"),
        },
        "summary": summary,
        "latency": {k: {"p50": v[0], "p95": v[1]} for k, v in latency.items()},
    }


def render(data: dict[str, Any]) -> str:
    m = data["meta"]
    s = cast(dict[str, dict[str, dict[str, Any]]], data["summary"])
    lines = [
        "# Evaluation v2",
        "",
        f"Workflow run: {m['run'] or '(local)'} · commit `{m['commit']}` · gatehouse "
        f"{m['gatehouse_version']} · Python {m['python']} · {m['platform']} · "
        f"{m['generated_at']}",
        "",
        "## Ablation (gatehouse layer combinations)",
        "",
        "Attacks prevented per set; chains completed are the `flow.*` exfiltration chains "
        "(lower is better); FP is benign scenarios changed, over all four sets; prompts are "
        "approval prompts per benign `flow.*` task and per benign scenario over all sets "
        "(the simulated user approves them); latency is the added round trip for a 1 KiB "
        "call.",
        "",
        "| Layers | Suite | Held-out v2 | MCPTox | egress-bench | Chains completed | FP | "
        "Prompts / flow task | Prompts / benign | p50 ms | p95 ms |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for layers in LAYERS:
        row = s.get(f"gatehouse:{layers}", {})
        cells = [_frac(row[k]["prevented"], row[k]["attacks"]) if k in row else "n/a" for k in SETS]
        suite = row.get("suite")
        chains = _frac(suite["chains_completed"], suite["chains"]) if suite else "n/a"
        fp = sum(v["false_positives"] for v in row.values())
        benign = sum(v["benign"] for v in row.values())
        appr = (
            f"{suite['flow_benign_approvals'] / suite['flow_benign']:.2f}"
            if suite and suite["flow_benign"]
            else "n/a"
        )
        prompts = sum(v["approvals"] for v in row.values())
        per_benign = f"{prompts / benign:.3f}" if benign else "n/a"
        p50, p95 = data["latency"][layers]["p50"], data["latency"][layers]["p95"]
        lines.append(
            f"| `{layers}` | {' | '.join(cells)} | {chains} | {_pct(fp, benign)} ({fp}) | "
            f"{appr} | {per_benign} | {p50} | {p95} |"
        )
    lines += [
        "",
        "## Comparison (same runner image, same commit)",
        "",
        "Prevented / detected only / missed, and false positives over benign scenarios.",
        "gatehouse is the `full` row.",
        "",
        "| Target | " + " | ".join(SET_TITLES[k] for k in SETS) + " | FP |",
        "|---|" + "---|" * (len(SETS) + 1),
    ]
    for target in TARGET_ORDER:
        row = s.get("gatehouse:full" if target == "gatehouse" else target)
        if not row:
            continue
        cells: list[str] = []
        for k in SETS:
            v = row.get(k)
            cells.append(f"{v['prevented']} / {v['detected_only']} / {v['missed']}" if v else "n/a")
        fp = sum(v["false_positives"] for v in row.values())
        benign = sum(v["benign"] for v in row.values())
        lines.append(f"| {target} | {' | '.join(cells)} | {_pct(fp, benign)} ({fp}/{benign}) |")
    return "\n".join(lines) + "\n"


def verdict_latency(root: Path) -> dict[str, Any]:
    """Classifier verdict latency from ``classifier.verdict`` events in the evidence of
    every ``gatehouse__<layers>__*`` report under ``root``.

    The bench can't measure a judge layer: once the judge withholds a few results the
    circuit breaker locks the session, and later calls never reach the model. Real
    verdicts from the scenario runs can, so this reads their LatencyMs."""
    by_layer: dict[str, list[float]] = {}
    errors: dict[str, int] = {}
    for events in sorted(root.glob("gatehouse__*__*/evidence/*/events.jsonl")):
        layers = events.parents[2].name.split("__")[1]
        for line in events.read_text(encoding="utf-8").splitlines():
            try:
                event = cast(dict[str, Any], json.loads(line))
            except ValueError:
                continue
            if event.get("EventType") != "classifier.verdict":
                continue
            latency = event.get("LatencyMs")
            if isinstance(latency, (int, float)):
                by_layer.setdefault(layers, []).append(float(latency))
            details = cast(dict[str, Any], event.get("Details") or {})
            if details.get("Error"):
                errors[layers] = errors.get(layers, 0) + 1
    out: dict[str, Any] = {}
    for layers, values in sorted(by_layer.items()):
        values.sort()

        def pct(q: float, v: list[float] = values) -> float:
            return round(v[min(len(v) - 1, int(q * len(v)))], 1)

        out[layers] = {
            "verdicts": len(values),
            "p50": pct(0.50),
            "p95": pct(0.95),
            "max": round(values[-1], 1),
            "errors": errors.get(layers, 0),
        }
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m attacks.evaluate")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collate")
    c.add_argument("root", type=Path)
    c.add_argument("--out", type=Path, required=True)
    v = sub.add_parser("verdict-latency", help="classifier verdict latency from evidence")
    v.add_argument("root", type=Path)
    args = p.parse_args(argv)
    if args.cmd == "verdict-latency":
        sys.stdout.write(json.dumps(verdict_latency(args.root), indent=2) + "\n")
        return 0
    data = collate(args.root)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "evaluation.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    md = render(data)
    (args.out / "evaluation.md").write_text(md, encoding="utf-8")
    sys.stderr.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
