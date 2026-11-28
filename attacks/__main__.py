"""Attack suite CLI.

    python -m attacks run --target gatehouse --out reports/gatehouse [--only ID ...]
    python -m attacks run --target direct --out reports/direct
    python -m attacks run --scenarios attacks/heldout2/scenarios --out reports/heldout2
    python -m attacks canary-check reports/gatehouse
    python -m attacks http --target gatehouse --out reports/gatehouse-http
    python -m attacks flow --out reports/flow   # flow.* chains under every flow.mode

``run`` writes report.json, report.md, and the raw evidence (gatehouse events and stderr
per scenario) under --out. ``run`` exits 1 if the direct baseline shows a broken scenario
or (for gatehouse) an MVP attack is missed or a benign scenario is a false positive, so CI
fails on regressions. ``canary-check`` exits 1 if any scenario canary appears verbatim in
the saved events or stderr (redaction regression).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from attacks.harness import (
    FLOW_MODES,
    HELDOUT,
    SCENARIO_DIR,
    approvals_asked,
    load_scenarios,
    run_scenario,
)
from attacks.layers import LAYERS
from attacks.report import Result, build_report, judge, render_markdown, write_report
from attacks.targets import TARGETS


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def cmd_run(args: argparse.Namespace) -> int:
    target = TARGETS[args.target]
    if not target.available():
        _err(f"target {target.name} is not installed")
        return 2
    out: Path = args.out
    (out / "evidence").mkdir(parents=True, exist_ok=True)
    results: list[Result] = []
    for sc in load_scenarios(args.scenarios, only=args.only or ()):
        if not sc.applies_to(target.name):
            continue
        obs = run_scenario(sc, target, layers=args.layers)
        res = judge(sc, obs)
        res.approvals = approvals_asked(obs)
        results.append(res)
        evidence = out / "evidence" / _safe(sc.id)
        evidence.mkdir(exist_ok=True)
        (evidence / "events.jsonl").write_text(
            "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in obs.events),
            encoding="utf-8",
        )
        (evidence / "stderr.txt").write_text("".join(obs.stderr), encoding="utf-8")
        # What the client saw, to explain an outcome. Not a gatehouse log, so canary-check
        # skips it (an attack that succeeds is *supposed* to show its payload here).
        client_view = {"lists": obs.lists, "calls": obs.calls, "errors": obs.errors}
        (evidence / CLIENT_VIEW).write_text(
            json.dumps(client_view, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        _err(f"{res.outcome:15} {sc.id}  {', '.join(res.detections)}")
    report = build_report(target.name, results)
    report["meta"]["layers"] = args.layers
    scen: Path = args.scenarios.resolve()
    root = SCENARIO_DIR.parent.parent
    report["meta"]["scenarios"] = (
        scen.relative_to(root).as_posix() if scen.is_relative_to(root) else scen.name
    )
    write_report(out, report)
    if args.summary:
        _err(render_markdown(report))
    # The held-out sets (milestones m3 and m6) are a measurement, not a regression gate:
    # gating on them would push rules to be tuned against them, which is exactly what they
    # exist to avoid (D-032). A broken held-out scenario still fails.
    failures = [
        r
        for r in results
        if r.outcome == "broken"
        or (r.outcome == "false_positive" and r.milestone not in HELDOUT)
        or (target.name == "gatehouse" and r.milestone == "mvp" and r.outcome == "missed")
    ]
    if target.name == "direct":
        failures = [r for r in results if r.outcome in ("broken", "false_positive")]
    elif target.name != "gatehouse":
        failures = []  # competitors: informational only
    for r in failures:
        _err(f"FAIL {r.id}: {r.outcome}")
    return 1 if failures else 0


CLIENT_VIEW = "client.json"


def cmd_flow(args: argparse.Namespace) -> int:
    """Run the flow-policy scenarios under monitor, approve and enforce (D-045).

    Reports, per mode: chains that completed, benign tasks that passed, and the approval
    prompts each benign task needed. Exit 1 if a chain completes in approve or enforce,
    or a benign task fails in monitor or approve."""
    target = TARGETS["gatehouse"]
    scenarios = [sc for sc in load_scenarios() if sc.policy == "flow"]
    rows: list[dict[str, Any]] = []
    for mode in FLOW_MODES:
        for sc in scenarios:
            obs = run_scenario(sc, target, flow_mode=mode)
            res = judge(sc, obs)
            rows.append(
                {
                    "mode": mode,
                    "id": sc.id,
                    "expect": sc.expect,
                    "outcome": res.outcome,
                    "approvals": approvals_asked(obs),
                    "detections": res.detections,
                }
            )
            _err(f"{mode:8} {res.outcome:15} {approvals_asked(obs)} {sc.id}")
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    meta = build_report(target.name, [])["meta"]
    (out / "flow.json").write_text(json.dumps({"meta": meta, "rows": rows}, indent=1), "utf-8")
    md = _flow_markdown(rows, meta)
    (out / "flow.md").write_text(md, encoding="utf-8")
    _err(md)
    bad = [
        r
        for r in rows
        if (r["expect"] == "attack" and r["mode"] != "monitor" and r["outcome"] != "prevented")
        or (r["expect"] == "benign" and r["mode"] != "enforce" and r["outcome"] != "pass")
    ]
    for r in bad:
        _err(f"FAIL {r['mode']} {r['id']}: {r['outcome']}")
    return 1 if bad else 0


def _flow_markdown(rows: list[dict[str, Any]], meta: dict[str, Any]) -> str:
    lines = [
        f"Command: `python -m attacks flow`, gatehouse {meta.get('gatehouse_version')}, "
        f"commit `{meta.get('git_commit')}`, Python {meta.get('python')}, "
        f"{meta.get('platform')}, {meta.get('generated_at')}.",
        "",
        "| flow.mode | Chains completed | Benign tasks passed | Approvals (benign) | "
        "Approvals per benign task |",
        "|---|---|---|---|---|",
    ]
    for mode in FLOW_MODES:
        mine = [r for r in rows if r["mode"] == mode]
        attacks = [r for r in mine if r["expect"] == "attack"]
        benign = [r for r in mine if r["expect"] == "benign"]
        completed = sum(r["outcome"] != "prevented" for r in attacks)
        passed = sum(r["outcome"] == "pass" for r in benign)
        asked = sum(int(r["approvals"]) for r in benign)
        per = f"{asked / len(benign):.2f}" if benign else "n/a"
        lines.append(
            f"| {mode} | {completed} / {len(attacks)} | {passed} / {len(benign)} | "
            f"{asked} | {per} |"
        )
    lines += ["", "| Benign task | Approvals (approve mode) |", "|---|---|"]
    for r in rows:
        if r["mode"] == "approve" and r["expect"] == "benign":
            lines.append(f"| `{r['id']}` | {r['approvals']} |")
    return "\n".join(lines) + "\n"


def cmd_canary_check(args: argparse.Namespace) -> int:
    root: Path = args.dir
    canaries = {sc.id: sc.canaries for sc in load_scenarios(args.scenarios) if sc.canaries}
    leaks: list[str] = []
    for path in sorted((root / "evidence").glob("*/*")):
        if path.name == CLIENT_VIEW:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for sid, values in canaries.items():
            for value in values:
                if value in text:
                    leaks.append(f"{path}: canary of {sid}")
    for leak in leaks:
        _err(f"LEAK {leak}")
    _err(f"canary-check: {len(leaks)} leak(s) in {root}")
    return 1 if leaks else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m attacks")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--target", choices=sorted(TARGETS), default="gatehouse")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--only", nargs="*", help="scenario ids or id prefixes")
    r.add_argument(
        "--scenarios",
        type=Path,
        default=SCENARIO_DIR,
        help="scenario directory (held-out v2: attacks/heldout2/scenarios)",
    )
    r.add_argument("--summary", action="store_true", help="also print report.md to stderr")
    r.add_argument(
        "--layers",
        choices=sorted(LAYERS),
        help="ablation row: merge this layer combination into the policy (gatehouse only)",
    )
    c = sub.add_parser("canary-check")
    c.add_argument("dir", type=Path)
    c.add_argument("--scenarios", type=Path, default=SCENARIO_DIR)
    fl = sub.add_parser("flow", help="flow.* scenarios under monitor, approve and enforce")
    fl.add_argument("--out", type=Path, required=True)
    h = sub.add_parser("http", help="Streamable HTTP scenarios (attacks/http_scenarios.yaml)")
    h.add_argument("--target", choices=("direct", "gatehouse"), default="gatehouse")
    h.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    if args.cmd == "flow":
        return cmd_flow(args)
    if args.cmd == "http":
        from attacks.http_suite import run as run_http

        return run_http(args.target, args.out)
    return cmd_run(args) if args.cmd == "run" else cmd_canary_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
