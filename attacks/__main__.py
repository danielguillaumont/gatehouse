"""Attack suite CLI.

    python -m attacks run --target gatehouse --out reports/gatehouse [--only ID ...]
    python -m attacks run --target direct --out reports/direct
    python -m attacks canary-check reports/gatehouse
    python -m attacks http --target gatehouse --out reports/gatehouse-http

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

from attacks.harness import load_scenarios, run_scenario
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
    for sc in load_scenarios(only=args.only or ()):
        if not sc.applies_to(target.name):
            continue
        obs = run_scenario(sc, target)
        res = judge(sc, obs)
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
    write_report(out, report)
    if args.summary:
        _err(render_markdown(report))
    # The held-out set (milestone m3) is a measurement, not a regression gate: gating on it
    # would push rules to be tuned against it, which is exactly what it exists to avoid
    # (D-032). A broken held-out scenario still fails.
    failures = [
        r
        for r in results
        if r.outcome == "broken"
        or (r.outcome == "false_positive" and r.milestone != "m3")
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


def cmd_canary_check(args: argparse.Namespace) -> int:
    root: Path = args.dir
    canaries = {sc.id: sc.canaries for sc in load_scenarios() if sc.canaries}
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
    r.add_argument("--summary", action="store_true", help="also print report.md to stderr")
    c = sub.add_parser("canary-check")
    c.add_argument("dir", type=Path)
    h = sub.add_parser("http", help="Streamable HTTP scenarios (attacks/http_scenarios.yaml)")
    h.add_argument("--target", choices=("direct", "gatehouse"), default="gatehouse")
    h.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    if args.cmd == "http":
        from attacks.http_suite import run as run_http

        return run_http(args.target, args.out)
    return cmd_run(args) if args.cmd == "run" else cmd_canary_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
