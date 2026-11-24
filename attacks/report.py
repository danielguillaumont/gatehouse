"""Turn per-scenario observations into report.json + report.md.

Outcomes
--------
attack scenarios:  ``prevented`` (attack goal not reached) | ``detected`` (reached, but the
                   target raised an alert) | ``missed`` | ``broken`` (direct baseline only:
                   the attack did not even work without a proxy, so the scenario is wrong)
benign scenarios:  ``pass`` | ``false_positive`` (target hid a tool, blocked a call or
                   altered a result). Alerts on benign traffic are counted separately.

Metrics (per milestone group and per category)
----------------------------------------------
* recall          = prevented / attacks
* detection rate  = (prevented + detected) / attacks
* precision       = prevented / (prevented + benign false positives)
* FP rate         = benign false positives / benign scenarios
* alert rate      = benign scenarios with any alert / benign scenarios
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attacks.harness import (
    MILESTONES,
    Observation,
    Scenario,
    attack_succeeded,
    benign_interference,
    detections,
    prevented_by,
)
from gatehouse import __version__


@dataclass
class Result:
    id: str
    category: str
    milestone: str
    expect: str
    title: str
    outcome: str
    detections: list[str] = field(default_factory=list[str])
    prevented_by: list[str] = field(default_factory=list[str])
    notes: list[str] = field(default_factory=list[str])
    owasp: list[str] = field(default_factory=list[str])
    atlas: list[str] = field(default_factory=list[str])
    duration_s: float = 0.0


def judge(sc: Scenario, obs: Observation) -> Result:
    dets = detections(obs)
    base: dict[str, Any] = {
        "id": sc.id,
        "category": sc.category,
        "milestone": sc.milestone,
        "expect": sc.expect,
        "title": sc.title,
        "detections": dets,
        "prevented_by": prevented_by(obs),
        "owasp": sc.owasp,
        "atlas": sc.atlas,
        "duration_s": obs.duration_s,
    }
    if sc.benign:
        problems = benign_interference(sc, obs)
        notes = list(problems)
        if obs.markers_stripped:
            notes.append(
                f"{obs.markers_stripped} target result marker(s) stripped before comparing"
            )
        return Result(outcome="false_positive" if problems else "pass", notes=notes, **base)
    succeeded = attack_succeeded(sc, obs)
    if obs.target == "direct":
        outcome = "missed" if succeeded else "broken"
    elif not succeeded:
        outcome = "prevented"
    elif dets:
        outcome = "detected"
    else:
        outcome = "missed"
    return Result(outcome=outcome, notes=list(obs.errors), **base)


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def metrics(results: list[Result]) -> dict[str, Any]:
    attacks = [r for r in results if r.expect == "attack"]
    benign = [r for r in results if r.expect == "benign"]
    prevented = sum(r.outcome == "prevented" for r in attacks)
    detected = sum(r.outcome == "detected" for r in attacks)
    fps = sum(r.outcome == "false_positive" for r in benign)
    alerts = sum(bool(r.detections) for r in benign)
    return {
        "attacks": len(attacks),
        "prevented": prevented,
        "detected_only": detected,
        "missed": sum(r.outcome == "missed" for r in attacks),
        "broken": sum(r.outcome == "broken" for r in attacks),
        "recall": _ratio(prevented, len(attacks)),
        "detection_rate": _ratio(prevented + detected, len(attacks)),
        "precision": _ratio(prevented, prevented + fps),
        "benign": len(benign),
        "false_positives": fps,
        "fp_rate": _ratio(fps, len(benign)),
        "benign_alerts": alerts,
        "alert_rate": _ratio(alerts, len(benign)),
    }


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def build_report(target: str, results: list[Result]) -> dict[str, Any]:
    benign = [r for r in results if r.expect == "benign"]
    by_milestone: dict[str, Any] = {}
    for m in MILESTONES:
        subset = [r for r in results if r.expect == "attack" and r.milestone == m]
        if subset:
            by_milestone[m] = metrics(subset + benign)
    by_category: dict[str, list[Result]] = defaultdict(list)
    for r in results:
        if r.expect == "attack":
            by_category[r.category].append(r)
    return {
        "meta": {
            "target": target,
            "gatehouse_version": __version__,
            "git_commit": _git_commit(),
            "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.release()}",
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "command": " ".join(["python", "-m", "attacks", *sys.argv[1:]]),
        },
        "overall": metrics(results),
        "by_milestone": by_milestone,
        "by_category": {c: metrics(rs + benign) for c, rs in sorted(by_category.items())},
        "results": [r.__dict__ for r in results],
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


_ICON = {
    "prevented": "prevented",
    "detected": "detected only",
    "missed": "**missed**",
    "broken": "**BROKEN**",
    "pass": "pass",
    "false_positive": "**false positive**",
}


def render_markdown(report: dict[str, Any]) -> str:
    meta = report["meta"]
    lines = [
        f"# Attack suite report: `{meta['target']}`",
        "",
        f"gatehouse {meta['gatehouse_version']} @ `{meta['git_commit']}` · Python "
        f"{meta['python']} · {meta['platform']} · {meta['generated_at']}",
        "",
        f"Reproduce: `uv run {meta['command']}`",
        "",
        "## Summary by milestone",
        "",
        "Milestone = when the detector for that scenario is planned. `bypass` scenarios are "
        "known limitations (see docs/known-bypasses.md); misses there are expected.",
        "",
        "| Milestone | Attacks | Prevented | Detected only | Missed | Recall | Precision |",
        "|---|---|---|---|---|---|---|",
    ]
    for m, s in report["by_milestone"].items():
        lines.append(
            f"| {m} | {s['attacks']} | {s['prevented']} | {s['detected_only']} | "
            f"{s['missed']} | {_pct(s['recall'])} | {_pct(s['precision'])} |"
        )
    o = report["overall"]
    lines += [
        "",
        f"Benign scenarios: {o['benign']} · false positives (traffic changed): "
        f"{o['false_positives']} ({_pct(o['fp_rate'])}) · benign scenarios with an alert: "
        f"{o['benign_alerts']} ({_pct(o['alert_rate'])})",
        "",
        "## By category",
        "",
        "| Category | Attacks | Prevented | Detected only | Missed | Recall |",
        "|---|---|---|---|---|---|",
    ]
    for c, s in report["by_category"].items():
        lines.append(
            f"| {c} | {s['attacks']} | {s['prevented']} | {s['detected_only']} | "
            f"{s['missed']} | {_pct(s['recall'])} |"
        )
    lines += [
        "",
        "## Scenarios",
        "",
        "| Scenario | Milestone | Outcome | Caught by |",
        "|---|---|---|---|",
    ]
    for r in report["results"]:
        caught = ", ".join(f"`{d}`" for d in r["detections"]) or ""
        note = f" ({'; '.join(r['notes'])})" if r["notes"] else ""
        lines.append(f"| `{r['id']}` | {r['milestone']} | {_ICON[r['outcome']]}{note} | {caught} |")
    return "\n".join(lines) + "\n"


def write_report(out: Path, report: dict[str, Any]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
