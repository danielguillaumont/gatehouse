"""Targets the suite can run against: how to wrap the mock server command.

* ``direct``    - no proxy. The baseline: every attack must succeed here, every benign
                  scenario must pass, otherwise the scenario itself is broken.
* ``gatehouse`` - ``gatehouse run`` with ``attacks/policy-eval.yaml``.
* ``mcp-watchdog`` / ``gateward`` - competitor gateways (M3). They are only used when the
  executable is on PATH; install them in an isolated venv or CI only (docs/decisions.md).
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MOCK_SERVER = ROOT / "mockserver.py"
EVAL_POLICY = ROOT / "policy-eval.yaml"
FLOW_POLICY = ROOT / "policy-flow.yaml"  # flow.* scenarios; FLOW_MODE is substituted


@dataclass(frozen=True)
class RunPaths:
    """Per-scenario state locations (all inside the scenario's temp directory)."""

    policy: Path
    pins: Path
    events_dir: Path


@dataclass(frozen=True)
class Target:
    name: str
    description: str
    emits_gatehouse_events: bool = False
    # A marker the target deliberately adds to every tool result (not a block or an
    # edit of the content). Stripped before benign results are compared, and counted.
    result_marker: str | None = None
    # For targets whose only alert channel is human-readable stderr: a regex whose matches
    # count as detections ("detected only" if the attack still succeeded).
    stderr_alert: str | None = None

    def available(self) -> bool:
        return True

    def argv(self, server_name: str, server_cmd: list[str], rp: RunPaths) -> list[str]:
        raise NotImplementedError


class Direct(Target):
    def argv(self, server_name: str, server_cmd: list[str], rp: RunPaths) -> list[str]:
        return server_cmd


class Gatehouse(Target):
    def argv(self, server_name: str, server_cmd: list[str], rp: RunPaths) -> list[str]:
        return [
            sys.executable,
            "-m",
            "gatehouse",
            "run",
            "--name",
            server_name,
            "--policy",
            str(rp.policy),
            "--pins",
            str(rp.pins),
            "--events-dir",
            str(rp.events_dir),
            "--",
            *server_cmd,
        ]


@dataclass(frozen=True)
class External(Target):
    """A competitor gateway invoked as ``<exe> <prefix...> <server cmd...>``."""

    exe: str = ""
    prefix: tuple[str, ...] = ()

    def available(self) -> bool:
        return shutil.which(self.exe) is not None

    def argv(self, server_name: str, server_cmd: list[str], rp: RunPaths) -> list[str]:
        found = shutil.which(self.exe)
        if found is None:
            raise RuntimeError(f"{self.exe} is not installed")
        return [found, *self.prefix, *server_cmd]


TARGETS: dict[str, Target] = {
    "direct": Direct("direct", "no proxy (baseline)"),
    "gatehouse": Gatehouse(
        "gatehouse", "gatehouse run, attacks/policy-eval.yaml", emits_gatehouse_events=True
    ),
    # Invocation verified against each project's README on 2026-11-24 (docs/prior-art.md).
    # mcp-watchdog prints alert panels ("CRITICAL [CMD-INJECT]") on stderr. LOW alerts are
    # excluded: a LOW "[ENTROPY] Unusual JSON nesting depth" fires on every session.
    "mcp-watchdog": External(
        "mcp-watchdog",
        "mcp-watchdog stdio wrapper",
        stderr_alert=r"\b(?:CRITICAL|HIGH|MEDIUM) \[[A-Z][A-Z_\- ]{1,30}\]",
        exe="mcp-watchdog",
        prefix=("--",),
    ),
    # gateward's rule 12 ("canary tripwire") appends <!-- gw:XXXXXXXX --> to every text
    # result to detect exfiltration of response data (src/gateward/canary.py, d2a65a4a81).
    "gateward": External(
        "gateward",
        "gateward stdio wrapper",
        result_marker=r"<!-- gw:[0-9a-f]{8} -->",
        exe="gateward",
        prefix=("run", "--"),
    ),
}


def server_command() -> list[str]:
    return [sys.executable, str(MOCK_SERVER)]
