"""Targets the suite can run against: how to wrap the mock server command.

* ``direct``    - no proxy. The baseline: every attack must succeed here, every benign
                  scenario must pass, otherwise the scenario itself is broken.
* ``gatehouse`` - ``gatehouse run`` with ``attacks/policy-eval.yaml``.
* ``mcp-watchdog`` / ``gateward`` - competitor gateways (M3). They are only used when the
  executable is on PATH; install them in an isolated venv or CI only (docs/decisions.md).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

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

    def prepare(self, rp: RunPaths, env: dict[str, str]) -> None:
        """Called once per scenario, before the first phase starts (with its spec)."""

    def unwrap_results(self, calls: list[dict[str, Any]]) -> None:
        """Undo a target's documented result envelope before results are compared."""


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


@dataclass(frozen=True)
class Pipelock(External):
    """``pipelock mcp proxy --config <strict.yaml>`` (v3.8.0, D-051).

    Pipelock starts the server with a cleaned environment, so the harness variables are
    passed through with ``--env``. The config comes from ``$PIPELOCK_CONFIG``, generated
    with ``pipelock generate config --preset strict``.
    """

    def argv(self, server_name: str, server_cmd: list[str], rp: RunPaths) -> list[str]:
        found = shutil.which(self.exe)
        config = os.environ.get("PIPELOCK_CONFIG")
        if found is None or not config:
            raise RuntimeError("pipelock or $PIPELOCK_CONFIG is missing")
        passthrough = [
            a for v in ("ATTACK_SPEC", "ATTACK_LOG", "PYTHONIOENCODING") for a in ("--env", v)
        ]
        return [found, "mcp", "proxy", "--config", config, *passthrough, "--", *server_cmd]


@dataclass(frozen=True)
class ContextProtector(External):
    """mcp-context-protector at 05e56c1 (archived), without a guardrail provider (D-051).

    It needs every server configuration approved before use. ``prepare`` approves the
    first phase's configuration with the tool's own ``--review-server`` prompt (trust on
    first use, like gatehouse's ``tofu``), so later phases are checked against it. Its
    results come wrapped as ``{"status": "completed", "response": "..."}``;
    ``unwrap_results`` undoes only that envelope.
    """

    def argv(self, server_name: str, server_cmd: list[str], rp: RunPaths) -> list[str]:
        found = shutil.which(self.exe)
        if found is None:
            raise RuntimeError(f"{self.exe} is not installed")
        return [found, "--command-args", *server_cmd]

    def prepare(self, rp: RunPaths, env: dict[str, str]) -> None:
        argv = [*self.argv("srv", server_command(), rp)]
        argv.insert(1, "--review-server")
        subprocess.run(
            argv,
            input="y\n" * 64,
            env={**os.environ, **env},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def unwrap_results(self, calls: list[dict[str, Any]]) -> None:
        for call in calls:
            result = cast(dict[str, Any], call.get("response", {})).get("result")
            if not isinstance(result, dict):
                continue
            content = cast(list[Any], cast(dict[str, Any], result).get("content") or [])
            if len(content) != 1 or not isinstance(content[0], dict):
                continue
            text = cast(dict[str, Any], content[0]).get("text")
            try:
                inner = json.loads(text) if isinstance(text, str) else None
            except ValueError:
                continue
            if isinstance(inner, dict):
                envelope = cast(dict[str, Any], inner)
                if envelope.get("status") == "completed" and isinstance(
                    envelope.get("response"), str
                ):
                    content[0] = {"type": "text", "text": envelope["response"]}


# Pipelock's stderr lines for blocks and findings (internal/mcp/input.go, proxy.go,
# tools/tools.go at v3.8.0); chain detections that only warn are left out. Bounded.
_PIPELOCK_ALERT = (
    r"pipelock: (?:input line \d+: (?:blocked\b|warning — )"
    r"|line \d+: (?:prompt injection|inbound DLP|tool \"[^\"]{1,120}\": |tools/list cannot"
    r"|media policy blocked|blocking unparseable)"
    r"|chain detected: [\w-]{1,40} \(severity=\w+, action=block\)"
    r"|tool \"[^\"]{1,120}\" added post-baseline|session deny)"
)
# mcp-context-protector's logging lines (mcp_wrapper.py at 05e56c1). Bounded.
_CONTEXT_PROTECTOR_ALERT = (
    r"(?:WARNING|ERROR):mcp_wrapper:(?:Blocking tool '[^']{1,120}' - [^\n]{1,80}"
    r"|Configuration differences detected|Guardrail alert triggered for tool)"
    r"|INFO:mcp_wrapper:Server instructions have changed"
)


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
    # Invocations verified against each project's source on 2026-11-28 (D-051).
    "pipelock": Pipelock(
        "pipelock",
        "pipelock mcp proxy, strict preset (v3.8.0)",
        stderr_alert=_PIPELOCK_ALERT,
        exe="pipelock",
    ),
    "mcp-context-protector": ContextProtector(
        "mcp-context-protector",
        "mcp-context-protector (05e56c1), first configuration approved, no guardrail",
        stderr_alert=_CONTEXT_PROTECTOR_ALERT,
        exe="mcp-context-protector",
    ),
}


def server_command() -> list[str]:
    return [sys.executable, str(MOCK_SERVER)]
