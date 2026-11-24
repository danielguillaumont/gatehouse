"""AgentSessionId: a correlation key shared by every gatehouse wrapper under one agent.

Each MCP server gets its own gatehouse process, so cross-server analytics ("injection from
server A, then egress via server B") need a key all wrappers agree on without talking to
each other. The agent process (e.g. Claude Code) is their common ancestor: the id is a
hash of host + agent PID + agent start time (PIDs get reused; PID + start time does not).
Launcher processes between the agent and gatehouse (shells, uv, npx) are skipped.
"""

from __future__ import annotations

import hashlib
import os
import socket

import psutil

ENV_OVERRIDE = "GATEHOUSE_AGENT_SESSION_ID"

_LAUNCHERS = frozenset(
    {
        "cmd.exe", "cmd", "conhost.exe", "powershell.exe", "powershell", "pwsh.exe", "pwsh",
        "sh", "bash", "dash", "zsh", "fish", "env", "uv", "uv.exe", "uvx", "uvx.exe",
        "npx", "npx.cmd", "gatehouse", "gatehouse.exe", "timeout", "nohup", "sudo",
    }
)  # fmt: skip
MAX_HOPS = 8


def agent_session_id() -> str:
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        return override[:128]
    try:
        proc = psutil.Process().parent()
        hops = 0
        while proc is not None and proc.name().lower() in _LAUNCHERS and hops < MAX_HOPS:
            parent = proc.parent()
            if parent is None:
                break
            proc = parent
            hops += 1
        if proc is None:
            raise psutil.NoSuchProcess(os.getpid())
        material = f"{socket.gethostname()}|{proc.pid}|{proc.create_time():.3f}"
    except (psutil.Error, OSError):
        material = f"{socket.gethostname()}|orphan|{os.getpid()}"
    return hashlib.sha256(material.encode()).hexdigest()[:32]
