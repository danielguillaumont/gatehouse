"""Detect tool calls that reference gatehouse's own policy, pins, key or logs.

An agent with a filesystem or shell tool could otherwise weaken its own guardrails
(edit the policy, delete pins, wipe the event log). MITRE ATT&CK T1562.001 (Impair
Defenses: Disable or Modify Tools).
"""

from __future__ import annotations

import os
import posixpath
from collections.abc import Iterable, Mapping
from pathlib import Path

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.walk import WalkStats, iter_strings

DETECTOR_ID = "args.self_protect"


def _norm(text: str) -> str:
    s = text.replace("\\", "/").casefold()
    while "//" in s:
        s = s.replace("//", "/")
    return s


def _normpath(text: str) -> str:
    """Collapse ``.`` and ``..`` segments so traversal can't hide a protected path."""
    s = _norm(text)
    if "/." not in s and "./" not in s:
        return s
    return posixpath.normpath(s)


def protected_variants(
    paths: Iterable[Path], env: Mapping[str, str] | None = None
) -> tuple[str, ...]:
    """All spellings of the protected paths worth matching, normalized.

    Computed once at startup (reads the environment); the detector itself stays pure.
    """
    env = env if env is not None else os.environ
    variants: set[str] = set()
    bases: list[tuple[str, str]] = []  # (absolute base, how it can be spelled)
    home = str(Path.home())
    bases += [(home, "~"), (home, "$HOME"), (home, "${HOME}"), (home, "%USERPROFILE%")]
    for var in ("LOCALAPPDATA", "APPDATA", "XDG_STATE_HOME", "GATEHOUSE_HOME"):
        if env.get(var):
            bases += [(env[var], f"%{var}%"), (env[var], f"${var}"), (env[var], f"${{{var}}}")]
    for path in paths:
        absolute = _norm(str(path.expanduser().absolute()))
        variants.add(absolute)
        # Windows drive-less form, e.g. /users/x/appdata/local/gatehouse/pins.json
        if len(absolute) > 2 and absolute[1] == ":":
            variants.add(absolute[2:])
        for base, spelled in bases:
            nbase = _norm(base).rstrip("/")
            if absolute.startswith(nbase + "/"):
                variants.add(_norm(spelled) + absolute[len(nbase) :])
    return tuple(sorted(v for v in variants if len(v) > 3))


def detect_self_protect(
    arguments: object, protected: tuple[str, ...], stats: WalkStats | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    if not protected:
        return findings
    for where, text in iter_strings(arguments, "arguments", stats, include_keys=False):
        candidate = _normpath(text)
        for p in protected:
            if p in candidate:
                findings.append(
                    Finding(
                        detector_id=DETECTOR_ID,
                        rule_id="gatehouse-protected-path",
                        severity=Severity.HIGH,
                        summary=f"argument references a gatehouse-protected path ({p})",
                        location=where,
                        mitre=("AML.T0081", "T1562.001"),
                        owasp=("LLM06",),
                    )
                )
                break
    return findings
