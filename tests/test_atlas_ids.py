"""Every MITRE ATLAS ID used anywhere in the repo must exist in the release we cite.

Verified against ATLAS 2026.10 (mitre-atlas/atlas-data, dist/v6/ATLAS-2026.10.yaml,
modified 2026-10-28) on 2026-11-24. When upgrading, re-check the names and update
docs/threat-model.md together with this list.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATLAS_RELEASE = "2026.10"
KNOWN = {
    "AML.T0010.005": "Supply Chain Compromise: AI Agent Tool",
    "AML.T0029": "Denial of AI Service",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0098": "AI Agent Tool Credential Harvesting",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
    "AML.T0110": "AI Agent Tool Poisoning",
}
SCANNED = ["src", "attacks", "detections/rules", "docs/threat-model.md", "README.md"]


def _files() -> list[Path]:
    out: list[Path] = []
    for rel in SCANNED:
        p = ROOT / rel
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out += [f for f in p.rglob("*") if f.suffix in {".py", ".yaml", ".md"}]
    return out


def test_only_verified_atlas_ids_are_used() -> None:
    unknown: set[str] = set()
    for f in _files():
        for match in re.findall(r"AML\.T\d{4}(?:\.\d{3})?", f.read_text(encoding="utf-8")):
            if match not in KNOWN:
                unknown.add(f"{f.relative_to(ROOT)}: {match}")
    assert not unknown, sorted(unknown)
