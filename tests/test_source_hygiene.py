"""Source files contain no control characters other than tab, LF and CR.

Escapes typed through a shell can land as raw bytes: ``\\b`` as a backspace, ``\\x00`` as
a NUL. Python then compiles a different string than the one that was reviewed, and git
treats the file as binary, which hides it from diffs. The detector-rule check
(``test_no_rule_contains_a_control_character``) covers only rules; this covers the rest.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIRS = ("src", "tests", "attacks", "bench", "demo", "scripts", "detections", "infra", "docs")
SUFFIXES = {".py", ".yaml", ".yml", ".json", ".md", ".kql", ".bicep", ".toml"}
ALLOWED = {0x09, 0x0A, 0x0D}


def test_no_control_characters_in_sources() -> None:
    bad: list[str] = []
    for top in DIRS:
        base = ROOT / top
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in SUFFIXES or not path.is_file():
                continue
            if any(part in {"__pycache__", ".venv", "node_modules"} for part in path.parts):
                continue
            data = path.read_bytes()
            for i, byte in enumerate(data):
                if byte < 0x20 and byte not in ALLOWED:
                    line = data.count(b"\n", 0, i) + 1
                    bad.append(f"{path.relative_to(ROOT)}:{line}: byte 0x{byte:02x}")
                    break
    assert not bad, "\n".join(bad)
