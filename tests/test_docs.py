"""Policy examples shown in the README and in demo/ must be valid policies."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from gatehouse.policy.loader import parse_policy

ROOT = Path(__file__).resolve().parents[1]


def _readme_policies() -> list[str]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    return [b for b in re.findall(r"```yaml\n(.*?)```", text, re.S) if "default_action" in b]


@pytest.mark.parametrize("block", _readme_policies())
def test_readme_policy_examples_are_valid(block: str) -> None:
    parse_policy(block)


@pytest.mark.parametrize("path", ["demo/policy.yaml", "attacks/policy-eval.yaml"])
def test_shipped_policies_are_valid(path: str) -> None:
    parse_policy((ROOT / path).read_text(encoding="utf-8"))
