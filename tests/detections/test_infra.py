"""The Bicep's generated inputs match the schema and the rules tested in Kusto."""

from __future__ import annotations

import json
import re

import pytest

from detections.build_infra import OUT, iso_duration, render


def test_generated_infra_files_are_up_to_date() -> None:
    for name, text in render().items():
        on_disk = (OUT / name).read_text(encoding="utf-8")
        assert on_disk == text, (
            f"infra/generated/{name} is stale: run python -m detections.build_infra"
        )


@pytest.mark.parametrize(("raw", "iso"), [("15m", "PT15M"), ("1h", "PT1H"), ("1d", "P1D")])
def test_iso_duration(raw: str, iso: str) -> None:
    assert iso_duration(raw) == iso


def test_rules_have_valid_ids_and_techniques() -> None:
    rules = json.loads(render()["rules.json"])
    assert len({r["id"] for r in rules}) == len(rules)
    for rule in rules:
        assert re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", rule["id"])
        props = rule["properties"]
        assert all(re.fullmatch(r"T\d{4}", t) for t in props["techniques"])
        assert props["triggerOperator"] in {"GreaterThan", "LessThan", "Equal", "NotEqual"}


def test_bicep_loads_the_generated_files_and_the_verified_role() -> None:
    bicep = (OUT.parent / "main.bicep").read_text(encoding="utf-8")
    assert "loadJsonContent('generated/columns.json')" in bicep
    assert "loadJsonContent('generated/rules.json')" in bicep
    # Monitoring Metrics Publisher, verified against learn.microsoft.com on 2026-11-24
    assert "3913510d-42f4-4e42-8a64-420c390055eb" in bicep
