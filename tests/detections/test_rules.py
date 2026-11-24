"""Analytics rules: structure always; real KQL execution when a Kusto emulator is up.

Set GATEHOUSE_KUSTO_URL (e.g. http://localhost:8080) to run the emulator tests; CI does
this in the `detections` job. Without it they are skipped, not faked.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

import pytest
import yaml

from detections.kusto import EXPECTED, SAMPLE, SCHEMA, Kusto, check_rule, load_rules, validate

ROOT = Path(__file__).resolve().parents[2]
SENTINEL_TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "Exfiltration",
    "CommandAndControl",
    "Impact",
}
REQUIRED = {
    "id",
    "name",
    "description",
    "severity",
    "queryFrequency",
    "queryPeriod",
    "triggerOperator",
    "triggerThreshold",
    "tactics",
    "relevantTechniques",
    "query",
    "entityMappings",
    "version",
    "kind",
}
RULES = load_rules()
COLUMNS = {c["name"] for c in json.loads(SCHEMA.read_text(encoding="utf-8"))["columns"]}


def test_there_are_rules_and_expectations_for_each() -> None:
    expected: dict[str, Any] = yaml.safe_load(EXPECTED.read_text(encoding="utf-8"))
    assert len(RULES) >= 5
    assert set(expected) == set(RULES)


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_structure(rule_id: str) -> None:
    rule = RULES[rule_id]
    assert REQUIRED <= set(rule), REQUIRED - set(rule)
    uuid.UUID(str(rule["id"]))
    assert rule["severity"] in {"Informational", "Low", "Medium", "High"}
    assert rule["kind"] == "Scheduled"
    assert set(rule["tactics"]) <= SENTINEL_TACTICS
    for t in rule["relevantTechniques"]:
        assert re.fullmatch(r"T\d{4}", t), t  # Sentinel accepts parent techniques here
    assert re.fullmatch(r"\d+[mhd]", rule["queryFrequency"])
    assert re.fullmatch(r"\d+\.\d+\.\d+", str(rule["version"]))
    assert "GatehouseEvents_CL" in rule["query"]


def test_rule_ids_are_unique() -> None:
    ids = [r["id"] for r in RULES.values()]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_filter_columns_exist_in_schema(rule_id: str) -> None:
    """Every column a rule filters on with `where X ==/in` must exist in the table, or be
    defined earlier in the query (`project Alias = Column`, `summarize Alias = ...`)."""
    query = RULES[rule_id]["query"]
    aliases = set(re.findall(r"\b([A-Z][A-Za-z0-9]+)\s*=(?!=)", query))
    for col in re.findall(r"\b([A-Z][A-Za-z0-9]+)\s*(?:==|!=|\bin\b|has\b)", query):
        assert col in COLUMNS or col in aliases, f"{rule_id}: unknown column {col}"


def test_sample_data_matches_schema_and_has_no_local_details() -> None:
    text = SAMPLE.read_text(encoding="utf-8")
    for line in text.splitlines():
        record = json.loads(line)
        assert set(record) == COLUMNS
    home = str(Path.home())
    assert home not in text and home.replace("\\", "/").lower() not in text.lower()


def test_check_rule_reports_mismatches() -> None:
    rows = [{"ToolName": "a", "AgentSessionId": "eval-benign.x"}]
    problems = check_rule(rows, {"rows": 2, "include": [{"ToolName": "b"}]})
    assert len(problems) == 3


KUSTO_URL = os.environ.get("GATEHOUSE_KUSTO_URL")


@pytest.mark.skipif(not KUSTO_URL, reason="set GATEHOUSE_KUSTO_URL to run rules in Kusto")
def test_rules_return_expected_rows_in_kusto() -> None:
    assert KUSTO_URL is not None
    k = Kusto(KUSTO_URL)
    k.wait_ready(120)
    results = validate(k)
    assert results and all(not v for v in results.values()), results
