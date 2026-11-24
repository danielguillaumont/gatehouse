"""Generate the JSON that ``infra/main.bicep`` loads, from the repo's single sources:

* ``detections/schema/GatehouseEvents_CL.json`` -> ``infra/generated/columns.json``
  (table columns and DCR stream columns);
* ``detections/rules/*.yaml`` -> ``infra/generated/rules.json`` (Sentinel scheduled
  analytics rules in the ``Microsoft.SecurityInsights/alertRules`` shape).

Run ``uv run python -m detections.build_infra``. ``tests/detections/test_infra.py`` fails
if the generated files are stale, so the Bicep can't drift from the rules tested in Kusto.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "detections" / "schema" / "GatehouseEvents_CL.json"
RULES = ROOT / "detections" / "rules"
OUT = ROOT / "infra" / "generated"

_OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
# Logs Ingestion stream declarations accept these types; tables accept them too.
_TYPES = {"string", "int", "long", "real", "boolean", "datetime", "dynamic"}


def iso_duration(value: str) -> str:
    """'15m' -> 'PT15M', '1h' -> 'PT1H', '1d' -> 'P1D' (KQL/Sentinel YAML to ISO 8601)."""
    m = re.fullmatch(r"(\d{1,4})([mhd])", value.strip())
    if m is None:
        raise ValueError(f"unsupported duration {value!r}")
    n, unit = m.groups()
    return f"P{n}D" if unit == "d" else f"PT{n}{unit.upper()}"


def columns() -> list[dict[str, str]]:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    out: list[dict[str, str]] = []
    for col in schema["columns"]:
        if col["type"] not in _TYPES:
            raise ValueError(f"column {col['name']}: type {col['type']} not ingestible")
        out.append({"name": col["name"], "type": col["type"]})
    return out


def rule_properties(rule: dict[str, Any]) -> dict[str, Any]:
    techniques = [str(t) for t in rule.get("relevantTechniques", [])]
    props: dict[str, Any] = {
        "displayName": rule["name"],
        "description": str(rule["description"]).strip(),
        "severity": rule["severity"],
        "enabled": True,
        "query": str(rule["query"]).strip(),
        "queryFrequency": iso_duration(rule["queryFrequency"]),
        "queryPeriod": iso_duration(rule["queryPeriod"]),
        "triggerOperator": _OPERATORS[rule["triggerOperator"]],
        "triggerThreshold": int(rule["triggerThreshold"]),
        "suppressionDuration": "PT1H",
        "suppressionEnabled": False,
        "tactics": list(rule.get("tactics", [])),
        "techniques": sorted({t.split(".")[0] for t in techniques}),
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": True,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities",
                "groupByEntities": [],
                "groupByAlertDetails": [],
                "groupByCustomDetails": [],
            },
        },
    }
    sub = sorted(t for t in techniques if "." in t)
    if sub:
        props["subTechniques"] = sub
    for key in ("entityMappings", "customDetails", "alertDetailsOverride"):
        if key in rule:
            props[key] = rule[key]
    if "eventGroupingSettings" in rule:
        props["eventGroupingSettings"] = rule["eventGroupingSettings"]
    return props


def rules() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(RULES.glob("*.yaml")):
        rule = cast(dict[str, Any], yaml.safe_load(path.read_text(encoding="utf-8")))
        if rule.get("kind") != "Scheduled":
            raise ValueError(f"{path.name}: only Scheduled rules are supported")
        out.append({"id": rule["id"], "file": path.name, "properties": rule_properties(rule)})
    return out


def render() -> dict[str, str]:
    return {
        "columns.json": json.dumps(columns(), indent=2) + "\n",
        "rules.json": json.dumps(rules(), indent=2, ensure_ascii=False) + "\n",
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
        sys.stderr.write(f"wrote {OUT / name}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
