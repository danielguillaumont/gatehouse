"""Run the analytics rules against the sample data in a Kusto engine (detection-as-code).

    docker run -d -e ACCEPT_EULA=Y -p 8080:8080 \
        mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
    uv run python -m detections.kusto --url http://localhost:8080

Uses the Kusto emulator ("Kustainer"), which runs the same KQL engine as Azure Data
Explorer and Log Analytics, so query syntax and semantics are checked for real. The client
uses only the standard library (urllib) and talks to the emulator's unauthenticated REST
API. Never point it at a production cluster.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parent
SCHEMA = ROOT / "schema" / "GatehouseEvents_CL.json"
SAMPLE = ROOT / "sample_data" / "events.jsonl"
RULES = ROOT / "rules"
HUNTING = ROOT / "hunting"
EXPECTED = ROOT / "expected.yaml"
DB = "NetDefaultDB"


class KustoError(RuntimeError):
    pass


@dataclass
class Kusto:
    url: str
    db: str = DB
    timeout: float = 60.0

    def _post(self, path: str, csl: str) -> dict[str, Any]:
        body = json.dumps({"db": self.db, "csl": csl}).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310 - URL is the local emulator given by the user
            self.url.rstrip("/") + path,
            data=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return cast(dict[str, Any], json.loads(resp.read().decode("utf-8")))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:2000]
            raise KustoError(f"{path} HTTP {exc.code}: {detail}") from None

    def mgmt(self, csl: str) -> list[dict[str, Any]]:
        return _rows(self._post("/v1/rest/mgmt", csl))

    def query(self, csl: str) -> list[dict[str, Any]]:
        return _rows(self._post("/v1/rest/query", csl))

    def wait_ready(self, seconds: float = 180.0) -> None:
        deadline = time.monotonic() + seconds
        last = ""
        while time.monotonic() < deadline:
            try:
                self.mgmt(".show version")
                return
            except (OSError, KustoError) as exc:
                last = str(exc)
                time.sleep(2)
        raise KustoError(f"Kusto at {self.url} not ready after {seconds}s: {last}")


def _rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    tables = cast(list[dict[str, Any]], payload.get("Tables") or [])
    if not tables:
        return []
    table = tables[0]
    cols = [str(c["ColumnName"]) for c in table["Columns"]]
    return [dict(zip(cols, row, strict=True)) for row in table["Rows"]]


def load_rules() -> dict[str, dict[str, Any]]:
    return {
        p.stem: cast(dict[str, Any], yaml.safe_load(p.read_text(encoding="utf-8")))
        for p in sorted(RULES.glob("*.yaml"))
    }


def create_table(k: Kusto) -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    name = schema["tableName"]
    cols = ", ".join(f"['{c['name']}']:{c['type']}" for c in schema["columns"])
    k.mgmt(f".drop table {name} ifexists")
    k.mgmt(f".create table {name} ({cols})")


def ingest_sample(k: Kusto, path: Path = SAMPLE) -> int:
    """Ingest via a datatable-free route: one .set-or-append per batch of JSON lines."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    name = schema["tableName"]
    lines = [x for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    mapping = json.dumps(
        [{"column": c["name"], "Properties": {"Path": f"$.{c['name']}"}} for c in schema["columns"]]
    )
    k.mgmt(f".create-or-alter table {name} ingestion json mapping 'gh' '{mapping}'")
    for start in range(0, len(lines), 50):
        batch = "\n".join(lines[start : start + 50])
        k.mgmt(
            f".ingest inline into table {name} with (format='multijson', "
            f"ingestionMappingReference='gh') <|\n{batch}"
        )
    count = k.query(f"{name} | count")
    return int(count[0]["Count"])


def _matches(row: dict[str, Any], want: dict[str, Any]) -> bool:
    return all(str(row.get(k)) == str(v) for k, v in want.items())


def check_rule(rows: list[dict[str, Any]], expected: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if "rows" in expected and len(rows) != int(expected["rows"]):
        problems.append(f"expected {expected['rows']} rows, got {len(rows)}")
    for want in cast(list[dict[str, Any]], expected.get("include") or []):
        if not any(_matches(r, want) for r in rows):
            problems.append(f"no row matches {want}")
    for r in rows:
        if str(r.get("AgentSessionId", "")).startswith("eval-benign"):
            problems.append(f"benign session in results: {r.get('AgentSessionId')}")
    return problems


def validate(k: Kusto) -> dict[str, list[str]]:
    create_table(k)
    n = ingest_sample(k)
    if n == 0:
        raise KustoError("sample ingestion produced 0 rows")
    expected = cast(dict[str, Any], yaml.safe_load(EXPECTED.read_text(encoding="utf-8")))
    results: dict[str, list[str]] = {}
    for rule_id, rule in load_rules().items():
        try:
            rows = k.query(str(rule["query"]))
        except KustoError as exc:
            results[rule_id] = [f"query failed: {exc}"]
            continue
        exp = expected.get(rule_id)
        results[rule_id] = ["no expectation in expected.yaml"] if exp is None else []
        if exp is not None:
            results[rule_id] = check_rule(rows, exp)
        sys.stderr.write(f"{rule_id}: {len(rows)} row(s) {results[rule_id] or 'OK'}\n")
    for path in sorted(HUNTING.glob("*.kql")):
        key = f"hunting/{path.stem}"
        try:
            rows = k.query(_strip_comments(path.read_text(encoding="utf-8")))
            exp = expected.get(key)  # optional for hunting queries
            results[key] = check_rule(rows, exp) if exp is not None else []
            sys.stderr.write(f"{key}: {len(rows)} row(s) {results[key] or 'OK'}\n")
        except KustoError as exc:
            results[key] = [f"query failed: {exc}"]
    return results


def _strip_comments(kql: str) -> str:
    return "\n".join(line for line in kql.splitlines() if not line.lstrip().startswith("//"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m detections.kusto")
    p.add_argument("--url", default="http://localhost:8080")
    p.add_argument("--wait", type=float, default=180.0, help="seconds to wait for Kusto")
    args = p.parse_args(argv)
    k = Kusto(args.url)
    k.wait_ready(args.wait)
    results = validate(k)
    failed = {r: v for r, v in results.items() if v}
    for rule_id, problems in failed.items():
        for problem in problems:
            sys.stderr.write(f"FAIL {rule_id}: {problem}\n")
    sys.stderr.write(f"{len(results) - len(failed)}/{len(results)} rules OK\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
