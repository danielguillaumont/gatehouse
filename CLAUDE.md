# gatehouse: contributor and coding-agent guide

gatehouse is a detection-engineering and SOC layer for AI agent tool use over MCP. It's a
per-server stdio proxy that enforces a YAML policy and tool pinning, emits redacted,
SIEM-ready security events, and ships Microsoft Sentinel KQL analytics plus a measured
attack suite. Design and milestones: `docs/PLAN.md`. Architecture:
`docs/architecture.md`.

## Layout

- `src/gatehouse/`: `proxy/` (framing, router, stdio, approval), `policy/`, `inspect/`
  (detectors), `state/` (pin store), `events/` (schema, emitter, redaction, sinks), `cli.py`
- `attacks/`: target-agnostic attack suite (scenarios in YAML, harness, report)
- `detections/`: Sentinel rules, hunting queries, sample data, Kusto test runner
- `infra/`: Bicep generated from the tested detection sources
- `bench/`: latency benchmark · `demo/`: rug-pull demo · `tests/`

## Stack and commands

- Python 3.11–3.13, `uv`, src layout, Pydantic v2 for all data models, pytest, ruff,
  pyright (strict). The official `mcp` SDK is an exact-pinned **dev** dependency only.
- Must work on Windows and Linux. CI: ubuntu + windows, py3.11–3.13.

```
uv sync
uv run pytest -q                 # set GATEHOUSE_KUSTO_URL to include the KQL tests
uv run ruff check . && uv run ruff format --check .
uv run pyright
uv run python -m attacks run --target gatehouse --out reports/gatehouse
uv run python -m bench.latency
```

## Conventions

- Small, focused commits with clear messages. Tests, ruff and pyright pass before merge.
- Record every non-obvious design decision in `docs/decisions.md` (date, decision, why,
  alternatives).
- New detection logic comes with attack and benign scenarios in `attacks/scenarios/`.
  Don't tune rules against `attacks/scenarios/heldout.yaml` (D-032); a fix for a held-out
  miss needs a new held-out set to measure it.
- Azure resources are described in Bicep and compiled in CI; nothing in CI deploys them.

## Security invariants (non-negotiable)

- **Stdout carries only MCP protocol frames.** Log to stderr or files. No `print`.
- **Fail closed** by default (`docs/adr/0001-fail-closed.md`). Any fail-open path must
  emit `gatehouse.fail_open`.
- **Redact before logging.** Never put raw tool arguments, results or secrets into events;
  fingerprints use HMAC with a per-install key. The canary check must stay green.
- **Message-level proxying.** Forward unknown methods and fields unchanged; don't put
  back-to-back high-level `ClientSession`/`Server` objects in the data path.
- Detectors and the policy engine are pure functions (no I/O).
- Regexes must be ReDoS-safe and inputs size-bounded. Write regexes with an editor, not
  unquoted shell heredocs (`\b` becomes a backspace;
  `test_no_rule_contains_a_control_character` catches it).
- Event field names and types must match `detections/schema/GatehouseEvents_CL.json`.
- Test data uses synthetic canaries only. Real-looking new secrets fail the gitleaks
  workflow; reviewed fakes are pinned by fingerprint in `.gitleaksignore`.

## Claims hygiene

Anything in README, `docs/prior-art.md` or `docs/evaluation.md` must be reproducible from
the repo (command + version + date). Verify facts about other tools against their own
repositories and docs before stating them.
