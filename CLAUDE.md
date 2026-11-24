# gatehouse

Detection-engineering / SOC layer for AI agent tool use over MCP: a per-server stdio proxy
that emits redacted, SIEM-ready security events, enforces a YAML policy and tool pinning,
and ships Microsoft Sentinel KQL analytics plus a measured attack suite.
Full plan, decisions and milestones: `docs/PLAN.md`.

## Working agreement

- Claude writes all code, tests, KQL, infrastructure and docs, and works through
  `docs/PLAN.md` milestone by milestone without waiting for approval.
- Every non-obvious decision is recorded in `docs/decisions.md` (date, decision, why,
  alternatives).
- Small, logical commits with clear messages; push after each milestone once tests, ruff
  and pyright pass. No AI/Claude attribution in commits or PRs.
- Azure/Sentinel resources are built (Bicep, KQL, sample data, `docs/sentinel-setup.md`)
  but never deployed.
- Stop and ask only for something irreversible, anything needing a password or payment,
  or anything that would make the repo public.

## Stack & commands

- Python, `uv`, src layout, Pydantic v2 for all data models, official `mcp` SDK
  (exact version pin), pytest, ruff, pyright.
- Must work on **Windows and Linux**. CI matrix: ubuntu + windows × py3.11–3.13.
- `uv sync` · `uv run pytest` · `uv run ruff check .` · `uv run pyright`

## Non-negotiable invariants

- **Stdout carries only MCP protocol frames.** All logging to stderr or files. No `print`.
- **Fail-closed** by default (see `docs/PLAN.md` §6 / ADR-0001). Any fail-open path must
  emit `gatehouse.fail_open`.
- **Redact before logging.** Never put raw tool arguments, results or secrets into events;
  fingerprints use HMAC with a per-install key. The canary test must stay green.
- **Message-level proxying.** Forward unknown methods/fields unchanged; don't use
  back-to-back high-level `ClientSession`/`Server`.
- Detectors and the policy engine are pure functions (no I/O).
- Regex patterns must be ReDoS-safe and inputs size-bounded.
- Event field names/types must match `detections/schema/GatehouseEvents_CL.json`.

## Claims hygiene

Anything in README, `docs/prior-art.md` or `docs/evaluation.md` must be reproducible from
the repo (command + version + date). Don't state facts about competing tools without
verifying them against their repos/docs.
