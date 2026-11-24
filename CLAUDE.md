# gatehouse

Detection-engineering / SOC layer for AI agent tool use over MCP: a per-server stdio proxy
that emits redacted, SIEM-ready security events, enforces a YAML policy and tool pinning,
and ships Microsoft Sentinel KQL analytics plus a measured attack suite.
Full plan, decisions and milestones: `docs/PLAN.md`.

## Ownership — read before writing code

This is a learning/portfolio project. The owner writes some modules by hand.

- **Owner writes (do NOT implement; explain, review, suggest tests, answer questions only):**
  - `src/gatehouse/inspect/pinning.py` (canonical hashing, pin compare, diff)
  - `detections/rules/*.yaml` and `detections/hunting/*.kql` (KQL rules)
- **Paired (propose small steps, let the owner drive; no large drops):**
  - `src/gatehouse/proxy/router.py`, `src/gatehouse/proxy/session.py`
- **Claude writes, then teaches (owner approves the design first, reviews the code, and
  must be able to explain it):**
  - `src/gatehouse/policy/` (models, loader, engine: decision logic and precedence).
    The policy schema needs the owner's approval before implementation.
- **Generate freely (owner reviews):** scaffold, CI, Pydantic models (after the owner
  designs the schema), CLI, sinks, redactor, secret catalog, mock servers, harness,
  report, benchmark, demo, docs.

Keep commits small and incremental. Never bulk-generate into an owner-written module.

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
