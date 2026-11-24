# Where work stopped and what's next

Stopped on **2026-11-24**, partway through **MVP Day 6** of `docs/PLAN.md` (the attack suite).
Last code commit: `1a1999e`.

## State at the stop

`uv run pytest -q` gives 274 passed and 1 expected xfail (the Cyrillic look-alike gap).
`ruff format --check`, `ruff check` and `pyright` (strict) are all clean. These were run
locally on Windows. CI (`.github/workflows/ci.yml`) runs on Ubuntu 3.11, Ubuntu 3.13 and
Windows 3.12. The first CI run on GitHub had not been checked yet at the stop.

## Done (MVP Days 1–5)

- **Policy engine** (`src/gatehouse/policy/`): schema v1 with optional `pinning` and
  `findings` sections, the hardened YAML loader, precedence rules, and fail-closed
  behaviour. See `docs/policy.md`.
- **Events** (`src/gatehouse/events/`): the `SecurityEvent` schema, which is serialized
  in PascalCase to match `GatehouseEvents_CL`. Also redaction, HMAC fingerprints, JSONL,
  stderr and memory sinks, and the emitter.
  - The table schema `detections/schema/GatehouseEvents_CL.json` is generated from the
    model, and a test checks it against the model.
- **Detectors** (`src/gatehouse/inspect/`):
  - secret catalog
  - self-protection
  - tool-risk classification
  - tool-definition pinning
  - `pipeline.py`, the single place detectors are attached to interception points
- **Pin store** (`src/gatehouse/state/pinstore.py`): writes take a lock file and replace
  the file atomically.
- **Proxy** (`src/gatehouse/proxy/`): strict framing, the router (all decisions), the
  stdio transport, agent-session correlation, and the policy-file watcher.
- **CLI**: `gatehouse run | pin | diff | validate-policy | policy-hash | table-schema`.
  `src/gatehouse/client.py` is a raw MCP client shared by the CLI and the tests.
- **Docs**:
  - `docs/decisions.md` (D-001…D-022)
  - `docs/adr/0001-fail-closed.md`
  - `docs/prior-art.md` (competitors checked against their repos on 2026-11-24)
  - `docs/policy.md`
  - `docs/PLAN.md`

## In progress: attack suite (Day 6)

Written and committed, but not run by anything yet:
- `attacks/mockserver.py`: the scripted raw MCP server. It reads a spec from
  `$ATTACK_SPEC` and logs every frame it receives to `$ATTACK_LOG`.
- `attacks/scenarios/*.yaml`: pinning, secrets, protocol, self_protect and poisoning.
  All of them parse as YAML. None has been executed.

**Next steps, in order:**

1. **Write the rest of the scenarios:** `injection.yaml` (prompt injection in tool
   results, including `structuredContent`, markdown-image exfil URLs, HTML comments and
   fake role markers), `commands.yaml`, `paths.yaml`, `pii.yaml` and `benign.yaml`.
   - Make the benign set realistic, so it can catch false positives: words like
     "password reset" and "ignore the previous paragraph", "IMPORTANT:" in harmless tool
     descriptions, benign commands such as `git status` and `pytest -q`, and benign
     markdown images.
2. **Write `attacks/harness.py`:**
   - **Inputs:** load the scenarios. Each one has `server` or `phases`, `steps` (`list`,
     `call`, `raw`) and a `success_if` predicate: `client_saw_tool`, `client_saw_result`,
     `server_received` or `server_received_raw`.
   - **Per run:** each phase writes the spec JSON, sets `ATTACK_SPEC` and `ATTACK_LOG`,
     and launches the target through `gatehouse.client.StdioClient`.
   - **Sync after raw frames:** after a `raw` step, send a `ping` to resync the stream.
   - **Isolation:** each scenario gets its own temp `GATEHOUSE_HOME`, pin store, HOME and
     USERPROFILE. Set `GATEHOUSE_AGENT_SESSION_ID=eval-<id>`.
   - **Placeholders:** substitute `{policy_path}` and `{pins_path}` in arguments.
   - **Scope:** respect `targets:`, so self-protection scenarios run only against
     gatehouse.
   - **Benign scenarios:** count a false positive if a tool is hidden, a call is blocked,
     or a result is altered.
3. **Define the targets in `attacks/targets.py`:**
   - `gatehouse`, using a new eval policy `attacks/policy-eval.yaml` (`default_action:
     allow`, `pinning: tofu`).
   - `direct`, with no proxy. This is the baseline: every attack must succeed here, or
     the scenario is broken.
   - Later (M3): `mcp-watchdog -- <cmd>` and `gateward run -- <cmd>`. Install those only
     in CI or an isolated venv (D-021).
4. **Write `attacks/report.py`** to produce `report.json` and `report.md`.
   - Per scenario: whether the attack succeeded, and which detector caught it (from
     gatehouse events).
   - Per category: recall.
   - Overall: precision, recall and false-positive rate on the benign set.
   - Group the results by `milestone` (mvp, m2, bypass). Until the M2 detectors exist,
     the M2 categories are expected to show as missed.
5. **Write `attacks/__main__.py`** with two subcommands: `run --target X --out DIR`, and
   `canary-check DIR`, which fails if any `canaries:` value appears in the events or
   stderr.
6. **Check three things I haven't verified:**
   - `secrets.base64`: is the canary really `base64("AKIAZQ3CANARY7B64EX3")`?
   - `poison.unicode-tags`: the `success_if` substring `"\udb40"` is probably wrong.
     Check for the actual tag characters in the client's view.
   - `secrets.split-across-arguments`: its `milestone` should be `bypass`, not `m3`.
7. **Add tests for the suite:** `tests/attacks/`, with a fast smoke run of a few
   scenarios against `direct` and `gatehouse`.
8. **Add the CI job** for the attack suite and the benchmark. The TODO is in `ci.yml`.
   The job was never committed, so write it fresh. It should run the suite, append
   `report.md` to `$GITHUB_STEP_SUMMARY`, run `canary-check`, run the benchmark
   (informational only), and upload `reports/`.

## Rest of the MVP (Day 6–7)

- `bench/latency.py`: direct vs. through-gatehouse at 1 KB, 100 KB and 1 MB, reporting
  p50/p95/p99 (`docs/PLAN.md` §11). Add `bench` and `demo` back to pyright's `include`
  in `pyproject.toml`.
  - Integration tests take about 5 s each on Windows. Find out whether that's SDK import
    time or proxy shutdown.
- `detections/`:
  - 4–5 KQL rules in Sentinel analytics-rule YAML (`docs/PLAN.md` §12): rug pull,
    unpinned tool, secret sent to an egress tool, `policy.tampered` / `fail_open`, and a
    burst of blocked calls.
  - `sample_data/events.jsonl` generated from real attack-suite runs.
  - Expected results for each rule, and structural tests (columns exist in the schema,
    required rule fields present).
- `demo/`: Claude Code config plus `tests/servers/weather_server.py` with
  `WEATHER_POISONED=1` (pin, then rug pull, then blocked), with a recording script.
- Docs: `architecture.md`, `threat-model.md` (verify ATLAS IDs against the current
  release), `event-schema.md`, `evaluation.md`, `known-bypasses.md`.
- Rewrite `README.md`, which is still a stub.

## After the MVP

- **M2:** the content detectors (stubs in `inspect/pipeline.py`), elicitation approval
  (`RouterConfig.approver` is already wired; it needs a non-blocking task so the client
  loop isn't deadlocked), the Sentinel Logs Ingestion sink (the `sentinel` extra already
  exists), Bicep, `docs/sentinel-setup.md`, and cross-server KQL rules.
- **M3:** evaluation v1, the competitor runs, and `docs/interview-guide.md`.
- See `docs/PLAN.md` §13 for the full plan.

## Known caveats

- In YAML, `pinning: off` without quotes parses as the boolean `false`, and the policy
  is rejected (fail closed). Document `"off"` with quotes, or improve the error message.
- `ToolRisk` is a name-keyword heuristic, so it may misclassify tools (`run_query` is
  classified as exec).
