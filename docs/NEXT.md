# Where work stopped and what's next

Last updated **2026-11-24**. Status: **MVP, M2 (detectors, approval) and the Sentinel
integration complete**; next is M3 (evaluation and write-up).

## State

- `uv run pytest -q`: all tests pass (1 expected xfail, the Cyrillic look-alike gap in
  *policy name matching*, which the M2 confusable-name detector now covers; 1 skip, the
  Kusto test, which runs only when `GATEHOUSE_KUSTO_URL` is set).
- ruff and pyright (strict) are clean.
- CI jobs:
  - lint
  - tests (ubuntu 3.11/3.13, windows 3.12)
  - attack suite + benchmark
  - detections (Kusto emulator)
  - infra (Bicep compile; nothing deployed)

## Done since the last pause

- **M2 content detectors** (D-029), all pure functions in `src/gatehouse/inspect/`:
  - `poisoning.py` (tool definitions, including shadowing and mixed-script names)
  - `injection.py` (tool results: phrases, hidden HTML comments, image/URL beacons)
  - `commands.py`, `paths.py`, `pii.py` (arguments)
  - `invisible.py` (tags, bidi, zero-width)
  - secret scanning now also covers zero-width splits and base64
- **Attack suite through gatehouse** (commit `6ebeb53`): MVP 19/19 prevented; M2 34/35
  prevented plus 1 detected (bulk email, MEDIUM by design); the 3 `bypass` scenarios are
  missed, as documented; benign false positives 0/10; canary leaks 0.
- **Latency:** p95 overhead at 1 KiB is 4.35 ms (target 5 ms, met). 1 MiB costs +215 ms
  at p50; the first M2 run measured +428 ms and the regex fixes in D-029 halved it.
- **Elicitation approval** (D-030): `require_approval` calls ask the user through
  `elicitation/create`, off the client reader loop; fail-closed on anything but an explicit
  yes, and the tool list is re-checked after approval. Unit and end-to-end tests.
- **Sentinel** (D-031): Logs Ingestion sink (`gatehouse[sentinel]`), Bicep for table,
  DCE, DCR, role, onboarding and rules (generated from the tested YAML),
  `docs/sentinel-setup.md`, and cross-server rule GH006. 6/6 rules pass in Kusto.
  **Not deployed**: run the commands in `docs/sentinel-setup.md` in your subscription.
- **Pin store:** fixed lost updates under lock contention on Windows (a delete-pending
  lock file raises PermissionError, not FileExistsError).

## Next steps, in order

1. **M3:**
   - held-out paraphrase scenarios, written after the detectors
   - competitor runs (gateward, mcp-watchdog) in CI or an isolated venv only
   - finalize `docs/prior-art.md` and `docs/evaluation.md`
   - `docs/interview-guide.md`
2. **Docs touch-ups for M2:** README feature list and `docs/threat-model.md` coverage
   column should name the new detectors.

## Caveats

- In YAML, `pinning: off` must be quoted (`"off"`). Unquoted, it parses as `false` and the
  policy is rejected (fail closed).
- `ToolRisk` is a name heuristic.
- Local Kusto runs use port 18080 because 8080 was taken: `docker run -d --name gh-kusto
  -e ACCEPT_EULA=Y -p 18080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`.
- When editing regexes, prefer the Edit tool over shell heredocs: a `\b` inside an
  unquoted Python heredoc string becomes a backspace character.
  `tests/inspect/test_content_detectors.py::test_no_rule_contains_a_control_character`
  catches it.
