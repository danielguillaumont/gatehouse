# Where work stopped and what's next

Last updated **2026-11-24**. Status: **MVP, M2, Sentinel integration and M3 evaluation
complete.** `docs/interview-guide.md` is written. What's left is optional.

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
- **Held-out set** (D-032): 18 attacks + 6 benign written after the detectors, not tuned
  on, not gated. gatehouse 6/18 prevented, 2/6 benign false positives.
- **Competitor comparison** (run `45507937200`, same runner and commit): held-out
  gatehouse 6/18, gateward 0.3.0 7/18, mcp-watchdog 0.1.9 1/18 + 9 alerted; benign FP 2,
  6, 0 of 16. Scoring adjustments (gateward's canary marker, watchdog's stderr alerts) are
  in `docs/evaluation.md`.
- **Pin store:** fixed lost updates under lock contention on Windows (a delete-pending
  lock file raises PermissionError, not FileExistsError).

## Next steps, in order

1. Optional improvements, each needing a **new** held-out set to measure (D-032):
   - hex decoding for secrets; base64 decoding for results
   - per-rule severity overrides in the policy (fixes the two held-out false positives
     without a global `high: log`)
   - more destructive verbs (`find -delete`, `dd`, `mkfs`), credential-directory globs
   - scan numbers for PII; reference-style markdown images
   - read gateward's SQLite audit log so its alerts can be scored
2. Deploy the Sentinel resources yourself (`docs/sentinel-setup.md`); nothing was deployed.

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
