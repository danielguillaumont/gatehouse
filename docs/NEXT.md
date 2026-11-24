# Status and next steps

Last updated **2026-11-24** (v0.1.0).

## Status

MVP, M2, the Sentinel integration and the M3 evaluation are complete.

- `uv run pytest -q` passes. There's 1 expected xfail: the Cyrillic look-alike gap in
  *policy name matching*, which the M2 confusable-name detector covers. There's 1 skip:
  the Kusto test, which runs only when `GATEHOUSE_KUSTO_URL` is set.
- ruff and pyright (strict) are clean.
- CI jobs:
  - lint
  - tests (ubuntu 3.11/3.13, windows 3.12)
  - attack suite + benchmark
  - detections (Kusto emulator)
  - infra (Bicep compile)
  - gitleaks (full history)

## Milestone summary

- **M2 content detectors** (D-029), all pure functions in `src/gatehouse/inspect/`:
  - `poisoning.py` (tool definitions, including shadowing and mixed-script names)
  - `injection.py` (tool results: phrases, hidden HTML comments, image/URL beacons)
  - `commands.py`, `paths.py`, `pii.py` (arguments)
  - `invisible.py` (tags, bidi, zero-width)
  - secret scanning also covers zero-width splits and base64
- **Attack suite** through gatehouse: MVP 19/19 prevented; M2 34/35 prevented plus 1
  detected (bulk email, MEDIUM by design). The 3 `bypass` scenarios are missed, as
  documented. Canary leaks: 0.
- **Latency:** p95 overhead at 1 KiB is 4.35 ms (target 5 ms). 1 MiB costs +215 ms at
  p50. The regex fixes in D-029 halved an earlier +428 ms.
- **Elicitation approval** (D-030): `require_approval` calls ask the user through
  `elicitation/create`, off the client reader loop. Anything but an explicit yes fails
  closed, and the tool list is re-checked after approval.
- **Sentinel** (D-031):
  - Logs Ingestion sink (`gatehouse[sentinel]`)
  - Bicep for the table, DCE, DCR, role, onboarding and rules, generated from the tested
    YAML; see `docs/sentinel-setup.md`
  - cross-server rule GH006; all 6 rules pass in Kusto
  - **Not deployed to a live workspace.**
- **Held-out set** (D-032): 18 attacks and 6 benign scenarios, written after the
  detectors; not tuned on, not gated. gatehouse prevented 6/18, with 2/6 benign false
  positives.
- **Competitor comparison** (D-033, run `45507937200`, same runner and commit):
  - held-out attacks prevented: gatehouse 6/18, gateward 0.3.0 7/18, mcp-watchdog 0.1.9
    1/18 (+9 alerted)
  - benign false positives: 2, 6 and 0 of 16

## Next steps

1. Detection improvements. Each needs a **new** held-out set to measure it (D-032).
   - hex decoding for secrets; base64 decoding for results
   - per-rule severity overrides in the policy: fixes the two held-out false positives
     without a global `high: log`
   - more destructive verbs (`find -delete`, `dd`, `mkfs`), credential-directory globs
   - scan numbers for PII; reference-style markdown images
   - read gateward's SQLite audit log so its alerts can be scored
2. Streamable HTTP transport; inspection of `resources/*`, `prompts/*` and sampling.
3. Deploy the Sentinel resources to a test workspace and measure end-to-end ingestion
   latency (`docs/sentinel-setup.md`).

## Caveats

- In YAML, `pinning: off` must be quoted (`"off"`). Unquoted, it parses as `false` and the
  policy is rejected (fail closed).
- `ToolRisk` is a name heuristic.
- Local Kusto emulator: `docker run -d --name gh-kusto -e ACCEPT_EULA=Y -p 18080:8080
  mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`, then
  `uv run python -m detections.kusto --url http://localhost:18080 --wait 300`. Use any
  free host port.
