# Where work stopped and what's next

Last updated **2026-11-24**. Status: **MVP complete**; M2 (content detectors) started.

## State

- `uv run pytest -q`: all tests pass (1 expected xfail, the Cyrillic look-alike gap; 1
  skip, the Kusto test, which runs only when `GATEHOUSE_KUSTO_URL` is set).
- ruff and pyright (strict) are clean.
- CI jobs:
  - lint
  - tests (ubuntu 3.11/3.13, windows 3.12)
  - attack suite + benchmark
  - detections (Kusto emulator)

## Done since the last pause

- **Attack suite:** 67 scenarios (57 attacks, 10 benign), the harness, targets, reports,
  `canary-check`, and a CI job.
  - Results through gatehouse: 19/19 MVP attacks prevented, 0 false positives, 0 canary
    leaks.
  - The M2 categories still show 0% until their detectors exist.
- **TOFU** now trusts only a server's first listing (D-023, found by the suite).
- **Latency benchmark** (`bench/latency.py`). It found a scanning bottleneck, now fixed
  with a keyword prefilter (D-026).
  - Overhead at p50: about 3 ms for 1 KiB, 12 ms for 100 KiB and 100 ms for 1 MiB, on
    Windows.
- **`gatehouse.fail_open`** is now actually emitted when telemetry is lost (ADR-0001).
- **Detections:**
  - 5 Sentinel rules and 4 hunting queries
  - sample data generated from real sessions
  - Kusto-emulator validation (`python -m detections.kusto`) and a CI job (D-027)
- **Demo:** `demo/run_demo.py` (scripted), plus the Claude Code config and README.

## Next steps, in order

1. **M2 content detectors.** `inspect/invisible.py` is written but not wired or tested.
   Next: `poisoning.py`, `injection.py`, `commands.py`, `paths.py`, `pii.py`, plus the
   zero-width and base64 secret variants. Wire them in `inspect/pipeline.py`, run the
   attack suite, and keep benign false positives at 0.
2. **Elicitation approval:** make `RouterConfig.approver` non-blocking.
3. **Sentinel:** the Logs Ingestion sink (`sentinel` extra), Bicep (DCR, table, rules),
   `docs/sentinel-setup.md`, and a cross-server KQL rule (injection followed by egress).
4. **M3:**
   - held-out paraphrase scenarios
   - competitor runs (gateward, mcp-watchdog) in CI only
   - finalize `docs/prior-art.md` and `docs/evaluation.md`
   - `docs/interview-guide.md`
5. **Latency:** p95 overhead at 1 KiB is 5.2 ms against a 5 ms target. Profile the
   per-call event writes.

## Caveats

- In YAML, `pinning: off` must be quoted (`"off"`). Unquoted, it parses as `false` and the
  policy is rejected (fail closed).
- `ToolRisk` is a name heuristic.
- Local Kusto runs use port 18080 because 8080 was taken: `docker run -d --name gh-kusto
  -e ACCEPT_EULA=Y -p 18080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`.
