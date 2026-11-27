# Status and next steps

Last updated **2026-11-27** (v0.1.0 released; v2 milestone M4 in progress).

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

## v2 progress (M4 → v0.2.0-alpha)

Built against MCP 2026-07-28 (spec commit `fdc75bd`, D-035). Claims in the v2 plan were
checked against primary sources first (`docs/research/landscape-2026-11.md`, D-037,
D-038).

Done:
- **stdio, both protocol eras** (D-036). Era latching; `server/discover` is inspected
  (version filter, instructions scan, ttl cap, downgrade pinning). `resultType` is
  validated. MRTR input requests and legacy server requests are inspected, and user
  answers are scanned for secrets. MRTR approval uses a signed, single-use
  `requestState`. gatehouse lists tools itself before a stateless call. Filtered
  listings become `cacheScope: private`, and subscription notifications are checked.
- **SDK interop** (`mcp` 2.3.0, `tests/integration/test_sdk_modern.py`):
  - `mode="auto"` negotiates 2026-07-28 through gatehouse;
  - legacy mode still works;
  - MRTR approval works with the stock SDK client.
- **Attack suite** (`attacks/scenarios/protocol_2026.yaml`, milestone `m4`): 9 attacks
  (downgrade ×2, MRTR phishing ×3, sampling injection, undeclared capability,
  public-cache rug pull, discover instructions) succeed without a proxy and are all
  prevented by gatehouse. All 6 benign twins pass. The v0.1 scenarios are unchanged.

Next in M4:
1. Streamable HTTP reverse proxy (`gatehouse serve --upstream`), with:
   - header/body consistency (-32020);
   - x-mcp-header inspection;
   - Origin checks;
   - no token passthrough.
   Plus its attack scenarios (header/body mismatch smuggling, x-mcp-header injection).
2. Conformance tests (official suite if one exists, else the SDK test servers), and a
   Claude Code 2.1.332 smoke test with a modern and a legacy server.
3. ADRs, `docs/research/mcp-2026-intermediary-security.md`, README, then tag
   v0.2.0-alpha.

## v0.1 milestone summary

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
2. Inspection of `resources/*` and `prompts/*` content (sampling and elicitation are
   inspected since M4).
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
