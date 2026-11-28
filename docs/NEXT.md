# Status and next steps

Last updated **2026-11-28** (v0.2.0 released: M5 done; M6 next).

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
  - conformance (official MCP suite, direct vs through `gatehouse serve`; on proxy
    changes and weekly)

## v2 progress

### M4 → v0.2.0-alpha (done)

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

- **Streamable HTTP** (`gatehouse serve`, D-039, ADR-0003):
  - header/body consistency (-32020) and x-mcp-header enforcement;
  - upstream headers rebuilt from the inspected body, no token passthrough;
  - gatehouse-issued legacy session ids, Origin/Host checks, loopback by default;
  - gatehouse resumes closed upstream SSE streams itself.
- **HTTP scenarios** (`python -m attacks http`): all 6 attacks are prevented and both
  benign twins pass.
- **Acceptance** (`docs/evaluation.md#protocol-fidelity-m4`):
  - the official conformance suite passes through gatehouse on both wires (33/33 at
    2025-11-25, 40/40 at 2026-07-28), the same as direct;
  - Claude Code 2.1.332 works through gatehouse with a dual-era stdio server, a
    legacy-only stdio server and an HTTP server;
  - the v0.1 suite is unchanged.
- **Bugs those runs found, all fixed:**
  - era latching on a pipelined `initialize`;
  - approval state not bound to the server;
  - five HTTP divergences (listed in evaluation.md).
- **Docs:**
  - ADR-0002 (eras), ADR-0003 (HTTP), ADR-0004 (MRTR approval);
  - `docs/research/mcp-2026-intermediary-security.md`;
  - README.

### M5 → v0.2.0 (done)

Done:
1. **Policy engine v2** (`6cc11ff`, `825ed0a`, `b8e20c7`; D-040, D-041):
   - a `PolicyEngine` interface with Cedar (`cedarpy` 4.12.2) behind it. YAML compiles
     to Cedar, which is checked against the native reference on every decision and
     fails strict on any disagreement;
   - argument conditions;
   - capability labels;
   - `gatehouse policy compile` (schema and entities from pins) and `gatehouse policy
     prove`: a bounded check, plus Cedar `symcc` with cvc5 1.3.1 in the Linux CI job
     `policy-prove`. A deliberately broken policy fails it. symcc found a real gap
     (`mail/read_delete`) that the bounded check missed.
2. **Session flow control** (`6fd152e`; ADR-0005, D-042):
   - a SQLite WAL store keyed by `AgentSessionId`, with no lost updates across 48
     writer processes;
   - Rule-of-Two modes `monitor`, `approve` and `enforce`, emitting
     `flow.rule_of_two`;
   - fails closed on read and on write.
3. **Provenance** (`0310d45`; D-043):
   - winnowed, keyed span fingerprints of `private_data` results, checked against
     egress arguments, including their base64, hex and percent decodings;
   - emits `flow.provenance_match`;
   - does not catch paraphrases.

4. **Response controls** (`b1010a6`; ADR-0006, D-044):
   - kill switch (the `<state dir>/KILL` file, `gatehouse kill`, SIGUSR1);
   - circuit breaker (`gatehouse unlock`);
   - quarantine with `gatehouse review` (release is replayed on the identical call);
   - scoped grants (`gatehouse grant`), which answer policy and Rule-of-Two approvals
     only;
   - approval budget;
   - a self-protection rule against agents running these commands.
5. **Approval channels:** MRTR, then legacy elicitation, then block. This was already
   built in M4 and is documented in `docs/policy.md`.
6. **`flow.*` scenarios** (`21eeb08`; D-045): eight chains and six benign tasks, each
   server behind its own gatehouse process; `python -m attacks flow` runs them in CI.

Acceptance, all from GitHub Actions run
[46101039038](https://github.com/danielguillaumont/gatehouse/actions/runs/46101039038)
(commit `e5d7b7c`):
- **0/8 chains complete in approve and in enforce.** Monitor lets 6/8 through.
- **The README reports approvals per benign task:** 0.50 in approve mode.
- **No v0.1 regressions:** mvp 19/19, m2 34/35 plus 1 detected, held-out 6/18, m4 9/9.
- **`policy prove` fails CI on a broken policy:** the `policy-prove` job expects exit 1
  on `tests/policy/fixtures/policy-flow-broken.yaml`.
- **Latency, 1 KiB p95:** +1.98 ms with Cedar, +2.67 ms with flow control.

### M6 → v0.3.0 (next)

Evaluation first, then detectors. Heavy runs go in GitHub Actions, not locally.

1. Held-out v2: a mutation engine, frozen and hashed before any detector work.
2. External corpora: MCPTox and agent-egress-bench (check their licenses first).
3. A benign corpus of 200+ scenarios.
4. An ablation table.
5. Competitors re-run: gateward, mcp-watchdog, Pipelock strict, mcp-context-protector.
6. Optional: a live agent driven by Ollama.
7. Detectors:
   - an async detector interface;
   - Prompt Guard 2 (ONNX);
   - Prompt Shields;
   - an Ollama judge in shadow mode;
   - per-rule severity overrides;
   - the rule fixes listed below.

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
   - ~~hex decoding for secrets; base64 decoding for results~~ (M6, D-052)
   - per-rule severity overrides in the policy: fixes the two held-out false positives
     without a global `high: log`
   - ~~more destructive verbs (`find -delete`, `dd`, `mkfs`), credential-directory globs~~ (M6, D-052)
   - ~~scan numbers for PII; reference-style markdown images~~ (M6, D-052; card numbers only)
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
