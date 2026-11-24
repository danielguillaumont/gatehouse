# Evaluation

Every number on this page comes from a command in this repo. The run is recorded with its
commit, Python version, OS and date. CI reruns the attack suite and benchmark on every
push and posts the report in the job summary.

## Method

- **Scenarios:** `attacks/scenarios/*.yaml` holds 67 scenarios: 57 attacks and 10 benign.
  Each attack has a machine-checkable `success_if` (did the client see the poisoned tool,
  did the server receive the canary, ...). Each has a category, OWASP LLM 2025 and ATLAS
  2026.10 ids, and a `milestone`: the milestone whose detector should stop it, or
  `bypass` for documented limitations.
- **Mock server:** `attacks/mockserver.py` is raw JSON-RPC with no SDK, so scenarios can
  send things a well-behaved server never would (duplicate tool names, swaps in the
  middle of a session). It logs every frame it receives, so "did it reach the server" is
  measured on the server side, not inferred from gatehouse's own logs.
- **Baseline:** every run also uses the `direct` target (no proxy). An attack that doesn't
  succeed directly is a broken scenario and fails the run (D-025).
- **Benign set:** realistic traffic full of words that naive rules trip over:
  - "password reset", "IMPORTANT:" and "ignore the previous paragraph"
  - `rm -rf build/`, `curl` against an API
  - badge images, and code that talks about tokens
  - non-English text and emoji

  A false positive is *any* change to benign traffic: a hidden tool, a blocked call or an
  altered result. Alerts on benign traffic are counted separately as the alert rate.
- **Isolation:** each scenario runs with its own temporary HOME, state directory and pin
  store, and a fixed `AgentSessionId`.
- **Eval policy:** `attacks/policy-eval.yaml` is deliberately permissive (`default_action:
  allow`, `pinning: tofu`). A deny-by-default policy would "prevent" everything and
  measure nothing (D-024).
- **Canary check:** `python -m attacks canary-check` fails if any scenario's canary
  secret appears in gatehouse's events or stderr.

Outcomes:

- **prevented:** the attacker's goal was not reached
- **detected only:** the goal was reached, but gatehouse raised an alert
- **missed**

Metrics:

- recall = prevented / attacks
- precision = prevented / (prevented + benign false positives)

## Results: M2 (content detectors)

Command: `uv run python -m attacks run --target gatehouse --out reports/gatehouse`, at
gatehouse 0.1.0, commit `6ebeb53`, Python 3.12.2, Windows 11, run on 2026-11-24.

| Milestone | Attacks | Prevented | Detected only | Missed | Recall | Precision |
|---|---|---|---|---|---|---|
| mvp | 19 | 19 | 0 | 0 | 100% | 100% |
| m2 | 35 | 34 | 1 | 0 | 97% | 100% |
| bypass | 3 | 0 | 0 | 3 | 0% | n/a |

Benign: 10 scenarios, 0 false positives, 0 benign alerts. Canary check: 0 leaks. The
`direct` baseline: 57/57 attacks succeed and 10/10 benign scenarios pass.

| Category | Attacks | Prevented | Detected only | Missed | Notes |
|---|---|---|---|---|---|
| rug_pull | 6 | 6 | 0 | 0 | pinning; `rugpull.new-tool-added` needed D-023 |
| protocol | 3 | 3 | 0 | 0 | strict framing and the availability check |
| self_protection | 2 | 2 | 0 | 0 | |
| tool_poisoning | 8 | 8 | 0 | 0 | |
| sensitive_path | 7 | 7 | 0 | 0 | |
| secrets_in_args | 11 | 10 | 0 | 1 | miss: `split-across-arguments` (bypass) |
| injection_in_result | 8 | 7 | 0 | 1 | miss: `inject.result.paraphrased` (bypass) |
| dangerous_command | 8 | 7 | 0 | 1 | miss: `cmd.obfuscated-quotes` (bypass) |
| pii_in_args | 4 | 3 | 1 | 0 | `pii.email-bulk` is MEDIUM, so it is logged, not blocked |

The three misses are the scenarios marked `bypass`: each is a known limitation of
deterministic rules, written down in `docs/known-bypasses.md` before the detectors
existed. The bulk-email finding is detect-only by design: five addresses in one argument
is normal for a mailing tool, so it's evidence for a SOC rule, not a reason to block.

**How to read the high numbers.** I wrote both these scenarios and the detectors. The
numbers show the controls do what they claim on the attacks they were designed for. They
are not an estimate of performance on unseen attacks. Held-out variants written after the
detectors (M3) and `docs/known-bypasses.md` are the honest counterweight.

Earlier result (MVP, commit `f628387`): mvp 19/19 prevented, m2 0/35 (detectors not
built), the same benign result.

### Findings the suite produced

The suite found real bugs, which is the point of building it before claiming numbers:

- Under TOFU, a **new tool added to an already-trusted server** was silently trusted.
  Fixed by D-023.
- Two scenario canaries had the wrong length (GitHub token and Azure key) and the
  `unicode-tags` predicate could never match. These were scenario bugs, caught because
  the `direct` baseline must show every attack succeeding.

## Latency

Command: `uv run python -m bench.latency --out reports/bench` (default iterations), at
commit `6ebeb53`, Windows 11 AMD64, Python 3.12.2, run on 2026-11-24. Each call is one
`tools/call` round trip with an argument and a result of the given size, so the argument
detectors *and* the result detectors run on that many bytes. Times are in ms.

| Payload | direct p50 | gatehouse p50 | overhead p50 | overhead p95 | overhead p99 |
|---|---|---|---|---|---|
| 1 KiB | 0.23 | 3.33 | +3.10 | +4.35 | +5.21 |
| 100 KiB | 1.99 | 24.52 | +22.54 | +27.00 | +28.72 |
| 1 MiB | 25.98 | 241.29 | +215.30 | +258.83 | +281.96 |

- **The 1 KiB target is met.** `docs/PLAN.md` set p95 overhead under 5 ms at 1 KiB; this
  run measured 4.35 ms (the MVP run, with fewer detectors, measured 5.21 ms, so the
  difference between runs is mostly noise). The fixed cost per call is the extra process
  hop (two more pipe writes and reads, asyncio scheduling) and the two flushed JSONL event
  writes.
- **Large payloads cost more than in the MVP** (1 MiB: +215 ms against +148 ms), because
  the result is now scanned too and there are five more detectors.
- **Bottlenecks found and fixed with the benchmark:**
  - The first MVP run measured about 940 ms at 1 MiB: every secret regex scanned the
    whole payload. The keyword prefilter (D-026) cut that by about 6x.
  - The first M2 run measured +428 ms at 1 MiB. Three causes (D-029): a rule whose
    keyword ("tool") is everywhere in agent traffic, so its full regex always ran; card,
    IBAN and base64 patterns starting with a lookbehind, which Python evaluates at every
    position; and case-insensitive alternations at the start of a pattern. Splitting the
    rule, moving the boundary checks into validators and skipping digit-free text halved
    it.
- **Shared CI runners are noisy.** CI publishes its numbers, but they are not gated.

## Competitor comparison (M3)

The harness is target-agnostic (`attacks/targets.py`). gateward and mcp-watchdog are
defined as targets and run only in an isolated environment (D-021). Results will be
added here with the tool versions, configs and run date.
