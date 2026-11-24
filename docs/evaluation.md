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

## Results: MVP

Command: `uv run python -m attacks run --target gatehouse --out reports/gatehouse`, at
gatehouse 0.1.0, commit `f628387`, Python 3.12.2, Windows 11, run on 2026-11-24.

| Milestone | Attacks | Prevented | Detected only | Missed | Recall | Precision |
|---|---|---|---|---|---|---|
| mvp | 19 | 19 | 0 | 0 | 100% | 100% |
| m2 | 35 | 0 | 0 | 35 | 0% | n/a |
| bypass | 3 | 0 | 0 | 3 | 0% | n/a |

Benign: 10 scenarios, 0 false positives, 0 benign alerts. Canary check: 0 leaks. The
`direct` baseline: 57/57 attacks succeed and 10/10 benign scenarios pass.

| Category | Attacks | Prevented | Missed | Recall | Notes |
|---|---|---|---|---|---|
| rug_pull | 6 | 6 | 0 | 100% | pinning; `rugpull.new-tool-added` needed D-023 |
| protocol | 3 | 3 | 0 | 100% | strict framing and the availability check |
| self_protection | 2 | 2 | 0 | 100% | |
| secrets_in_args | 11 | 8 | 3 | 73% | the 3 misses are `zero-width-split`, `base64` (M2) and `split-across-arguments` (bypass) |
| tool_poisoning, injection_in_result, dangerous_command, sensitive_path, pii_in_args | 35 | 0 | 35 | 0% | M2 detectors not built yet |

**How to read the 100%.** I wrote both these scenarios and the detectors. The numbers
show the MVP controls do what they claim on the attacks they were designed for. They are
not an estimate of performance on unseen attacks. Held-out variants written after the
detectors (M3) and `docs/known-bypasses.md` are the honest counterweight.

### Findings the suite produced

The suite found real bugs, which is the point of building it before claiming numbers:

- Under TOFU, a **new tool added to an already-trusted server** was silently trusted.
  Fixed by D-023.
- Two scenario canaries had the wrong length (GitHub token and Azure key) and the
  `unicode-tags` predicate could never match. These were scenario bugs, caught because
  the `direct` baseline must show every attack succeeding.

## Latency

Command: `uv run python -m bench.latency --iterations 300`, at commit `f628387`, Windows
11 AMD64, Python 3.12.2, run on 2026-11-24. Each call is one `tools/call` round trip with
an argument and a result of the given size, so the argument detectors run on that many
bytes. 300 calls per size (75 at 1 MiB) after 5 warm-up calls. Times are in ms.

| Payload | direct p50 | gatehouse p50 | overhead p50 | overhead p95 | overhead p99 |
|---|---|---|---|---|---|
| 1 KiB | 0.30 | 3.62 | +3.32 | +5.21 | +7.07 |
| 100 KiB | 2.83 | 14.69 | +11.85 | +18.42 | +23.93 |
| 1 MiB | 34.60 | 182.81 | +148.21 | +312.16 | +398.22 |

- **Target missed, narrowly.** `docs/PLAN.md` set a target of p95 overhead under 5 ms at
  1 KiB; this run measured 5.21 ms.
  - Most of the fixed cost per call is the extra process hop: two more pipe writes and
    reads, plus asyncio scheduling.
  - The rest is the two events written per call. Each JSONL write is flushed, so events
    survive a crash.
  - Profiling and batching the event writes is on the list.
- **A big bottleneck was found and fixed.** The first benchmark run measured about
  940 ms at 1 MiB, because every secret regex scanned the whole payload. The keyword
  prefilter (D-026) cut that by about 6x. The variance at 1 MiB (p95 roughly 2x p50) is
  mostly GC and pipe buffering; 1 MiB tool calls are rare in practice.
- **Shared CI runners are noisy.** CI publishes its numbers, but they are not gated.

## Competitor comparison (M3)

The harness is target-agnostic (`attacks/targets.py`). gateward and mcp-watchdog are
defined as targets and run only in an isolated environment (D-021). Results will be
added here with the tool versions, configs and run date.
