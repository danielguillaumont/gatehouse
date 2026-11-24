# Evaluation

Every number on this page comes from a command in this repo. The run is recorded with its
commit, Python version, OS and date. CI reruns the attack suite and benchmark on every
push and posts the report in the job summary.

## Method

- **Scenarios:** `attacks/scenarios/*.yaml` holds 91 scenarios: 75 attacks and 16 benign
  (the held-out set adds 18 and 6).
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

## Results: held-out set (M3)

`attacks/scenarios/heldout.yaml` holds 18 attacks and 6 benign scenarios. I wrote them on
2026-11-24, after the M2 detectors, phrased the way an attacker or a real tool would
phrase things, and **did not change any rule afterwards** (D-032). They are reported, not
gated: CI doesn't fail on them, because a gate would push rules to be tuned against them.

Command: `uv run python -m attacks run --target gatehouse --out reports/gatehouse`, at
commit `d4de1b5`, Python 3.12.2, Windows 11, run on 2026-11-24. The `direct` baseline:
18/18 held-out attacks succeed and all 6 benign scenarios pass.

| Category | Attacks | Prevented | Missed | Caught | Missed scenarios |
|---|---|---|---|---|---|
| injection_in_result | 7 | 1 | 6 | `structured-field` | polite request, `[SYSTEM]:` prefix, markdown link, French, base64, reference-style image |
| tool_poisoning | 3 | 1 | 2 | `schema-default` | "REQUIRED:" step, "supersedes" shadowing |
| dangerous_command | 3 | 2 | 1 | Python reverse shell, PowerShell cradle | `find ~ -delete` |
| sensitive_path | 2 | 1 | 1 | Windows `%USERPROFILE%\.ssh\id_ecdsa` | `~/.ssh/*` glob |
| secrets_in_args | 2 | 1 | 1 | Slack bot token | hex-encoded AWS key |
| pii_in_args | 1 | 0 | 1 | | card number as a JSON number |
| **Total** | **18** | **6 (33%)** | **12** | | |

Benign held-out: **2 of 6 false positives.** An XML `<system>` element tripped
`hidden-instruction-tag`, and "Note to the model:" in an honest tool description tripped
`addresses-the-model`. Across all 16 benign scenarios that is 2 false positives (12%).

**What this says.**

- On attacks written to the detectors' design, recall is 97 to 100%. On attacks written
  afterwards, it is 33%. The second number is the estimate to quote.
- The rules that held up target *structure*: credential file paths, reverse-shell
  shapes, token formats. Those generalize.
- The rules that failed target *phrasing*: how an injection is worded. Paraphrase defeats
  them almost every time.
- The false positives show the cost of blocking on phrasing: honest text uses the same
  words.
- This is the case for gatehouse's design: pinning, policy and approval are the controls;
  content rules are high-signal telemetry for the SOC, not a filter to rely on. Every miss
  and false positive is in `docs/known-bypasses.md` with a reproducing scenario.

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

The same suite through the two other stdio-wrapping MCP gateways (D-021), each in its own
virtualenv on a GitHub-hosted runner (`.github/workflows/competitors.yml`), with default
configuration (neither has a policy file).

Run: workflow run `45507937200`, commit `f4708d8`, ubuntu-latest (Linux 7.0, Azure
runner), Python 3.12.16, 2026-11-24. Versions from `pip freeze` in each venv:
`gateward==0.3.0`, `mcp-watchdog==0.1.9`. gatehouse ran in the same workflow.

| Scenario set | gatehouse 0.1.0 | gateward 0.3.0 | mcp-watchdog 0.1.9 |
|---|---|---|---|
| MVP (19 for gatehouse, 17 for others) | 19 prevented | 5 prevented | 1 prevented, 6 alerted |
| M2 (35) | 34 prevented, 1 logged | 11 prevented | 2 prevented, 12 alerted |
| **Held-out (18)** | **6 prevented** | **7 prevented** | **1 prevented, 9 alerted** |
| Documented bypasses (3) | 0 | 0 | 0 |
| Benign false positives (16) | 2 | 6 | 0 |
| Benign scenarios with an alert (16) | 2 | not measured | 8 |

"Prevented" means the attacker's goal wasn't reached. "Alerted" means the attack
succeeded but the tool raised an alert. The two self-protection scenarios target
gatehouse's own files and run only against gatehouse, hence 17 instead of 19.

Held-out, per scenario (P prevented, A alerted only, - missed):

| Scenario | gatehouse | gateward | mcp-watchdog |
|---|---|---|---|
| `cmd.python-reverse-shell` | P | P | A |
| `cmd.powershell-cradle` | P | - | - |
| `cmd.find-delete` | - | - | - |
| `inject.structured-field` | P | - | A |
| `inject.base64-instruction` | - | P | A |
| `inject.bracket-system` | - | - | P |
| `inject.markdown-link-exfil`, `inject.non-english`, `inject.reference-image` | - | - | A |
| `inject.polite-request` | - | - | - |
| `poison.schema-default` | P | P | A |
| `poison.required-prefix` | - | P | - |
| `poison.shadow-copy-to` | - | - | - |
| `paths.windows-ssh-key` | P | P | A |
| `paths.ssh-glob` | - | P | A |
| `secrets.slack-bot-token` | P | - | - |
| `secrets.hex-encoded` | - | P | - |
| `pii.card-as-number` | - | - | - |

**How the tools were scored, and why it's fair to them:**

- **gateward's canary tripwire.** gateward appends a marker `<!-- gw:XXXXXXXX -->` to
  every text result. It's its rule 12, which detects response data being copied into
  later requests (`src/gateward/canary.py` at `d2a65a4a81`). That's a detection
  technique, not a block, so the harness strips that exact marker before comparing benign
  results and records the count (`attacks/targets.py`, `result_marker`). Without this,
  every benign scenario would have counted as a false positive.
- **gateward's remaining 6 false positives are real blocks:**
  - `destructive_shell` on `rm -rf build/ dist/` and on clearing an app cache
  - `path_traversal` on reading `~/projects/app/.env.example` and
    `docs/configuration/.env.sample`
  - `tool_description_scan` on a security scanner's tool list
  - `injection_phrase` on a security article that quotes payloads
- **gateward's alerts** go to a SQLite audit database. The harness doesn't read it, so
  its "alerted" column isn't measured.
- **mcp-watchdog only alerts**, as human-formatted panels on stderr; it lets the traffic
  through. The harness counts CRITICAL, HIGH and MEDIUM panels as alerts
  (`stderr_alert`). It excludes LOW alerts, because a LOW "Unusual JSON nesting depth"
  alert fires on every session against the mock server. Its banner printed `v0.1.6`
  although pip installed 0.1.9.

**What the comparison does and doesn't show.**

- I wrote the scenarios, and the MVP and M2 sets were written alongside gatehouse's
  detectors. On those sets, the comparison mostly measures how closely each tool's design
  matches gatehouse's threat model: blocking secrets in *arguments*, pins that survive a
  restart, strict JSON-RPC framing. It doesn't rank the tools in general.
- The held-out set is the fairest part, and there gatehouse and gateward are level
  (6 and 7 of 18), with different strengths. gateward decodes hex and base64 and catches
  directory globs and "REQUIRED:" phrasing. gatehouse catches the PowerShell cradle, the
  Slack token and injection in `structuredContent`.
- mcp-watchdog alerts on the most held-out attacks (10 of 18 alerted or prevented), but
  also on half the benign traffic.
- None of the three catches the polite paraphrased injection, `find -delete`, the
  shadowing variant or a card number sent as a JSON number.
- gatehouse's advantages that this table doesn't capture are SOC-side: structured,
  redacted events in a published schema; Sentinel rules tested in Kusto, including
  cross-server correlation; a configurable policy; and approval through elicitation.
  `docs/prior-art.md` compares those features.
