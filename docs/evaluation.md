# Evaluation

The current results are in [Evaluation v2](#evaluation-v2-m6-v030). The sections after it
are the earlier milestones' measurements, kept as they were run.

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

## Evaluation v2 (M6, v0.3.0)

Every number in this section comes from one GitHub Actions run:
[46112090830](https://github.com/danielguillaumont/gatehouse/actions/runs/46112090830)
(workflow `evaluation.yml`, commit `37da760`, gatehouse 0.3.0, Python 3.12.16, Ubuntu
runners, 2026-11-28). The artifact `evaluation` holds the collated tables
(`evaluation.md`, `evaluation.json`). The per-job artifacts hold every raw report and
the evidence events.

**Reproduce:** `gh workflow run evaluation.yml`. One cell, locally:

```
uv run python -m attacks.heldout2.mutate --check          # the frozen set is intact
uv run python -m attacks.external prepare --out .cache/external   # MCPTox, egress-bench
uv run python -m attacks run --target gatehouse --layers full \
    --scenarios attacks/heldout2/scenarios --out reports/gatehouse__full__heldout2
uv run python -m bench.latency --iterations 100 --sizes 1024 65536 1048576 \
    --layers full --out reports/bench-full
uv run python -m attacks.evaluate collate reports --out reports/evaluation
```

### The sets

| Set | Attacks | Benign | What it is |
|---|---|---|---|
| Suite | 102 | 38 | `attacks/scenarios/*.yaml`, written with the detectors (it includes held-out v1, which no longer measures anything, D-052). The 3 documented `bypass` scenarios are left out. |
| Held-out v2 | 330 | 119 | 54 seeds through 22 mutation operators, frozen and hashed before any M6 detector work (D-046). **The number to read.** |
| MCPTox | 485 | 362 | Poisoned tool definitions, from the public benchmark at a pinned commit (D-047). |
| agent-egress-bench | 32 | 12 | Exfiltration through tool arguments, the MCP stdio cases (D-047). |

That makes 531 benign scenarios in all. A false positive is *any* change to benign
traffic.

### Structural result (prevents)

The cross-server exfiltration chains (`flow.*`, M5) are what a content detector can't
stop: the injections in them are polite requests that no rule flags.

| Layers | Chains completed | Approval prompts per benign flow task | per benign scenario |
|---|---|---|---|
| `observe`, `pinning`, `detectors`, `v0.1` | 8 / 8 | 0 | 0 |
| `structural` (pinning + flow control, no content enforcement) | **0 / 8** | 0.50 | 0.006 |
| `full` | **0 / 8** | 0.50 | 0.006 |

Flow control (`flow.mode: approve`) prevents all 8 chains. It costs 3 approval prompts
over the 6 benign multi-server tasks, which the simulated user accepts. That is 0.006
prompts per benign scenario over the 531, since single-server traffic never
completes the Rule-of-Two trifecta.

### Ablation (detection: detects, blocks high and critical)

Attacks stopped per set, the false positives over all 531 benign scenarios, and the
added latency at 1 KiB:

| Layers | Suite | Held-out v2 | MCPTox | egress-bench | FP | p50 ms | p95 ms |
|---|---|---|---|---|---|---|---|
| `observe` | 3 / 102 | 0 / 330 | 0 / 485 | 0 / 32 | 0.0% (0) | +0.74 | +0.76 |
| `pinning` | 12 / 102 | 0 / 330 | 0 / 485 | 0 / 32 | 0.0% (0) | +0.73 | +0.79 |
| `detectors` | 81 / 102 | 123 / 330 | 62 / 485 | 17 / 32 | 0.9% (5) | +0.74 | +0.75 |
| `v0.1` | 87 / 102 | 123 / 330 | 62 / 485 | 17 / 32 | 0.9% (5) | +0.73 | +0.80 |
| `structural` | 20 / 102 | 0 / 330 | 0 / 485 | 0 / 32 | 0.0% (0) | +1.27 | +1.35 |
| `full` | 95 / 102 | 123 / 330 | 62 / 485 | 17 / 32 | 0.9% (5) | +1.27 | +1.32 |
| `judge` | 99 / 102 | 193 / 330 | n/a | n/a | 20.4% (32 / 157) | n/a | n/a |

How to read the rows:
- **`observe` stops 3 suite attacks.** These are protocol violations that gatehouse
  always rejects: a duplicate tool name, a frame with duplicate JSON keys and a
  JSON-RPC batch. It still runs every detector,
  in log mode, which is why its latency equals `detectors`.
- **Held-out v2 and the external sets come from content detection alone.** Pinning and
  flow control add nothing there: each scenario is one session on one server, with no
  rug pull.
- **`judge`** = `full` plus a local LLM judge (Qwen2.5 1.5B Instruct via Ollama, on CPU)
  in `enforce` mode on tool results (D-053).
  - It raises held-out v2 from 123 to 193 of 330. The 70 extra catches are spread
    over the mutation operators. 22 of them come from the paraphrase and translation
    operators, and the rest from casing, splitting, base64, lexical swaps, invisible
    characters and others.
  - But it changes 32 of 157 benign scenarios (suite and held-out v2, the sets it runs
    on): 22 of 119 in held-out v2 and 10 of 38 in the suite. Among them are a security
    article, a non-English message and a refund note.
  - That FP rate is why classifiers default to `shadow` (D-050), and why no
    configuration with a model in `enforce` is recommended.
  - The bench can't time this row. Once the judge withholds a result, the circuit
    breaker locks the session, so every timed call was a refusal (30 of 30). The
    collator now prints n/a for such rows, and the latency comes from the verdict
    events below.

**Before and after M6.** The same workflow at commit `1e28862` (gatehouse 0.2.0, before
the M6 detectors), run
[46106751618](https://github.com/danielguillaumont/gatehouse/actions/runs/46106751618),
`full` row:

| | Suite | Held-out v2 | MCPTox | egress-bench | FP |
|---|---|---|---|---|---|
| before (0.2.0) | 79 / 92 | 112 / 330 | 62 / 485 | 16 / 32 | 1.0% (5 / 522) |
| after (0.3.0) | 95 / 102 | 123 / 330 | 62 / 485 | 17 / 32 | 0.9% (5 / 531) |

- The suite grew by the 10 `m6-rules` attacks and 9 benign twins, which were written
  with the fixes. The suite is not evidence of generalisation.
- Held-out v2 is: **+11 attacks (33.9% → 37.3%) with no new false positive**. It was
  frozen before the fixes were written.

### Latency per layer

The added round trip of one `tools/call` (argument and result of the given size),
gatehouse minus direct, in ms: p50 / p95 / p99, over 100 iterations. Command:
`python -m bench.latency --layers <row>`.

| Layers | 1 KiB | 64 KiB | 1 MiB |
|---|---|---|---|
| `observe` | +0.74 / +0.76 / +0.76 | +8.75 / +8.82 / +8.97 | +119.96 / +121.86 / +131.79 |
| `pinning` | +0.73 / +0.79 / +0.92 | +8.75 / +8.82 / +8.99 | +119.41 / +119.74 / +119.84 |
| `detectors` | +0.74 / +0.75 / +0.76 | +8.74 / +8.84 / +9.11 | +119.56 / +120.10 / +120.56 |
| `v0.1` | +0.73 / +0.80 / +0.80 | +8.78 / +8.82 / +8.84 | +119.19 / +121.02 / +121.24 |
| `structural` | +1.27 / +1.35 / +1.38 | +20.62 / +20.75 / +20.94 | +165.16 / +167.57 / +167.82 |
| `full` | +1.27 / +1.32 / +1.39 | +20.57 / +20.81 / +20.87 | +164.77 / +164.95 / +165.19 |

- Flow control costs about +0.5 ms at 1 KiB, +12 ms at 64 KiB and +45 ms at 1 MiB.
  That cost is the provenance index: keyed span fingerprints of private-data results,
  kept in SQLite (D-043).
- The content detectors cost nothing measurable over `observe`, because `observe`
  runs them too.

**Classifier verdict latency**, from the `classifier.verdict` events of the judge
runs (`python -m attacks.evaluate verdict-latency reports`):

| Classifier | Verdicts | p50 ms | p95 ms | max ms | No answer |
|---|---|---|---|---|---|
| Ollama judge, Qwen2.5 1.5B, GitHub CPU runner | 352 | 714.1 | 1758.1 | 3668.4 | 0 |

In `enforce` mode this delay is added to every tool result. Prompt Guard 2 and Prompt
Shields are not measured (D-050): the first is gated on Hugging Face, and the second
needs an Azure resource.

### Comparison (same runner image, same commit)

Prevented / detected only / missed, and false positives over all benign scenarios.
gatehouse is the `full` row, in its default `flow.mode: approve`.

| Target | Suite (written with gatehouse's detectors) | Held-out v2 (frozen) | MCPTox (poisoned tools) | agent-egress-bench | FP |
|---|---|---|---|---|---|
| gatehouse 0.3.0 | 95 / 1 / 6 | **123** / 16 / 191 | **62** / 15 / 408 | 17 / 5 / 10 | **0.9%** (5 / 531) |
| Pipelock 3.8.0 (strict) | 46 / 10 / 33 | 97 / 0 / 233 | 39 / 0 / 446 | **27** / 4 / 1 | 5.8% (31 / 531) |
| mcp-context-protector `05e56c1` (no guardrail provider) | 16 / 0 / 73 | 10 / 0 / 320 | 0 / 0 / 485 | 2 / 0 / 30 | 5.1% (27 / 531) |
| gateward 0.3.0 | 28 / 0 / 61 | 43 / 0 / 287 | 38 / 0 / 447 | 9 / 0 / 23 | 2.3% (12 / 531) |
| mcp-watchdog 0.1.9 | 4 / 37 / 48 | 10 / **160** / 160 | 0 / **462** / 23 | 1 / 21 / 10 | 1.7% (9 / 531) |
| direct (no proxy) | 0 / 0 / 102 | 0 / 0 / 330 | 0 / 0 / 485 | 0 / 0 / 32 | 0.0% |

What it says:
- **Held-out v2 and MCPTox:** gatehouse stops the most, at the lowest FP rate.
- **agent-egress-bench:** Pipelock stops the most (27 of 32 against 17) of these
  argument-exfiltration cases. Closing that gap is an open item in `docs/NEXT.md`.
- **mcp-watchdog** blocks little but alerts on most poisoned definitions (462 of
  485). A SOC that triages alerts gets signal from it. A user who relies on it to stop
  attacks gets little.

### Fairness notes

- **Different denominators on the suite.** Competitors get 89 suite attacks, not 102.
  The 8 `flow.*` chains and 5 self-protection scenarios need several gatehouse
  processes or gatehouse's own CLI (`targets: [gatehouse]`). The suite was also written
  alongside gatehouse's detectors, so treat that column as a regression check. The
  frozen and external sets are the comparison.
- **Default configurations** (D-051). The invocations were checked against each tool's
  source at the pinned version:
  - Pipelock runs its `strict` preset;
  - mcp-context-protector runs without LlamaFirewall, which needs the gated Prompt
    Guard 2 model, so it gets pinning only;
  - gateward and mcp-watchdog run with no configuration.
- **Schema rewriting is not counted as a change** (D-053). mcp-context-protector
  rebuilds every tool schema and adds `required: []` and `description: ""`. Run
  46106751618 counted that as an altered listing (66.9% FP). Listings are now compared
  up to these no-op keywords, for every target.
- **Pipelock's pinning is per process** (D-051). Its baseline is set on each start, so
  it can't see a rug pull across restarts, by design.
- **gateward's audit log adds nothing to score.** Its blocks are already visible to the
  client, and its only other rows are framing errors (D-051).
- **Detected only** counts a tool's own alert channel: Pipelock's stderr findings,
  mcp-watchdog's alerts and gatehouse's `detection` events. The goal was reached, but a
  SOC would have been told.
- **One run, one runner image.** There's no variance estimate. The scenarios are
  deterministic, but the judge and the latency are not.

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

## Protocol fidelity (M4)

A security proxy that breaks the protocol gets switched off, so M4 measures what
gatehouse does to protocol traffic it has no objection to.

**Official conformance suite.** Command: `uv run --with click python
scripts/conformance.py --server-dir <everything-server> --out reports/conformance`.
Harness `@modelcontextprotocol/conformance@0.2.0-alpha.11` (the version MCP Python SDK
2.3.0's own CI pins), against that SDK's `examples/servers/everything-server` at tag
`v2.3.0`, `--suite all` per wire, run directly and through `gatehouse serve` (policy
allows everything, pinning off). Windows 11, Python 3.12.2, Node 26.13.1, 2026-11-27,
commit `8bcb6f7`. The `conformance` workflow reruns it in CI. Its first run, on Ubuntu
at `40ac48a` (Actions run 46088920475), gave the same result.

| Wire | Scenarios direct | Through gatehouse | Checks through gatehouse |
|---|---|---|---|
| 2025-11-25 | 33/33 | 33/33 | 84 passed, 2 warnings |
| 2026-07-28 | 40/40 | 40/40 | 151 passed |

The two warnings are in `server-sse-polling`: gatehouse doesn't pass the upstream's
priming event and `retry` hint downstream. When the upstream closes a stream before
answering, gatehouse resumes it itself (GET with `Last-Event-ID`, D-039) and the client
gets the inspected result on its original stream, so the client has nothing to resume.

The first run found five gatehouse bugs, all fixed in `8bcb6f7`. One hung the client: a
2026-07-28 request with a broken envelope. One used the wrong -32022 version list. One
misparsed a `=?base64?` value without its closing `?=`. One dropped an id-less upstream
error. One waited for the request timeout when an upstream stream closed early.

**A real client.** Claude Code 2.1.332 (`claude -p ... --mcp-config ...
--strict-mcp-config --model haiku`, 2026-11-27) called a tool through gatehouse on
three servers:
- a dual-era stdio server (`demo/weather_server.py`, SDK 2.3.0), which negotiated
  2026-07-28;
- a legacy-only stdio server (`attacks/mockserver.py`), which used the 2025-11-25
  handshake;
- the weather server over Streamable HTTP behind `gatehouse serve`, which negotiated
  2026-07-28.

gatehouse's events confirm the version each connection used. The first run found a bug:
Claude Code sends `server/discover` and `initialize` back to back, and gatehouse latched
the legacy era on the forwarded `initialize`, so the modern server's tools never loaded
(fixed in `ea8473e`, ADR-0002).

## Session flow control (M5)

M5 asks whether an exfiltration chain can be stopped when nothing detects the injection.
All numbers in this section come from one GitHub Actions run:
[46101039038](https://github.com/danielguillaumont/gatehouse/actions/runs/46101039038),
job `attack-suite`, commit `e5d7b7c`, gatehouse 0.2.0a0, Python 3.12.16, Ubuntu
(Linux 7.0.0-1020-azure), 2026-11-28. The artifact `attack-reports` holds the raw
reports.

**Command:** `uv run python -m attacks flow --out reports/flow`. It runs every
`attacks/scenarios/flow.yaml` scenario under each `flow.mode`, with
`attacks/policy-flow.yaml`.

- **Real processes.** Each server in a scenario (notes, web, mail, issues, files) runs
  behind its own `gatehouse run` process. They share one state directory and one agent
  session, as they do under a real agent.
- **The agent is scripted to follow every injection**, which is the worst case.
- **The injections are polite requests that no content rule flags.** No
  `response.injection` finding fired on any of them.
- **The simulated user** declines gatehouse's approval prompts in the attack chains and
  accepts them in the benign tasks, so approvals can be counted (D-045). A user who
  approves everything gets the `monitor` row.

| flow.mode | Chains completed | Benign tasks passed | Approval prompts (benign) | Approvals per benign task |
|---|---|---|---|---|
| monitor | 6 / 8 | 6 / 6 | 0 | 0.00 |
| **approve** | **0 / 8** | **6 / 6** | **3** | **0.50** |
| enforce | 0 / 8 | 3 / 6 | 0 | 0.00 |

- **approve** (the recommended mode) stops every chain. The benign tasks need 0 or 1
  prompt each:

  | Benign task | Properties | Prompts |
  |---|---|---|
  | `notes-to-colleague` | private data + egress | 0 |
  | `web-research` | untrusted input + egress | 0 |
  | `share-report` | private data + egress | 0 |
  | `research-then-email` | all three | 1 |
  | `inbox-reply` | all three | 1 |
  | `issue-to-note` | all three, via a write | 1 |

- **Every prevented chain was stopped by structure.** The enforcing detection is
  `tool.call/flow` in every case.
  - Provenance also matched the two chains that copy the memo verbatim or in base64
    (`flow.provenance/private-data-copied`).
  - The paraphrased chain has no copy to match, and it's stopped anyway.
- **monitor isn't purely passive.** It stops 2 of the 8 chains: a verbatim or encoded
  copy of private data sent after untrusted input escalates to approval through
  `flow.provenance` (default `require_approval`).
- **enforce** blocks the three benign tasks that need all three properties, as it is
  meant to.
- **Limits:**
  - Eight chains and six benign tasks is a small set, written by the author. The 200+
    benign corpus and external sets are M6.
  - The labels come from a policy written for these servers. A tool the policy forgot
    to label isn't counted (`docs/known-bypasses.md`).

**The rest of the suite in the same run** (`python -m attacks run --target gatehouse`):
95 attacks and 29 benign scenarios.

| Milestone | Attacks | Prevented | Detected only | Missed |
|---|---|---|---|---|
| mvp | 19 | 19 | 0 | 0 |
| m2 | 35 | 34 | 1 | 0 |
| m3 (held-out) | 18 | 6 | 0 | 12 |
| m4 | 9 | 9 | 0 | 0 |
| m5 (flow chains in approve mode, plus self-protection) | 11 | 11 | 0 | 0 |
| bypass (documented) | 3 | 0 | 0 | 3 |

- There are no v0.1 regressions.
- Benign false positives: 2 of 29. Both are the documented held-out ones
  (`benign.heldout.xml-config`, `benign.heldout.note-to-model`).
- Canary check: 0 leaks.

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

**Cedar and flow control (M5).** Same GitHub Actions run as above
([46101039038](https://github.com/danielguillaumont/gatehouse/actions/runs/46101039038),
commit `e5d7b7c`, Ubuntu, Python 3.12.16, 100 calls per size). The three policies ran
one after the other on one runner:

- `allow`: allow-all, decided by Cedar and checked against the native reference (the
  default engine);
- `native`: the reference engine alone;
- `flow`: `flow.mode: approve` with the tool labelled `private_data`, so every call
  reads the shared flow store and every result is fingerprinted.

Command: `uv run python -m bench.latency --iterations 100 --policy allow|native|flow`.

| Payload | overhead p50: native | allow (Cedar) | flow | overhead p95: native | allow (Cedar) | flow |
|---|---|---|---|---|---|---|
| 1 KiB | +1.22 | +1.46 | +2.48 | +1.28 | +1.98 | +2.67 |
| 100 KiB | +14.99 | +15.10 | +37.11 | +16.43 | +15.57 | +38.42 |
| 1 MiB | +124.36 | +126.19 | +178.67 | +124.83 | +128.28 | +180.79 |

- **Cedar costs about 0.2 ms per call.** That's allow minus native at 1 KiB p50. At
  larger sizes it's lost in the detector cost. The 1 KiB p95 target (5 ms) holds in all
  three configurations on this runner.
- **Flow control costs about 1 ms per call**, mostly the flow-store reads and writes,
  plus fingerprinting `private_data` results.
  - Fingerprinting is capped at 32 KiB of text (D-043). That's why it adds about 22 ms
    at 100 KiB and about 52 ms at 1 MiB, not more.
  - Only results from tools labelled `private_data` are fingerprinted, and only
    arguments to `egress` tools are checked.

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
