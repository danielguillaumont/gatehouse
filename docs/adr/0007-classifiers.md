# ADR-0007: Model-based detectors behind one async interface, with a mode per classifier

- Status: accepted (2026-11-28)
- Decision log: D-050.

## Context

gatehouse's content detectors are pure functions over strings (regexes and decoders).
They are fast and deterministic, and they explain themselves, but they miss paraphrases
and translations of an injection. The held-out v2 set measures exactly that
(`llm-paraphrase`, `llm-translate-*`). The v2 plan asks for three model-based detectors:

- Meta's Prompt Guard 2, run locally;
- Azure Prompt Shields;
- a local LLM judge.

All three do I/O, have latency in the tens to hundreds of milliseconds, and can fail.
None of them can be a pure function in `gatehouse.inspect`.

## Decision

- **A separate package**, `gatehouse.classify`.
  - `base` holds the pure parts:
    - what text a model sees (strings only, with MCP framing fields left out, in
      chunks of 2,000 characters, at most 5);
    - how a verdict becomes a finding.
  - `backends` does the I/O.
  - `runner` applies the latency budget, and its `classify` never raises.
  - The detectors and the policy engine stay pure.
- **One interface:** `async scores(texts, timeout) -> list[float]`, a probability of
  attack per chunk. The verdict is the highest chunk. Blocking clients (ONNX Runtime,
  urllib) run in a worker thread, so the event loop never waits on them.
- **A mode per classifier** (`policy.classifiers[].mode`):

  | mode | traffic waits? | a hit | no answer (timeout, error, model missing) |
  |---|---|---|---|
  | `enforce` | yes, up to `budget_ms` | a finding at `severity`; the normal findings table decides | a HIGH `classifier-unavailable` finding: fail closed |
  | `alert` | no (task group) | a `detection` event, Action `logged` | a verdict event with the error |
  | `shadow` (default) | no (task group) | a `classifier.verdict` event only | a verdict event with the error |

- **Fail-open accounting.** A shadow or alert classifier never decides anything, so
  when one is unavailable no control is bypassed. Its timeouts are recorded in its
  `classifier.verdict` events (Details.Error), not as `gatehouse.fail_open`. ADR-0001's
  single fail-open path, telemetry loss, is unchanged. A classifier that can't start
  emits `gatehouse.internal_error` (Component `classifier`) at startup in every mode.
- **Not a circuit-breaker strike.** `classifier-unavailable` doesn't count toward the
  circuit breaker. An outage of a classifier would otherwise lock every agent session.
- **Surfaces:** `results` (tools/call results) and `definitions` (tool descriptions and
  schemas). For each classifier, definition verdicts are cached by tool digest, so an
  unchanged listing isn't classified again. "No answer" is never cached.
- **Events:** one `classifier.verdict` per classifier per input. It uses existing
  columns: DetectorId `classifier.<id>`; RuleId `prompt-injection`, `no-hit` or
  `classifier-unavailable`; LatencyMs; and Details with Mode, Kind, Score, Threshold,
  Chunks, Truncated and Error. No text is logged, because the verdict carries scores,
  not content.
- **Where text may go:**
  - Ollama endpoints must be loopback `http://`. Tool results are private, and the
    judge must be a local process.
  - Prompt Shields needs `https://`, and its key comes from an environment variable,
    never the policy.
  - Prompt Guard's model is read from a local directory. gatehouse never downloads it.

## Consequences

- An `enforce` classifier adds its latency to every result it covers. The budget bounds
  that latency, and a slow model then turns into blocked results, never into results
  that weren't checked. Users who want detections without that cost choose `alert`.
- Shadow mode makes measurement possible before trusting a model: the evaluation can
  score a classifier's verdicts on the held-out sets without changing what's blocked.
- **Prompt Guard 2** is gated by Meta on Hugging Face (Llama license). CI has no token,
  so the ONNX path is tested with an injected fake session and tokenizer. The project
  reports no Prompt Guard detection numbers it hasn't measured.
- **Prompt Shields** needs an Azure Content Safety resource. It is tested with a stubbed
  HTTP layer until M7 provides one.

## Alternatives considered

- **Classifiers as detectors in the pure pipeline:** this would break the "detectors
  are pure" invariant and block the event loop on inference.
- **A sidecar classification service:** this adds a process and a socket to every
  install. A worker thread inside the proxy is enough for a ~86M-parameter model.
- **Fail open for enforce on timeout:** a slow model would quietly become no model.
  ADR-0001 forbids that.
