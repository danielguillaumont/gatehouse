# Known bypasses and limitations

Deterministic detection is incomplete by nature, so this page lists the ways around
gatehouse that I know of. Entries with a scenario id can be reproduced:
`uv run python -m attacks run --target gatehouse --out reports/x --only <id>`. Scenarios
tagged `milestone: bypass` are expected to be missed and do not fail CI.

## Detection gaps (content)

| Bypass | Why it works | Reproduce | Mitigation / plan |
|---|---|---|---|
| **Secret split across two arguments** | Each argument is scanned separately and neither half matches a pattern | `secrets.split-across-arguments` | Scan concatenated argument text as well (M3). Can never be complete: the agent can split a secret across *calls*. |
| **Encoded secrets** (base64, hex, rot13) | Patterns match plaintext only | `secrets.base64` | M2: decode base64-looking substrings (size-bounded) and rescan |
| **Zero-width characters inside a token** | `ghp_​ABC…` breaks the regex | `secrets.zero-width-split` | M2: scan a copy with Unicode format characters removed |
| **Paraphrased injection** | No trigger phrases, so rules don't fire | `inject.result.paraphrased` | None with rules alone. A classifier or LLM judge (M7) helps but is also bypassable. This is the main reason gatehouse is *telemetry plus defense-in-depth*, not a guarantee. |
| **Shell quoting / variable tricks** | `r''m -r''f`, `$'\x72m'`, `${IFS}` defeat string rules | `cmd.obfuscated-quotes` | M2 normalizes common quoting. A full shell parser is out of scope. Prefer `require_approval` for exec tools. |
| **Cross-script look-alike names** | NFKC doesn't fold Cyrillic `е` to Latin `e`, so `dеlete_repo` escapes a `delete_*` rule | `tests/policy/test_engine.py::test_cyrillic_confusable_is_a_known_gap` (xfail) | Pinning still hides the unpinned look-alike. M2 adds a mixed-script name detector. Use allowlists. |

## Trust-model gaps

| Gap | Detail |
|---|---|
| **Poisoned from the first day** | Pinning catches *changes*. Under TOFU, a tool that is malicious in its very first listing is trusted. Under strict pinning, the person running `gatehouse pin` must read what they approve (`gatehouse diff` shows it). M2 content detectors scan definitions on every listing, pinned or not. |
| **Honest-looking names** | Policy rules match names, and the server chooses them. An exfiltration tool called `get_weather` passes a name rule. See `docs/policy.md`, "Tool names are attacker-controlled". |
| **The server's own network** | A malicious server can send whatever it receives to the internet. gatehouse only sees the MCP pipe. |
| **Compromised host** | Anyone who can run code as the user can kill or reconfigure gatehouse. `self_protect` only stops the *agent* from doing it through its tools. |
| **Telemetry loss** | If the JSONL sink fails, traffic continues (the one fail-open path, ADR-0001), reported as `gatehouse.fail_open`. An attacker who fills the disk loses you logs, not enforcement. |

## Protocol coverage gaps

| Not inspected yet | Status |
|---|---|
| `resources/*`, `prompts/*`, sampling and elicitation content | Forwarded unchanged; inspection planned for M5 |
| Streamable HTTP transport | M4. Only stdio is proxied today. |
| 2026 stateless protocol era | gatehouse answers `server/discover` with -32601, so clients fall back to the `initialize` era, which it fully inspects (D-003). A client that refuses to fall back can't connect through gatehouse. That fails closed, not open. |
| Server-sent elicitation that imitates gatehouse | A malicious server can send its own `elicitation/create` whose message looks like a gatehouse approval prompt, to get a "yes" for something else. gatehouse forwards server requests unchanged. Mitigation idea: tag gatehouse prompts with a per-install phrase the user learns, and flag server elicitations that mention gatehouse. |

If you find a bypass that isn't listed here, it's a bug in this document. Please open an
issue with a scenario.
