# Threat model

**Framework versions:** MITRE ATLAS **2026.10**, checked on 2026-11-24 against
`mitre-atlas/atlas-data` `dist/v6/ATLAS-2026.10.yaml` (see D-028), plus OWASP Top 10 for LLM
Applications **2025**. ATT&CK IDs are given where an enterprise technique fits better.
`tests/test_atlas_ids.py` fails if an ATLAS ID outside the verified list appears in the
repo.

## Assets and trust boundaries

- **The agent's tool use:** which tools it can see, and what it sends to and receives from
  them.
- **Secrets and data** in the agent's context: keys, tokens, files, PII.
- **gatehouse's own control files:** policy, pin store, HMAC key, event log. The agent's
  own tools can reach them on disk.

Trust boundaries:

- agent ↔ gatehouse
- gatehouse ↔ MCP server: **the server is untrusted**, including names, descriptions,
  schemas, annotations and results
- MCP server ↔ its own network: invisible to gatehouse
- the local disk

## Attacks, where they are seen, and coverage

| # | Attack | Seen at | Detector / control | Status | OWASP LLM 2025 | ATLAS 2026.10 · ATT&CK |
|---|---|---|---|---|---|---|
| 1 | Rug pull: definition changed after approval | `tools/list`, `list_changed` | `listing.pin_mismatch` | MVP | LLM03 | AML.T0010.005 · T1195 |
| 2 | Unapproved or newly added tool | `tools/list` | `listing.unpinned` (strict; TOFU after the first listing) | MVP | LLM03 | AML.T0010.005 |
| 3 | Calling a hidden or unlisted tool | `tools/call` | availability check (`unlisted_tool`, `stale_tool_list`) | MVP | LLM06 | AML.T0053 |
| 4 | Duplicate tool names | `tools/list` | `listing.duplicate_name` | MVP | LLM03 | AML.T0010.005 |
| 5 | Secrets in tool arguments | `tools/call` | `args.secrets` (18 rules) | MVP | LLM02 | AML.T0086 · T1552 |
| 6 | Agent tampers with gatehouse (policy, pins, key, logs) | `tools/call`, disk | `args.self_protect`, `policy.tampered` | MVP | LLM06 | AML.T0081 · T1562.001 |
| 7 | Parser-differential smuggling (duplicate keys, batches) | any frame | strict framing (`protocol.*`) | MVP | LLM06 | AML.T0053 |
| 8 | Resource exhaustion (huge frames, deep nesting) | any frame | frame size limit, bounded walk | MVP | LLM10 | AML.T0029 |
| 9 | Tool poisoning in description or schema | `tools/list` | `listing.poisoning` | M2 | LLM01, LLM03 | AML.T0110, AML.T0051.001 |
| 10 | Tool shadowing (instructions about *other* tools) | `tools/list` | `listing.cross_tool_ref` | M2 | LLM01, LLM06 | AML.T0110 |
| 11 | Invisible Unicode smuggling | any text | `normalize.invisible` | M2 | LLM01 | AML.T0068 · T1027 |
| 12 | Indirect prompt injection in results | `tools/call` result | `response.injection` | M2 | LLM01 | AML.T0051.001 |
| 13 | Markdown/URL exfiltration beacon | `tools/call` result | `response.exfil_url` | M2 | LLM05, LLM02 | AML.T0086 |
| 14 | Dangerous commands | `tools/call` | `args.commands` | M2 | LLM06 | AML.T0053, AML.T0050 · T1059 |
| 15 | Credential-store / sensitive path access | `tools/call` | `args.paths` | M2 | LLM02, LLM06 | AML.T0098 · T1552.004 |
| 16 | PII in arguments | `tools/call` | `args.pii` | M2 | LLM02 | AML.T0086 |
| 17 | Malicious sampling / elicitation phishing | server→client requests | `server_request.*` | M5 | LLM01 | AML.T0051 |

The attack suite (`attacks/scenarios/*.yaml`) has scenarios for rows 1–16. Results are in
`docs/evaluation.md`.

## Non-goals

- A malicious server misusing data it legitimately received, or making its own network
  calls. gatehouse only sees the MCP pipe.
- A compromised host or client: an attacker with code execution can just kill gatehouse.
  The `self_protect` detector only stops the *agent* from doing that through its tools.
- Guaranteed prompt-injection prevention. Deterministic detection is incomplete by
  nature (`docs/known-bypasses.md`). gatehouse is one layer of defense and a source of SOC
  telemetry, not a sandbox.

## gatehouse's own attack surface

| Risk | Mitigation |
|---|---|
| ReDoS in detectors | Linear-time patterns (bounded repetition, no nested quantifiers); input capped by `inspect/walk.py`; keyword prefilter (D-026) |
| Parser differentials (gatehouse vs. server see different messages) | Strict framing: duplicate keys, NaN/Infinity, batches, invalid UTF-8 and non-scalar ids are rejected; the bytes forwarded are the bytes inspected |
| Stdout pollution | `sys.stdout` redirected to stderr; `print` banned by lint |
| Log injection | Events are JSON-encoded; invisible/bidi characters are escaped as `\uXXXX` |
| The log as an exfiltration sink | Redaction before logging, HMAC fingerprints instead of values, `canary-check` in CI |
| Policy weakened by the agent | Explicit block wins; the policy loads once (no hot reload); on-disk changes raise `policy.tampered`; `--expect-policy-sha256` pins the file's hash |
| Pin store corruption | Lock file plus atomic replace; an unreadable store hides all tools (fail closed) |
| Approval-prompt injection (M2) | Attacker-controlled text is quoted, truncated and escaped in elicitation messages |
