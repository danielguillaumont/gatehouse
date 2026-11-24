# Prior art

Checked **2026-11-24** against each project's own repository, README/docs and package
metadata (commit noted per project). Claims are what each project documents unless marked
"(source)" (read from code). "not found" means not found in the repo/docs at that commit,
not proven absence. Corrections welcome: open an issue with a link.

gatehouse's positioning follows from this survey: several projects already proxy and
filter MCP traffic; **none we found ships SIEM detection content (Sentinel/KQL) or
publishes a detection evaluation** (precision/recall, false-positive rate). gatehouse is the
detection-engineering layer: telemetry-first events, Sentinel analytics with cross-server
session correlation, and a reproducible evaluation that is also run against other tools.

## Projects

### gateward (formerly "mcpgate")
- https://github.com/mcpgatehq/gateward (old `mcpgatehq/mcpgate` URL redirects). Apache-2.0,
  Python ≥3.11. PyPI 0.3.0 (2026-04-22); HEAD `d2a65a4a81`. The current PyPI package named
  `mcpgate` is an unrelated project.
- Transparent stdio wrapper: `gateward run -- <server-command>`; `gateward scan --json-output`.
  Stdio only ("HTTP/SSE not yet supported").
- 12 hard-coded rules incl. response injection phrases, tool description scan, schema drift
  fingerprints (rug pull), secrets in responses, destructive commands, path traversal, SSRF,
  exfil URLs, canary tokens. "Rules are hard-coded. No config file or policy DSL."
- Audit log in SQLite (`~/.gateward/audit.db`), "No alerting". README: "Linux/macOS only.
  Windows not supported."

### mcp-watchdog
- https://github.com/bountyyfi/mcp-watchdog. README/PyPI say MIT (no LICENSE file in repo).
  Python ≥3.11. v0.1.9 (2026-02-24); HEAD `f7d4db5274`.
- Transparent stdio wrapper: `mcp-watchdog -- <cmd>`. Stdio only (source).
- Claims: injection in tool/resource/prompt results (incl. `<IMPORTANT>` blocks, zero-width,
  ANSI, homoglyphs), tool poisoning/shadowing/name squatting, rug pull via definition hashing,
  30+ secret patterns redacted, command/SQL/reverse-shell argument injection, SSRF, sampling/
  elicitation abuse, optional LLM classifier.
- No configurable policy ("only strips malicious content and raises alerts"). Alerts are
  human-formatted stderr panels; no structured log (source). Windows claimed.

### mcpkernel
- https://github.com/piyushptiwari1/mcpkernel. Apache-2.0, Python ≥3.12. v0.3.0 (2026-05-25);
  HEAD `bdab6f579e`.
- Gateway (HTTP by default; `--transport stdio` documented) with stdio/SSE/HTTP upstreams.
- Claims: tool-poisoning scanner, description pinning/drift, taint tracking for secrets/PII,
  DLP, SSRF guard, sandboxed execution. YAML policy (`deny/allow/audit/sandbox`, presets,
  `policy-lint`). SQLite audit exportable as CEF/JSONL/CSV/SARIF; OTLP/Prometheus. Windows
  listed as out of scope in its v0.4 roadmap.

### Arbitus
- https://github.com/harbefas/arbitus. AGPL-3.0, Rust. GitHub release v1.0.0 (2026-04-06,
  Windows binary included); crates.io latest 0.19.1. HEAD `d55d1dffda`.
- Gateway with stdio mode via config; HTTP+SSE.
- Claims: encoding-aware secret filtering in arguments, 7 prompt-injection regexes
  (source), response pattern filtering, inputSchema validation, allow/deny globs per agent,
  rate limits, HITL approval via REST, OPA/Rego, shadow mode. Tool-description poisoning and
  definition pinning: not found. Audit: SQLite with hash chain, webhook, CloudEvents, OTLP.

### mcpsafetywarden
- https://github.com/gautamvarmadatla/mcpsafetywarden. Apache-2.0 (LICENSE/pyproject),
  Python ≥3.10. 1.7.18 (2026-11-21); HEAD `3bcc21f87d`.
- **Not a transparent proxy**: an MCP server exposing its own tools (`safe_tool_call(...)`);
  upstream servers are registered via CLI.
- Claims: injection detection in outputs with quarantine, malicious metadata, source-hash
  drift guard, secret redaction, 20+ argument-injection categories, SAST and LLM pentest
  pipeline. Per-tool allow/block, risk gate with approval. SQLite audit.

### Reference: Snyk Agent Scan (formerly Invariant Labs mcp-scan)
- https://github.com/snyk/agent-scan (old `invariantlabs-ai/mcp-scan` redirects). Apache-2.0.
  v0.7.1 (2026-11-24); HEAD `a856127135`.
- Invariant Labs' research named and popularized **tool poisoning** and **MCP rug pulls**.
- Today a static/discovery scanner (needs `SNYK_TOKEN`; sends tool names/descriptions to
  Snyk's API), not a runtime proxy in current docs. v0.3.4 documented a proxy mode and
  hash-based change detection; not found in current docs.

## Comparison

| | gateward | mcp-watchdog | mcpkernel | Arbitus | mcpsafetywarden | **gatehouse** |
|---|---|---|---|---|---|---|
| Transparent stdio wrap | yes | yes | via config | via config | no (meta-tools) | yes |
| Configurable policy | no | no | YAML | YAML + OPA | per-tool + gate | YAML (explicit-deny, specificity) |
| Rug pull / pinning | yes | yes | claimed | not found | source hash | yes (strict / TOFU) |
| Structured security events | SQLite | no | SQLite → CEF/JSONL | SQLite/CloudEvents/OTLP | SQLite | JSONL, Sentinel schema |
| Sentinel / KQL content | not found | not found | not found | not found | not found | **yes** |
| Cross-server correlation | not found | not found | not found | not found | not found | **yes** (`AgentSessionId`) |
| Published detection eval | not found | not found | latency only | not found | not found | **yes** (`docs/evaluation.md`) |
| Windows | no (stated) | claimed | no (roadmap) | binary | implied | yes (CI) |

## What gatehouse borrows and credits

- Attack taxonomy and terms (tool poisoning, rug pull, shadowing) from Invariant Labs.
- Secret-rule ideas from the public gitleaks and detect-secrets catalogs (patterns
  rewritten, not copied).

## Comparison runs

`docs/evaluation.md` reports the gatehouse attack suite run against gatehouse, gateward
0.3.0 and mcp-watchdog 0.1.9: the two stdio-wrapping proxies with a non-interactive
`-- <command>` interface. They ran in the same GitHub Actions workflow (run `45507937200`,
2026-11-24), each competitor in its own virtualenv.

Behaviour observed in those runs, which confirms or adds to the claims above:

- **gateward** blocks: errors such as `Gateward blocked: destructive_shell` or
  `tool_description_scan`. It also appends `<!-- gw:XXXXXXXX -->` to every text result;
  that is its canary tripwire (`src/gateward/canary.py`).
- **mcp-watchdog** alerts with stderr panels such as `CRITICAL [CMD-INJECT]` and passes
  most traffic unchanged. It prevented 4 of 73 attacks and alerted on 27. The installed
  0.1.9 package prints `v0.1.6` in its banner.

On the held-out scenarios, gatehouse prevented 6 of 18 and gateward 7 of 18, with
different strengths. The suite was written by gatehouse's author, so the MVP and M2 sets
favour gatehouse's threat model; read `docs/evaluation.md` for the caveats.
