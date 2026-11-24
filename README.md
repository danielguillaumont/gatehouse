# gatehouse

**Detection engineering for AI agent tool use.** gatehouse is a small stdio proxy that
sits between an MCP client (Claude Code, Cursor, any agent) and each MCP server. It:

- **blocks** rug pulls, unapproved tools, credential exfiltration through tool arguments,
  protocol smuggling, and agents tampering with their own guardrails;
- **emits redacted, SIEM-ready events** (`GatehouseEvents_CL`) for every listing, call and
  decision;
- ships **Microsoft Sentinel analytics rules and hunting queries** that are tested in a
  real Kusto engine in CI;
- is **measured**: a 67-scenario attack suite (with a benign set for false positives) and a
  latency benchmark run on every push.

Other MCP gateways focus on blocking. gatehouse is built for the SOC: what happened, in
which agent session, across which servers, with enough context to triage, and without
putting secrets in the log. See [`docs/prior-art.md`](docs/prior-art.md) for how it
compares.

```
MCP client  <-- stdio -->  gatehouse  <-- stdio -->  MCP server
                              |
                              +--> JSONL events --> Sentinel (KQL rules in detections/)
```

## Status

MVP, M2 and the Sentinel integration are done; M3 (evaluation and write-up) is in
progress. See `docs/PLAN.md` and `docs/NEXT.md`.

| Area | Status |
|---|---|
| stdio proxy, strict framing, policy engine, pinning (strict / TOFU), secret detection, self-protection | ✅ MVP |
| Events + redaction + HMAC fingerprints, `gatehouse.fail_open` | ✅ MVP |
| Attack suite + report + canary check in CI, latency benchmark | ✅ MVP |
| Content detectors: tool poisoning and shadowing, injection and exfil beacons in results, dangerous commands, credential paths, PII, invisible Unicode, look-alike names | ✅ M2 |
| Approval of `require_approval` calls through MCP elicitation | ✅ M2 |
| Sentinel: Logs Ingestion sink, Bicep (table, DCE, DCR, rules), 6 rules incl. cross-server GH006, validated in the Kusto emulator | ✅ built, **not deployed** ([setup](docs/sentinel-setup.md)) |
| Held-out evaluation, competitor comparison | 🚧 M3 |

## Results (reproducible)

From `uv run python -m attacks run --target gatehouse --out reports/gatehouse`. Details,
methodology and the full table are in [`docs/evaluation.md`](docs/evaluation.md).

| Scenario set | Attacks | Prevented | Recall | Benign false positives |
|---|---|---|---|---|
| MVP scope (rug pull, protocol, secrets, self-protection) | 19 | 19 | 100% | |
| M2 scope (content detectors) | 35 | 34 (+1 logged) | 97% | |
| **Held-out: written after the detectors, not tuned on** | **18** | **6** | **33%** | **2 / 6** |
| Documented bypasses | 3 | 0 | 0% | |
| All benign scenarios | | | | 2 / 16 |

The MVP and M2 sets were written alongside the detectors, so they show the controls do
what they're designed to do. **The held-out 33% is the number to quote for unseen
attacks.** Rules that match structure (credential paths, token formats, reverse-shell
shapes) generalize; rules that match phrasing don't. That's why gatehouse's controls are
pinning, policy and approval, with content detection as SOC telemetry.
`docs/known-bypasses.md` lists every miss with a scenario that reproduces it.

## Quick start

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). Works on Windows and Linux.

```
git clone <this repo> && cd gatehouse
uv sync

# 1. Approve a server's tools (pins their definitions)
uv run gatehouse pin --name weather -- uv run python demo/weather_server.py

# 2. Run it through gatehouse (this is the command your MCP client launches)
uv run gatehouse run --name weather --policy demo/policy.yaml -- uv run python demo/weather_server.py
```

With Claude Code: `claude mcp add weather -- uv run gatehouse run --name weather --policy
demo/policy.yaml -- uv run python demo/weather_server.py`. See
[`demo/README.md`](demo/README.md) for the rug-pull demo, or run it unattended with
`uv run python demo/run_demo.py`.

Commands:

| Command | What it does |
|---|---|
| `gatehouse run --name N --policy P -- CMD...` | Proxy one stdio MCP server (stdout is MCP only) |
| `gatehouse pin --name N [--tool T] -- CMD...` | Approve the server's current tool definitions |
| `gatehouse diff --name N -- CMD...` | Show what changed since approval (exit 1 on drift) |
| `gatehouse validate-policy P` / `policy-hash P` | Check a policy / print the hash for `--expect-policy-sha256` |
| `gatehouse table-schema` | Print the `GatehouseEvents_CL` column schema |

## Policy

```yaml
version: 1
default_action: block        # required: allowlist style
pinning: strict              # strict | tofu | "off"
servers:
  github:
    tools:
      "list_*": allow
      "merge_*": {action: require_approval, reason: "Merges need a human"}
      delete_repo: block     # an explicit block always wins
findings:                    # detector severity -> action (these are the defaults)
  critical: block
  high: block
  medium: log
```

An invalid policy blocks everything. See [`docs/policy.md`](docs/policy.md) for
precedence, Unicode-normalized matching, and why tool names are attacker-controlled.

## Detections

`detections/rules/` holds Sentinel scheduled analytics rules in the Azure-Sentinel repo
format. `detections/hunting/` holds hunting queries.

| Rule | Fires on |
|---|---|
| GH001 | Tool definition changed after approval (rug pull) |
| GH002 | Unapproved tool offered, or a hidden tool invoked |
| GH003 | Credential in the arguments of an egress/exec tool |
| GH004 | Policy tampering, policy load failure, self-protection hit, telemetry loss |
| GH005 | Burst of blocked calls in one agent session |

`uv run python -m detections.kusto --url http://localhost:8080` runs every rule against
`detections/sample_data/events.jsonl` (generated from real gatehouse sessions) in the
Kusto emulator and checks the results in `detections/expected.yaml`. CI does the same.

## Docs

[Architecture](docs/architecture.md) ·
[Threat model](docs/threat-model.md) ·
[Event schema](docs/event-schema.md) ·
[Policy](docs/policy.md) ·
[Evaluation](docs/evaluation.md) ·
[Known bypasses](docs/known-bypasses.md) ·
[Prior art](docs/prior-art.md) ·
[Decisions](docs/decisions.md) ·
[ADR-0001 fail-closed](docs/adr/0001-fail-closed.md)

## Development

```
uv run pytest -q          # unit + integration (set GATEHOUSE_KUSTO_URL for the KQL tests)
uv run ruff check . && uv run ruff format --check .
uv run pyright            # strict
uv run python -m attacks run --target gatehouse --out reports/gatehouse
uv run python -m bench.latency
```

Invariants: stdout carries only MCP frames; fail closed; redact before logging; detectors
are pure functions over size-bounded input.
