# Policy file (schema v1)

A policy decides, for every `tools/call`, whether gatehouse should **allow**, **block**, or
**require_approval** for it. Examples: [`examples/policy-filesystem.yaml`](../examples/policy-filesystem.yaml),
[`examples/policy-multi-server.yaml`](../examples/policy-multi-server.yaml).

## Schema

```yaml
version: 1                        # required; only 1 is accepted
default_action: block             # required; allow | block | require_approval

servers:                          # optional
  "<server pattern>":
    tools:                        # required
      "<tool pattern>": allow                     # shorthand
      "<tool pattern>":                           # object form
        action: require_approval                  # required
        reason: "Writes need a human"             # optional, 1-500 chars, shown in events
      "<tool pattern>":                           # with argument conditions
        action: allow
        when:                                     # every condition must hold
          to: {email_domains: ["example.com"]}
        otherwise: require_approval               # optional; default block

engine: cedar                     # optional; cedar (default) | native
```

- Patterns are globs (`*`, `?`, `[abc]`, `[!abc]`), matched with `fnmatchcase` against
  normalized names (see below). They are not regexes and not paths: `.` and `/` are literal.
- **Quote patterns that start with `*`.** A bare `*` is YAML alias syntax and is rejected.
- `default_action` is required. There is no implicit default, so "allow" can never be an
  accident. The recommended style is an allowlist with `default_action: block`.

## Precedence

For a call to tool `T` on server `S`:

1. **Fail closed.** No valid policy → **block** (see "Load errors" below).
   A rule with `when:` conditions acts as its `action` when they all hold and as its
   `otherwise` when they don't; everything below uses the action the rule acts as.
2. **Explicit block wins.** If *any* matching rule says `block`, the result is **block**,
   regardless of how specific other rules are (IAM-style explicit deny).
3. **Most specific match.** Otherwise, each pattern is ranked
   `exact (3) > glob with literals, e.g. delete_* (2) > * (1)`. Rule X *dominates* rule Y
   if X is at least as specific on both server and tool, and strictly more specific on
   one. The rules that no other matching rule dominates win. If they all agree, that action
   is the result.
4. **Incomparable tie → require_approval.** If those winning rules disagree (for example,
   `github/*: allow` vs `*/merge_*: require_approval`, where each is more specific in a
   different dimension), the result is **require_approval**.
5. **No match** → `default_action`.

Rule order in the file never matters. Decisions record their `basis`
(`fail_closed | explicit_block | most_specific | tie | default | flow |
engine_disagreement`) for telemetry.

Consequences worth knowing:

- `"*": block` under a server blocks **every** tool on it, including any you also allow.
  Express allowlists with `default_action: block` plus allow rules instead.
- You cannot carve an exception out of a block. To allow `delete_draft` but block other
  deletes, write the block rules more narrowly.
- A server-specific allow beats a global `require_approval` on the same tool pattern rank
  (`github/list_*: allow` beats `*/*_exec*: require_approval` for `github.list_exec_jobs`).
  Only `block` is global by force.

## Argument conditions

A rule can depend on the call's arguments. `when:` maps argument names to one condition
each. If every condition holds, the rule acts as `action`. Otherwise it acts as
`otherwise`, which defaults to `block` and must be stricter than `action`.

| Condition | Holds when every value of the argument… |
|---|---|
| `email_domains: [example.com, "*.corp.example"]` | …contains addresses, and every address has a listed domain (`*.x` means a subdomain of `x`, not `x` itself) |
| `url_hosts: [api.example.com]` (+ optional `schemes: [https]`) | …is an absolute URL with an allowed scheme (default `https`) and a listed host. IP literals only match when listed. |
| `path_under: [/srv/data, "C:\\Users\\me\\Docs"]` | …is an absolute path that stays under a root after `.`/`..` are resolved (Windows paths compare case-insensitively) |
| `max: 100`, `min: 0` | …is a JSON number in range (`true` and `"50"` are not numbers) |
| `one_of: [main, dev]` | …is one of the listed strings or numbers (exact) |

"Every value" means a string or number, or a list of them, of up to 64 items. The
condition **fails** when the argument is missing, `null`, an empty list, the wrong type,
too long (4096 characters) or doesn't parse. Because `otherwise` is always stricter,
an argument gatehouse can't understand never loosens a decision.

```yaml
servers:
  mail:
    tools:
      send_email:
        action: allow
        when:
          to: {email_domains: ["example.com"]}
          cc: {email_domains: ["example.com"]}
        otherwise: require_approval
  fs:
    tools:
      read_file:
        action: allow
        when: {path: {path_under: ["/srv/project"]}}
```

Limits:

- Conditions are lexical. `path_under` doesn't resolve symlinks, so a server that follows
  a symlink inside the root can still reach outside it. Point roots at directories the
  agent can't write symlinks into, or rely on the server's own sandbox for that.
- An argument the rule doesn't name is not checked. In the `send_email` example a `bcc`
  argument would go through, so name every recipient field the tool has. The tool's
  pinned `inputSchema` lists them. `policy prove` treats conditions as opaque, so it
  can't catch a missing one.
- `block` rules can't have conditions: block is unconditional.

## Flow control (Rule of Two)

An agent that holds all three of these can be talked into exfiltration by one injected
sentence:

- **untrusted input:** web pages, inbound email, issues written by strangers;
- **private data:** notes, inbox, files;
- **a way to act or send data out:** email, uploads, outbound requests, writes.

The Rule of Two (Meta, 2025) says a session should hold at most two. gatehouse tracks
which of them the agent session holds, across every server, and checks each call
(ADR-0005):

```yaml
flow:
  mode: approve            # off (default) | monitor | approve | enforce
  annotation_hints: true   # server annotations may add labels (default true)
  name_hints: true         # tool-name keywords may add labels (default true)

servers:
  notes:
    labels: {"*": [private_data]}
  web:
    labels: {fetch: [untrusted_input, egress]}   # a URL can carry data out
  mail:
    labels:
      "read_*": [untrusted_input, private_data]
      send_email: [egress]
```

- **Labels:** `untrusted_input`, `private_data`, `state_change` and `egress`. Every
  matching `labels:` entry applies.
  - Hints can only add labels. `destructiveHint: true` or `readOnlyHint: false` adds
    `state_change`; `openWorldHint: true` adds `untrusted_input` and `egress`.
  - Name keywords add labels too: `send`, `upload`, `fetch` and others give `egress`;
    `delete`, `write` and others give `state_change`. A server can't remove a label,
    because a server choosing its own labels could hide an egress tool.
  - **Label every egress tool explicitly.** Hints are a safety net, not a policy.
- **The check.** A call *completes the trifecta* if the session's labels plus the
  tool's labels cover all three properties (`state_change` and `egress` count as the
  same one) and the tool adds at least one. The order doesn't matter, and there's no
  time window: reading the inbox after sending mail trips it just as sending after
  reading does.
- **Modes:**
  - `monitor` allows and logs `flow.rule_of_two`;
  - `approve` asks a human (elicitation or MRTR), or blocks if the client can't be asked;
  - `enforce` blocks.
- **When labels join the session.** A call's labels are added when gatehouse forwards
  it (blocked calls add nothing). A delivered result in which a detector finds injected
  instructions adds `untrusted_input`, whatever its tool's labels.
- **The session** is the agent process (`AgentSessionId`). Every gatehouse under one
  Claude Code, Cursor or similar process shares labels through
  `<state dir>/flow.sqlite3`. `GATEHOUSE_AGENT_SESSION_ID` overrides the key.
- **Failures are closed.** An unreadable store counts as holding every label. A label
  that can't be recorded blocks its call.

### Provenance: copies of private data

With flow control on, gatehouse also fingerprints what `private_data` tools return. When
an `egress` call's arguments contain a copy, it emits `flow.provenance_match` and names
the tool the data came from (D-043).

- **What counts as a copy:**
  - a span of about 55 characters or more, after case and whitespace are normalized;
  - the same text in base64, hex or percent encoding;
  - any secret from a private result.
- **What happens:**
  - If the session also holds `untrusted_input`, the call gets `flow.provenance`
    (default `require_approval`; `block` and `log` are the other choices).
  - Otherwise the match is logged, because sending your own notes on is normal.
- Fingerprints are keyed HMACs, so the store never holds the text.
- **Limit:** a paraphrase or summary doesn't match. Treat a match as evidence; the
  Rule of Two is the guarantee.

```yaml
flow:
  mode: monitor
  provenance: block     # a copy of private data after untrusted input is blocked
```

`gatehouse policy prove` can check flow invariants, for example "no `egress` tool is
allowed in a session holding `untrusted_input` and `private_data`" (see
[`examples/invariants.yaml`](../examples/invariants.yaml)).

## Engines: Cedar and the reference

The policy compiles to [Cedar](https://www.cedarpolicy.com/) and Cedar (via
[cedarpy](https://pypi.org/project/cedarpy/)) makes the runtime decision. The original
evaluator is kept as the reference semantics. Property-based tests generate thousands of
random policies and calls and require both to agree (D-040). If they ever disagreed at
runtime, gatehouse would use the stricter result and record
`basis: engine_disagreement`. `engine: native` uses only the reference evaluator. A
policy Cedar can't compile fails to load (`ErrorKind: engine`), which blocks every call.

`gatehouse policy compile POLICY` prints the Cedar policy; `--out DIR` writes
`policy.cedar` and `schema.cedarschema.json`, plus `entities.json` (one entity per pinned
tool, with its labels) when `--pins` is given.

## Proving invariants

`gatehouse policy prove POLICY --invariants FILE` checks statements that must hold for
**every** call, whatever the names, labels or arguments (D-041):

```yaml
version: 1
invariants:
  - name: deletes always need a human
    tools: "*delete*"
    never: allow                  # never allowed without approval
  - name: shells are always blocked
    tools: "*shell*"
    never: allow_or_approve       # always blocked
  - name: nothing leaves a session that read untrusted input and private data
    tool_labels: [egress]         # tools carrying egress (policy labels or hints)
    session_labels: [untrusted_input, private_data]
    never: allow
```

Scopes use `servers` and `tools` (`*` globs only), `tool_labels` and `session_labels`.
It exits with 0 if every invariant holds, 1 if one doesn't (with a counterexample), and
2 on errors.

- With the Cedar CLI built with `analyze` and cvc5 (`--cedar PATH`,
  `$GATEHOUSE_CEDAR_CLI`, or `cedar` on `PATH`), each invariant is **proved** by Cedar's
  symbolic compiler for every request the schema allows. Patterns with `?` or `[...]`
  are opaque to the solver, so a counterexample involving them may not be reachable.
  The output says so.
- Without it, a **bounded check** enumerates names built from the policy's own patterns
  (and pinned tools with `--pins`) and every outcome of their conditions. It finds real
  counterexamples but is not a proof, and says so. `--require-symcc` makes a missing
  prover an error; the `policy-prove` CI workflow uses it.

Argument conditions are opaque to `prove`: it considers both outcomes of every
condition. "`send_email` is allowed only to example.com" is the condition's own unit
test, not an invariant.

[`examples/invariants.yaml`](../examples/invariants.yaml) goes with
[`examples/policy-flow.yaml`](../examples/policy-flow.yaml). `prove` found two holes in its
first drafts:
- `delete_*` let a tool named `delete` through (the bounded check found this one);
- on `mail`, `read_*: allow` also allowed `read_delete`, because a server-specific glob
  beats a global `*delete*` rule (SymCC found this; the bounded check had missed it).

## Name normalization

Both names and patterns are normalized before matching:
drop Unicode format characters (zero-width, bidi controls, soft hyphen, tag characters)
→ NFKC → casefold → NFKC. So `Delete_Repo`, `ＤＥＬＥＴＥ_repo` (fullwidth), `𝐝𝐞𝐥𝐞𝐭𝐞_repo`
(mathematical bold) and `dele​te_repo` all match `delete_*`. Two patterns that are
identical after normalization (e.g. `Delete_*` and `delete_*`) are rejected as duplicates.

## Tool names are attacker-controlled

Server and tool names come from the MCP server, which is exactly the party a policy is meant
to constrain. A malicious or compromised server can call its exfiltration tool
`get_weather` instead of `upload_file`, so a name-based rule only constrains servers that
name their tools honestly. Normalization defeats cheap evasions of a rule you already have
(case changes, fullwidth letters, invisible characters). It does not make names
trustworthy, and it does not catch cross-script confusables such as Cyrillic `е` (U+0435)
standing in for Latin `e`. That gap is documented by an `xfail` test.

Treat policy as **one layer**:

- **Pinning** (MVP) binds each approved tool name to a hash of its full definition
  (description and input schema). A renamed, newly added or silently changed tool is not
  pinned, so it is filtered out or blocked before the policy is even consulted.
- **M2 content detectors** inspect what a tool *does* and *says* (poisoned descriptions,
  dangerous arguments, injected responses) regardless of its name. A planned
  confusable/mixed-script detector will flag names like `dеlete_repo`.
- Prefer allowlists (`default_action: block`). Against a dishonest server, a denylist of
  dangerous names is the weakest form of policy.

## Pinning

```yaml
pinning: strict            # optional, global: strict (default) | tofu | "off"
servers:
  "scratch-*":
    pinning: tofu          # per-server override; a server block may set only pinning
```

A pin is the SHA-256 of a tool's canonical definition: name, title, description,
inputSchema, outputSchema and annotations. Pins live in the pin store (`pins.json` in the
state directory, or `--pins`).

| Mode | Unpinned tool | Pinned tool whose definition changed |
|---|---|---|
| `strict` (default) | hidden (`listing.unpinned/tool-not-pinned`) until `gatehouse pin` | hidden (`listing.pin_mismatch`) |
| `tofu` | pinned automatically **only in the first listing of a server that has no pins yet**; tools that appear later are hidden (`listing.unpinned/new-tool-on-pinned-server`) until `gatehouse pin --tool NAME` | hidden (`listing.pin_mismatch`), never re-trusted automatically |
| `"off"` | visible | visible, and calls to tools that were never listed are allowed |

Hidden tools can't be called: a `tools/call` for a tool the client wasn't shown is
blocked (`DecisionBasis = unlisted_tool`), and so is a call made after
`notifications/tools/list_changed` and before the client lists tools again
(`stale_tool_list`).

The per-server override uses the most specific matching server pattern. Equally specific
patterns resolve to the strictest mode.

**Quote `"off"`.** YAML 1.1 reads a bare `off` as the boolean `false`, which the schema
rejects (and then gatehouse fails closed).

Why TOFU covers only the first listing (D-023): if a newly added tool on an
already-trusted server were trusted automatically, adding an `upload_everything` tool
would be a silent rug pull. The attack suite's `rugpull.new-tool-added` scenario covers
this.

## Findings

Detectors report findings with a severity. `findings:` maps severity to what gatehouse
does:

```yaml
findings:                  # optional; these are the defaults
  critical: block
  high: block
  medium: log
  low: log
  informational: log
```

`block` stops the call (or hides the tool, or withholds the result). `require_approval`
asks the user through MCP elicitation when the client supports it, and blocks otherwise
(see [Approval](#approval-through-elicitation)).
`log` lets the traffic through and records the detection. When several findings apply,
the strictest action wins. A finding can only make the policy decision stricter: a
`log` finding never turns a policy `block` into an allow.

### Per-rule severity

`findings.rules` changes the severity of individual rules, before the table above
applies. The event records the new severity, so Sentinel sees it too.

```yaml
findings:
  rules:
    "response.injection/xml-tag-instruction": medium   # noisy here: log, don't block
    "args.pii/*": high                                 # every PII rule blocks
```

- **Keys** are `detector_id/rule_id`, as they appear in events (`DetectorId`,
  `RuleId`). Either part may use `*` globs.
- **Precedence:** an exact key wins, then the longest matching glob.
- **Limits:** up to 256 entries. Keys must be lowercase. A key that doesn't match any
  rule is accepted and does nothing, so check event names before relying on one.
- **Scope:** the content detectors, meaning arguments, tool definitions and tool
  results. Pinning, policy decisions and flow control don't have severities to change.

## Classifiers

Model-based detectors run next to the rule detectors (ADR-0007). They catch paraphrased
and translated injections that regexes miss, but they cost latency and can fail, so each
one has a mode:

```yaml
classifiers:
  - id: pg2                       # [a-z0-9_], used in DetectorId classifier.pg2
    kind: prompt_guard            # local ONNX model: pip install 'gatehouse[classify]'
    model_dir: ~/models/prompt-guard-2-86m
    mode: shadow                  # shadow (default) | alert | enforce
    applies_to: [results, definitions]
    threshold: 0.9                # score >= threshold is a hit
    severity: high                # severity of a hit (enforce and alert)
    budget_ms: 500                # enforce: no answer in time = blocked
  - id: judge
    kind: ollama                  # a local model asked to judge
    model: llama3.2:3b
    endpoint: http://127.0.0.1:11434   # loopback only
  - id: shields
    kind: prompt_shields          # Azure AI Content Safety
    endpoint: https://<resource>.cognitiveservices.azure.com
    key_env: GATEHOUSE_CONTENT_SAFETY_KEY   # the key comes from the environment
```

- **`shadow`:** the classifier runs alongside the traffic without delaying it. Each
  verdict is a `classifier.verdict` event and nothing else. Use it to measure a model
  on your own traffic before trusting it.
- **`alert`:** also runs alongside. A hit is also a `detection` event (Action `logged`),
  so Sentinel rules fire. Nothing is blocked.
- **`enforce`:** the result or listing waits for the verdict, up to `budget_ms`.
  - A hit is a finding at `severity`, and the [findings table](#findings) decides: a
    result is withheld, or a tool is filtered.
  - No answer in time, an error or a missing model is a HIGH `classifier-unavailable`
    finding, so gatehouse fails closed. These findings don't count toward the circuit
    breaker.

**What a model sees.** It reads the strings of a result, or a tool's name, description
and schemas. MCP framing fields (`type`, `mimeType`, `uri`) are left out. Text is cut
into chunks of 2,000 characters, at most 5. The verdict is the highest chunk score,
and `Details.Truncated` says when text was left over. Definition verdicts are cached
per tool digest. No text is logged, only scores.

**Backends:**

- **`prompt_guard`** needs a local ONNX export of Meta's
  `meta-llama/Llama-Prompt-Guard-2-86M` in `model_dir` (`model.onnx`,
  `tokenizer.json`, `config.json`).
  - The model is gated on Hugging Face under the Llama license. Accept the license
    there, then export it yourself, for example
    `optimum-cli export onnx --model meta-llama/Llama-Prompt-Guard-2-86M --task text-classification ~/models/prompt-guard-2-86m`.
  - gatehouse never downloads or ships the model.
  - The attack class is read from `id2label` in `config.json`, and it defaults to
    index 1.
- **`ollama`** sends the text to a model on loopback (`/api/generate`, temperature 0,
  JSON answer). Any other host is rejected when the policy loads, because tool results
  are private. A yes/no judge scores 1.0 or 0.0, so leave `threshold` at its default.
- **`prompt_shields`** calls Azure AI Content Safety `text:shieldPrompt` (api-version
  `2024-09-01`) and sends the chunks as `documents`.
  - The text leaves the machine, so only use it where that is allowed.
  - Watch the resource's rate limit: F0 allows 5 requests per second.
  - A yes/no answer scores 1.0 or 0.0.

A classifier that can't start (missing key, `gatehouse[classify]` not installed, no
model) is announced at startup as `gatehouse.internal_error` (Component `classifier`).
In `enforce` mode, every verdict it should give then fails closed.

## Approval through elicitation

When a call resolves to `require_approval` (a policy rule, an incomparable tie, or a
finding mapped to it) and the client declared the `elicitation` capability in
`initialize`, gatehouse sends the client an `elicitation/create` request of its own: a
message naming the server, the tool, why approval is needed and the argument *names*
(never their values), and a one-field form, `approve` (boolean, default false).

- **Only an explicit yes approves:** `action: accept` with `approve: true`. Decline,
  cancel, an unchecked box, a JSON-RPC error, a malformed answer or no answer within
  `--approval-timeout` seconds (default 120) all deny the call.
- **The model never sees the request.** It goes to the client UI, and the answer is
  consumed by gatehouse and never forwarded to the server.
- **Approval is re-checked against the tool list.** If the server changes its tools while
  the user is deciding, the approved call is blocked (`(after approval)` in the reason).
- **Other traffic keeps flowing** while a call waits for the user.
- **Clients without elicitation** get the call blocked with outcome `approval_required`
  and the reason in the error text. `--approval-timeout 0` turns prompts off everywhere.
- Events: `approval.requested`, then `approval.granted` or `approval.denied`, then the
  `tool.call` event with action `approved`, `denied` or `blocked`.

**2026-07-28 clients** can't be sent requests, so gatehouse asks through MRTR instead: it
answers the `tools/call` itself with an `InputRequiredResult` holding the same form under
the key `gatehouse.approval`, plus a signed `requestState`. The client shows the form and
retries. The state is bound to the exact tool and arguments, expires after 10 minutes and
works once; gatehouse removes its own fields before forwarding the approved call, and
lets the server's own follow-up rounds for that same call through without asking again
(10 minutes, 8 uses). The events carry `Details.Channel: mrtr` (D-036).

Server requests and MRTR input requests that imitate gatehouse's prompt (they mention
gatehouse, or carry a `requestState` shaped like its own) are withheld
(`server_request.elicitation/mentions-gatehouse`, `server_request.shape/forged-gatehouse-state`).

**Order of approval channels:**
1. MRTR when the client speaks 2026-07-28 and declares form elicitation.
2. Otherwise legacy `elicitation/create` when the client declared `elicitation`.
3. Otherwise the call is blocked, with outcome `approval_required` on its `tool.call`
   event.

## Response controls

What gatehouse does after it has decided (ADR-0006, D-044). Every gatehouse on the
machine shares these through `<state dir>/control.sqlite3` and `<state dir>/KILL`. They
are on by default:

```yaml
controls:
  quarantine: true          # keep withheld results for `gatehouse review`
  circuit_breaker: 5        # lock the session after 5 calls/results with high findings; 0 = off
  approval_budget: {prompts: 20, minutes: 60}   # prompts per session per window; 0 = unlimited
```

| Control | What it does | Commands |
|---|---|---|
| **Kill switch** | While `<state dir>/KILL` exists, every gatehouse blocks every tool call and withholds every result. On POSIX, SIGUSR1 kills one process. | `gatehouse kill [--reason R]`, `gatehouse kill --off`. `touch` works too. |
| **Circuit breaker** | Counts one strike per call or result with a high or critical finding, across every server in the agent session. At the threshold the session is locked: every call is blocked until a human unlocks it. | `gatehouse unlock [--session ID \| --all]` |
| **Quarantine** | A withheld result is kept, owner-only and for 7 days, and the agent gets a stub with its id. After a human releases it, the agent's next identical call (same server, tool and arguments) gets the result once, without calling the server again. | `gatehouse review [list]`, `review show ID` (hidden characters shown as `⟦U+XXXX⟧`), `review release ID`, `review discard ID` |
| **Scoped grants** | "Allow `send_email` to `@mycorp.com` for 30 minutes." A live grant answers an approval that the policy or the Rule of Two asks for, but never one a detector asks for. | `gatehouse grant add mail send_email --when '{to: {email_domains: [mycorp.com]}}' --for 30m [--uses N]`, `grant list`, `grant revoke ID` |
| **Approval budget** | After N prompts in the window, calls that need approval are blocked instead of asked, and the reason suggests a scoped grant. The point is that the user isn't trained to click yes. | — |

- `gatehouse status` shows all of them.
- **The agent can't use these commands on itself.** A tool call whose arguments run
  `gatehouse review show|release|discard`, `grant add|revoke`, `unlock` or `kill --off`
  is blocked (`args.self_protect/gatehouse-control-command`). The state directory is
  already a protected path.
- **Failures are closed.**
  - An unreadable kill file counts as engaged.
  - An unreadable control store counts as locked.
  - A budget that can't be read doesn't ask (the call is blocked).
  - A grant that can't be read or spent grants nothing.
  - A result that can't be quarantined is still withheld.
- **Grant conditions** use the same syntax as rule conditions (see
  [Argument conditions](#argument-conditions)), so arguments a grant doesn't name aren't
  checked.

## Protocol settings

```yaml
protocol:
  max_ttl_ms: 300000      # cap on server cache hints (ttlMs); 0 disables client caching
  allow_downgrade: false  # true: report protocol downgrades, don't refuse them
  sampling: inspect       # or block: refuse every server sampling request
```

- **`max_ttl_ms`.** 2026-07-28 servers tell clients how long to cache discover, list and
  read results. A long TTL lets a client keep using a tool list after the server
  changed it, so gatehouse lowers larger values (`protocol.cache_hint_capped`). A
  listing gatehouse filtered is also marked `cacheScope: private`.
- **`allow_downgrade`.** gatehouse remembers the protocol revisions each server spoke (in
  the pin store). If a server that spoke 2026-07-28 later fails `server/discover`, drops
  that version, or negotiates an older handshake revision than the one the client asked
  for, that's a downgrade: an attacker in the middle, or a swapped server, pushing the
  client to a revision with weaker guarantees. By default gatehouse refuses it.
- **`sampling`.** Sampling requests are inspected for injected instructions either way;
  `block` refuses them outright.

## Load errors → fail closed

Any problem loading the policy makes gatehouse **block every call** and emit one
`policy.load_failed` event (severity `critical`, with `ErrorKind`, `Message`, `PolicyPath`,
and `PolicySha256` when the file was readable):

| ErrorKind | Examples |
|---|---|
| `io` | missing file, permission denied, path is a directory |
| `too_large` | over 1 MiB |
| `encoding` | not UTF-8 (a UTF-8 BOM is accepted) |
| `yaml` | syntax error, unquoted leading `*`, nesting too deep |
| `duplicate_key` | the same key twice in one mapping (PyYAML would otherwise keep the last) |
| `alias` | YAML anchors, aliases or `<<` merge keys |
| `schema` | unknown keys (typos), wrong types, unsupported `version`, unknown action, non-string keys such as unquoted `on`, empty/whitespace patterns, patterns colliding after normalization |
| `engine` | the Cedar engine could not be built (cedarpy missing, compiled policy rejected) |
| `internal` | a gatehouse bug; still fails closed |
