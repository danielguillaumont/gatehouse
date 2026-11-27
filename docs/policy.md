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
```

- Patterns are globs (`*`, `?`, `[abc]`, `[!abc]`), matched with `fnmatchcase` against
  normalized names (see below). They are not regexes and not paths: `.` and `/` are literal.
- **Quote patterns that start with `*`.** A bare `*` is YAML alias syntax and is rejected.
- `default_action` is required. There is no implicit default, so "allow" can never be an
  accident. The recommended style is an allowlist with `default_action: block`.

## Precedence

For a call to tool `T` on server `S`:

1. **Fail closed.** No valid policy → **block** (see "Load errors" below).
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
(`fail_closed | explicit_block | most_specific | tie | default`) for telemetry.

Consequences worth knowing:

- `"*": block` under a server blocks **every** tool on it, including any you also allow.
  Express allowlists with `default_action: block` plus allow rules instead.
- You cannot carve an exception out of a block. To allow `delete_draft` but block other
  deletes, write the block rules more narrowly.
- A server-specific allow beats a global `require_approval` on the same tool pattern rank
  (`github/list_*: allow` beats `*/*_exec*: require_approval` for `github.list_exec_jobs`).
  Only `block` is global by force.

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
| `internal` | a gatehouse bug; still fails closed |
