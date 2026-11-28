# ADR-0005: Session flow control lives in a shared, grow-only store

- Status: accepted (2026-11-27)
- Decision log: D-040, D-042.

## Context

The Rule of Two (Meta, 2025) says an agent session should have at most two of:

- (A) untrusted input;
- (B) private data;
- (C) the ability to change state or send data out.

A prompt injection in A can then reach B or C, but not both, which rules out the classic
exfiltration chain whatever the injection says.

gatehouse runs one process per MCP server, so the three properties usually come from
different processes: notes on one server, the web on a second, email on a third. A
decision on the email server needs to know what the agent read through the other two.
The processes don't talk to each other, and the v0.1 pin store showed how a shared file
loses updates under contention (D-010, `7577e2d`).

## Decision

- **State.** A grow-only set of facts per agent session: capability labels now,
  provenance fingerprints next. It lives in one SQLite database in the state directory
  (WAL, busy timeout), keyed by `AgentSessionId`, which every gatehouse under the same
  agent process derives alike.
  - Every write is a single `INSERT OR IGNORE` row. With no read-modify-write anywhere,
    concurrent writers can't lose updates. A test runs 48 writer processes.
- **When labels join.**
  - A tool's labels join the session *before* gatehouse forwards the call, so another
    server never decides against a session older than a call already in flight.
  - A result in which a detector finds injected instructions adds `untrusted_input`
    whatever the tool's labels.
- **Where labels come from.** The policy is the source. Server annotations and the
  tool-name heuristic may only add labels.
- **The check.** It's part of the policy decision, in both engines: a call completes the
  trifecta if the session's labels plus the tool's labels cover A, B and C and the tool
  contributes at least one. Modes:
  - `monitor`: log only;
  - `approve`: allow becomes require approval;
  - `enforce`: block.
  - It is order-independent and has no time window (D-037).
- **Failures stay closed** (ADR-0001), so no new fail-open path:
  - A store that can't be read counts as holding every label.
  - A label that can't be written blocks the call (or withholds the result) instead of
    being forgotten.
- **Off by default.** With `flow.mode: off` (the default, v0.1 behaviour) the store is
  never opened.

## Consequences

- Cross-server exfiltration chains are stopped by structure, not by spotting the
  injection. The `flow.*` attack scenarios measure this, including chains whose
  injection no detector flags.
- **Approval fatigue is real.** Once a session holds A and B, every labelled egress or
  state change needs a human. The README reports approvals per benign task. Scoped
  grants and the approval budget (M5) are the mitigation.
- **Labels can be wrong.** A tool the policy doesn't label and whose name and
  annotations don't give it away isn't counted. `gatehouse policy prove` can check
  invariants such as "no egress-labelled tool is allowed in a tainted session", but it
  can't find tools the policy forgot to label. Operators should label every egress tool.
- **One serve process is one session.** `gatehouse serve` (HTTP) derives the session
  from its own parent process, so every client of one serve instance shares labels.
  That errs on the strict side. Per-client sessions need authenticated principals (M7).
- **Results are not attributed.** A label says the session saw something, not which
  value went where. Provenance fingerprints (D-043) add that evidence for verbatim
  copies.
