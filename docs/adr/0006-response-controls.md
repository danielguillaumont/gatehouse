# ADR-0006: Response controls share one machine-wide store and a kill file

- Status: accepted (2026-11-27)
- Decision log: D-044.

## Context

v0.1 could block a call, but nothing came after that. There was no way to review what it
withheld, stop everything during an incident, slow down an agent that keeps tripping
detectors, or keep approvals from becoming reflexive. The v2 plan (L5) asks for:

- quarantine with review;
- scoped grants and an approval budget;
- a circuit breaker;
- a kill switch (file, signal, CLI, and later a remote signal).

gatehouse is one process per MCP server, and a human acts from a separate terminal. So
whatever a human does has to reach processes that are already running, and whatever
one process counts has to be visible to the others.

## Decision

- **One SQLite database**, `<state dir>/control.sqlite3` (WAL, busy timeout), holds
  strikes, locks, the approval budget, quarantined results and scoped grants. Counters
  and single-use operations run inside `BEGIN IMMEDIATE` transactions:
  - strikes;
  - prompts;
  - grant uses;
  - release delivery.

  So concurrent processes can't lose an increment or deliver a release twice. Tests run
  16 processes.
- **The kill switch is a file**, `<state dir>/KILL`, checked on every call and every
  result.
  - A file is what you can still create in a panic (`touch`), from a script, or from a
    future remote-control poller (M7).
  - A file that exists but can't be read counts as engaged.
  - SIGUSR1 kills a single process on POSIX. There's no Windows equivalent, so Windows
    uses the file.
- **Quarantine returns content by replay, not by injection.**
  - The agent gets a stub with an id.
  - After release, the agent's next identical call gets the stored result once, without
    reaching the server again, so a tool with side effects isn't run twice. The call is
    identified by an HMAC binding of server, tool and arguments.
  - gatehouse doesn't add a tool of its own to `tools/list`. That would change what the
    server offered and what pinning checks.
  - A released result adds `untrusted_input` to the session when flow control is on: it
    was withheld for a reason.
- **Grants answer only structural approvals.** A grant can stand in for an approval the
  policy or the Rule of Two asked for, but never for one a detector asked for: the
  injection that a detector flags is exactly what a pre-approved grant would wave
  through.
- **Humans only.** The control commands are blocked when they appear in tool-call
  arguments (`args.self_protect/gatehouse-control-command`), and the state directory
  was already a protected path.
- **Fail closed everywhere** (ADR-0001). See D-044 for each case.

## Consequences

- **Raw tool output now sits on disk.** Quarantined results stay in the control store
  for up to 7 days or until discarded or delivered. The file is created owner-only on
  POSIX; on Windows it inherits the per-user state directory's ACL. Results over 1 MiB
  are withheld but not kept. Events never carry the content.
- **The breaker can lock a benign session.** Five high findings in one session is a
  strong signal, but false positives count too. Unlocking is one command, and
  `circuit_breaker: 0` turns it off.
- **A same-user agent with an unrestricted shell can still tamper.** It could write the
  database through a path the self-protection rule doesn't recognise, or run gatehouse
  under another name. These controls stop the tool-call path, not a hostile local user.
  See `docs/known-bypasses.md`.
- **`gatehouse serve` sessions** share one AgentSessionId (ADR-0005), so the breaker and
  the budget count for every client of that serve process together.
