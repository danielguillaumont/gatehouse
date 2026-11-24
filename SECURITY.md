# Security policy

gatehouse is a security tool, so bugs in it can be security bugs. Thank you for reporting
them privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on
this repository. Please don't open a public issue for anything in the "in scope" list
below.

Include the gatehouse version (`gatehouse --version`), OS and Python version, the policy
you used, and ideally an attack-suite scenario (`attacks/scenarios/*.yaml`) that
reproduces it. The harness makes this easy: a scenario that succeeds through
`--target gatehouse` is a precise bug report.

You can expect an acknowledgement within a week. gatehouse is maintained by one person,
so fixes are best-effort.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## In scope

- **A fail-open path that isn't announced:** traffic allowed when the policy is invalid,
  the pin store is unreadable, approval fails, or anything else ADR-0001 lists as fail
  closed, without a `gatehouse.fail_open` event.
- **Secrets or raw arguments in logs:** any event, stderr line or Sentinel record that
  contains a tool argument value, a tool result, or an unredacted secret.
- **Non-MCP output on stdout,** or a frame that gatehouse and the server parse
  differently (parser-differential smuggling).
- **Policy or pinning bypass:** a call to a blocked or unlisted tool reaching the server,
  or a changed tool definition reaching the client without `listing.pin_mismatch`.
- **Approval bypass:** a `require_approval` call forwarded without an explicit accept.
- **Denial of service:** a regex or input that makes gatehouse use excessive CPU or memory
  (rules are meant to be bounded and keyword-gated).

## Out of scope (already documented)

Detection misses listed in [`docs/known-bypasses.md`](docs/known-bypasses.md), such as
paraphrased prompt injection or encodings the detectors don't decode. Content detection
is defense in depth, not a guarantee, and those limits are published. A *new* bypass
class is still welcome as a regular issue with a scenario.
