# ADR-0004: Approval in 2026-07-28 is a signed, single-use MRTR round

- Status: accepted (2026-11-27)
- Decision log: D-036.

## Context

In v0.1 a `require_approval` call is held while gatehouse sends the client an
`elicitation/create` request on the same connection and waits for the answer. 2026-07-28
removes server-to-client requests on stdio and makes every request self-contained. A
server that needs user input returns `resultType: "input_required"` with
`inputRequests` and an opaque `requestState`, and the client retries the same call with
`inputResponses` and the state.

gatehouse can use the same mechanism to ask for approval. But the retry comes back as a
new request, possibly on a different HTTP POST, so gatehouse has to recognise its own
round and tell it apart from a forged or replayed one.

## Decision

- gatehouse answers a `require_approval` call itself with `input_required`: one form
  elicitation that names the server, the tool and the policy reason, and a
  `requestState` that gatehouse owns.
- The state is an HMAC (per-install key) over the server, tool, a hash of the
  arguments, a random nonce and an expiry. It is bound to that exact call, so a state
  issued for `merge_pr {"id": 1}` can't approve `merge_pr {"id": 2}` or `delete_repo`.
- A state is accepted once (the nonce is consumed), and only before its expiry. A replay
  is blocked and reported.
- On approval, gatehouse forwards the original call **without** its own state or
  answers, so the server never sees gatehouse's input round. A server's own MRTR rounds
  pass through and are inspected as before.
- An approval can open a short grant (600 s, at most 8 uses, same server, tool and
  argument hash) so an agent retrying the identical call is not asked again.

## Consequences

- Approval works over stdio and HTTP, statelessly, with no held request.
- The approval form is visibly gatehouse's (`gatehouse` in the message). A server's input
  request that impersonates gatehouse is a detection
  (`modern.mrtr.impersonates-gatehouse`).
- Consumed nonces live in memory, so after a restart a replay within the expiry window
  would be accepted once. The window is 600 s, and the
  replayed call is the one the user approved.
