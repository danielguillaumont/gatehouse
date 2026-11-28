"""Capability labels for a tool (D-040). Pure functions, no I/O.

The policy is the source of truth: every ``labels:`` entry whose server and tool patterns
match applies, and they add up. Two kinds of hint can only *add* labels, never remove
them, because both come from the server:

- MCP annotations: ``destructiveHint: true`` or ``readOnlyHint: false`` add
  ``state_change``; ``openWorldHint: true`` adds ``untrusted_input`` and ``egress``.
- Name keywords (the same tokenizer as ``inspect.risk``): ``send_email`` adds ``egress``,
  ``fetch_url`` adds ``untrusted_input`` and ``egress``, ``delete_file`` adds
  ``state_change``.

A server that wants an egress tool to look harmless can rename it and drop its
annotations; that is why flow control is only as good as the policy's own labels, and
why docs/policy.md tells operators to label every egress tool explicitly.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from gatehouse.inspect.risk import tokens
from gatehouse.policy.models import Label, Policy

_EGRESS = frozenset(
    "send post upload publish email mail webhook notify message tweet share push sync "
    "http https fetch request curl wget browse navigate url slack sms invite forward reply "
    "comment".split()
)
_UNTRUSTED = frozenset("fetch browse navigate download scrape crawl web url http https".split())
_STATE = frozenset(
    "write create update delete remove rm move mv rename set put edit patch insert drop "
    "merge commit append modify save replace truncate chmod chown install kill exec "
    "execute run shell command cmd bash sh powershell pwsh eval script spawn deploy "
    "transfer pay".split()
)
_EXEC = frozenset("exec execute run shell command cmd bash sh powershell pwsh eval spawn".split())
_PRIVATE = frozenset(
    "secret secrets credential credentials password passwords vault keychain".split()
)


def policy_labels(policy: Policy, server: str, tool: str) -> frozenset[Label]:
    """Labels the policy gives the tool (every matching entry applies)."""
    return policy.labels_for(server, tool)


def name_hints(tool: str) -> frozenset[Label]:
    words = tokens(tool)
    out: set[Label] = set()
    if words & _EGRESS:
        out.add(Label.EGRESS)
    if words & _UNTRUSTED:
        out.add(Label.UNTRUSTED_INPUT)
    if words & _STATE:
        out.add(Label.STATE_CHANGE)
    if words & _EXEC:  # a shell can do anything, including sending data out
        out.add(Label.EGRESS)
    if words & _PRIVATE:
        out.add(Label.PRIVATE_DATA)
    return frozenset(out)


def annotation_hints(annotations: Mapping[str, Any] | None) -> frozenset[Label]:
    if not annotations:
        return frozenset()
    out: set[Label] = set()
    if annotations.get("destructiveHint") is True or annotations.get("readOnlyHint") is False:
        out.add(Label.STATE_CHANGE)
    if annotations.get("openWorldHint") is True:
        out |= {Label.UNTRUSTED_INPUT, Label.EGRESS}
    return frozenset(out)


def tool_labels(
    policy: Policy, server: str, tool: str, annotations: Mapping[str, Any] | None = None
) -> frozenset[Label]:
    """Every label the tool carries: the policy's, plus hints the policy allows."""
    labels = policy_labels(policy, server, tool)
    if policy.flow.name_hints:
        labels |= name_hints(tool)
    if policy.flow.annotation_hints:
        labels |= annotation_hints(annotations)
    return labels
