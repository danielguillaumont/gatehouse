"""Response-control commands (ADR-0006): status, kill, unlock, review, grant.

These act on the machine's control store (``<state dir>/control.sqlite3``) and kill
switch file, which every running gatehouse checks on each call. They are for a human:
the self-protection detector blocks tool calls that try to run them (D-044).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from datetime import UTC, datetime
from typing import Any, cast

from pydantic import ValidationError

from gatehouse import paths
from gatehouse.policy.conditions import dump_conditions, parse_conditions
from gatehouse.policy.errors import PolicyError
from gatehouse.policy.loader import strict_yaml
from gatehouse.state.control import CONTROL_DB, ControlStore, ControlStoreError

MAX_GRANT_S = 7 * 24 * 3600
_DURATION = re.compile(r"(\d{1,6})([smhd])")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _out(text: str) -> None:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    sys.stdout.write(text.encode(encoding, "replace").decode(encoding, "replace") + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _store() -> ControlStore:
    return ControlStore(paths.state_dir() / CONTROL_DB)


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def duration(text: str) -> float:
    m = _DURATION.fullmatch(text.strip())
    if m is None:
        raise ValueError(f"bad duration {text!r}: use e.g. 90s, 30m, 8h, 2d")
    seconds = int(m.group(1)) * _UNITS[m.group(2)]
    if not 0 < seconds <= MAX_GRANT_S:
        raise ValueError("a grant lasts between 1 second and 7 days")
    return float(seconds)


def reveal(text: str) -> str:
    """Make hidden characters visible for a reviewer: format, control, private-use and
    unassigned code points are shown as ``⟦U+XXXX⟧`` (newlines and tabs are kept)."""
    out: list[str] = []
    for ch in text:
        if ch in "\n\t":
            out.append(ch)
        elif unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cn", "Zl", "Zp"):
            out.append(f"⟦U+{ord(ch):04X}⟧")
        else:
            out.append(ch)
    return "".join(out)


# ------------------------------------------------------------------ commands


def cmd_status(args: argparse.Namespace) -> int:
    store = _store()
    kill = store.kill_state()
    _out(f"kill switch: {'ENGAGED (' + kill.reason + ')' if kill else 'off'}")
    locks = store.locks()
    _out(f"locked sessions: {len(locks)}")
    for session, reason, at in locks:
        _out(f"  {session}  since {_when(at)}  {reason}")
    held = store.quarantined()
    _out(
        f"quarantined results: {sum(q.status == 'held' for q in held)} held, "
        f"{sum(q.status == 'released' for q in held)} released (not yet delivered)"
    )
    grants = store.grants()
    _out(f"live grants: {len(grants)}")
    return 0


def cmd_kill(args: argparse.Namespace) -> int:
    store = _store()
    if args.off:
        released = store.release_kill()
        _out("kill switch released" if released else "kill switch was not engaged")
        return 0
    path = store.engage(args.reason or "engaged with gatehouse kill")
    _out(f"kill switch ENGAGED: every gatehouse now blocks every tool call ({path})")
    _out("release it with: gatehouse kill --off")
    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    store = _store()
    if not args.all and not args.session:
        locks = store.locks()
        if len(locks) != 1:
            _err(f"{len(locks)} sessions are locked; name one with --session or use --all")
            for session, reason, _ in locks:
                _err(f"  {session}  {reason}")
            return 2
        args.session = locks[0][0]
    n = store.unlock(None if args.all else args.session)
    _out(f"unlocked {n} session(s)")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    store = _store()
    action = args.review_cmd or "list"
    if action == "list":
        items = store.quarantined(include_closed=args.all)
        if not items:
            _out("nothing in quarantine")
            return 0
        for q in items:
            _out(
                f"{q.id}  {q.status:<9} {_when(q.created)}  {q.server}/{q.tool}  "
                f"{q.size} bytes  {q.summary}"
            )
        return 0
    qid = args.id
    item = next((q for q in store.quarantined(include_closed=True) if q.id == qid), None)
    if item is None:
        _err(f"no quarantined result {qid}")
        return 1
    if action == "show":
        payload = store.quarantine_payload(qid)
        _out(f"id:      {item.id}\nstatus:  {item.status}\ntool:    {item.server}/{item.tool}")
        _out(f"when:    {_when(item.created)}\nsession: {item.session}\nwhy:     {item.summary}")
        if payload is None:
            _out("(content not kept: too large, discarded or delivered)")
            return 0
        _out("--- content (hidden characters shown as ⟦U+XXXX⟧) ---")
        _out(reveal(_render(json.loads(payload.decode("utf-8")))))
        return 0
    if action == "release":
        ok = store.set_status(qid, "released")
        if ok:
            _out(f"released {qid}: the agent receives it when it repeats the same call")
        else:
            _err(f"{qid} is {item.status} (only held results with content can be released)")
        return 0 if ok else 1
    ok = store.set_status(qid, "discarded")
    _out(f"discarded {qid}" if ok else f"{qid} is already {item.status}")
    return 0 if ok else 1


def _render(result: object) -> str:
    """Text content as text; everything else as indented JSON."""
    if not isinstance(result, dict):
        return json.dumps(result, indent=2, ensure_ascii=False)
    obj = cast(dict[str, Any], result)
    parts: list[str] = []
    content = obj.get("content")
    if isinstance(content, list):
        for raw in cast(list[Any], content):
            item = cast(dict[str, Any], raw) if isinstance(raw, dict) else None
            if item is not None and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(json.dumps(raw, indent=2, ensure_ascii=False))
    rest = {k: v for k, v in obj.items() if k != "content"}
    if rest:
        parts.append(json.dumps(rest, indent=2, ensure_ascii=False))
    return "\n".join(parts)


def cmd_grant(args: argparse.Namespace) -> int:
    store = _store()
    action = args.grant_cmd or "list"
    if action == "list":
        grants = store.grants(live_only=not args.all)
        if not grants:
            _out("no live grants")
        for g in grants:
            uses = "unlimited" if g.uses_left is None else str(g.uses_left)
            state = "revoked" if g.revoked else f"until {_when(g.expires)}"
            _out(
                f"{g.id}  {g.server}/{g.tool}  {state}  uses left: {uses}  "
                f"when: {json.dumps(g.conditions) if g.conditions else 'any arguments'}"
                + (f"  ({g.note})" if g.note else "")
            )
        return 0
    if action == "revoke":
        if not args.all and not args.id:
            _err("give a grant id, or --all")
            return 2
        n = store.revoke_grant(None if args.all else args.id)
        _out(f"revoked {n} grant(s)")
        return 0 if n else 1
    try:
        ttl = duration(args.duration)
        conditions = (
            dump_conditions(parse_conditions(strict_yaml(args.when, "--when"))) if args.when else {}
        )
    except (ValueError, ValidationError, PolicyError) as exc:
        _err(f"gatehouse grant add: {exc}")
        return 2
    if args.uses is not None and args.uses < 1:
        _err("gatehouse grant add: --uses must be at least 1")
        return 2
    grant = store.add_grant(
        server=args.server,
        tool=args.tool,
        conditions=conditions,
        ttl_s=ttl,
        uses=args.uses,
        note=args.note or "",
    )
    _out(
        f"granted {grant.id}: {grant.server}/{grant.tool} until {_when(grant.expires)}"
        + (f", {grant.uses_left} uses" if grant.uses_left is not None else "")
    )
    if not conditions:
        _out("note: no --when, so it covers any arguments to this tool")
    return 0


def add_parsers(sub: Any) -> None:
    sub.add_parser("status", help="kill switch, locked sessions, quarantine and grants")

    k = sub.add_parser("kill", help="engage the kill switch: every gatehouse blocks every call")
    k.add_argument("--reason", default=None)
    k.add_argument("--off", action="store_true", help="release the kill switch")

    u = sub.add_parser("unlock", help="unlock a session the circuit breaker locked")
    u.add_argument("--session", default=None, help="AgentSessionId (see gatehouse status)")
    u.add_argument("--all", action="store_true")

    r = sub.add_parser("review", help="review results gatehouse withheld")
    rs = r.add_subparsers(dest="review_cmd")
    rl = rs.add_parser("list", help="held and released results (default)")
    rl.add_argument("--all", action="store_true", help="include delivered and discarded")
    for name, text in (
        ("show", "show a result, with hidden characters made visible"),
        ("release", "deliver it when the agent repeats the call"),
        ("discard", "delete its content"),
    ):
        rs.add_parser(name, help=text).add_argument("id")

    g = sub.add_parser("grant", help="scoped approvals: allow a tool for a while without asking")
    gs = g.add_subparsers(dest="grant_cmd")
    ga = gs.add_parser(
        "add",
        help="allow a tool: grant add mail send_email --when '{to: {email_domains: [x.com]}}'",
    )
    ga.add_argument("server")
    ga.add_argument("tool", help="tool name (glob patterns allowed)")
    ga.add_argument("--when", default=None, help="argument conditions, as in a policy rule (YAML)")
    ga.add_argument("--for", dest="duration", default="30m", help="how long (default 30m, max 7d)")
    ga.add_argument("--uses", type=int, default=None, help="at most this many calls")
    ga.add_argument("--note", default=None)
    gl = gs.add_parser("list", help="live grants (default)")
    gl.add_argument("--all", action="store_true", help="include expired and revoked")
    gr = gs.add_parser("revoke")
    gr.add_argument("id", nargs="?")
    gr.add_argument("--all", action="store_true")


def dispatch(args: argparse.Namespace) -> int:
    handlers = {
        "status": cmd_status,
        "kill": cmd_kill,
        "unlock": cmd_unlock,
        "review": cmd_review,
        "grant": cmd_grant,
    }
    if args.cmd == "review" and args.review_cmd is None:
        args.all = False
    if args.cmd == "grant" and args.grant_cmd is None:
        args.all = False
    try:
        return handlers[args.cmd](args)
    except ControlStoreError as exc:
        _err(f"gatehouse {args.cmd}: {exc}")
        return 1


COMMANDS = frozenset({"status", "kill", "unlock", "review", "grant"})
