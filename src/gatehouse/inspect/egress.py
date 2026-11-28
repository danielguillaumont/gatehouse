"""Where an egress call is sending data: registrable domains only (D-057).

``egress_domains`` finds URL hosts and email domains in a call's arguments and reduces
each to its registrable domain (``mail.evil.example`` -> ``evil.example``). It drops the
subdomain, the URL path and query, and the email local part, because those are where
an exfiltrated secret travels (``<secret>.evil.example``, ``?d=<secret>``). The result
goes into ``tool.call`` events as ``Details.EgressDomains`` for egress tools, so
Sentinel can hunt rare destinations without ever seeing argument values.

The reduction is a heuristic, not the Public Suffix List: the last two labels, or the
last three when the top-level domain is two letters and the label before it is at most
three (``example.co.uk``). IP literals are kept as they are. Pure; bounded by
``iter_strings`` and ``MAX_DOMAINS``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from gatehouse.inspect.walk import WalkStats, iter_strings

MAX_DOMAINS = 8
MAX_SCAN_CHARS = 256 * 1024

# Bounded quantifiers only (ReDoS-safe): optional userinfo, then the host.
_URL_HOST = re.compile(
    r"(?i)\b(?:https?|wss?|ftp)://(?:[^\s/?#@]{0,256}@)?(\[[0-9a-f:.]{2,45}\]|[^\s/?#:\[\]@\"'<>]{1,253})"
)
_EMAIL_DOMAIN = re.compile(
    r"(?i)[a-z0-9._%+-]{1,64}@([a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,8}\.?)"
)


def registrable(host: str) -> str | None:
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2 or not all(re.fullmatch(r"[a-z0-9-]{1,63}", x) for x in labels):
        return None
    keep = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else 2
    return ".".join(labels[-keep:])


def egress_domains(arguments: Mapping[str, Any] | None) -> tuple[str, ...]:
    if not arguments:
        return ()
    found: list[str] = []
    scanned = 0
    for _, text in iter_strings(dict(arguments), "$", WalkStats(), include_keys=False):
        if scanned >= MAX_SCAN_CHARS:
            break
        chunk = text[: MAX_SCAN_CHARS - scanned]
        scanned += len(chunk)
        for pattern in (_URL_HOST, _EMAIL_DOMAIN):
            for m in pattern.finditer(chunk):
                domain = registrable(m.group(1))
                if domain is not None and domain not in found:
                    found.append(domain)
                    if len(found) >= MAX_DOMAINS:
                        return tuple(found)
    return tuple(found)
