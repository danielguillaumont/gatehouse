"""Argument conditions for policy rules (D-040). Pure functions, no I/O.

A rule's ``when:`` maps argument names to one condition each; the rule's ``action``
applies only if every condition holds, otherwise its ``otherwise`` action does.

Each condition applies to *every* value the argument carries: a string, or a list of
strings (and numbers, for ``max``/``min``/``one_of``). A missing argument, an empty list,
a value of the wrong type or a value that does not parse fails the condition. Failing is
always the safe direction because ``otherwise`` must be stricter than ``action``.

Inputs come from the agent (and, through it, possibly from an injected prompt), so every
parser here is bounded: at most ``MAX_VALUES`` values per argument and ``MAX_VALUE_LEN``
characters per value, and the one regex is linear.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Iterable, Mapping
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    TypeAdapter,
    model_validator,
)

MAX_VALUES = 64
MAX_VALUE_LEN = 4096
MAX_LIST_ITEMS = 256

# Addresses inside a recipient string: "a@x.com, B <b@y.org>; c@z.net". Linear: the
# local part and domain are bounded character classes with no nested quantifiers.
_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]{1,64}@([A-Za-z0-9.-]{1,253})")
_SPLIT = re.compile(r"[,;\s]+")
_DOMAIN = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9-]{1,63}")

HostPattern = Annotated[StrictStr, Field(min_length=1, max_length=253)]
Number = StrictInt | float


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _check_hosts(patterns: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for p in patterns:
        low = p.lower().rstrip(".")
        if p != p.strip() or not _DOMAIN.fullmatch(low):
            raise ValueError(f"{p!r} is not a host name or '*.' suffix pattern")
        out.append(low)
    return tuple(out)


class EmailDomains(_Strict):
    """Every address in the argument has a domain in the list (exact or ``*.suffix``)."""

    email_domains: Annotated[tuple[HostPattern, ...], Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def _hosts(self) -> EmailDomains:
        object.__setattr__(self, "email_domains", _check_hosts(self.email_domains))
        return self


class UrlHosts(_Strict):
    """Every value is an http(s) URL whose host is in the list (exact or ``*.suffix``)."""

    url_hosts: Annotated[tuple[HostPattern, ...], Field(min_length=1, max_length=256)]
    schemes: tuple[Literal["http", "https"], ...] = ("https",)

    @model_validator(mode="after")
    def _hosts(self) -> UrlHosts:
        object.__setattr__(self, "url_hosts", _check_hosts(self.url_hosts))
        return self


class PathUnder(_Strict):
    """Every value is a path that stays under one of the roots after normalization."""

    path_under: Annotated[
        tuple[Annotated[StrictStr, Field(min_length=1, max_length=1024)], ...],
        Field(min_length=1, max_length=64),
    ]

    @model_validator(mode="after")
    def _roots(self) -> PathUnder:
        roots: list[str] = []
        for r in self.path_under:
            norm = normalize_path(r)
            if norm is None:
                raise ValueError(f"path root {r!r} is not an absolute path")
            roots.append(norm)
        object.__setattr__(self, "path_under", tuple(roots))
        return self


class NumberRange(_Strict):
    """Every value is a number (not a bool, not a numeric string) within the bounds."""

    max: Number | None = None
    min: Number | None = None

    @model_validator(mode="after")
    def _bounded(self) -> NumberRange:
        if self.max is None and self.min is None:
            raise ValueError("a numeric condition needs `max` and/or `min`")
        for v in (self.max, self.min):
            if isinstance(v, float) and not math.isfinite(v):
                raise ValueError("numeric bounds must be finite")
        if self.max is not None and self.min is not None and self.min > self.max:
            raise ValueError("`min` is greater than `max`")
        return self


class OneOf(_Strict):
    """Every value is one of the listed strings or numbers (exact, case-sensitive)."""

    one_of: Annotated[
        tuple[Annotated[StrictStr, Field(max_length=MAX_VALUE_LEN)] | Number, ...],
        Field(min_length=1, max_length=MAX_LIST_ITEMS),
    ]


Condition = EmailDomains | UrlHosts | PathUnder | NumberRange | OneOf


# ---------------------------------------------------------------------- evaluation


def _values(value: object) -> list[object] | None:
    """The values a condition is checked against, or None if there are none or too many."""
    items: list[object] = list(value) if isinstance(value, list) else [value]  # pyright: ignore[reportUnknownArgumentType]
    if not items or len(items) > MAX_VALUES:
        return None
    return items


def _strings(value: object) -> list[str] | None:
    items = _values(value)
    if items is None or not all(isinstance(v, str) and len(v) <= MAX_VALUE_LEN for v in items):
        return None
    return [v for v in items if isinstance(v, str)]


def host_matches(host: str, patterns: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    for p in patterns:
        if p.startswith("*."):
            if host.endswith(p[1:]) and len(host) > len(p) - 1:
                return True
        elif host == p:
            return True
    return False


def email_domains(value: object) -> list[str] | None:
    """Domains of every address in the value; None if any piece is not an address."""
    strings = _strings(value)
    if strings is None:
        return None
    domains: list[str] = []
    for s in strings:
        pieces = [p for p in _SPLIT.split(s) if p]
        found = False
        for piece in pieces:
            m = _EMAIL.search(piece)
            if m is None:
                # A display name ("Alice <a@x.com>") splits into words; only pieces that
                # carry an '@' must parse. A bare '@' fragment means a malformed address.
                if "@" in piece:
                    return None
                continue
            domains.append(m.group(1).lower().rstrip("."))
            found = True
            if len(domains) > MAX_VALUES:
                return None
        if not found:
            return None
    return domains or None


def url_host(value: str, schemes: Iterable[str]) -> str | None:
    """Host of an absolute http(s) URL, or None. Userinfo, ports and IDNA are handled;
    an IP literal is returned as text so only an explicit allowlist entry matches it."""
    if any(c in value for c in "\r\n\t\\ ") or not value.isascii():
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
        _ = parts.port  # raises on a malformed port
    except ValueError:
        return None
    if parts.scheme.lower() not in schemes or not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.lower().rstrip(".")
    return host if _DOMAIN.fullmatch(host) and not host.startswith("*") else None


def normalize_path(value: str) -> str | None:
    """Lexical normalization of an absolute POSIX or Windows path, or None.

    ``/a/./b/../c`` -> ``/a/c``; ``C:\\Users\\x`` -> ``c:/users/x`` (Windows paths are
    case-insensitive). A ``..`` that would climb above the root, a relative path, a NUL,
    a UNC/device path or a ``~`` that was not expanded fails. Symlinks are not resolved
    (this is a pure function); the server could still follow one out of the root, which
    is documented in docs/policy.md.
    """
    if not value or len(value) > MAX_VALUE_LEN or "\x00" in value:
        return None
    windows = re.match(r"[A-Za-z]:[\\/]", value) is not None
    if windows:
        drive, rest = value[:2].lower(), value[2:].replace("\\", "/")
    elif value.startswith("/") and not value.startswith("//"):
        drive, rest = "", value
    else:
        return None
    out: list[str] = []
    for part in rest.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not out:
                return None
            out.pop()
            continue
        out.append(part.lower() if windows else part)
    return drive + "/" + "/".join(out)


def path_is_under(path: str, roots: Iterable[str]) -> bool:
    norm = normalize_path(path)
    if norm is None:
        return False
    return any(norm == r or norm.startswith(r.rstrip("/") + "/") for r in roots)


def _number(v: object) -> float | int | None:
    if isinstance(v, bool) or not isinstance(v, int | float):
        return None
    if isinstance(v, float) and not math.isfinite(v):
        return None
    return v


def holds(condition: Condition, value: object) -> bool:
    """True if the condition holds for every value of the argument."""
    match condition:
        case EmailDomains(email_domains=allowed):
            domains = email_domains(value)
            return domains is not None and all(host_matches(d, allowed) for d in domains)
        case UrlHosts(url_hosts=allowed, schemes=schemes):
            strings = _strings(value)
            if strings is None:
                return False
            hosts = [url_host(s, schemes) for s in strings]
            return all(h is not None and host_matches(h, allowed) for h in hosts)
        case PathUnder(path_under=roots):
            strings = _strings(value)
            return strings is not None and all(path_is_under(s, roots) for s in strings)
        case NumberRange(max=hi, min=lo):
            items = _values(value)
            if items is None:
                return False
            for item in items:
                n = _number(item)
                if n is None or (hi is not None and n > hi) or (lo is not None and n < lo):
                    return False
            return True
        case OneOf(one_of=allowed):
            items = _values(value)
            if items is None:
                return False
            for item in items:
                if isinstance(item, bool) or item not in allowed:
                    return False
                if not isinstance(item, str | int | float):
                    return False
            return True


def all_hold(conditions: Mapping[str, Condition], arguments: Mapping[str, Any] | None) -> bool:
    """True if every condition holds for its argument. No arguments: nothing holds."""
    if arguments is None:
        return False
    for name, condition in conditions.items():
        if name not in arguments or arguments[name] is None:
            return False
        if not holds(condition, arguments[name]):
            return False
    return True


_CONDITIONS: TypeAdapter[dict[str, Condition]] = TypeAdapter(dict[str, Condition])


def parse_conditions(data: object) -> dict[str, Condition]:
    """Validate an ``{argument: condition}`` mapping (scoped grants store them as JSON)."""
    parsed = _CONDITIONS.validate_python(data)
    if len(parsed) > 32:
        raise ValueError("at most 32 argument conditions")
    return parsed


def dump_conditions(conditions: Mapping[str, Condition]) -> dict[str, Any]:
    return _CONDITIONS.dump_python(dict(conditions), mode="json", exclude_defaults=False)
