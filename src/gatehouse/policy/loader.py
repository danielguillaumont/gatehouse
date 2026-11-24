"""Load and validate policy files. Any failure means fail-closed.

Two entry points:

- ``parse_policy(data)`` is strict and raises ``PolicyError``. Use it for tests and for a
  future ``gatehouse validate-policy`` command.
- ``load_policy(path)`` never raises. It returns a ``PolicyLoad``. On failure, ``policy``
  is ``None`` and ``error`` holds a ``PolicyLoadFailed`` event; ``engine.decide`` then
  blocks every call.
"""

# PyYAML's Composer/Constructor internals are untyped in types-PyYAML; the strict
# "unknown type" checks are relaxed for this file only.
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from gatehouse.policy.errors import (
    MAX_ERROR_MESSAGE_LEN,
    PolicyError,
    PolicyErrorKind,
    PolicyLoadFailed,
)
from gatehouse.policy.models import Policy

MAX_POLICY_BYTES = 1024 * 1024
_QUOTE_HINT = 'Hint: patterns starting with \'*\' must be quoted, e.g. "*" or "*_exec*".'


def _line(item: Any) -> int:
    """1-based line of a YAML event or node, or 0 if unknown."""
    mark = getattr(item, "start_mark", None)
    return mark.line + 1 if mark is not None else 0


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that also rejects duplicate keys, anchors and aliases.

    - Duplicate keys: PyYAML silently keeps the last value, so a second
      `delete_repo: allow` could silently override an earlier `delete_repo: block`.
    - Anchors/aliases (and therefore `<<` merge keys): they make the effective policy
      differ from what a reviewer reads line by line, and they enable alias-expansion
      ("billion laughs") tricks.
    """

    def compose_node(self, parent: Any, index: Any) -> Any:
        event: Any = self.peek_event()
        if isinstance(event, yaml.AliasEvent):
            raise PolicyError(
                PolicyErrorKind.ALIAS,
                f"YAML aliases are not allowed (line {_line(event)}). {_QUOTE_HINT}",
            )
        if getattr(event, "anchor", None) is not None:
            raise PolicyError(
                PolicyErrorKind.ALIAS, f"YAML anchors are not allowed (line {_line(event)})"
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        if isinstance(node, yaml.MappingNode):
            first_seen: dict[Any, int] = {}
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=True)
                line = _line(key_node)
                try:
                    previous = first_seen.get(key)
                except TypeError:
                    raise PolicyError(
                        PolicyErrorKind.SCHEMA, f"mapping keys must be scalars (line {line})"
                    ) from None
                if previous is not None:
                    raise PolicyError(
                        PolicyErrorKind.DUPLICATE_KEY,
                        f"duplicate key {key!r} at line {line} (first defined at line {previous})",
                    )
                first_seen[key] = line
        return super().construct_mapping(node, deep=deep)


def _one_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _format_validation_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


def parse_policy(data: bytes | str) -> Policy:
    """Parse and validate policy content. Raises ``PolicyError`` on any problem."""
    raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw_bytes) > MAX_POLICY_BYTES:
        raise PolicyError(PolicyErrorKind.TOO_LARGE, f"policy exceeds {MAX_POLICY_BYTES} bytes")
    try:
        # utf-8-sig: tolerate a BOM (Windows PowerShell 5.1 `Out-File` writes one).
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PolicyError(
            PolicyErrorKind.ENCODING, f"policy is not valid UTF-8 (byte offset {exc.start})"
        ) from None

    try:
        document = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except PolicyError:
        raise
    except yaml.YAMLError as exc:
        message = _one_line(str(exc))
        if "alias" in message:  # e.g. an unquoted `*: allow` is scanned as an alias
            message += f" {_QUOTE_HINT}"
        raise PolicyError(PolicyErrorKind.YAML, message) from None
    except RecursionError:
        raise PolicyError(PolicyErrorKind.YAML, "policy YAML is nested too deeply") from None

    if document is None:
        raise PolicyError(PolicyErrorKind.SCHEMA, "policy file is empty")
    if not isinstance(document, dict):
        raise PolicyError(
            PolicyErrorKind.SCHEMA,
            f"top level must be a mapping, got {type(document).__name__}",
        )

    try:
        return Policy.model_validate(document)
    except ValidationError as exc:
        raise PolicyError(PolicyErrorKind.SCHEMA, _format_validation_error(exc)) from None


class PolicyLoad(BaseModel):
    """Result of ``load_policy``: exactly one of ``policy`` / ``error`` is set."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str | None
    policy: Policy | None
    error: PolicyLoadFailed | None

    @model_validator(mode="after")
    def _exactly_one(self) -> PolicyLoad:
        if (self.policy is None) == (self.error is None):
            raise ValueError("exactly one of policy / error must be set")
        return self

    @property
    def ok(self) -> bool:
        return self.policy is not None


def load_policy(path: str | Path) -> PolicyLoad:
    """Load a policy file. Never raises: every failure becomes a fail-closed ``PolicyLoad``."""
    path_str = str(path)
    sha256: str | None = None
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_POLICY_BYTES + 1)
        if len(data) <= MAX_POLICY_BYTES:
            sha256 = hashlib.sha256(data).hexdigest()
        policy = parse_policy(data)
        return PolicyLoad(path=path_str, sha256=sha256, policy=policy, error=None)
    except PolicyError as exc:
        kind, message = exc.kind, exc.message
    except OSError as exc:
        kind, message = PolicyErrorKind.IO, f"cannot read policy file: {exc.strerror or exc}"
    except Exception as exc:  # fail closed on bugs too, but say so
        kind, message = PolicyErrorKind.INTERNAL, f"{type(exc).__name__}: {exc}"

    event = PolicyLoadFailed(
        time_generated=datetime.now(UTC),
        policy_path=path_str,
        policy_sha256=sha256,
        error_kind=kind,
        message=message[:MAX_ERROR_MESSAGE_LEN],
    )
    return PolicyLoad(path=path_str, sha256=sha256, policy=None, error=event)
