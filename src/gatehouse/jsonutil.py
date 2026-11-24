"""Narrow untrusted JSON values to concrete types (or None) in one place."""

from __future__ import annotations

from typing import Any, cast


def as_obj(value: object) -> dict[str, Any] | None:
    return cast(dict[str, Any], value) if isinstance(value, dict) else None


def as_list(value: object) -> list[Any] | None:
    return cast(list[Any], value) if isinstance(value, list) else None


def as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None
