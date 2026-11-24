from __future__ import annotations

import textwrap
from collections.abc import Callable

import pytest

from gatehouse.policy import Policy, parse_policy


@pytest.fixture
def policy_from() -> Callable[[str], Policy]:
    """Parse a dedented YAML snippet into a Policy."""

    def _parse(text: str) -> Policy:
        return parse_policy(textwrap.dedent(text))

    return _parse
