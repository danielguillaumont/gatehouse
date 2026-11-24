from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Never touch the real per-user state directory from tests."""
    home = tmp_path / "gatehouse-home"
    monkeypatch.setenv("GATEHOUSE_HOME", str(home))
    monkeypatch.setenv("GATEHOUSE_AGENT_SESSION_ID", "test-agent-session")
    yield home
