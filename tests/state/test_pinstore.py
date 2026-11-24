from __future__ import annotations

import threading
from pathlib import Path

import pytest

from gatehouse.state.pinstore import PinStoreError, load_pins, pin_tools


def _tool(name: str, desc: str = "d") -> dict[str, object]:
    return {"name": name, "description": desc, "inputSchema": {"type": "object"}}


def test_missing_store_is_empty(tmp_path: Path) -> None:
    assert load_pins(tmp_path / "none.json").servers == {}


def test_pin_and_reload(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    pin_tools(path, "fs", {"read": _tool("read")}, pinned_by="pin")
    store = load_pins(path)
    pin = store.server("fs").tools["read"]
    assert pin.pinned_by == "pin" and len(pin.sha256) == 64
    assert not path.with_name("pins.json.lock").exists()


def test_replace_server_drops_old_pins(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    pin_tools(path, "fs", {"a": _tool("a"), "b": _tool("b")}, pinned_by="pin")
    pin_tools(path, "fs", {"a": _tool("a")}, pinned_by="pin", replace_server=True)
    assert set(load_pins(path).server("fs").tools) == {"a"}


def test_only_new_does_not_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    pin_tools(path, "fs", {"a": _tool("a", "v1")}, pinned_by="tofu")
    pin_tools(path, "fs", {"a": _tool("a", "v2")}, pinned_by="tofu", only_new=True)
    assert load_pins(path).server("fs").tools["a"].definition["description"] == "v1"


def test_servers_are_independent(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    pin_tools(path, "a", {"t": _tool("t")}, pinned_by="pin")
    pin_tools(path, "b", {"t": _tool("t")}, pinned_by="pin", replace_server=True)
    assert set(load_pins(path).servers) == {"a", "b"}


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        '{"version": 2, "servers": {}}',
        '{"version": 1, "servers": {"s": {"tools": {"t": {"sha256": "x"}}}}}',
    ],
)
def test_corrupt_store_raises(tmp_path: Path, content: str) -> None:
    path = tmp_path / "pins.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PinStoreError):
        load_pins(path)


def test_concurrent_writers_do_not_lose_updates(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    errors: list[BaseException] = []

    def writer(i: int) -> None:
        try:
            pin_tools(path, f"server{i}", {"t": _tool("t")}, pinned_by="tofu")
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(load_pins(path).servers) == 12


def test_stale_lock_is_broken(tmp_path: Path) -> None:
    import os
    import time

    path = tmp_path / "pins.json"
    lock = tmp_path / "pins.json.lock"
    lock.write_text("999999", encoding="utf-8")
    old = time.time() - 3600
    os.utime(lock, (old, old))
    pin_tools(path, "fs", {"a": _tool("a")}, pinned_by="pin")
    assert "a" in load_pins(path).server("fs").tools
