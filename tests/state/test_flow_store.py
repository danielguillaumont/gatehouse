"""The shared flow store: grow-only, shared across processes, no lost updates."""

from __future__ import annotations

import multiprocessing
import sqlite3
from pathlib import Path

import pytest

from gatehouse.policy import Label
from gatehouse.state.flow import FlowStore, FlowStoreError

WRITERS = 48
FACTS_PER_WRITER = 40


def test_labels_are_shared_between_stores(tmp_path: Path) -> None:
    db = tmp_path / "flow.sqlite3"
    a, b = FlowStore(db), FlowStore(db)
    a.add_labels("s1", [Label.PRIVATE_DATA], server="notes", tool="read")
    b.add_labels("s1", [Label.UNTRUSTED_INPUT], server="web", tool="fetch")
    b.add_labels("s2", [Label.EGRESS], server="mail", tool="send")
    assert a.labels("s1") == {Label.PRIVATE_DATA, Label.UNTRUSTED_INPUT}
    assert a.labels("s2") == {Label.EGRESS}
    assert a.labels("nobody") == frozenset()


def test_find_reports_where_a_fact_came_from(tmp_path: Path) -> None:
    db = tmp_path / "flow.sqlite3"
    a, b = FlowStore(db), FlowStore(db)
    a.add("s", "fp", [f"s:{i:016x}" for i in range(1200)], server="notes", tool="read_note")
    found = b.find("s", "fp", ["s:0000000000000005", "s:00000000000004af", "s:ffff"])
    assert found == {
        "s:0000000000000005": ("notes", "read_note"),
        "s:00000000000004af": ("notes", "read_note"),
    }
    assert b.find("other", "fp", ["s:0000000000000005"]) == {}


def test_memory_store() -> None:
    store = FlowStore(None)
    store.add_labels("s", [Label.EGRESS, Label.EGRESS], server="x", tool="y")
    assert store.labels("s") == {Label.EGRESS}


def test_unknown_label_values_are_ignored(tmp_path: Path) -> None:
    db = tmp_path / "flow.sqlite3"
    store = FlowStore(db)
    store.add("s", "label", ["egress", "made_up"], server="x", tool="y")
    assert store.labels("s") == {Label.EGRESS}


def test_write_failure_keeps_the_fact_locally(tmp_path: Path) -> None:
    store = FlowStore(tmp_path / "flow.sqlite3")
    assert store._conn is not None  # pyright: ignore[reportPrivateUsage]
    store._conn.close()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(FlowStoreError):
        store.add_labels("s", [Label.EGRESS], server="x", tool="y")
    store._conn = None  # pyright: ignore[reportPrivateUsage]
    assert store.labels("s") == {Label.EGRESS}


def test_read_failure_raises(tmp_path: Path) -> None:
    store = FlowStore(tmp_path / "flow.sqlite3")
    assert store._conn is not None  # pyright: ignore[reportPrivateUsage]
    store._conn.close()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(FlowStoreError):
        store.labels("s")


def test_unsupported_schema_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "flow.sqlite3"
    FlowStore(db).close()
    conn = sqlite3.connect(db)
    conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema'")
    conn.commit()
    conn.close()
    with pytest.raises(FlowStoreError, match="schema"):
        FlowStore(db)


def _writer(db: str, n: int) -> None:
    store = FlowStore(Path(db))
    for i in range(FACTS_PER_WRITER):
        store.add("shared", "fp", [f"w{n}-{i}"], server=f"s{n}", tool="t")
        store.add_labels(f"own{n}", [Label.EGRESS], server=f"s{n}", tool="t")
    store.close()


def test_concurrent_writers_lose_nothing(tmp_path: Path) -> None:
    # ROADMAP M5: the v0.1 pin store lost updates under contention (7577e2d). Many
    # processes write to one database at once; every fact must survive.
    db = tmp_path / "flow.sqlite3"
    FlowStore(db).close()
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(str(db), n)) for n in range(WRITERS)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=180)
        assert p.exitcode == 0
    store = FlowStore(db)
    assert len(store.facts("shared", "fp")) == WRITERS * FACTS_PER_WRITER
    assert all(store.labels(f"own{n}") == {Label.EGRESS} for n in range(WRITERS))
