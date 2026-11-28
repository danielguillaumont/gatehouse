"""The control store: atomic counters and single-use releases across processes."""

from __future__ import annotations

import multiprocessing
import sys
from pathlib import Path

import pytest

from gatehouse.state.control import ControlStore

PROCS = 16
PER_PROC = 25


def _striker(db: str) -> None:
    store = ControlStore(Path(db))
    for _ in range(PER_PROC):
        store.strike("s")
        store.take_prompt("budget", 10_000, 3600)
    store.close()


def test_concurrent_strikes_and_prompts_are_all_counted(tmp_path: Path) -> None:
    db = tmp_path / "control.sqlite3"
    ControlStore(db).close()
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_striker, args=(str(db),)) for _ in range(PROCS)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=180)
        assert p.exitcode == 0
    store = ControlStore(db)
    assert store.strike("s") == PROCS * PER_PROC + 1
    # The budget row holds exactly the prompts taken.
    assert store.take_prompt("budget", PROCS * PER_PROC + 1, 3600)
    assert not store.take_prompt("budget", PROCS * PER_PROC + 1, 3600)


def test_budget_window_resets(tmp_path: Path) -> None:
    store = ControlStore(tmp_path / "c.sqlite3")
    assert store.take_prompt("s", 1, 3600)
    assert not store.take_prompt("s", 1, 3600)
    assert store.take_prompt("s", 1, 0.0)  # a zero-length window has always expired
    assert store.take_prompt("other", 1, 3600)  # per session
    assert store.take_prompt("s", 0, 3600)  # 0 = unlimited


def test_release_is_delivered_once(tmp_path: Path) -> None:
    db = tmp_path / "c.sqlite3"
    a, b = ControlStore(db), ControlStore(db)
    qid = a.quarantine(
        session="s", server="mail", tool="read", call_key="k", summary="x", payload=b'{"a":1}'
    )
    assert a.take_released("s", "mail", "k") is None  # held, not released
    assert b.set_status(qid, "released")
    assert a.take_released("s", "mail", "k") == (qid, b'{"a":1}')
    assert b.take_released("s", "mail", "k") is None
    assert a.quarantine_payload(qid) is None  # content dropped once delivered
    assert not b.set_status(qid, "released")


def test_oversized_results_are_withheld_but_not_kept(tmp_path: Path) -> None:
    store = ControlStore(tmp_path / "c.sqlite3")
    qid = store.quarantine(
        session="s", server="m", tool="t", call_key="k", summary="x", payload=b"x" * (2 << 20)
    )
    assert store.quarantine_payload(qid) is None
    assert not store.set_status(qid, "released")  # nothing to release
    assert store.set_status(qid, "discarded")


def test_grant_uses_are_spent_once(tmp_path: Path) -> None:
    db = tmp_path / "c.sqlite3"
    a, b = ControlStore(db), ControlStore(db)
    g = a.add_grant(server="mail", tool="send_email", conditions={}, ttl_s=60, uses=1)
    assert [x.id for x in b.grants(server="mail")] == [g.id]
    assert b.use_grant(g.id)
    assert not a.use_grant(g.id)
    assert a.grants(server="mail") == []
    assert [x.id for x in a.grants(live_only=False)] == [g.id]


def test_unlock_resets_strikes(tmp_path: Path) -> None:
    store = ControlStore(tmp_path / "c.sqlite3")
    store.strike("s")
    store.lock("s", "breaker")
    assert store.locked("s") == "breaker"
    assert store.unlock("s") == 1
    assert store.locked("s") is None
    assert store.strike("s") == 1


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_database_is_owner_only(tmp_path: Path) -> None:
    db = tmp_path / "c.sqlite3"
    store = ControlStore(db)
    store.quarantine(session="s", server="m", tool="t", call_key="k", summary="x", payload=b"{}")
    for p in tmp_path.iterdir():
        assert p.stat().st_mode & 0o077 == 0, p
