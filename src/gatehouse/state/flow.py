"""Session flow state shared by every gatehouse process under one agent (D-040, D-042).

Each MCP server gets its own gatehouse process, so what the agent read on one server has
to be visible when it calls another. The state is a grow-only set of facts per
``AgentSessionId``: capability labels the session holds (``label``) and provenance
fingerprints of private data it has seen (``fp``, used by ``inspect.provenance``).

Storage is one SQLite database in the state directory, in WAL mode with a busy timeout.
Every write is a single ``INSERT OR IGNORE`` of one row, so concurrent writers can't
lose each other's updates: there is no read-modify-write anywhere. That's the failure
mode that hit the v0.1 JSON pin store (D-010, fixed in ``7577e2d``); a test runs 40+
writer processes against one database.

Failures:

- reads fail closed: if the store can't be read, ``labels`` raises and the router
  treats the session as holding every label;
- writes keep the fact in this process's memory and raise, so the router can emit
  ``gatehouse.fail_open`` (other processes won't see the fact).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable
from pathlib import Path

from gatehouse.policy.models import Label

SCHEMA_VERSION = 1
RETENTION_S = 14 * 24 * 3600.0
BUSY_TIMEOUT_MS = 2000
MAX_FACT_LEN = 128
_LABELS = frozenset(label.value for label in Label)

_DDL = """
CREATE TABLE IF NOT EXISTS facts (
    session TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    first_seen REAL NOT NULL,
    PRIMARY KEY (session, kind, value)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


_FIND = (
    "SELECT value, server, tool FROM facts WHERE session = ? AND kind = ? AND value IN ({marks})"
)


class FlowStoreError(Exception):
    """The shared flow store could not be read or written."""


class FlowStore:
    """Grow-only facts per agent session. ``path=None`` keeps them in memory only."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        # facts this process wrote: (session, kind) -> value -> (server, tool)
        self._local: dict[tuple[str, str], dict[str, tuple[str, str]]] = {}
        self._conn: sqlite3.Connection | None = None
        if path is not None:
            self._conn = self._open(path)

    @staticmethod
    def _open(path: Path) -> sqlite3.Connection:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None, check_same_thread=False
            )
            conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.executescript(_DDL)
            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema', ?)",
                (str(SCHEMA_VERSION),),
            )
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()
            if row is None or row[0] != str(SCHEMA_VERSION):
                raise FlowStoreError(f"flow store schema {row and row[0]} is not supported")
            # Best effort: old sessions are useless and the file shouldn't grow forever.
            conn.execute("DELETE FROM facts WHERE first_seen < ?", (time.time() - RETENTION_S,))
            return conn
        except (sqlite3.Error, OSError) as exc:
            raise FlowStoreError(f"cannot open flow store {path}: {exc}") from exc

    # ------------------------------------------------------------------ generic facts

    def facts(self, session: str, kind: str) -> frozenset[str]:
        local = set(self._local.get((session, kind), {}))
        if self._conn is None:
            return frozenset(local)
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT value FROM facts WHERE session = ? AND kind = ?", (session, kind)
                ).fetchall()
        except sqlite3.Error as exc:
            raise FlowStoreError(f"cannot read flow store: {exc}") from exc
        return frozenset(local | {str(r[0]) for r in rows})

    def add(
        self, session: str, kind: str, values: Iterable[str], *, server: str, tool: str
    ) -> None:
        vals = [v for v in values if 0 < len(v) <= MAX_FACT_LEN]
        if not vals:
            return
        local = self._local.setdefault((session, kind), {})
        for v in vals:
            local.setdefault(v, (server, tool))
        if self._conn is None:
            return
        now = time.time()
        rows = [(session, kind, v, server[:128], tool[:128], now) for v in vals]
        try:
            with self._lock:
                # One transaction per call: a private result adds thousands of rows.
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    self._conn.executemany(
                        "INSERT OR IGNORE INTO facts"
                        " (session, kind, value, server, tool, first_seen)"
                        " VALUES (?, ?, ?, ?, ?, ?)",
                        rows,
                    )
                except BaseException:
                    self._conn.execute("ROLLBACK")
                    raise
                self._conn.execute("COMMIT")
        except sqlite3.Error as exc:
            raise FlowStoreError(f"cannot write flow store: {exc}") from exc

    def find(self, session: str, kind: str, values: Iterable[str]) -> dict[str, tuple[str, str]]:
        """The given values the session holds, each with the (server, tool) that first
        added it."""
        wanted = sorted({v for v in values if 0 < len(v) <= MAX_FACT_LEN})
        local = self._local.get((session, kind), {})
        out = {v: local[v] for v in wanted if v in local}
        if self._conn is None or not wanted:
            return out
        try:
            with self._lock:
                for i in range(0, len(wanted), 500):
                    chunk = wanted[i : i + 500]
                    marks = ",".join("?" * len(chunk))  # placeholders only, never values
                    query = _FIND.format(marks=marks)
                    for value, server, tool in self._conn.execute(query, (session, kind, *chunk)):
                        out.setdefault(str(value), (str(server), str(tool)))
        except sqlite3.Error as exc:
            raise FlowStoreError(f"cannot read flow store: {exc}") from exc
        return out

    # ------------------------------------------------------------------ labels

    def labels(self, session: str) -> frozenset[Label]:
        return frozenset(Label(v) for v in self.facts(session, "label") if v in _LABELS)

    def add_labels(self, session: str, labels: Iterable[Label], *, server: str, tool: str) -> None:
        self.add(session, "label", (label.value for label in labels), server=server, tool=tool)

    def close(self) -> None:
        if self._conn is not None:
            with self._lock:
                self._conn.close()
            self._conn = None
