"""Response controls shared by every gatehouse on the machine (ADR-0006, D-044).

- **Kill switch:** a file, ``<state dir>/KILL``. While it exists every gatehouse blocks
  every tool call and withholds every result. A file is the simplest thing that works
  in a panic: ``gatehouse kill`` writes it, but so does ``touch``. A process can also
  be killed on its own (SIGUSR1 on POSIX).
- **Circuit breaker:** a count of strikes (calls or results with a high or critical
  finding) per agent session. At the threshold the session is locked until a human runs
  ``gatehouse unlock``.
- **Approval budget:** approval prompts per agent session per window. Past it, calls
  that need approval are blocked instead of asked, so the user isn't trained to click
  yes, and is told to add a scoped grant.
- **Quarantine:** withheld results are kept for review (``gatehouse review``). A
  released result is delivered once, when the agent repeats the same call (bound by a
  keyed fingerprint of server, tool and arguments), without calling the server again.
- **Scoped grants:** "allow ``send_email`` to ``@mycorp.com`` for 30 minutes". A live
  grant answers an approval the policy or the Rule of Two asks for, never one a
  detector asks for.

Everything but the kill switch lives in one SQLite database (``control.sqlite3``, WAL).
Counters and grant uses are updated inside ``BEGIN IMMEDIATE`` transactions, so
concurrent processes can't lose an update. Every failure raises ``ControlStoreError``
and the router fails closed (see each caller).
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

SCHEMA_VERSION = 1
BUSY_TIMEOUT_MS = 2000
QUARANTINE_RETENTION_S = 7 * 24 * 3600.0
MAX_QUARANTINE_BYTES = 1024 * 1024  # one result; bigger ones are withheld but not kept
MAX_QUARANTINE_ITEMS = 1000  # oldest held items are dropped first
KILL_FILE = "KILL"
CONTROL_DB = "control.sqlite3"

_DDL = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS strikes (
    session TEXT PRIMARY KEY, n INTEGER NOT NULL, updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS locks (
    session TEXT PRIMARY KEY, reason TEXT NOT NULL, at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS budget (
    session TEXT PRIMARY KEY, window_start REAL NOT NULL, n INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    call_key TEXT NOT NULL,
    created REAL NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL,
    payload BLOB
);
CREATE INDEX IF NOT EXISTS quarantine_call ON quarantine (session, server, call_key, status);
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    conditions TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    uses_left INTEGER,
    note TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
"""


_T = TypeVar("_T")

_QUARANTINE_COLUMNS = (
    "SELECT id, session, server, tool, created, summary, status, length(payload) FROM quarantine"
)
_QUARANTINE_OPEN = _QUARANTINE_COLUMNS + " WHERE status IN ('held', 'released') ORDER BY created"
_QUARANTINE_ALL = _QUARANTINE_COLUMNS + " ORDER BY created"


class ControlStoreError(Exception):
    """The control store could not be read or written."""


@dataclass(frozen=True)
class KillState:
    reason: str
    source: str  # "file" or "signal"


@dataclass(frozen=True)
class QuarantineItem:
    id: str
    session: str
    server: str
    tool: str
    created: float
    summary: str
    status: str  # held | released | delivered | discarded
    size: int


@dataclass(frozen=True)
class ScopedGrant:
    id: str
    server: str
    tool: str
    conditions: dict[str, Any]  # argument -> condition (policy.conditions models, as JSON)
    created: float
    expires: float
    uses_left: int | None
    note: str
    revoked: bool


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(5)}"


class ControlStore:
    """``path=None`` keeps everything in memory (tests, and no kill-switch file)."""

    def __init__(self, path: Path | None, kill_file: Path | None = None) -> None:
        self.path = path
        self.kill_file = (
            kill_file
            if kill_file is not None
            else (path.parent / KILL_FILE if path is not None else None)
        )
        self._lock = threading.Lock()
        self._local_kill: KillState | None = None
        self._conn = self._open(path if path is not None else None)

    # ------------------------------------------------------------------ plumbing

    @staticmethod
    def _open(path: Path | None) -> sqlite3.Connection:
        target = ":memory:" if path is None else str(path)
        try:
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                # Quarantined results are raw tool output, so the file is owner-only.
                # SQLite gives the -wal and -shm files the database file's mode.
                os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
                if sys.platform != "win32":
                    os.chmod(path, 0o600)
            conn = sqlite3.connect(
                target,
                timeout=BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
                check_same_thread=False,
            )
            conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            if path is not None:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
            conn.executescript(_DDL)
            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema', ?)",
                (str(SCHEMA_VERSION),),
            )
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()
            if row is None or row[0] != str(SCHEMA_VERSION):
                raise ControlStoreError(f"control store schema {row and row[0]} is not supported")
            conn.execute(
                "DELETE FROM quarantine WHERE created < ?",
                (time.time() - QUARANTINE_RETENTION_S,),
            )
            return conn
        except (sqlite3.Error, OSError) as exc:
            raise ControlStoreError(f"cannot open control store {path}: {exc}") from exc

    def _tx(self, fn: Callable[[sqlite3.Connection], _T]) -> _T:
        """Run ``fn(conn)`` in one write transaction."""
        try:
            with self._lock:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    out = fn(self._conn)
                except BaseException:
                    self._conn.execute("ROLLBACK")
                    raise
                self._conn.execute("COMMIT")
                return out
        except sqlite3.Error as exc:
            raise ControlStoreError(f"control store: {exc}") from exc

    def _read(self, sql: str, args: tuple[Any, ...] = ()) -> list[Any]:
        try:
            with self._lock:
                return self._conn.execute(sql, args).fetchall()
        except sqlite3.Error as exc:
            raise ControlStoreError(f"control store: {exc}") from exc

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --------------------------------------------------------------- kill switch

    def engage_local(self, reason: str) -> None:
        """Kill this process only (the signal handler calls this)."""
        self._local_kill = KillState(reason, "signal")

    def kill_state(self) -> KillState | None:
        """The kill switch, if engaged. A file that exists but can't be read, or a
        directory that can't be checked, counts as engaged (fail closed)."""
        if self._local_kill is not None:
            return self._local_kill
        if self.kill_file is None:
            return None
        try:
            raw = self.kill_file.read_bytes()[:4096]
        except FileNotFoundError:
            return None
        except OSError as exc:
            return KillState(f"kill switch file unreadable ({exc.__class__.__name__})", "file")
        try:
            data = json.loads(raw.decode("utf-8"))
            reason = str(data.get("reason") or "kill switch engaged")[:200]
        except (ValueError, UnicodeDecodeError, AttributeError):
            reason = "kill switch engaged"
        return KillState(reason, "file")

    def engage(self, reason: str) -> Path:
        if self.kill_file is None:
            raise ControlStoreError("no kill switch file for an in-memory store")
        self.kill_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.kill_file.with_name(KILL_FILE + ".tmp")
        tmp.write_text(json.dumps({"reason": reason[:200], "at": time.time()}), encoding="utf-8")
        os.replace(tmp, self.kill_file)
        return self.kill_file

    def release_kill(self) -> bool:
        if self.kill_file is None:
            return False
        try:
            self.kill_file.unlink()
        except FileNotFoundError:
            return False
        return True

    # ----------------------------------------------------------- circuit breaker

    def strike(self, session: str) -> int:
        """Count one strike for the session; returns the new total."""

        def fn(conn: sqlite3.Connection) -> int:
            conn.execute(
                "INSERT INTO strikes (session, n, updated) VALUES (?, 1, ?)"
                " ON CONFLICT (session) DO UPDATE SET n = n + 1, updated = excluded.updated",
                (session, time.time()),
            )
            row = conn.execute("SELECT n FROM strikes WHERE session = ?", (session,)).fetchone()
            return int(row[0])

        return int(self._tx(fn))

    def lock(self, session: str, reason: str) -> None:
        self._tx(
            lambda conn: conn.execute(
                "INSERT OR IGNORE INTO locks (session, reason, at) VALUES (?, ?, ?)",
                (session, reason[:300], time.time()),
            )
        )

    def locked(self, session: str) -> str | None:
        rows = self._read("SELECT reason FROM locks WHERE session = ?", (session,))
        return str(rows[0][0]) if rows else None

    def locks(self) -> list[tuple[str, str, float]]:
        rows = self._read("SELECT session, reason, at FROM locks ORDER BY at")
        return [(str(s), str(r), float(a)) for s, r, a in rows]

    def unlock(self, session: str | None) -> int:
        """Unlock one session (or all with None) and reset its strikes."""

        def fn(conn: sqlite3.Connection) -> int:
            if session is None:
                n = conn.execute("DELETE FROM locks").rowcount
                conn.execute("DELETE FROM strikes")
            else:
                n = conn.execute("DELETE FROM locks WHERE session = ?", (session,)).rowcount
                conn.execute("DELETE FROM strikes WHERE session = ?", (session,))
            return int(n)

        return int(self._tx(fn))

    # ------------------------------------------------------------ approval budget

    def take_prompt(self, session: str, limit: int, window_s: float) -> bool:
        """Spend one approval prompt from the session's budget; False if it's used up."""
        if limit <= 0:
            return True
        now = time.time()

        def fn(conn: sqlite3.Connection) -> bool:
            row = conn.execute(
                "SELECT window_start, n FROM budget WHERE session = ?", (session,)
            ).fetchone()
            start, n = (float(row[0]), int(row[1])) if row else (now, 0)
            if now - start >= window_s:
                start, n = now, 0
            if n >= limit:
                return False
            conn.execute(
                "INSERT INTO budget (session, window_start, n) VALUES (?, ?, ?)"
                " ON CONFLICT (session) DO UPDATE SET window_start = excluded.window_start,"
                " n = excluded.n",
                (session, start, n + 1),
            )
            return True

        return bool(self._tx(fn))

    # ----------------------------------------------------------------- quarantine

    def quarantine(
        self,
        *,
        session: str,
        server: str,
        tool: str,
        call_key: str,
        summary: str,
        payload: bytes,
    ) -> str:
        qid = _new_id("q")
        kept = payload if len(payload) <= MAX_QUARANTINE_BYTES else None

        def fn(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO quarantine (id, session, server, tool, call_key, created, summary,"
                " status, payload) VALUES (?, ?, ?, ?, ?, ?, ?, 'held', ?)",
                (
                    qid,
                    session,
                    server[:128],
                    tool[:128],
                    call_key,
                    time.time(),
                    summary[:500],
                    kept,
                ),
            )
            conn.execute(
                "DELETE FROM quarantine WHERE id IN (SELECT id FROM quarantine"
                " ORDER BY created DESC LIMIT -1 OFFSET ?)",
                (MAX_QUARANTINE_ITEMS,),
            )

        self._tx(fn)
        return qid

    def quarantined(self, *, include_closed: bool = False) -> list[QuarantineItem]:
        rows = self._read(_QUARANTINE_ALL if include_closed else _QUARANTINE_OPEN)
        return [
            QuarantineItem(
                str(r[0]),
                str(r[1]),
                str(r[2]),
                str(r[3]),
                float(r[4]),
                str(r[5]),
                str(r[6]),
                int(r[7] or 0),
            )
            for r in rows
        ]

    def quarantine_payload(self, qid: str) -> bytes | None:
        rows = self._read("SELECT payload FROM quarantine WHERE id = ?", (qid,))
        return bytes(rows[0][0]) if rows and rows[0][0] is not None else None

    def set_status(self, qid: str, status: str) -> bool:
        """held -> released | discarded. Returns False if the id isn't held."""
        if status not in ("released", "discarded"):
            raise ValueError(status)

        def fn(conn: sqlite3.Connection) -> bool:
            if status == "released":
                cur = conn.execute(
                    "UPDATE quarantine SET status = 'released'"
                    " WHERE id = ? AND status = 'held' AND payload IS NOT NULL",
                    (qid,),
                )
            else:
                cur = conn.execute(
                    "UPDATE quarantine SET status = 'discarded', payload = NULL"
                    " WHERE id = ? AND status IN ('held', 'released')",
                    (qid,),
                )
            return cur.rowcount == 1

        return bool(self._tx(fn))

    def take_released(self, session: str, server: str, call_key: str) -> tuple[str, bytes] | None:
        """A released result for this exact call, marked delivered (at most once)."""
        # Every allowed call asks, and almost always the answer is no: check with a read
        # before taking the write lock.
        if not self._read(
            "SELECT 1 FROM quarantine WHERE session = ? AND server = ? AND call_key = ?"
            " AND status = 'released' LIMIT 1",
            (session, server, call_key),
        ):
            return None

        def fn(conn: sqlite3.Connection) -> tuple[str, bytes] | None:
            row = conn.execute(
                "SELECT id, payload FROM quarantine WHERE session = ? AND server = ?"
                " AND call_key = ? AND status = 'released' ORDER BY created LIMIT 1",
                (session, server, call_key),
            ).fetchone()
            if row is None or row[1] is None:
                return None
            conn.execute(
                "UPDATE quarantine SET status = 'delivered', payload = NULL WHERE id = ?",
                (row[0],),
            )
            return str(row[0]), bytes(row[1])

        out: tuple[str, bytes] | None = self._tx(fn)
        return out

    # -------------------------------------------------------------- scoped grants

    def add_grant(
        self,
        *,
        server: str,
        tool: str,
        conditions: dict[str, Any],
        ttl_s: float,
        uses: int | None,
        note: str = "",
    ) -> ScopedGrant:
        now = time.time()
        grant = ScopedGrant(
            _new_id("g"), server, tool, conditions, now, now + ttl_s, uses, note[:200], False
        )
        self._tx(
            lambda conn: conn.execute(
                "INSERT INTO grants (id, server, tool, conditions, created, expires, uses_left,"
                " note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    grant.id,
                    server,
                    tool,
                    json.dumps(conditions, sort_keys=True),
                    now,
                    grant.expires,
                    uses,
                    grant.note,
                ),
            )
        )
        return grant

    def grants(self, *, server: str | None = None, live_only: bool = True) -> list[ScopedGrant]:
        sql = (
            "SELECT id, server, tool, conditions, created, expires, uses_left, note, revoked"
            " FROM grants"
        )
        clauses: list[str] = []
        args: list[Any] = []
        if server is not None:
            clauses.append("server = ?")
            args.append(server)
        if live_only:
            clauses.append("revoked = 0 AND expires > ? AND (uses_left IS NULL OR uses_left > 0)")
            args.append(time.time())
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        rows = self._read(sql + " ORDER BY created", tuple(args))
        return [
            ScopedGrant(
                str(r[0]),
                str(r[1]),
                str(r[2]),
                json.loads(r[3]),
                float(r[4]),
                float(r[5]),
                None if r[6] is None else int(r[6]),
                str(r[7]),
                bool(r[8]),
            )
            for r in rows
        ]

    def use_grant(self, gid: str) -> bool:
        """Spend one use of a live grant; False if it expired, ran out or was revoked."""

        def fn(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                "UPDATE grants SET uses_left = CASE WHEN uses_left IS NULL THEN NULL"
                " ELSE uses_left - 1 END WHERE id = ? AND revoked = 0 AND expires > ?"
                " AND (uses_left IS NULL OR uses_left > 0)",
                (gid, time.time()),
            )
            return cur.rowcount == 1

        return bool(self._tx(fn))

    def revoke_grant(self, gid: str | None) -> int:
        """Revoke one grant, or every grant with None."""
        if gid is None:
            return int(self._tx(lambda c: c.execute("UPDATE grants SET revoked = 1").rowcount))
        return int(
            self._tx(
                lambda c: c.execute("UPDATE grants SET revoked = 1 WHERE id = ?", (gid,)).rowcount
            )
        )
