"""
Observation stores — where the clone detector keeps its per-UID history.

The `CloneDetector` reasons over the *history* of authentic taps for a UID
(counters, times, readers). Kept in a plain dict, that history lives inside one
process: behind several API workers or replicas each process would see only a
slice of the taps, and counter-divergence / impossible-velocity scoring would
depend on which worker happened to answer. A shared, durable store fixes that.

Contract
--------
`observe(uid_hex, obs, limit)` must, **atomically**, return the history seen
*before* `obs` and append `obs`, trimming to the newest `limit` entries. The
atomicity matters: two concurrent taps for the same UID must be serialized, so
that the second one is scored against a history that includes the first.

Implementations:
- `MemoryObservationStore` — in-process, lock-protected (default; tests, demos).
- `SqliteObservationStore` — durable and shared across processes on one host
  (`BEGIN IMMEDIATE` serializes writers, as in `SqliteCounterStore`).
"""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass
class Observation:
    counter: int
    timestamp: float
    reader_id: str | None = None


@runtime_checkable
class ObservationStore(Protocol):
    def history(self, uid_hex: str) -> list[Observation]: ...

    def observe(self, uid_hex: str, obs: Observation, limit: int) -> list[Observation]:
        """Atomically return the prior history (oldest first) and append `obs`."""
        ...


class MemoryObservationStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: dict[str, list[Observation]] = {}

    def history(self, uid_hex: str) -> list[Observation]:
        with self._lock:
            return list(self._history.get(uid_hex.upper(), []))

    def observe(self, uid_hex: str, obs: Observation, limit: int) -> list[Observation]:
        with self._lock:
            hist = self._history.setdefault(uid_hex.upper(), [])
            prior = list(hist)
            hist.append(obs)
            if len(hist) > limit:
                del hist[0 : len(hist) - limit]
            return prior


_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uid         TEXT NOT NULL,
    counter     INTEGER NOT NULL,
    ts          REAL NOT NULL,
    reader_id   TEXT
);
CREATE INDEX IF NOT EXISTS observations_uid ON observations (uid, id);
"""


class SqliteObservationStore:
    """
    Durable observation history shared by every process using the same file.

    One connection per thread; writers are serialized by `BEGIN IMMEDIATE`, so
    `observe` is atomic across threads and processes.
    """

    def __init__(self, path: str | os.PathLike = "observations.db") -> None:
        self._path = str(path)
        self._local = threading.local()
        self._all_conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        from .sqlstore import secure_db_file
        secure_db_file(self._path)
        self._connection().executescript(_SCHEMA)

    def _connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, isolation_level=None, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
            with self._conns_lock:
                self._all_conns.append(conn)
        return conn

    @staticmethod
    def _rows(conn: sqlite3.Connection, uid_hex: str) -> list[Observation]:
        rows = conn.execute(
            "SELECT counter, ts, reader_id FROM observations "
            "WHERE uid = ? ORDER BY id",
            (uid_hex,),
        ).fetchall()
        return [Observation(int(c), float(t), r) for c, t, r in rows]

    def history(self, uid_hex: str) -> list[Observation]:
        return self._rows(self._connection(), uid_hex.upper())

    def observe(self, uid_hex: str, obs: Observation, limit: int) -> list[Observation]:
        uid_hex = uid_hex.upper()
        conn = self._connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            prior = self._rows(conn, uid_hex)
            conn.execute(
                "INSERT INTO observations (uid, counter, ts, reader_id) "
                "VALUES (?, ?, ?, ?)",
                (uid_hex, obs.counter, obs.timestamp, obs.reader_id),
            )
            # Keep only the newest `limit` rows for this UID.
            conn.execute(
                "DELETE FROM observations WHERE uid = ? AND id NOT IN ("
                "SELECT id FROM observations WHERE uid = ? ORDER BY id DESC LIMIT ?)",
                (uid_hex, uid_hex, limit),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return prior

    def close(self) -> None:
        with self._conns_lock:
            for conn in self._all_conns:
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_conns.clear()
        self._local = threading.local()

    def __enter__(self) -> "SqliteObservationStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
