"""
SQLite-backed counter store — the production anti-replay floor.

The JSON `CounterStore` is fine for demos but does not survive concurrent
writers across processes. This backend keeps the same tiny interface
(`last_counter`, `check_and_advance`) but enforces monotonicity **atomically**
inside a database transaction, which is the property a production
anti-counterfeiting backend must not get wrong.

Concurrency model
-----------------
Each thread gets its own SQLite connection (a single connection must not run
interleaved statements from multiple threads). Serialization is delegated to
SQLite itself:

- `BEGIN IMMEDIATE` acquires the write lock up front, so the
  read-then-conditional-write cannot interleave with another writer (no TOCTOU),
  across threads *and* processes.
- WAL mode lets readers proceed without blocking the writer.
- `busy_timeout` makes a contending writer wait and retry instead of failing.

Scaling further: the same logic is one statement on Postgres —
`INSERT ... ON CONFLICT (uid) DO UPDATE SET counter = excluded.counter
WHERE excluded.counter > counters.counter` — treating "no row changed" as a
replay. SQLite keeps this repo dependency-free while showing the pattern.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time

from .counterstore import TapRecord


def secure_db_file(path: str) -> None:
    """Create the database file readable by its owner only (0600), if new.
    UIDs and counters are not keys, but they are tracking data."""
    if path != ":memory:" and not os.path.exists(path):
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))

# Provenance columns (crypto agility): which backend, algorithm and key version
# produced a row. Rows written before they existed read back as NULL: unknown.
PROVENANCE_COLUMNS = {"backend": "TEXT", "algorithm": "TEXT", "key_version": "INTEGER"}


def add_missing_columns(conn: sqlite3.Connection, table: str,
                        columns: dict[str, str]) -> None:
    """Migrate `table` in place by adding the `columns` it lacks."""
    present = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, sql_type in columns.items():
        if name not in present:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
            except sqlite3.OperationalError as exc:   # another process got there first
                if "duplicate column" not in str(exc):
                    raise


_SCHEMA = """
CREATE TABLE IF NOT EXISTS counters (
    uid         TEXT PRIMARY KEY,
    counter     INTEGER NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tap_counters (
    uid         TEXT NOT NULL,
    counter     INTEGER NOT NULL,
    first_seen  REAL NOT NULL,
    PRIMARY KEY (uid, counter)
);
CREATE TABLE IF NOT EXISTS tap_ledgers (
    uid         TEXT PRIMARY KEY,
    since       INTEGER
);
"""


class SqliteCounterStore:
    def __init__(self, path: str | os.PathLike = "counters.db") -> None:
        self._path = str(path)
        self._local = threading.local()
        self._all_conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        secure_db_file(self._path)
        # Create the schema once up front.
        self._connection().executescript(_SCHEMA)

    def _connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, isolation_level=None, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            # FULL: an acknowledged floor advance survives a power loss; with
            # NORMAL the last transactions of a WAL can roll back, and the
            # taps they accepted would verify again.
            conn.execute("PRAGMA synchronous=FULL")
            self._local.conn = conn
            with self._conns_lock:
                self._all_conns.append(conn)
        return conn

    def last_counter(self, uid_hex: str) -> int | None:
        row = self._connection().execute(
            "SELECT counter FROM counters WHERE uid = ?", (uid_hex.upper(),)
        ).fetchone()
        return None if row is None else int(row[0])

    def check_and_advance(self, uid_hex: str, counter: int) -> bool:
        """
        Atomically accept `counter` only if strictly greater than the stored
        value, advancing it in the same transaction. Returns False on replay or
        rollback. Safe under concurrent threads and processes: the IMMEDIATE
        transaction serializes writers via SQLite's write lock.
        """
        uid_hex = uid_hex.upper()
        now = time.time()
        conn = self._connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT counter FROM counters WHERE uid = ?", (uid_hex,)
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO counters (uid, counter, updated_at) VALUES (?, ?, ?)",
                    (uid_hex, counter, now),
                )
                accepted = True
            elif counter > int(row[0]):
                conn.execute(
                    "UPDATE counters SET counter = ?, updated_at = ? WHERE uid = ?",
                    (counter, now, uid_hex),
                )
                accepted = True
            else:
                accepted = False
            conn.execute("COMMIT")
            return accepted
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def seen(self, uid_hex: str, counter: int) -> bool:
        return self._connection().execute(
            "SELECT 1 FROM tap_counters WHERE uid = ? AND counter = ?",
            (uid_hex.upper(), counter),
        ).fetchone() is not None

    def record_tap(self, uid_hex: str, counter: int) -> TapRecord:
        """
        Tap ledger (`counterstore.TapLedger`): record `counter` for the UID and
        advance the floor if it is new and higher, in one IMMEDIATE transaction.
        """
        uid_hex = uid_hex.upper()
        now = time.time()
        conn = self._connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT counter FROM counters WHERE uid = ?", (uid_hex,)).fetchone()
            floor = None if row is None else int(row[0])
            conn.execute("INSERT OR IGNORE INTO tap_ledgers (uid, since) VALUES (?, ?)",
                         (uid_hex, floor))
            since = conn.execute("SELECT since FROM tap_ledgers WHERE uid = ?",
                                 (uid_hex,)).fetchone()[0]
            new = conn.execute(
                "INSERT OR IGNORE INTO tap_counters (uid, counter, first_seen) "
                "VALUES (?, ?, ?)", (uid_hex, counter, now)).rowcount == 1
            record = TapRecord(counter, new, floor, since)
            if record.fresh:
                conn.execute(
                    "INSERT INTO counters (uid, counter, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT (uid) DO UPDATE SET counter = excluded.counter, "
                    "updated_at = excluded.updated_at", (uid_hex, counter, now))
            conn.execute("COMMIT")
            return record
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        with self._conns_lock:
            for conn in self._all_conns:
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_conns.clear()
        self._local = threading.local()

    def __enter__(self) -> "SqliteCounterStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
