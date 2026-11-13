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

from .counterstore import TapRecord, check_ledger_window, compaction_mark
from .identity import store_key


def secure_db_file(path: str) -> None:
    """Create the database file readable by its owner only (0600), if new.
    UIDs and counters are not keys, but they are tracking data.

    In-memory databases are refused: every thread opens its own connection,
    and each `:memory:` connection is a separate, empty database, so a store
    would lose its schema and data on the first request served by another
    thread (FastAPI runs sync endpoints in a thread pool)."""
    if path == ":memory:" or path.startswith("file::memory:") or "mode=memory" in path:
        raise ValueError("SQLite stores need a database file; :memory: gives every "
                         "thread its own empty database (use a temporary file)")
    if not os.path.exists(path):
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))


class ThreadConnections:
    """
    One SQLite connection per thread, all closable from any thread.

    Each thread uses only its own connection; `check_same_thread=False` is
    what lets `close()` reach the connections of other threads (a worker
    pool's), which sqlite3 otherwise refuses with an error that used to be
    swallowed, leaving them open.
    """

    def __init__(self, path: str, pragmas: tuple[str, ...]) -> None:
        self._path, self._pragmas = path, pragmas
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._lock = threading.Lock()

    def get(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, isolation_level=None, timeout=30.0,
                                   check_same_thread=False)
            for pragma in self._pragmas:
                conn.execute(pragma)
            self._local.conn = conn
            with self._lock:
                self._all.append(conn)
        return conn

    def close(self) -> None:
        with self._lock:
            conns, self._all = self._all, []
        for conn in conns:
            conn.close()
        self._local = threading.local()

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
    def __init__(self, path: str | os.PathLike = "counters.db",
                 ledger_window: int | None = None) -> None:
        self._path = str(path)
        self._window = check_ledger_window(ledger_window)
        secure_db_file(self._path)
        # FULL: an acknowledged floor advance survives a power loss; with
        # NORMAL the last transactions of a WAL can roll back, and the taps
        # they accepted would verify again.
        self._conns = ThreadConnections(self._path, (
            "PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000",
            "PRAGMA synchronous=FULL"))
        # Create the schema once up front.
        self._connection().executescript(_SCHEMA)

    def _connection(self) -> sqlite3.Connection:
        return self._conns.get()

    def last_counter(self, uid_hex: str) -> int | None:
        row = self._connection().execute(
            "SELECT counter FROM counters WHERE uid = ?", (store_key(uid_hex),)
        ).fetchone()
        return None if row is None else int(row[0])

    def check_and_advance(self, uid_hex: str, counter: int) -> bool:
        """
        Atomically accept `counter` only if strictly greater than the stored
        value, advancing it in the same transaction. Returns False on replay or
        rollback. Safe under concurrent threads and processes: the IMMEDIATE
        transaction serializes writers via SQLite's write lock.
        """
        uid_hex = store_key(uid_hex)
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
            if accepted:
                # A UID whose tap ledger has started keeps it complete, so a
                # later replay of this tap reads as a replay, not a rollback.
                conn.execute(
                    "INSERT OR IGNORE INTO tap_counters (uid, counter, first_seen) "
                    "SELECT uid, ?, ? FROM tap_ledgers WHERE uid = ?",
                    (counter, now, uid_hex))
            conn.execute("COMMIT")
            return accepted
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def seen(self, uid_hex: str, counter: int) -> bool:
        return self._connection().execute(
            "SELECT 1 FROM tap_counters WHERE uid = ? AND counter = ?",
            (store_key(uid_hex), counter),
        ).fetchone() is not None

    def record_tap(self, uid_hex: str, counter: int) -> TapRecord:
        """
        Tap ledger (`counterstore.TapLedger`): record `counter` for the UID and
        advance the floor if it is new and higher, in one IMMEDIATE transaction.
        """
        uid_hex = store_key(uid_hex)
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
                mark = compaction_mark(self._window, counter, since)
                if mark is not None:            # retention, in the same transaction
                    conn.execute("UPDATE tap_ledgers SET since = ? WHERE uid = ?",
                                 (mark, uid_hex))
                    conn.execute("DELETE FROM tap_counters WHERE uid = ? AND counter <= ?",
                                 (uid_hex, mark))
            conn.execute("COMMIT")
            return record
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self._conns.close()

    def __enter__(self) -> "SqliteCounterStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --- Shared rate limiting and challenges (#72) ------------------------------------

_LIMITER_SCHEMA = """
CREATE TABLE IF NOT EXISTS rate_buckets (
    key      TEXT PRIMARY KEY,
    tokens   REAL NOT NULL,
    updated  REAL NOT NULL,
    allowed  INTEGER NOT NULL
);
"""

_CHALLENGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge  BLOB PRIMARY KEY,
    expires    REAL NOT NULL
);
"""

# Token bucket in one statement: refill since `updated`, cap at the burst,
# take a token if one is there, and report whether it was taken.
_BUCKET_UPSERT = (
    "INSERT INTO rate_buckets (key, tokens, updated, allowed) VALUES (?, ? - 1, ?, 1) "
    "ON CONFLICT (key) DO UPDATE SET "
    "tokens = CASE WHEN MIN(?, tokens + (excluded.updated - updated) * ?) >= 1 "
    "         THEN MIN(?, tokens + (excluded.updated - updated) * ?) - 1 "
    "         ELSE MIN(?, tokens + (excluded.updated - updated) * ?) END, "
    "allowed = MIN(?, tokens + (excluded.updated - updated) * ?) >= 1, "
    "updated = excluded.updated "
    "RETURNING tokens, allowed"
)


class SqliteRateLimiter:
    """
    Token buckets shared by every process using the same database file: the
    budget holds across workers on one host (Postgres: `PostgresRateLimiter`
    for several hosts). Same semantics as `TokenBucketLimiter`; idle buckets
    are dropped once full again.
    """

    def __init__(self, path: str | os.PathLike, rate: float, burst: int,
                 clock=time.time) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self.rate, self.burst, self._clock = rate, burst, clock
        self._path = str(path)
        secure_db_file(self._path)
        self._conns = ThreadConnections(self._path, ("PRAGMA journal_mode=WAL",
                                                     "PRAGMA busy_timeout=5000"))
        self._conns.get().executescript(_LIMITER_SCHEMA)
        self._checks = 0

    def check(self, key: str):
        from .ratelimit import RateDecision
        now = self._clock()
        b, r = float(self.burst), self.rate
        conn = self._conns.get()
        tokens, allowed = conn.execute(
            _BUCKET_UPSERT, (key, b, now, b, r, b, r, b, r, b, r)).fetchone()
        self._checks += 1
        if self._checks % 1000 == 0:      # buckets idle long enough to be full again
            conn.execute("DELETE FROM rate_buckets WHERE updated < ?", (now - b / r,))
        if allowed:
            return RateDecision(True, 0.0)
        return RateDecision(False, (1.0 - tokens) / r)

    def close(self) -> None:
        self._conns.close()


class SqliteChallengeStore:
    """Single-use WebAuthn challenges shared by every process on one database."""

    def __init__(self, path: str | os.PathLike, ttl_seconds: float = 120.0,
                 size: int = 32, clock=time.time) -> None:
        self._ttl, self._size, self._clock = ttl_seconds, size, clock
        self._path = str(path)
        secure_db_file(self._path)
        self._conns = ThreadConnections(self._path, ("PRAGMA journal_mode=WAL",
                                                     "PRAGMA busy_timeout=5000"))
        self._conns.get().executescript(_CHALLENGE_SCHEMA)

    def issue(self) -> bytes:
        import secrets
        challenge = secrets.token_bytes(self._size)
        now = self._clock()
        conn = self._conns.get()
        conn.execute("DELETE FROM webauthn_challenges WHERE expires < ?", (now,))
        conn.execute("INSERT INTO webauthn_challenges (challenge, expires) VALUES (?, ?)",
                     (challenge, now + self._ttl))
        return challenge

    def consume(self, challenge: bytes) -> bool:
        """True once for an issued, unexpired challenge, whichever process asks."""
        row = self._conns.get().execute(
            "DELETE FROM webauthn_challenges WHERE challenge = ? AND expires >= ? "
            "RETURNING 1", (bytes(challenge), self._clock())).fetchone()
        return row is not None

    def close(self) -> None:
        self._conns.close()
