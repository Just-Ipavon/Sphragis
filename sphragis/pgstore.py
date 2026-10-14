"""
Postgres backends for multi-host deployments (optional extra `sphragis[pg]`).

SQLite serializes writers on one host; behind replicas on several hosts the
anti-replay floor, the detector history and the alert audit trail must live in
one shared database. These classes implement the same contracts as their
SQLite counterparts on Postgres (psycopg 3):

- `PostgresCounterStore`: `check_and_advance` is a single atomic statement,

      INSERT ... ON CONFLICT (uid) DO UPDATE SET counter = EXCLUDED.counter
      WHERE stored.counter < EXCLUDED.counter RETURNING ...

  The conflicting row is locked by the upsert itself, so two hosts racing on
  the same UID cannot both accept a counter; no row returned means replay or
  rollback.
- `PostgresObservationStore`: `observe` reads the prior history, appends the
  tap and trims it in one transaction, serialized per UID with a transaction
  scoped advisory lock, so concurrent taps are scored against each other.
- `PostgresAlertSink`: append-only audit trail of flagged verifications.

Tables are created on first use (`IF NOT EXISTS`, under an advisory lock so
concurrent first starts do not race) with a `sphragis_` prefix. Each thread
uses its own connection in autocommit mode; a broken connection is replaced on
the next call, and errors propagate so callers fail closed.

Credentials: prefer libpq's PGPASSWORD / ~/.pgpass over a password inside the
DSN, so it does not end up in process listings or configuration dumps.
"""

from __future__ import annotations

import json
import threading
import time

from .alerts import Alert
from .observations import Observation

try:
    import psycopg
except ImportError:  # pragma: no cover - exercised only without the extra
    psycopg = None

# First key of every advisory lock taken here ("SPHR"), keeping them apart
# from locks an application sharing the database might take.
_LOCK_NS = 0x53504852


def _require_driver() -> None:
    if psycopg is None:
        raise ImportError("the Postgres backends need psycopg 3: "
                          "pip install 'sphragis[pg]'")


class _PgBase:
    _SCHEMA: str = ""

    def __init__(self, dsn: str) -> None:
        _require_driver()
        self._dsn = dsn
        self._local = threading.local()
        self._all_conns: list = []
        self._conns_lock = threading.Lock()
        conn = self._connection()
        with conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s, 0)", (_LOCK_NS,))
            conn.execute(self._SCHEMA)

    def _connection(self):
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed or conn.broken:
            conn = psycopg.connect(self._dsn, autocommit=True)
            self._local.conn = conn
            with self._conns_lock:
                self._all_conns.append(conn)
        return conn

    def close(self) -> None:
        with self._conns_lock:
            for conn in self._all_conns:
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_conns.clear()
        self._local = threading.local()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class PostgresCounterStore(_PgBase):
    """Anti-replay floor shared by every host using the same database."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS sphragis_counters (
        uid         TEXT PRIMARY KEY,
        counter     BIGINT NOT NULL,
        updated_at  DOUBLE PRECISION NOT NULL
    );
    """

    def last_counter(self, uid_hex: str) -> int | None:
        row = self._connection().execute(
            "SELECT counter FROM sphragis_counters WHERE uid = %s",
            (uid_hex.upper(),),
        ).fetchone()
        return None if row is None else int(row[0])

    def check_and_advance(self, uid_hex: str, counter: int) -> bool:
        """Accept `counter` iff strictly greater than the stored one, atomically."""
        row = self._connection().execute(
            "INSERT INTO sphragis_counters AS c (uid, counter, updated_at) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (uid) DO UPDATE "
            "SET counter = EXCLUDED.counter, updated_at = EXCLUDED.updated_at "
            "WHERE c.counter < EXCLUDED.counter "
            "RETURNING c.counter",
            (uid_hex.upper(), counter, time.time()),
        ).fetchone()
        return row is not None


class PostgresObservationStore(_PgBase):
    """Detector history shared by every host using the same database."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS sphragis_observations (
        id          BIGSERIAL PRIMARY KEY,
        uid         TEXT NOT NULL,
        counter     BIGINT NOT NULL,
        ts          DOUBLE PRECISION NOT NULL,
        reader_id   TEXT
    );
    CREATE INDEX IF NOT EXISTS sphragis_observations_uid
        ON sphragis_observations (uid, id);
    """

    @staticmethod
    def _rows(conn, uid_hex: str) -> list[Observation]:
        rows = conn.execute(
            "SELECT counter, ts, reader_id FROM sphragis_observations "
            "WHERE uid = %s ORDER BY id",
            (uid_hex,),
        ).fetchall()
        return [Observation(int(c), float(t), r) for c, t, r in rows]

    def history(self, uid_hex: str) -> list[Observation]:
        return self._rows(self._connection(), uid_hex.upper())

    def observe(self, uid_hex: str, obs: Observation, limit: int) -> list[Observation]:
        uid_hex = uid_hex.upper()
        conn = self._connection()
        with conn.transaction():
            # Serialize per UID: the lock is held until commit, so the next
            # tap for this UID sees this one in its prior history.
            conn.execute("SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                         (_LOCK_NS, uid_hex))
            prior = self._rows(conn, uid_hex)
            conn.execute(
                "INSERT INTO sphragis_observations (uid, counter, ts, reader_id) "
                "VALUES (%s, %s, %s, %s)",
                (uid_hex, obs.counter, obs.timestamp, obs.reader_id),
            )
            conn.execute(
                "DELETE FROM sphragis_observations WHERE uid = %s AND id NOT IN ("
                "SELECT id FROM sphragis_observations WHERE uid = %s "
                "ORDER BY id DESC LIMIT %s)",
                (uid_hex, uid_hex, limit),
            )
        return prior


class PostgresAlertSink(_PgBase):
    """Append-only audit trail of flagged verifications, shared across hosts."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS sphragis_alerts (
        event_id        TEXT PRIMARY KEY,
        ts              DOUBLE PRECISION NOT NULL,
        classification  TEXT NOT NULL,
        risk_score      INTEGER NOT NULL,
        uid_ref         TEXT,
        read_counter    BIGINT,
        reader_id       TEXT,
        signals         JSONB NOT NULL,
        detail          TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sphragis_alerts_uid ON sphragis_alerts (uid_ref, ts);
    """

    def emit(self, alert: Alert) -> None:
        self._connection().execute(
            "INSERT INTO sphragis_alerts VALUES "
            "(%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)",
            (alert.event_id, alert.timestamp, alert.classification,
             alert.risk_score, alert.uid_ref, alert.read_counter,
             alert.reader_id, json.dumps(list(alert.signals)), alert.detail),
        )

    def recent(self, limit: int = 100, uid_ref: str | None = None) -> list[Alert]:
        sql = ("SELECT event_id, ts, classification, risk_score, uid_ref, "
               "read_counter, reader_id, signals, detail FROM sphragis_alerts")
        args: tuple = ()
        if uid_ref is not None:
            sql += " WHERE uid_ref = %s"
            args = (uid_ref,)
        sql += " ORDER BY ts DESC LIMIT %s"
        rows = self._connection().execute(sql, args + (limit,)).fetchall()
        return [Alert(r[0], r[1], r[2], r[3], r[4], r[5], r[6], tuple(r[7]), r[8])
                for r in rows]
