"""
Alerting on flagged verifications.

A `CLONE_LIKELY` verdict is the event this whole engine exists to surface; it
must not disappear into a log line nobody reads. An `AlertSink` receives each
flagged verification. Sinks are deliberately small and composable:

- `LogAlertSink`     — a CRITICAL structured log event (wire it to your pager).
- `SqliteAlertSink`  — a durable, queryable audit trail for investigation.
- `WebhookAlertSink` — an HMAC-signed JSON POST to an incident endpoint
                       (redirects refused; `verify_webhook` for receivers).
- `BackgroundAlertSink` — delivers through another sink on a worker thread, so
                       a slow endpoint never delays a verification.

`AlertThrottle` sits in front of the sinks (see `VerificationService`): it
de-duplicates repeated alerts and caps the alerts per UID, so a holder of
many withheld URLs for one tag cannot flood the queue and push out the alerts
for every other tag.

Sinks must never break verification: `dispatch` isolates each sink and logs its
failure instead of raising.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import queue
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, OrderedDict
from dataclasses import asdict, dataclass
from typing import Iterable, Protocol, runtime_checkable
from urllib.parse import urlparse

_log = logging.getLogger("sphragis.alert")


@dataclass(frozen=True)
class Alert:
    event_id: str
    timestamp: float
    classification: str
    risk_score: int
    uid_ref: str | None          # pseudonymized UID (see logs.UidPseudonymizer)
    read_counter: int | None
    reader_id: str | None
    signals: tuple[str, ...]
    detail: str
    # Provenance (crypto agility): None when unknown.
    backend: str | None = None
    algorithm: str | None = None
    key_version: int | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["signals"] = list(self.signals)
        return d


@runtime_checkable
class AlertSink(Protocol):
    def emit(self, alert: Alert) -> None: ...


def dispatch(alert: Alert, sinks: Iterable[AlertSink]) -> int:
    """Deliver `alert` to every sink; return how many succeeded."""
    delivered = 0
    for sink in sinks:
        try:
            sink.emit(alert)
            delivered += 1
        except Exception:  # noqa: BLE001 - a broken sink must not stop the others
            _log.exception(
                "alert_sink_failed",
                extra={"fields": {"event_id": alert.event_id,
                                  "sink": type(sink).__name__}},
            )
    return delivered


class AlertThrottle:
    """
    Per-UID de-duplication and rate limiting of alerts, in this process.

    - An alert identical to one let through for the same UID within
      `dedup_seconds` (same classification and signals) is suppressed.
    - Each UID gets a token bucket of `per_uid_burst` alerts refilled over
      `per_uid_window` seconds; alerts past it are suppressed.

    Alerts without a UID (none are raised by default) share one bucket.
    Suppressed alerts are counted by reason (`suppressed`) and logged; the
    signed events and the verification log still record every tap. At most
    `max_uids` UIDs are tracked; the least recently alerted are forgotten.
    """

    def __init__(self, per_uid_burst: int = 5, per_uid_window: float = 3600.0,
                 dedup_seconds: float = 300.0, max_uids: int = 100_000,
                 clock=time.monotonic) -> None:
        if per_uid_burst < 1 or per_uid_window <= 0 or dedup_seconds < 0 or max_uids < 1:
            raise ValueError("per_uid_burst >= 1, per_uid_window > 0, "
                             "dedup_seconds >= 0 and max_uids >= 1 are required")
        self._burst, self._window = per_uid_burst, per_uid_window
        self._dedup, self._max = dedup_seconds, max_uids
        self._clock = clock
        # uid -> [tokens, updated, {fingerprint: last time let through}]
        self._state: OrderedDict[str, list] = OrderedDict()
        self._lock = threading.Lock()
        self.suppressed: Counter[str] = Counter()

    def allow(self, alert: Alert) -> bool:
        key = alert.uid_ref or "-"
        fingerprint = (alert.classification, tuple(sorted(alert.signals)))
        now = self._clock()
        with self._lock:
            state = self._state.get(key)
            if state is None:
                state = [float(self._burst), now, {}]
                self._state[key] = state
                while len(self._state) > self._max:
                    self._state.popitem(last=False)
            self._state.move_to_end(key)
            tokens, updated, seen = state
            last = seen.get(fingerprint)
            if last is not None and now - last < self._dedup:
                reason = "duplicate"
            else:
                tokens = min(float(self._burst),
                             tokens + (now - updated) * self._burst / self._window)
                state[0], state[1] = tokens, now
                if tokens >= 1:
                    state[0] = tokens - 1
                    seen[fingerprint] = now
                    if len(seen) > 32:                  # keep the newest fingerprints
                        for old in sorted(seen, key=seen.get)[:len(seen) - 32]:
                            del seen[old]
                    return True
                reason = "rate"
            self.suppressed[reason] += 1
        _log.warning("alert_suppressed", extra={"fields": {
            "event_id": alert.event_id, "uid_ref": alert.uid_ref,
            "classification": alert.classification, "reason": reason}})
        return False


class LogAlertSink:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or _log

    def emit(self, alert: Alert) -> None:
        self._log.critical("alert", extra={"fields": alert.to_dict()})


_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    event_id        TEXT PRIMARY KEY,
    ts              REAL NOT NULL,
    classification  TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    uid_ref         TEXT,
    read_counter    INTEGER,
    reader_id       TEXT,
    signals         TEXT NOT NULL,
    detail          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_uid ON alerts (uid_ref, ts);
"""


class SqliteAlertSink:
    """Append-only audit trail of flagged verifications."""

    def __init__(self, path: str | os.PathLike = "alerts.db") -> None:
        self._path = str(path)
        from .sqlstore import (
            PROVENANCE_COLUMNS,
            ThreadConnections,
            add_missing_columns,
            secure_db_file,
        )
        secure_db_file(self._path)
        self._conns = ThreadConnections(self._path, (
            "PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000"))
        conn = self._connection()
        conn.executescript(_SCHEMA)
        add_missing_columns(conn, "alerts", PROVENANCE_COLUMNS)

    def _connection(self) -> sqlite3.Connection:
        return self._conns.get()

    def close(self) -> None:
        self._conns.close()

    def __enter__(self) -> "SqliteAlertSink":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def emit(self, alert: Alert) -> None:
        self._connection().execute(
            "INSERT INTO alerts (event_id, ts, classification, risk_score, uid_ref, "
            "read_counter, reader_id, signals, detail, backend, algorithm, "
            "key_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (alert.event_id, alert.timestamp, alert.classification,
             alert.risk_score, alert.uid_ref, alert.read_counter,
             alert.reader_id, json.dumps(list(alert.signals)), alert.detail,
             alert.backend, alert.algorithm, alert.key_version),
        )

    def recent(self, limit: int = 100, uid_ref: str | None = None) -> list[Alert]:
        sql = ("SELECT event_id, ts, classification, risk_score, uid_ref, "
               "read_counter, reader_id, signals, detail, backend, algorithm, "
               "key_version FROM alerts")
        args: tuple = ()
        if uid_ref is not None:
            sql += " WHERE uid_ref = ?"
            args = (uid_ref,)
        sql += " ORDER BY ts DESC LIMIT ?"
        rows = self._connection().execute(sql, args + (limit,)).fetchall()
        return [
            Alert(r[0], r[1], r[2], r[3], r[4], r[5], r[6],
                  tuple(json.loads(r[7])), r[8], r[9], r[10], r[11])
            for r in rows
        ]


def sign_webhook(secret: bytes, timestamp: str, body: bytes) -> str:
    """Signature over `timestamp + "." + body`, so a captured delivery cannot be
    replayed with a fresh timestamp."""
    mac = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify_webhook(secret: bytes, timestamp: str, signature: str, body: bytes,
                   *, tolerance: float = 300.0, now: float | None = None) -> bool:
    """
    Receiver side of `WebhookAlertSink`: constant-time signature check and a
    freshness window on the timestamp (`tolerance` seconds either way).
    Remember the event ids already processed to drop duplicates inside it.
    """
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    if abs(current - ts) > tolerance:
        return False
    if not isinstance(signature, str):
        return False
    return hmac.compare_digest(sign_webhook(secret, timestamp, body).encode(),
                               signature.encode("utf-8", "surrogatepass"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would turn the signed POST into a GET elsewhere (possibly
    over http) carrying the signature headers: refuse it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code,
                                     f"webhook redirect to {newurl} refused",
                                     headers, fp)


_opener = urllib.request.build_opener(_NoRedirect)


class WebhookAlertSink:
    """
    POST the alert as JSON to an incident endpoint, signed with HMAC-SHA256.

    Headers: `X-Sphragis-Timestamp` (unix seconds) and `X-Sphragis-Signature`
    (`sha256=<hex>` over `timestamp + "." + body`). The receiver should verify
    the signature in constant time and reject stale timestamps.

    Delivery is synchronous with a short timeout and no retries (wrap it in
    `BackgroundAlertSink` to keep it off the request path); a durable sink
    (`SqliteAlertSink`) should run alongside it as the system of record. Only a
    2xx answer counts as delivered; redirects are refused.
    """

    def __init__(self, url: str, secret: bytes, timeout: float = 2.0,
                 allow_insecure: bool = False) -> None:
        scheme = urlparse(url).scheme
        if scheme != "https" and not (allow_insecure and scheme == "http"):
            raise ValueError("webhook URL must use https")
        if len(secret) < 16:
            raise ValueError("webhook secret must be at least 16 bytes")
        self._url = url
        self._secret = secret
        self._timeout = timeout

    def emit(self, alert: Alert) -> None:
        body = json.dumps(alert.to_dict(), separators=(",", ":")).encode()
        ts = str(int(time.time()))
        req = urllib.request.Request(
            self._url, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Sphragis-Timestamp": ts,
                "X-Sphragis-Signature": sign_webhook(self._secret, ts, body),
            },
        )
        try:
            with _opener.open(req, timeout=self._timeout) as resp:  # noqa: S310
                if not 200 <= resp.status < 300:
                    raise RuntimeError(f"webhook answered HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            exc.close()                  # it holds the response and its socket
            raise


class BackgroundAlertSink:
    """
    Hand alerts to `sink` on a daemon worker thread through a bounded queue.
    `emit` never blocks: when the queue is full the alert is dropped and logged
    (a durable sink running alongside keeps the record). Failures of `sink`
    are logged, as `dispatch` would.
    """

    def __init__(self, sink: AlertSink, maxsize: int = 1000) -> None:
        self._sink = sink
        self.dropped = 0                 # alerts refused because the queue was full
        self._queue: queue.Queue[Alert | None] = queue.Queue(maxsize)
        self._thread = threading.Thread(target=self._run, name="sphragis-alerts",
                                        daemon=True)
        self._thread.start()

    def emit(self, alert: Alert) -> None:
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            self.dropped += 1
            _log.error("alert queue full: alert dropped",
                       extra={"fields": {"event_id": alert.event_id}})
            raise RuntimeError("alert queue full") from None

    def _run(self) -> None:
        while True:
            alert = self._queue.get()
            try:
                if alert is None:
                    return
                self._sink.emit(alert)
            except Exception:
                _log.exception("background alert delivery failed",
                               extra={"fields": {"event_id": alert.event_id,
                                                 "sink": type(self._sink).__name__}})
            finally:
                self._queue.task_done()

    @property
    def pending(self) -> int:
        """Alerts queued and not yet handed to the sink."""
        return self._queue.qsize()

    @property
    def capacity(self) -> int:
        return self._queue.maxsize

    def flush(self, timeout: float | None = None) -> bool:
        """Wait until every queued alert has been handed to the sink, at most
        `timeout` seconds; return whether the queue drained."""
        if timeout is None:
            self._queue.join()
            return True
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def close(self, timeout: float = 5.0) -> bool:
        """Deliver what is queued, then stop the worker. Returns whether every
        queued alert was handed to the sink within `timeout` seconds; the
        alerts left behind are logged (the durable sink kept them anyway)."""
        deadline = time.monotonic() + timeout
        try:
            self._queue.put(None, timeout=timeout)    # after the queued alerts
        except queue.Full:
            pass
        self._thread.join(max(0.0, deadline - time.monotonic()))
        left = self._queue.qsize()
        if self._thread.is_alive() or left:
            _log.error("alert worker stopped with alerts undelivered",
                       extra={"fields": {"pending": left,
                                         "sink": type(self._sink).__name__}})
            return False
        return True
