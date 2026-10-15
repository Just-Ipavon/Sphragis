"""
Read-counter store for clone / replay detection.

A genuine NTAG 424 DNA increments SDMReadCtr on every tap and never goes
backwards. By remembering the highest counter we have seen for each UID, we can
flag:
  - a replayed URL (same or lower counter than already seen), and
  - a cloned tag that cannot reproduce a correct, strictly-increasing counter.

This reference implementation is a simple JSON file. In production you would
back it with a database and guard against races, but the contract is the same.

Tap ledger
----------
The floor alone cannot tell a replayed URL (a counter value already submitted)
from a lower counter never submitted before (a clone's own stream, or a
genuine URL that was read and withheld). `TapLedger` adds a durable record of
every counter value submitted for a UID, updated in the same atomic step as
the floor (`record_tap`), so the analyzer can classify stale taps exactly,
without relying on the detector's trimmed history window.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

_FORMAT = 2   # JSON file layout with the tap ledger; older files are a bare floor map


@dataclass(frozen=True)
class TapRecord:
    """Outcome of recording one counter value for a UID."""

    counter: int
    new: bool                 # this counter value had never been recorded
    floor_before: int | None  # the floor before this record (None: unknown UID)
    ledger_since: int | None = None   # the floor when this UID's ledger began:
                                      # counters up to it predate the ledger

    @property
    def fresh(self) -> bool:
        """New and above the previous floor: the floor advanced to it."""
        return self.new and (self.floor_before is None or self.counter > self.floor_before)

    @property
    def predates_ledger(self) -> bool:
        """At or below the floor the UID already had when its ledger began
        (a store upgraded from a bare floor): whether it was submitted before
        is unknown."""
        return self.ledger_since is not None and self.counter <= self.ledger_since


@runtime_checkable
class TapLedger(Protocol):
    """
    Floor plus the set of counter values submitted per UID. `record_tap`
    must, atomically, add `counter` to the set if absent, read the floor, and
    advance it when `counter` is new and higher.
    """

    def last_counter(self, uid_hex: str) -> int | None: ...

    def record_tap(self, uid_hex: str, counter: int) -> TapRecord: ...


@runtime_checkable
class CounterBackend(Protocol):
    """
    Anti-replay floor. Any backend (JSON file, SQLite, a real RDBMS) that
    implements these two methods is a drop-in for the Verifier/TagAnalyzer.
    """

    def last_counter(self, uid_hex: str) -> int | None: ...

    def check_and_advance(self, uid_hex: str, counter: int) -> bool:
        """Atomically accept `counter` iff strictly greater than the stored one."""
        ...


class CounterStore:
    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._seen: dict[str, int] = {}
        self._taps: dict[str, set[int]] = {}
        self._since: dict[str, int | None] = {}
        if self._path and self._path.exists():
            data = json.loads(self._path.read_text() or "{}")
            if data.get("format") == _FORMAT:
                self._seen = dict(data["floors"])
                self._taps = {uid: set(values) for uid, values in data["taps"].items()}
                self._since = dict(data["since"])
            else:                                    # bare floor map (older files)
                self._seen = data

    def last_counter(self, uid_hex: str) -> int | None:
        return self._seen.get(uid_hex.upper())

    def is_fresh(self, uid_hex: str, counter: int) -> bool:
        """True if this counter is strictly greater than the last one seen."""
        last = self.last_counter(uid_hex)
        return last is None or counter > last

    def check_and_advance(self, uid_hex: str, counter: int) -> bool:
        """
        Atomically accept a counter only if it is strictly greater than the
        last one seen, advancing the floor in the same critical section.

        Returns True if accepted (fresh), False if it is a replay/rollback.
        This closes the check-then-act race that `is_fresh` + `record` leaves
        open under concurrency. For multi-process deployments, back this with a
        database using an atomic conditional update (e.g. UPDATE ... WHERE
        new > stored) and treat "0 rows affected" as a replay.
        """
        uid_hex = uid_hex.upper()
        with self._lock:
            last = self._seen.get(uid_hex)
            if last is not None and counter <= last:
                return False
            self._seen[uid_hex] = counter
            self._flush()
            return True

    def seen(self, uid_hex: str, counter: int) -> bool:
        with self._lock:
            return counter in self._taps.get(uid_hex.upper(), ())

    def record_tap(self, uid_hex: str, counter: int) -> TapRecord:
        uid_hex = uid_hex.upper()
        with self._lock:
            floor = self._seen.get(uid_hex)
            if uid_hex not in self._taps:
                self._taps[uid_hex] = set()
                self._since[uid_hex] = floor
            taps = self._taps[uid_hex]
            record = TapRecord(counter, counter not in taps, floor, self._since[uid_hex])
            if record.new:
                taps.add(counter)
                if record.fresh:
                    self._seen[uid_hex] = counter
                self._flush()
            return record

    def record(self, uid_hex: str, counter: int) -> None:
        """Advance the stored counter for a UID (never moves it backwards)."""
        uid_hex = uid_hex.upper()
        with self._lock:
            if counter > self._seen.get(uid_hex, -1):
                self._seen[uid_hex] = counter
                self._flush()

    def _flush(self) -> None:
        if not self._path:
            return
        # Atomic write so a crash cannot corrupt the store.
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent)
        try:
            with os.fdopen(fd, "w") as f:
                if self._taps:
                    data = {"format": _FORMAT, "floors": self._seen,
                            "taps": {u: sorted(v) for u, v in self._taps.items()},
                            "since": self._since}
                else:                      # keep the bare map until the ledger is used
                    data = self._seen
                json.dump(data, f, indent=2, sort_keys=True)
            os.replace(tmp, self._path)
        except Exception:
            os.unlink(tmp)
            raise
