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
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: no cross-process lock
    fcntl = None

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


class CounterStoreError(Exception):
    """The counter file cannot be trusted (empty, corrupt, unreadable)."""


class CounterStore:
    """
    JSON-file floor and tap ledger (in memory when `path` is None).

    Durability: every change re-reads the file under an exclusive lock
    (`fcntl.flock` on `<path>.lock`, POSIX), writes a temporary file, fsyncs
    it, renames it over the old one and fsyncs the directory; memory is
    updated only once the file is on disk. Several processes may share one
    file this way. An empty or corrupt file is refused rather than read as
    "no floors", which would let every captured tap replay once more. Use
    `SqliteCounterStore` for anything beyond a single host's tools.
    """

    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._seen: dict[str, int] = {}
        self._taps: dict[str, set[int]] = {}
        self._since: dict[str, int | None] = {}
        if self._path and self._path.exists():
            self._seen, self._taps, self._since = self._read()

    # -- file I/O ----------------------------------------------------------------
    def _read(self):
        try:
            text = self._path.read_text()
        except OSError as exc:
            raise CounterStoreError(f"cannot read {self._path}: {exc}") from exc
        if not text.strip():
            raise CounterStoreError(
                f"{self._path} is empty: refusing to start without the anti-replay "
                "floors it should hold (restore it, or delete it to start afresh)")
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
            if data.get("format") == _FORMAT:
                floors = {u.upper(): int(c) for u, c in data["floors"].items()}
                taps = {u.upper(): {int(c) for c in v} for u, v in data["taps"].items()}
                since = {u.upper(): (None if c is None else int(c))
                         for u, c in data["since"].items()}
            else:                                    # bare floor map (older files)
                floors = {u.upper(): int(c) for u, c in data.items()}
                taps, since = {}, {}
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise CounterStoreError(f"{self._path} is not a valid counter store: "
                                    f"{exc}") from exc
        return floors, taps, since

    def _write(self, floors, taps, since) -> None:
        if taps:
            data = {"format": _FORMAT, "floors": floors,
                    "taps": {u: sorted(v) for u, v in taps.items()}, "since": since}
        else:                                  # keep the bare map until the ledger is used
            data = floors
        directory = self._path.parent
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory)   # created 0600
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    @contextmanager
    def _file_lock(self):
        if self._path is None or fcntl is None:
            yield
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(f"{self._path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _mutate(self, change):
        """
        Apply `change(floors, taps, since) -> (result, dirty)` to the latest
        state on disk; persist before memory moves.
        """
        with self._lock, self._file_lock():
            if self._path is not None and self._path.exists():
                floors, taps, since = self._read()
            else:
                floors = dict(self._seen)
                taps = {u: set(v) for u, v in self._taps.items()}
                since = dict(self._since)
            result, dirty = change(floors, taps, since)
            if dirty and self._path is not None:
                self._write(floors, taps, since)
            self._seen, self._taps, self._since = floors, taps, since
            return result

    # -- floor ---------------------------------------------------------------------
    def last_counter(self, uid_hex: str) -> int | None:
        with self._lock:
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
        """
        uid_hex = uid_hex.upper()

        def change(floors, taps, since):
            last = floors.get(uid_hex)
            if last is not None and counter <= last:
                return False, False
            floors[uid_hex] = counter
            return True, True

        return self._mutate(change)

    def record(self, uid_hex: str, counter: int) -> None:
        """Advance the stored counter for a UID (never moves it backwards)."""
        uid_hex = uid_hex.upper()

        def change(floors, taps, since):
            if counter > floors.get(uid_hex, -1):
                floors[uid_hex] = counter
                return None, True
            return None, False

        self._mutate(change)

    # -- tap ledger -----------------------------------------------------------------
    def seen(self, uid_hex: str, counter: int) -> bool:
        with self._lock:
            return counter in self._taps.get(uid_hex.upper(), ())

    def record_tap(self, uid_hex: str, counter: int) -> TapRecord:
        uid_hex = uid_hex.upper()

        def change(floors, taps, since):
            floor = floors.get(uid_hex)
            dirty = False
            if uid_hex not in taps:
                taps[uid_hex], since[uid_hex] = set(), floor
                dirty = True
            record = TapRecord(counter, counter not in taps[uid_hex], floor, since[uid_hex])
            if record.new:
                taps[uid_hex].add(counter)
                if record.fresh:
                    floors[uid_hex] = counter
                dirty = True
            return record, dirty

        return self._mutate(change)
