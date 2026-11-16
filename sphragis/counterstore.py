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

from .identity import store_key

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: no cross-process lock
    fcntl = None

_FORMAT = 2   # JSON file layout with the tap ledger; older files are a bare floor map


@dataclass(frozen=True)
class PendingTap:
    """
    A counter the ledger recorded whose detector history write was not
    confirmed (`settle`): the process stopped, or the history store failed,
    in between. The next tap of the UID completes it from `note`.
    """

    counter: int
    floor_before: int | None
    note: dict


@dataclass(frozen=True)
class TapRecord:
    """Outcome of recording one counter value for a UID."""

    counter: int
    new: bool                 # this counter value had never been recorded
    floor_before: int | None  # the floor before this record (None: unknown UID)
    ledger_since: int | None = None   # the floor when this UID's ledger began:
                                      # counters up to it predate the ledger
    pending: tuple[PendingTap, ...] = ()  # unsettled taps of this UID, read before
                                          # this one was recorded

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


def check_ledger_window(window: int | None) -> int | None:
    if window is not None and (isinstance(window, bool) or not isinstance(window, int)
                               or window < 1):
        raise ValueError("the ledger window must be a positive number of counter values")
    return window


def compaction_mark(window: int | None, floor: int, since: int | None) -> int | None:
    """
    Ledger retention: with a `window`, only the counters within `window` of the
    floor are kept one by one; everything at or below `floor - window` is
    summarised by the UID's `since` mark, which only moves up. A counter at or
    below the mark is then reported as `predates_ledger` (a replay whose
    earlier submission is no longer on record), exactly as for a store
    upgraded from a bare floor. Returns the new mark, or None to keep the
    current one.
    """
    if window is None:
        return None
    mark = floor - window
    if mark < 0 or (since is not None and mark <= since):
        return None
    return mark


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
class SettlingLedger(TapLedger, Protocol):
    """
    A tap ledger that also keeps, in the same transaction as a new counter, a
    note to finish its history write (`record_tap(..., note=...)`), drops it
    once that write succeeded (`settle`), and returns a UID's unsettled notes
    with every `TapRecord` (`pending`), so a crash or a failing history store
    between the two writes never loses an observation or a regression alert
    (#86).
    """

    def record_tap(self, uid_hex: str, counter: int,
                   note: dict | None = None) -> TapRecord: ...

    def settle(self, uid_hex: str, counter: int) -> None: ...


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

    Durability: every read and change re-reads the file under an exclusive lock
    (`fcntl.flock` on `<path>.lock`, POSIX), writes a temporary file, fsyncs
    it, renames it over the old one and fsyncs the directory; memory is
    updated only once the file is on disk. Several processes may share one
    file this way. An empty or corrupt file is refused rather than read as
    "no floors", which would let every captured tap replay once more. Use
    `SqliteCounterStore` for anything beyond a single host's tools.
    """

    def __init__(self, path: str | os.PathLike | None = None,
                 ledger_window: int | None = None) -> None:
        self._path = Path(path) if path else None
        self._window = check_ledger_window(ledger_window)
        self._lock = threading.Lock()
        self._seen: dict[str, int] = {}
        self._taps: dict[str, set[int]] = {}
        self._since: dict[str, int | None] = {}
        self._pending: dict[str, dict[int, dict]] = {}
        if self._path and self._path.exists():
            self._seen, self._taps, self._since, self._pending = self._read()

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
                floors = {store_key(u): int(c) for u, c in data["floors"].items()}
                taps = {store_key(u): {int(c) for c in v} for u, v in data["taps"].items()}
                since = {store_key(u): (None if c is None else int(c))
                         for u, c in data["since"].items()}
                pending = {store_key(u): {int(c): dict(n) for c, n in v.items()}
                           for u, v in data.get("pending", {}).items()}
            else:                                    # bare floor map (older files)
                floors = {store_key(u): int(c) for u, c in data.items()}
                taps, since, pending = {}, {}, {}
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise CounterStoreError(f"{self._path} is not a valid counter store: "
                                    f"{exc}") from exc
        return floors, taps, since, pending

    def _write(self, floors, taps, since, pending) -> None:
        if taps:
            data = {"format": _FORMAT, "floors": floors,
                    "taps": {u: sorted(v) for u, v in taps.items()}, "since": since}
            live = {u: {str(c): n for c, n in v.items()} for u, v in pending.items() if v}
            if live:
                data["pending"] = live
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

    def _mutate(self, change, with_pending: bool = False):
        """
        Apply `change(floors, taps, since) -> (result, dirty)` (with
        `pending` as a fourth argument when `with_pending`) to the latest
        state on disk; persist before memory moves.
        """
        with self._lock, self._file_lock():
            if self._path is not None and self._path.exists():
                floors, taps, since, pending = self._read()
            else:
                floors = dict(self._seen)
                taps = {u: set(v) for u, v in self._taps.items()}
                since = dict(self._since)
                pending = {u: dict(v) for u, v in self._pending.items()}
            if with_pending:
                result, dirty = change(floors, taps, since, pending)
            else:
                result, dirty = change(floors, taps, since)
            if dirty and self._path is not None:
                self._write(floors, taps, since, pending)
            self._seen, self._taps, self._since = floors, taps, since
            self._pending = pending
            return result

    # -- floor ---------------------------------------------------------------------
    def _view(self, read):
        """`read(floors, taps)` on the latest state: the file may have moved on
        under another process sharing it."""
        return self._mutate(lambda floors, taps, since: (read(floors, taps), False))

    def last_counter(self, uid_hex: str) -> int | None:
        uid_hex = store_key(uid_hex)
        return self._view(lambda floors, taps: floors.get(uid_hex))

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
        uid_hex = store_key(uid_hex)

        def change(floors, taps, since):
            last = floors.get(uid_hex)
            if last is not None and counter <= last:
                return False, False
            floors[uid_hex] = counter
            if uid_hex in taps:          # keep a started ledger complete
                taps[uid_hex].add(counter)
            return True, True

        return self._mutate(change)

    def record(self, uid_hex: str, counter: int) -> None:
        """Advance the stored counter for a UID (never moves it backwards)."""
        uid_hex = store_key(uid_hex)

        def change(floors, taps, since):
            if counter > floors.get(uid_hex, -1):
                floors[uid_hex] = counter
                return None, True
            return None, False

        self._mutate(change)

    # -- tap ledger -----------------------------------------------------------------
    def seen(self, uid_hex: str, counter: int) -> bool:
        uid_hex = store_key(uid_hex)
        return self._view(lambda floors, taps: counter in taps.get(uid_hex, ()))

    def record_tap(self, uid_hex: str, counter: int,
                   note: dict | None = None) -> TapRecord:
        uid_hex = store_key(uid_hex)

        def change(floors, taps, since, pending):
            floor = floors.get(uid_hex)
            dirty = False
            if uid_hex not in taps:
                taps[uid_hex], since[uid_hex] = set(), floor
                dirty = True
            unsettled = tuple(PendingTap(c, n.get("floor_before"), n)
                              for c, n in sorted(pending.get(uid_hex, {}).items()))
            record = TapRecord(counter, counter not in taps[uid_hex], floor, since[uid_hex],
                               unsettled)
            if record.new and note is not None:
                pending.setdefault(uid_hex, {})[counter] = {**note, "floor_before": floor}
            if record.new:
                taps[uid_hex].add(counter)
                if record.fresh:
                    floors[uid_hex] = counter
                    mark = compaction_mark(self._window, counter, since[uid_hex])
                    if mark is not None:
                        taps[uid_hex] = {c for c in taps[uid_hex] if c > mark}
                        since[uid_hex] = mark
                dirty = True
            return record, dirty

        return self._mutate(change, with_pending=True)

    def settle(self, uid_hex: str, counter: int) -> None:
        """The history write for `counter` succeeded: drop its pending note."""
        uid_hex = store_key(uid_hex)

        def change(floors, taps, since, pending):
            notes = pending.get(uid_hex)
            if not notes or counter not in notes:
                return None, False
            del notes[counter]
            if not notes:
                del pending[uid_hex]
            return None, True

        self._mutate(change, with_pending=True)
