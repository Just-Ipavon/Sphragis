"""
Read-counter store for clone / replay detection.

A genuine NTAG 424 DNA increments SDMReadCtr on every tap and never goes
backwards. By remembering the highest counter we have seen for each UID, we can
flag:
  - a replayed URL (same or lower counter than already seen), and
  - a cloned tag that cannot reproduce a correct, strictly-increasing counter.

This reference implementation is a simple JSON file. In production you would
back it with a database and guard against races, but the contract is the same.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable


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
        if self._path and self._path.exists():
            self._seen = json.loads(self._path.read_text() or "{}")

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
                json.dump(self._seen, f, indent=2, sort_keys=True)
            os.replace(tmp, self._path)
        except Exception:
            os.unlink(tmp)
            raise
