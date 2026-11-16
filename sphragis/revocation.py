"""
Tag lifecycle: retired and revoked identities.

A lost, stolen or returned tag keeps producing valid SUN taps: its keys are
still on the chip. A `RevocationList` lets the operator withdraw it. The
analyzer checks the list once the tap is proven authentic and before any
state is touched, and answers `REVOKED` for a listed identity:

- `revoked`: the tag must not be trusted any more (lost, stolen, compromised);
  a tap from it is an alert by default.
- `retired`: the tag was taken out of service on purpose (returned, replaced,
  its counter close to the 24-bit limit); still `REVOKED`, but the signal
  names the reason so routine retirements can be told apart.

Only authentic taps are checked, so the answer never tells an anonymous
caller whether a UID it made up is on the list.

Implementations: `MemoryRevocationList` (tests, single process),
`sphragis.sqlstore.SqliteRevocationList`, `sphragis.pgstore.PostgresRevocationList`.
Manage them with `sphragis revoke`, `sphragis reinstate` and
`sphragis revocations`.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from .identity import store_key

MAX_REASON_LENGTH = 200


class RevocationStatus(str, Enum):
    REVOKED = "revoked"
    RETIRED = "retired"


@dataclass(frozen=True)
class Revocation:
    identity: str
    status: RevocationStatus
    reason: str
    since: float


@runtime_checkable
class RevocationList(Protocol):
    def get(self, identity: str) -> Revocation | None: ...

    def revoke(self, identity: str, status: RevocationStatus = RevocationStatus.REVOKED,
               reason: str = "") -> Revocation: ...

    def reinstate(self, identity: str) -> bool: ...

    def entries(self, limit: int = 1000) -> list[Revocation]: ...


def check_entry(identity: str, status, reason: str) -> tuple[str, RevocationStatus, str]:
    """Normalise and validate what an implementation is about to store."""
    if not identity or not identity.strip():
        raise ValueError("an identity is required")
    status = RevocationStatus(status)
    reason = (reason or "").strip()
    if len(reason) > MAX_REASON_LENGTH or any(ord(c) < 0x20 for c in reason):
        raise ValueError(f"reason must be one line of at most {MAX_REASON_LENGTH} "
                         "characters")
    return store_key(identity.strip()), status, reason


class MemoryRevocationList:
    """In-process list (tests, demos, one-process deployments)."""

    def __init__(self, clock=time.time) -> None:
        self._entries: dict[str, Revocation] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def get(self, identity: str) -> Revocation | None:
        return self._entries.get(store_key(identity))

    def revoke(self, identity: str, status: RevocationStatus = RevocationStatus.REVOKED,
               reason: str = "") -> Revocation:
        key, status, reason = check_entry(identity, status, reason)
        entry = Revocation(key, status, reason, self._clock())
        with self._lock:
            self._entries[key] = entry
        return entry

    def reinstate(self, identity: str) -> bool:
        with self._lock:
            return self._entries.pop(store_key(identity), None) is not None

    def entries(self, limit: int = 1000) -> list[Revocation]:
        with self._lock:
            return sorted(self._entries.values(), key=lambda e: -e.since)[:limit]

    def close(self) -> None:
        pass
