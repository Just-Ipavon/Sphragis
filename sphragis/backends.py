"""
Verification backends — the chip-specific half of the pipeline.

Everything after the cryptographic check (anti-replay ledger, clone detector,
rate limits, alerts, stores, API) only needs three facts about a tap: *which*
chip produced it, its monotonic counter, and that the chip's authenticator
verified. A `VerificationBackend` turns a tapped URL into those facts; the rest
of the engine never looks at chip-specific fields.

Contract
--------
`accepts(url_or_query)` is a cheap shape check used to pick the backend for a
tap; it must not do any cryptography. `authenticate(url_or_query)` parses and
verifies the tap and either

- returns an `AuthenticTap` (the authenticator verified, under the key
  version it reports),
- raises `ForgedTap` (the tap parsed but its authenticator does not verify; the
  decoded identity and counter are unauthenticated and must not leak), or
- raises `SdmError` / `ValueError` for malformed input.

`AuthenticTap.identity` keys every per-tag store (ledger, history, rate limit,
pseudonymized logs), so it must be stable for a chip and must not collide with
identities from another backend sharing the same stores. The NTAG 424 DNA
backends use the bare UID in upper-case hex, as every store already holds;
other backends should prefix theirs (e.g. `"fido2:<credential id>"`).

Backends shipped with the engine:
- `Ntag424SunBackend` (`sphragis.verifier`): plain SUN, PICCData + SDMMAC.
- `Ntag424EncBackend` (`sphragis.encverifier`): SUN with SDMENCFileData.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol, runtime_checkable


@dataclass(frozen=True)
class AuthenticTap:
    """A tap whose authenticator verified, normalized across chip families."""

    identity: str              # stable chip identity: the key of every per-tag store
    counter: int | None        # monotonic counter emitted by the chip; None if
                               # it keeps none (e.g. a synced passkey)
    backend: str               # name of the backend that verified it
    algorithm: str             # authenticator algorithm, e.g. "AES-128-CMAC"
    payload: bytes | None = None   # authenticated payload (e.g. decrypted file data)
    key_version: int | None = None  # version of the key that verified it


@dataclass(frozen=True)
class Provenance:
    """What produced a record: kept with observations, alerts and log lines."""

    backend: str | None = None
    algorithm: str | None = None
    key_version: int | None = None

    @classmethod
    def of(cls, tap: AuthenticTap) -> "Provenance":
        return cls(tap.backend, tap.algorithm, tap.key_version)


class ForgedTap(Exception):
    """The tap parsed, but its authenticator does not verify."""


@runtime_checkable
class VerificationBackend(Protocol):
    name: str

    def accepts(self, url_or_query: str) -> bool:
        """Whether this tap has the shape this backend verifies (no crypto)."""
        ...

    def authenticate(self, url_or_query: str) -> AuthenticTap:
        """Verify the tap; raise `ForgedTap` or `SdmError`/`ValueError`."""
        ...


def select_backend(backends: Iterable[VerificationBackend],
                   url_or_query: str) -> VerificationBackend | None:
    """The first backend that accepts the tap: list the most specific first."""
    for backend in backends:
        if backend.accepts(url_or_query):
            return backend
    return None
