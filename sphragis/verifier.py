"""
High-level verifier: URL in, verdict out.

Pipeline for each tapped URL:
  1. Parse `picc_data` and `cmac` from the query string.
  2. Decrypt PICCData with the meta-read key -> UID + read counter.
  3. Recompute the SDMMAC with the (possibly UID-diversified) file-read key and
     compare in constant time -> proves authenticity.
  4. Check the read counter against the counter store -> catches replay/clone.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from urllib.parse import parse_qs, urlparse

from .counterstore import CounterBackend, CounterStore
from .sdm import SdmError, compute_sdmmac, decrypt_picc_data


class Verdict(str, Enum):
    AUTHENTIC = "AUTHENTIC"   # genuine tag, fresh tap
    REPLAY = "REPLAY"         # valid MAC but counter not advancing -> replay/clone
    FORGED = "FORGED"         # MAC mismatch -> not a genuine tag
    ERROR = "ERROR"           # malformed input


@dataclass(frozen=True)
class VerificationResult:
    verdict: Verdict
    uid: str | None = None
    read_counter: int | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.AUTHENTIC


class KeyProvider(Protocol):
    """Supplies the SDM keys. Split so the file key can be diversified by UID."""

    def meta_read_key(self) -> bytes: ...
    def file_read_key(self, uid: bytes) -> bytes: ...


class StaticKeys:
    """Simplest provider: one fixed key pair for every tag."""

    def __init__(self, meta_read_key: bytes, file_read_key: bytes) -> None:
        self._meta = meta_read_key
        self._file = file_read_key

    def meta_read_key(self) -> bytes:
        return self._meta

    def file_read_key(self, uid: bytes) -> bytes:
        return self._file


def _consttime_eq(a: bytes, b: bytes) -> bool:
    # hmac.compare_digest compares the full length without an early return, so
    # the time taken does not reveal how many leading bytes matched. (The
    # previous implementation returned as soon as it hit a differing byte.)
    return hmac.compare_digest(a, b)


def _extract_params(url_or_query: str) -> tuple[bytes, bytes]:
    """Pull picc_data and cmac (hex) from a full URL or a bare query string."""
    parsed = urlparse(url_or_query)
    query = parsed.query or url_or_query
    params = parse_qs(query)

    # Fail-closed: SDMENCFileData is not supported yet. Refuse rather than
    # verify a partial message and return a misleading verdict.
    lower = {k.lower() for k in params}
    if lower & {"enc", "encfiledata", "encdata"}:
        raise SdmError("encrypted file data present but unsupported: refusing")

    # Reject duplicated parameters (parameter pollution) instead of silently
    # taking the first value.
    for name in ("picc_data", "cmac"):
        if len(params.get(name, [])) > 1:
            raise SdmError(f"duplicated parameter '{name}'")

    try:
        picc = bytes.fromhex(params["picc_data"][0])
        cmac = bytes.fromhex(params["cmac"][0])
    except (KeyError, IndexError, ValueError) as exc:
        raise SdmError(f"missing or malformed picc_data/cmac: {exc}") from exc
    return picc, cmac


class Verifier:
    def __init__(self, keys: KeyProvider, store: CounterBackend | None = None) -> None:
        self._keys = keys
        self._store: CounterBackend = store or CounterStore()

    def verify(self, url_or_query: str) -> VerificationResult:
        # 1 + 2: parse and decrypt
        try:
            enc_picc, cmac = _extract_params(url_or_query)
            picc = decrypt_picc_data(enc_picc, self._keys.meta_read_key())
        except SdmError as exc:
            return VerificationResult(Verdict.ERROR, detail=str(exc))

        uid_hex = picc.uid_hex

        # 3: authenticity
        expected = compute_sdmmac(
            self._keys.file_read_key(picc.uid), picc.uid, picc.read_counter
        )
        if not _consttime_eq(expected, cmac):
            return VerificationResult(
                Verdict.FORGED, uid=uid_hex, read_counter=picc.read_counter,
                detail="SDMMAC mismatch: payload is not from a genuine tag",
            )

        # 4: freshness (replay / clone). Atomic check-and-advance closes the
        # TOCTOU window between "is it fresh?" and "record it".
        if not self._store.check_and_advance(uid_hex, picc.read_counter):
            last = self._store.last_counter(uid_hex)
            return VerificationResult(
                Verdict.REPLAY, uid=uid_hex, read_counter=picc.read_counter,
                detail=f"counter {picc.read_counter} <= last seen {last}: "
                       f"replayed URL or cloned tag",
            )

        return VerificationResult(
            Verdict.AUTHENTIC, uid=uid_hex, read_counter=picc.read_counter,
            detail="genuine tag, fresh tap",
        )
