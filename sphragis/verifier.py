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
import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from urllib.parse import parse_qs, urlparse

from .backends import AuthenticTap, ForgedTap
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


# PICCDataTag of the layout this engine provisions and verifies: UID mirror,
# SDMReadCtr mirror, 7-byte UID, RFU bits clear (NT4H2421Gx §9.3.3).
STANDARD_PICC_TAG = 0xC7


def _require_standard_picc(picc) -> None:
    """
    Refuse any PICCData other than UID (7 bytes) + SDMReadCtr. A random block
    decrypts to an arbitrary tag byte; accepting only the one layout keeps
    crafted input from reaching key derivation with odd UID lengths, and a
    missing counter from silently reading as 0.
    """
    if picc.raw_tag != STANDARD_PICC_TAG or len(picc.uid) != 7:
        raise SdmError("PICCData is not the UID + SDMReadCtr layout (tag 0xC7)")


def _query_of(url_or_query: str) -> str:
    """
    The query string of a full URL, or the input itself when it is a bare
    query. A URL without a query has none: its fragment or path is never read
    as one, so a tap has a single encoding.
    """
    try:
        parsed = urlparse(url_or_query)
    except ValueError as exc:           # e.g. an unbalanced IPv6 bracket
        raise SdmError(f"unparsable URL: {exc}") from exc
    if parsed.scheme or parsed.netloc or "?" in url_or_query or "#" in url_or_query:
        return parsed.query
    return url_or_query


_ENC_MARKERS = frozenset({"enc", "encfiledata", "encdata"})

_HEX_FIELD = {"picc_data": re.compile(r"[0-9A-Fa-f]{32}"),
              "cmac": re.compile(r"[0-9A-Fa-f]{16}")}


def _extract_params(url_or_query: str) -> tuple[bytes, bytes]:
    """Pull picc_data and cmac (hex) from a full URL or a bare query string."""
    # Blank values are kept so that an empty `enc=` still trips the
    # fail-closed check below.
    params = parse_qs(_query_of(url_or_query), keep_blank_values=True)

    # Fail-closed: SDMENCFileData is verified by its own backend. Refuse rather
    # than verify a partial message and return a misleading verdict.
    lower = {k.lower() for k in params}
    if lower & _ENC_MARKERS:
        raise SdmError("encrypted file data present but unsupported: refusing")

    # Reject duplicated parameters (parameter pollution) instead of silently
    # taking the first value.
    for name in ("picc_data", "cmac"):
        if len(params.get(name, [])) > 1:
            raise SdmError(f"duplicated parameter '{name}'")

    values = []
    for name in ("picc_data", "cmac"):
        if name not in params:
            raise SdmError(f"missing parameter '{name}'")
        # bytes.fromhex() tolerates whitespace and parse_qs() decodes '+' and
        # %xx; the tag emits neither, so only the exact hex form is accepted.
        if not _HEX_FIELD[name].fullmatch(params[name][0]):
            raise SdmError(f"malformed parameter '{name}'")
        values.append(bytes.fromhex(params[name][0]))
    picc, cmac = values
    return picc, cmac


class Ntag424SunBackend:
    """
    Plain SUN on NTAG 424 DNA: AES-128 PICCData (UID + SDMReadCtr) and a
    truncated AES-CMAC (SDMMAC). The identity is the UID in upper-case hex.

    It accepts every tap without an encrypted file-data parameter, malformed
    ones included, so that it reports why they cannot be verified.
    """

    name = "ntag424-sun"
    algorithm = "AES-128-CMAC"

    def __init__(self, keys: KeyProvider) -> None:
        self._keys = keys

    def accepts(self, url_or_query: str) -> bool:
        try:
            params = parse_qs(_query_of(url_or_query), keep_blank_values=True)
        except SdmError:
            return True
        return not {k.lower() for k in params} & _ENC_MARKERS

    def authenticate(self, url_or_query: str) -> AuthenticTap:
        enc_picc, cmac = _extract_params(url_or_query)
        picc = decrypt_picc_data(enc_picc, self._keys.meta_read_key())
        _require_standard_picc(picc)
        expected = compute_sdmmac(
            self._keys.file_read_key(picc.uid), picc.uid, picc.read_counter
        )
        if not _consttime_eq(expected, cmac):
            # UID and counter come from an unauthenticated decryption: they go
            # nowhere (decryption oracle).
            raise ForgedTap("SDMMAC mismatch: payload is not from a genuine tag")
        return AuthenticTap(picc.uid_hex, picc.read_counter, self.name, self.algorithm)


class Verifier:
    def __init__(self, keys: KeyProvider, store: CounterBackend | None = None) -> None:
        self._backend = Ntag424SunBackend(keys)
        self._store: CounterBackend = store or CounterStore()

    def verify(self, url_or_query: str) -> VerificationResult:
        # 1-3: parse, decrypt, check the SDMMAC
        try:
            tap = self._backend.authenticate(url_or_query)
        except SdmError as exc:
            return VerificationResult(Verdict.ERROR, detail=str(exc))
        except ForgedTap as exc:
            return VerificationResult(Verdict.FORGED, detail=str(exc))

        # 4: freshness (replay / clone). Atomic check-and-advance closes the
        # TOCTOU window between "is it fresh?" and "record it".
        if not self._store.check_and_advance(tap.identity, tap.counter):
            last = self._store.last_counter(tap.identity)
            return VerificationResult(
                Verdict.REPLAY, uid=tap.identity, read_counter=tap.counter,
                detail=f"counter {tap.counter} <= last seen {last}: "
                       f"replayed URL or cloned tag",
            )

        return VerificationResult(
            Verdict.AUTHENTIC, uid=tap.identity, read_counter=tap.counter,
            detail="genuine tag, fresh tap",
        )
