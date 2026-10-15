"""
Verifier for SUN URLs that carry SDMENCFileData (encrypted mirrored file data).

Kept separate from `verifier.py`, which stays fail-closed on these URLs: pick
this verifier explicitly for tags provisioned with an encrypted file mirror.

Supported layout (the one in NXP AN12196 §3.4.4.2.2):

    ...?picc_data=<32 hex>&enc=<n*32 hex>&cmac=<16 hex>

  - SDMMACInputOffset points at the first character of the `enc` value, so the
    SDMMAC covers the mirrored ASCII text `<enc hex>...&cmac=` byte for byte.
  - UID and SDMReadCtr are both mirrored in the PICCData (the ENC session key
    and IV depend on them).

Pipeline for each tapped URL:
  1. Locate picc_data / enc / cmac in the raw query string, keeping offsets.
  2. Decrypt PICCData with the meta-read key -> UID + read counter.
  3. Recompute the SDMMAC over the raw MAC input and compare in constant time.
  4. Check the read counter against the counter store (replay / clone).
  5. Only then decrypt SDMENCFileData and return it.

The URL must reach the verifier exactly as the tag emitted it: the MAC is over
raw bytes, so re-encoding or changing the hex case turns a genuine tap into
FORGED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus, urlparse

from .counterstore import CounterBackend, CounterStore
from .sdm import SdmError, compute_sdmmac, decrypt_picc_data
from .sdmenc import decrypt_file_data
from .verifier import (
    KeyProvider,
    Verdict,
    VerificationResult,
    _consttime_eq,
    _require_standard_picc,
)

_HEX = re.compile(r"[0-9A-Fa-f]+")
_PICC_TAG_CTR_MIRROR = 0x40


@dataclass(frozen=True)
class EncVerificationResult(VerificationResult):
    # Decrypted file data; set only when the verdict is AUTHENTIC.
    file_data: bytes | None = None


@dataclass(frozen=True)
class _EncTap:
    picc_data: bytes
    enc_file_data: bytes
    cmac: bytes
    mac_input: bytes


def _hex_field(name: str, value: str, *, size: int | None = None,
               block: int | None = None) -> bytes:
    # bytes.fromhex() tolerates whitespace; the tag never emits any.
    if not _HEX.fullmatch(value) or len(value) % 2:
        raise SdmError(f"parameter '{name}' is not a hex string")
    data = bytes.fromhex(value)
    if size is not None and len(data) != size:
        raise SdmError(f"parameter '{name}' must be {size} bytes, got {len(data)}")
    if block is not None and len(data) % block:
        raise SdmError(
            f"parameter '{name}' must be a multiple of {block} bytes, got {len(data)}"
        )
    return data


def _parse_tap(url_or_query: str, picc_name: str, enc_name: str,
               mac_name: str) -> _EncTap:
    """Pull the three fields and the raw SDMMAC input from the query string."""
    try:
        parsed = urlparse(url_or_query)
    except ValueError as exc:           # e.g. an unbalanced IPv6 bracket
        raise SdmError(f"unparsable URL: {exc}") from exc
    query = parsed.query or url_or_query

    wanted = {name.lower(): name for name in (picc_name, enc_name, mac_name)}
    found: dict[str, tuple[int, str]] = {}   # name -> (value offset, value)
    offset = 0
    for segment in query.split("&"):
        raw_name, sep, value = segment.partition("=")
        name = wanted.get(unquote_plus(raw_name).lower())
        if name is not None:
            # A percent-encoded or re-cased name would shift the MAC input
            # away from what the tag produced: refuse instead of guessing.
            if raw_name != name:
                raise SdmError(f"parameter '{name}' must appear literally, "
                               f"got '{raw_name}'")
            if name in found:
                raise SdmError(f"duplicated parameter '{name}'")
            if not sep:
                raise SdmError(f"parameter '{name}' has no value")
            found[name] = (offset + len(raw_name) + 1, value)
        offset += len(segment) + 1

    missing = [n for n in (picc_name, enc_name, mac_name) if n not in found]
    if missing:
        raise SdmError(f"missing parameter(s): {', '.join(missing)}")

    enc_offset, enc_hex = found[enc_name]
    mac_offset, mac_hex = found[mac_name]
    if mac_offset < enc_offset:
        raise SdmError(f"'{mac_name}' must follow '{enc_name}': the SDMMAC "
                       f"input runs from the encrypted data up to the MAC")
    try:
        mac_input = query[enc_offset:mac_offset].encode("ascii")
    except UnicodeEncodeError as exc:
        raise SdmError("SDMMAC input is not ASCII") from exc

    return _EncTap(
        picc_data=_hex_field(picc_name, found[picc_name][1], size=16),
        enc_file_data=_hex_field(enc_name, enc_hex, block=16),
        cmac=_hex_field(mac_name, mac_hex, size=8),
        mac_input=mac_input,
    )


class EncFileVerifier:
    """URL in, verdict + decrypted file data out (SDMENCFileData layout)."""

    def __init__(self, keys: KeyProvider, store: CounterBackend | None = None,
                 *, picc_param: str = "picc_data", enc_param: str = "enc",
                 mac_param: str = "cmac") -> None:
        names = (picc_param, enc_param, mac_param)
        if len({n.lower() for n in names}) != 3:
            raise ValueError("parameter names must be distinct")
        self._keys = keys
        self._store: CounterBackend = store or CounterStore()
        self._names = names

    def verify(self, url_or_query: str) -> EncVerificationResult:
        # 1 + 2: parse and decrypt PICCData
        try:
            tap = _parse_tap(url_or_query, *self._names)
            picc = decrypt_picc_data(tap.picc_data, self._keys.meta_read_key())
            if not picc.raw_tag & _PICC_TAG_CTR_MIRROR:
                raise SdmError("SDMENCFileData requires SDMReadCtr in PICCData")
            _require_standard_picc(picc)
        except SdmError as exc:
            return EncVerificationResult(Verdict.ERROR, detail=str(exc))

        uid_hex = picc.uid_hex
        file_key = self._keys.file_read_key(picc.uid)

        # 3: authenticity, over the raw mirrored bytes
        expected = compute_sdmmac(file_key, picc.uid, picc.read_counter,
                                  tap.mac_input)
        if not _consttime_eq(expected, tap.cmac):
            # Never echo the unauthenticated UID and counter (decryption oracle).
            return EncVerificationResult(
                Verdict.FORGED,
                detail="SDMMAC mismatch: payload is not from a genuine tag",
            )

        # 4: freshness (replay / clone), atomic check-and-advance
        if not self._store.check_and_advance(uid_hex, picc.read_counter):
            last = self._store.last_counter(uid_hex)
            return EncVerificationResult(
                Verdict.REPLAY, uid=uid_hex, read_counter=picc.read_counter,
                detail=f"counter {picc.read_counter} <= last seen {last}: "
                       f"replayed URL or cloned tag",
            )

        # 5: the ciphertext is authenticated, now it is safe to decrypt
        file_data = decrypt_file_data(file_key, picc.uid, picc.read_counter,
                                      tap.enc_file_data)
        return EncVerificationResult(
            Verdict.AUTHENTIC, uid=uid_hex, read_counter=picc.read_counter,
            detail="genuine tag, fresh tap", file_data=file_data,
        )
