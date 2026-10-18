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
  4. Only then decrypt SDMENCFileData.
  5. Check the read counter against the counter store (replay / clone); the
     file data is returned for a fresh tap only.

The URL must reach the verifier exactly as the tag emitted it: the MAC is over
raw bytes, so re-encoding or changing the hex case turns a genuine tap into
FORGED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

from .backends import AuthenticTap, ForgedTap
from .counterstore import CounterBackend, CounterStore
from .sdm import SdmError, compute_sdmmac
from .sdmenc import decrypt_file_data
from .keyring import KeyRing
from .verifier import (
    _ENC_MARKERS,
    KeyProvider,
    Verdict,
    VerificationResult,
    _first_verifying,
    _query_of,
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
    query = _query_of(url_or_query)

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


class Ntag424EncBackend:
    """
    SUN with SDMENCFileData on NTAG 424 DNA: the SDMMAC covers the mirrored
    encrypted file data, which is decrypted once the MAC verifies and returned
    as the tap's payload. The identity is the UID in upper-case hex.

    `keys` is one provider (key version 1) or a `KeyRing`: each version is
    tried, newest first, and the one that verifies is reported.
    """

    name = "ntag424-sun-enc"
    algorithm = "AES-128-CMAC+AES-128-CBC"

    def __init__(self, keys: "KeyProvider | KeyRing", *, picc_param: str = "picc_data",
                 enc_param: str = "enc", mac_param: str = "cmac") -> None:
        names = (picc_param, enc_param, mac_param)
        if len({n.lower() for n in names}) != 3:
            raise ValueError("parameter names must be distinct")
        self._ring = KeyRing.of(keys)
        self._names = names

    def accepts(self, url_or_query: str) -> bool:
        try:
            query = _query_of(url_or_query)
        except SdmError:
            return False
        enc = self._names[1].lower()
        return any(unquote_plus(seg.partition("=")[0]).lower() in (enc, *_ENC_MARKERS)
                   for seg in query.split("&"))

    def authenticate(self, url_or_query: str) -> AuthenticTap:
        tap = _parse_tap(url_or_query, *self._names)

        def require_counter(picc):
            if not picc.raw_tag & _PICC_TAG_CTR_MIRROR:
                raise SdmError("SDMENCFileData requires SDMReadCtr in PICCData")

        # Authenticity, over the raw mirrored bytes
        def mac_of(picc, keys):
            return compute_sdmmac(keys.file_read_key(picc.uid), picc.uid,
                                  picc.read_counter, tap.mac_input)

        version, picc = _first_verifying(self._ring, tap.picc_data, tap.cmac,
                                         mac_of, require_counter)
        keys = dict(iter(self._ring))[version]

        # The ciphertext is authenticated, now it is safe to decrypt
        file_data = decrypt_file_data(keys.file_read_key(picc.uid), picc.uid,
                                      picc.read_counter, tap.enc_file_data)
        return AuthenticTap(picc.uid_hex, picc.read_counter, self.name,
                            self.algorithm, file_data, key_version=version)


class EncFileVerifier:
    """URL in, verdict + decrypted file data out (SDMENCFileData layout)."""

    def __init__(self, keys: "KeyProvider | KeyRing", store: CounterBackend | None = None,
                 *, picc_param: str = "picc_data", enc_param: str = "enc",
                 mac_param: str = "cmac") -> None:
        self._backend = Ntag424EncBackend(keys, picc_param=picc_param,
                                          enc_param=enc_param, mac_param=mac_param)
        self._store: CounterBackend = store or CounterStore()

    def verify(self, url_or_query: str) -> EncVerificationResult:
        # 1-3: parse, decrypt PICCData, check the SDMMAC, decrypt the file data
        try:
            tap = self._backend.authenticate(url_or_query)
        except SdmError as exc:
            return EncVerificationResult(Verdict.ERROR, detail=str(exc))
        except ForgedTap as exc:
            return EncVerificationResult(Verdict.FORGED, detail=str(exc))

        # 4: freshness (replay / clone), atomic check-and-advance. File data
        # is returned only for a fresh tap.
        if not self._store.check_and_advance(tap.identity, tap.counter):
            last = self._store.last_counter(tap.identity)
            return EncVerificationResult(
                Verdict.REPLAY, uid=tap.identity, read_counter=tap.counter,
                detail=f"counter {tap.counter} <= last seen {last}: "
                       f"replayed URL or cloned tag",
            )

        return EncVerificationResult(
            Verdict.AUTHENTIC, uid=tap.identity, read_counter=tap.counter,
            detail="genuine tag, fresh tap", file_data=tap.payload,
        )
