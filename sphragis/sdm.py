"""
Core SDM / SUN verification for NTAG 424 DNA tags.

This implements the *standard* NXP Secure Dynamic Messaging (SDM) scheme, also
called SUN (Secure Unique NFC). It is documented publicly in NXP application
note AN12196 and is NOT proprietary — it is the plumbing every NTAG 424 DNA
deployment shares.

A tag, on each tap, emits a URL whose query string carries:
  - PICCData : AES-CBC encrypted block containing a tag tag-byte, the UID and a
               monotonically increasing read counter (SDMReadCtr).
  - SDMMAC   : a truncated AES-CMAC that authenticates that read.

Verifying both proves the tag is genuine (holds the secret keys) and, by
tracking the read counter, lets a backend detect cloned or replayed taps.

References:
  NXP AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints".
"""

from __future__ import annotations

from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

# --- Protocol constants ------------------------------------------------------

# 16 zero bytes, used as the IV for PICCData decryption (AES-CBC).
_ZERO_IV = b"\x00" * 16

# Session-vector header for the SDM file-read MAC session key (AN12196 §4.3.3).
_SV2_PREFIX = bytes([0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80])

# PICCDataTag bit flags (first decrypted byte).
_TAG_UID_MIRROR = 0x80   # UID is present in the PICCData
_TAG_CTR_MIRROR = 0x40   # SDMReadCtr is present in the PICCData
_TAG_UID_LEN_MASK = 0x0F  # low nibble = UID length in bytes


class SdmError(Exception):
    """Raised when a tag payload is structurally invalid or fails verification."""


@dataclass(frozen=True)
class PiccData:
    """Decrypted, still-unauthenticated contents of the PICCData block."""

    uid: bytes          # tag UID (usually 7 bytes)
    read_counter: int   # SDMReadCtr, little-endian 24-bit value
    raw_tag: int        # the PICCDataTag byte, for debugging

    @property
    def uid_hex(self) -> str:
        return self.uid.hex().upper()


# --- Low-level primitives ----------------------------------------------------


def _aes_cmac(key: bytes, message: bytes) -> bytes:
    """Full 16-byte AES-CMAC."""
    c = CMAC.new(key, ciphermod=AES)
    c.update(message)
    return c.digest()


def _truncate_mac(mac16: bytes) -> bytes:
    """SDM MAC truncation: take the 8 bytes at odd indices (1,3,5,...,15)."""
    return bytes(mac16[i] for i in range(1, 16, 2))


def decrypt_picc_data(enc_picc_data: bytes, meta_read_key: bytes) -> PiccData:
    """
    Decrypt the PICCData block with K_SDMMetaReadKey (AES-CBC, zero IV) and
    parse out the UID and read counter.
    """
    if len(enc_picc_data) != 16:
        raise SdmError(
            f"PICCData must be 16 bytes, got {len(enc_picc_data)}"
        )
    plain = AES.new(meta_read_key, AES.MODE_CBC, _ZERO_IV).decrypt(enc_picc_data)

    tag_byte = plain[0]
    if not tag_byte & _TAG_UID_MIRROR:
        raise SdmError("PICCData does not contain a UID (UID mirror flag unset)")

    uid_len = tag_byte & _TAG_UID_LEN_MASK
    if uid_len == 0:
        raise SdmError("invalid PICCData: UID length is zero")
    needed = 1 + uid_len + (3 if tag_byte & _TAG_CTR_MIRROR else 0)
    if needed > len(plain):
        raise SdmError(
            f"invalid PICCData: declared fields ({needed} B) exceed block "
            f"length ({len(plain)} B)"
        )

    offset = 1
    uid = plain[offset : offset + uid_len]
    offset += uid_len

    read_counter = 0
    if tag_byte & _TAG_CTR_MIRROR:
        ctr_bytes = plain[offset : offset + 3]
        read_counter = int.from_bytes(ctr_bytes, "little")

    return PiccData(uid=uid, read_counter=read_counter, raw_tag=tag_byte)


def derive_session_mac_key(file_read_key: bytes, uid: bytes, read_counter: int) -> bytes:
    """
    Derive K_SesSDMFileReadMAC from K_SDMFileReadKey, the UID and the read
    counter (AN12196 §4.3.3): CMAC over SV2 = prefix || UID || SDMReadCtr.
    """
    sv2 = _SV2_PREFIX + uid + read_counter.to_bytes(3, "little")
    return _aes_cmac(file_read_key, sv2)


def compute_sdmmac(
    file_read_key: bytes,
    uid: bytes,
    read_counter: int,
    enc_file_data: bytes = b"",
) -> bytes:
    """
    Compute the expected 8-byte SDMMAC for a given tag read.

    For a plain SUN message (no encrypted file data mirrored) the MAC'd message
    is empty. If encrypted file data is mirrored it is included here.
    """
    session_key = derive_session_mac_key(file_read_key, uid, read_counter)
    return _truncate_mac(_aes_cmac(session_key, enc_file_data))
