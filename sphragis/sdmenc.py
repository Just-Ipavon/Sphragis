"""
SDMENCFileData primitives for NTAG 424 DNA (pure, no I/O).

When SDMENCFileData mirroring is enabled the tag encrypts a slice of the NDEF
file's static data on every read and mirrors it, as ASCII hex, into the URL
(typically an `enc` query parameter). This module holds the crypto for that
mirror; the plain SUN path in `sdm.py` is reused unchanged.

  SV1        = C3h 3Ch 00h 01h 00h 80h || UID || SDMReadCtr [|| zero padding]
  KSesENC    = AES-CMAC(K_SDMFileReadKey, SV1)
  IVe        = AES-ECB(KSesENC, SDMReadCtr || 00h * 13)
  FileData   = AES-CBC-Decrypt(KSesENC, IVe, SDMENCFileData)

With an encrypted mirror the SDMMAC is no longer computed over an empty
message: it covers the mirrored ASCII bytes from SDMMACInputOffset up to
SDMMACOffset - 1, which must include the whole SDMENCFileData (for the usual
layout: `<enc hex>&cmac=`). `sdm.compute_sdmmac` already accepts that input.

References:
  NXP AN12196 Rev. 2.0, §3.4.3 (Table 3) and §3.4.4.2.2 (Table 5).
"""

from __future__ import annotations

from Crypto.Cipher import AES

from .sdm import SdmError, _aes_cmac

# Session-vector header for the SDM file-read ENC session key (AN12196 §3.4.3).
_SV1_PREFIX = bytes([0xC3, 0x3C, 0x00, 0x01, 0x00, 0x80])

_BLOCK = 16


def _counter_bytes(read_counter: int) -> bytes:
    if not 0 <= read_counter < 1 << 24:
        raise SdmError(f"SDMReadCtr out of 24-bit range: {read_counter}")
    return read_counter.to_bytes(3, "little")


def derive_session_enc_key(file_read_key: bytes, uid: bytes, read_counter: int) -> bytes:
    """
    Derive K_SesSDMFileReadENC from K_SDMFileReadKey, the UID and the read
    counter: CMAC over SV1 = prefix || UID || SDMReadCtr, zero-padded to a
    whole block (a 7-byte UID fills exactly one block).
    """
    sv1 = _SV1_PREFIX + uid + _counter_bytes(read_counter)
    sv1 += b"\x00" * (-len(sv1) % _BLOCK)
    return _aes_cmac(file_read_key, sv1)


def file_data_iv(session_enc_key: bytes, read_counter: int) -> bytes:
    """IVe = AES-ECB(K_SesSDMFileReadENC, SDMReadCtr || 13 zero bytes)."""
    block = _counter_bytes(read_counter) + b"\x00" * 13
    return AES.new(session_enc_key, AES.MODE_ECB).encrypt(block)


def _check_length(data: bytes) -> None:
    if not data or len(data) % _BLOCK:
        raise SdmError(
            f"SDMENCFileData must be a non-empty multiple of {_BLOCK} bytes, "
            f"got {len(data)}"
        )


def decrypt_file_data(
    file_read_key: bytes, uid: bytes, read_counter: int, enc_file_data: bytes
) -> bytes:
    """
    Decrypt SDMENCFileData. The result is the raw static file slice; there is
    no padding to strip. Only call this after the SDMMAC has been verified:
    CBC decryption on its own authenticates nothing.
    """
    _check_length(enc_file_data)
    key = derive_session_enc_key(file_read_key, uid, read_counter)
    iv = file_data_iv(key, read_counter)
    return AES.new(key, AES.MODE_CBC, iv).decrypt(enc_file_data)


def encrypt_file_data(
    file_read_key: bytes, uid: bytes, read_counter: int, file_data: bytes
) -> bytes:
    """Tag side of `decrypt_file_data`, for emulators and tests."""
    _check_length(file_data)
    key = derive_session_enc_key(file_read_key, uid, read_counter)
    iv = file_data_iv(key, read_counter)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(file_data)
