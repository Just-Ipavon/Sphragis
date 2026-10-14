"""
Software tag emulator.

Lets the whole project run with no physical NTAG 424 DNA tag: given a set of
SDM keys, a UID and a read counter, it produces exactly the SUN URL a real tag
would emit on that tap. Useful for development, CI and reproducible tests.

The emulator is the *inverse* of the verifier: it builds a valid PICCData block
and SDMMAC that the verifier then accepts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlencode

from Crypto.Cipher import AES

from .sdm import _ZERO_IV, compute_sdmmac
from .sdmenc import encrypt_file_data

# PICCDataTag for "UID mirrored (7 bytes) + read counter present".
_PICC_TAG_UID7_CTR = 0xC7


@dataclass
class EmulatedTag:
    """A virtual NTAG 424 DNA tag with fixed keys and UID, counting up per tap."""

    uid: bytes
    meta_read_key: bytes          # K_SDMMetaReadKey (PICCData encryption)
    file_read_key: bytes          # K_SDMFileReadKey (MAC)
    base_url: str = "https://example.com/t"
    read_counter: int = 0

    def __post_init__(self) -> None:
        if len(self.uid) != 7:
            raise ValueError("this emulator models a 7-byte UID")
        for name, k in (("meta_read_key", self.meta_read_key),
                        ("file_read_key", self.file_read_key)):
            if len(k) != 16:
                raise ValueError(f"{name} must be an AES-128 (16-byte) key")

    def _encrypt_picc_data(self) -> bytes:
        """Build and encrypt the PICCData block for the current counter value."""
        plain = bytes([_PICC_TAG_UID7_CTR])
        plain += self.uid
        plain += self.read_counter.to_bytes(3, "little")
        # Pad the remaining bytes with random data, as a real tag does.
        plain += os.urandom(16 - len(plain))
        return AES.new(self.meta_read_key, AES.MODE_CBC, _ZERO_IV).encrypt(plain)

    def tap(self) -> str:
        """
        Simulate one physical tap: increment the counter and return the SUN URL.
        """
        self.read_counter += 1
        enc_picc = self._encrypt_picc_data()
        mac = compute_sdmmac(self.file_read_key, self.uid, self.read_counter)
        query = urlencode({
            "picc_data": enc_picc.hex().upper(),
            "cmac": mac.hex().upper(),
        })
        return f"{self.base_url}?{query}"


@dataclass
class EmulatedEncTag(EmulatedTag):
    """
    An EmulatedTag with SDMENCFileData mirroring: each tap also encrypts
    `file_data` and emits `...&enc=<hex>&cmac=<hex>`, with the SDMMAC over the
    ASCII text `<enc hex>&cmac=` (SDMMACInputOffset at the `enc` value).
    """

    file_data: bytes = b"\x00" * 16   # static plaintext, n * 16 bytes

    def tap(self) -> str:
        self.read_counter += 1
        enc_picc = self._encrypt_picc_data()
        enc_hex = encrypt_file_data(
            self.file_read_key, self.uid, self.read_counter, self.file_data
        ).hex().upper()
        mac = compute_sdmmac(self.file_read_key, self.uid, self.read_counter,
                             f"{enc_hex}&cmac=".encode("ascii"))
        return (f"{self.base_url}?picc_data={enc_picc.hex().upper()}"
                f"&enc={enc_hex}&cmac={mac.hex().upper()}")


def random_tag(base_url: str = "https://example.com/t") -> EmulatedTag:
    """Create an emulated tag with random keys and UID (handy for demos/tests)."""
    return EmulatedTag(
        uid=os.urandom(7),
        meta_read_key=os.urandom(16),
        file_read_key=os.urandom(16),
        base_url=base_url,
    )


def tag_from_provider(provider, uid: bytes,
                      base_url: str = "https://example.com/t",
                      read_counter: int = 0) -> EmulatedTag:
    """
    Build an emulated tag whose keys come from a KeyProvider (e.g. a
    DiversifiedKeys instance). Keeps the emulator and verifier perfectly in
    sync when per-UID key diversification is in use.
    """
    return EmulatedTag(
        uid=uid,
        meta_read_key=provider.meta_read_key(),
        file_read_key=provider.file_read_key(uid),
        base_url=base_url,
        read_counter=read_counter,
    )
