"""
Per-UID key diversification (NXP AN10922, AES-128).

A fixed master key on every tag is a single point of total failure: extract it
from one tag and you can forge them all. Real deployments therefore store a
*diversified* key on each tag, derived from a master key and tag-unique data
(the UID). The backend re-derives the same key on demand.

AN10922 AES-128 diversification is the standard AES-CMAC construction
(NIST SP 800-38B) over `0x01 || DivInput`, where `0x01` is the AES-128
diversification constant and `DivInput` is tag-unique data.

This is exactly the key-management pattern a production NTAG 424 DNA system
needs, so the same code serves both this portfolio project and real work.
"""

from __future__ import annotations

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# AES-128 diversification constant (AN10922 §2.2.1).
_DIV_CONSTANT_AES128 = b"\x01"


def diversify_key(master_key: bytes, div_input: bytes) -> bytes:
    """
    Derive a 16-byte diversified AES-128 key from a master key and
    diversification input, per AN10922: CMAC(master, 0x01 || div_input).
    """
    if len(master_key) != 16:
        raise ValueError("master key must be AES-128 (16 bytes)")
    if not 1 <= len(div_input) <= 31:
        # AN10922 bounds the AES-128 diversification input to 1..31 bytes.
        raise ValueError("div_input must be between 1 and 31 bytes")
    c = CMAC.new(master_key, ciphermod=AES)
    c.update(_DIV_CONSTANT_AES128 + div_input)
    return c.digest()


class DiversifiedKeys:
    """
    KeyProvider that diversifies the file-read (MAC) key per UID.

    The meta-read key (needed to decrypt PICCData *before* the UID is known) is
    kept fixed, as in a typical deployment; the file-read key — which actually
    authenticates the tap — is unique to every tag.

    `context` is an optional application/system label mixed into the
    diversification input so the same master key yields different keys across
    unrelated deployments.
    """

    def __init__(
        self,
        master_file_key: bytes,
        meta_read_key: bytes,
        context: bytes = b"",
    ) -> None:
        if len(master_file_key) != 16 or len(meta_read_key) != 16:
            raise ValueError("keys must be AES-128 (16 bytes)")
        if len(context) > 24:
            raise ValueError("context too long (leaves no room for the UID)")
        self._master_file = master_file_key
        self._meta = meta_read_key
        self._context = context

    def _div_input(self, uid: bytes) -> bytes:
        return self._context + uid

    def meta_read_key(self) -> bytes:
        return self._meta

    def file_read_key(self, uid: bytes) -> bytes:
        return diversify_key(self._master_file, self._div_input(uid))
