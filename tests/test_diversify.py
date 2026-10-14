"""
AN10922 AES-128 key diversification.

Pinned to the NXP AN10922 §2.2.1 worked example, including its sub-keys, and
cross-checked against a standard CMAC wherever AN10922 says the two coincide
(M longer than 15 bytes). Shorter inputs, such as a bare 7-byte UID, must use
the two-block padding of the application note, not a standard CMAC.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from Crypto.Cipher import AES  # noqa: E402
from Crypto.Hash import CMAC  # noqa: E402

from sphragis.diversify import DiversifiedKeys, _dbl, diversify_key  # noqa: E402

H = bytes.fromhex
AN_MASTER = H("00112233445566778899AABBCCDDEEFF")
AN_M = H("04782E21801D803042F54E585020416275")   # UID || AID || "NXP Abu"


def test_an10922_subkeys():
    k0 = AES.new(AN_MASTER, AES.MODE_ECB).encrypt(bytes(16))
    assert k0.hex().upper() == "FDE4FBAE4A09E020EFF722969F83832B"
    k1 = _dbl(k0)
    assert k1.hex().upper() == "FBC9F75C9413C041DFEE452D3F0706D1"
    assert _dbl(k1).hex().upper() == "F793EEB928278083BFDC8A5A7E0E0D25"


def test_an10922_aes128_example():
    assert diversify_key(AN_MASTER, AN_M).hex().upper() == \
        "A8DD63A3B89D54B37CA802473FDA9175"


def _standard_cmac(key, m):
    c = CMAC.new(key, ciphermod=AES)
    c.update(b"\x01" + m)
    return c.digest()


@pytest.mark.parametrize("length", range(16, 32))
def test_matches_standard_cmac_when_input_is_long(length):
    # AN10922: "If the length of M is more than 15 bytes, standard CMAC
    # algorithm can be used".
    key, m = os.urandom(16), os.urandom(length)
    assert diversify_key(key, m) == _standard_cmac(key, m)


@pytest.mark.parametrize("length", range(1, 16))
def test_short_input_uses_two_block_padding(length):
    key, m = os.urandom(16), os.urandom(length)
    # Explicit AN10922 construction: pad D to 32 bytes, XOR K2, CBC-MAC.
    d = b"\x01" + m + b"\x80" + bytes(30 - length)
    k2 = _dbl(_dbl(AES.new(key, AES.MODE_ECB).encrypt(bytes(16))))
    d = d[:16] + bytes(a ^ b for a, b in zip(d[16:], k2))
    expected = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(d)[16:]
    assert diversify_key(key, m) == expected
    assert diversify_key(key, m) != _standard_cmac(key, m)


def test_bare_uid_known_answer():
    # Regression pin for the most common input, a bare 7-byte UID, which a
    # standard CMAC would get wrong (it gave 30443849…E1B4 for this input).
    master = H("C8EE97FD8B00185EDC7598D7FEBC818A")
    assert diversify_key(master, H("04958CAA5C5E80")).hex().upper() == \
        "F7FEBC360ACF72957B3D8DCFFEAA97EE"


def test_input_and_key_length_limits():
    with pytest.raises(ValueError):
        diversify_key(AN_MASTER, b"")
    with pytest.raises(ValueError):
        diversify_key(AN_MASTER, bytes(32))
    with pytest.raises(ValueError):
        diversify_key(bytes(15), b"\x01")
    assert len(diversify_key(AN_MASTER, bytes(31))) == 16


def test_diversified_keys_provider_uses_context_then_uid():
    master, meta, uid = os.urandom(16), os.urandom(16), H("04112233445566")
    keys = DiversifiedKeys(master, meta, context=b"CTX")
    assert keys.file_read_key(uid) == diversify_key(master, b"CTX" + uid)
    assert keys.meta_read_key() == meta
    assert keys.file_read_key(uid) != keys.file_read_key(H("04112233445567"))
