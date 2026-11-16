"""
Master keys in an HSM, through PKCS#11 (optional extra: `sphragis[hsm]`).

`Pkcs11KeyProvider` is a `KeyProvider` whose master keys are non-extractable
objects in a PKCS#11 token (a hardware HSM, a cloud HSM with a PKCS#11
library, or SoftHSM2 for tests). The process never holds them:

- **file_read_key(uid)**: the AN10922 diversification is a CMAC under the
  master file key. The token computes the two AES operations it needs
  (`L = E_K(0)` for the CMAC subkeys, then AES-CBC with a zero IV over the
  32-byte diversification block); only the per-UID key comes back. AN10922
  pads short input to 32 bytes and uses the K2 subkey, which a token's
  `CKM_AES_CMAC` cannot express, hence the two raw operations.
- **decrypt_picc(enc)**: PICCData is decrypted in the token (AES-CBC, zero
  IV, one block) with the meta-read key, so this fleet-wide key stays inside
  too. `meta_read_key()` refuses.

Key objects need `CKA_ENCRYPT` (master file) or `CKA_DECRYPT` (meta read) for
`CKM_AES_CBC`, and are imported with `CKA_SENSITIVE` set and `CKA_EXTRACTABLE`
cleared (`import_keys`, or `sphragis hsm-import`). Labels are
`<prefix><name>` for version 1 and `<prefix><name>_v<N>` after, as in
`sphragis.keyring`, so `build_pkcs11_keyring` gives a `KeyRing` that rotates
exactly like the secrets-backed one.

Per-UID keys are cached for `cache_seconds` (default 60, 0 disables), at most
`cache_size` of them, to spare the token a round trip per tap; they are the
keys of single tags, never the masters. The SDM session key and MAC are still
computed in the process from the per-UID key.

What it does not cover: provisioning (`tools/rekey.py`) writes keys to tags,
so it needs the keys themselves; keep the offline copy you imported from for
that, in the place and under the controls key management describes.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Iterable, Sequence

from .keyring import KeyRing, versioned_name

_BLOCK = 16
_ZERO = bytes(_BLOCK)
_RB = 0x87
DEFAULT_PREFIX = "sphragis."


def _pkcs11():
    try:
        import pkcs11
    except ImportError as exc:  # pragma: no cover - depends on the extra
        raise ImportError("PKCS#11 support needs python-pkcs11: "
                          "pip install 'sphragis[hsm]'") from exc
    return pkcs11


def _dbl(block: bytes) -> bytes:
    n = int.from_bytes(block, "big") << 1
    if n >> 128:
        n = (n & ((1 << 128) - 1)) ^ _RB
    return n.to_bytes(_BLOCK, "big")


def an10922_block(subkey_source: bytes, div_input: bytes) -> bytes:
    """The 32-byte block AN10922 encrypts with AES-CBC (zero IV) to diversify:
    0x01 || M, padded and with its last block masked by K1 or K2, where the
    subkeys come from `subkey_source` = E_K(0)."""
    if not 1 <= len(div_input) <= 31:
        raise ValueError("div_input must be between 1 and 31 bytes")
    k1 = _dbl(subkey_source)
    k2 = _dbl(k1)
    d = b"\x01" + div_input
    if len(d) < 2 * _BLOCK:
        d += b"\x80" + bytes(2 * _BLOCK - 1 - len(d))
        last = k2
    else:
        last = k1
    return d[:_BLOCK] + bytes(a ^ b for a, b in zip(d[_BLOCK:], last, strict=True))


class Pkcs11Token:
    """An open, logged-in session on one token, shared by the providers.
    Read-only unless `rw` (only `import_keys` writes)."""

    def __init__(self, module: str, token_label: str, pin: str, *, rw: bool = False) -> None:
        pkcs11 = _pkcs11()
        self._lib = pkcs11.lib(module)
        token = self._lib.get_token(token_label=token_label)
        try:
            self._session = token.open(user_pin=pin, rw=rw)
        except pkcs11.UserAlreadyLoggedIn:
            # PKCS#11 logins are per process: another session of ours already
            # logged in, and this one shares it (and will not log it out).
            self._session = token.open(rw=rw)
        self._lock = threading.Lock()

    def key(self, label: str):
        pkcs11 = _pkcs11()
        try:
            return self._session.get_key(object_class=pkcs11.ObjectClass.SECRET_KEY,
                                         key_type=pkcs11.KeyType.AES, label=label)
        except (pkcs11.NoSuchKey, pkcs11.MultipleObjectsReturned) as exc:
            raise KeyError(f"no single AES key labelled {label!r} on the token") from exc

    def cbc(self, key, data: bytes, *, decrypt: bool = False) -> bytes:
        mech = _pkcs11().Mechanism.AES_CBC
        with self._lock:                      # one operation at a time per session
            if decrypt:
                return bytes(key.decrypt(data, mechanism=mech, mechanism_param=_ZERO))
            return bytes(key.encrypt(data, mechanism=mech, mechanism_param=_ZERO))

    def close(self) -> None:
        with self._lock:
            self._session.close()


class Pkcs11KeyProvider:
    """KeyProvider over one key version held in a PKCS#11 token."""

    def __init__(self, token: Pkcs11Token, master_file_label: str, meta_read_label: str,
                 context: bytes = b"", cache_seconds: float = 60.0,
                 cache_size: int = 10_000, clock=time.monotonic) -> None:
        if len(context) > 24:
            raise ValueError("context too long (leaves no room for the UID)")
        if master_file_label == meta_read_label:
            raise ValueError("master_file and meta_read must be different keys")
        self._token = token
        self._master = token.key(master_file_label)
        self._meta = token.key(meta_read_label)
        self._context = context
        self._ttl, self._size, self._clock = cache_seconds, cache_size, clock
        self._cache: OrderedDict[bytes, tuple[bytes, float]] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._subkey_source = token.cbc(self._master, _ZERO)      # E_K(0)

    def meta_read_key(self) -> bytes:
        raise RuntimeError("the meta-read key stays in the HSM: use decrypt_picc")

    def decrypt_picc(self, enc_picc: bytes) -> bytes:
        if len(enc_picc) != _BLOCK:
            from .sdm import SdmError
            raise SdmError(f"PICCData must be 16 bytes, got {len(enc_picc)}")
        return self._token.cbc(self._meta, bytes(enc_picc), decrypt=True)

    def diversify(self, div_input: bytes) -> bytes:
        """AN10922 AES-128 diversification under the master file key, in the
        token: only the derived key comes back."""
        block = an10922_block(self._subkey_source, bytes(div_input))
        return self._token.cbc(self._master, block)[_BLOCK:]

    def file_read_key(self, uid: bytes) -> bytes:
        uid = bytes(uid)
        now = self._clock()
        if self._ttl > 0:
            with self._cache_lock:
                hit = self._cache.get(uid)
                if hit is not None and hit[1] > now:
                    self._cache.move_to_end(uid)
                    return hit[0]
        key = self.diversify(self._context + uid)
        if self._ttl > 0:
            with self._cache_lock:
                self._cache[uid] = (key, now + self._ttl)
                self._cache.move_to_end(uid)
                while len(self._cache) > self._size:
                    self._cache.popitem(last=False)
        return key


def build_pkcs11_keyring(token: Pkcs11Token, versions: Sequence[int] = (1,),
                         context: bytes = b"", prefix: str = DEFAULT_PREFIX,
                         cache_seconds: float = 60.0) -> KeyRing:
    """A KeyRing of every listed version, current first, as in build_keyring."""
    return KeyRing(
        (v, Pkcs11KeyProvider(token, prefix + versioned_name("master_file", v),
                              prefix + versioned_name("meta_read", v),
                              context=context, cache_seconds=cache_seconds))
        for v in versions)


def import_keys(token: Pkcs11Token, secrets, versions: Iterable[int] = (1,),
                prefix: str = DEFAULT_PREFIX) -> list[str]:
    """
    Copy master_file and meta_read (each version) from a SecretsBackend into
    the token as sensitive, non-extractable AES keys usable only for the one
    direction the verifier needs. Refuses to overwrite: a label already
    present is an error. Returns the labels created.
    """
    pkcs11 = _pkcs11()
    A = pkcs11.Attribute
    plan = []
    for v in versions:
        for name, usage in (("master_file", A.ENCRYPT), ("meta_read", A.DECRYPT)):
            label = prefix + versioned_name(name, v)
            try:
                token.key(label)
            except KeyError:
                plan.append((label, usage, secrets.get_key(versioned_name(name, v))))
                continue
            raise ValueError(f"the token already holds {label!r}")
    created = []
    with token._lock:
        for label, usage, value in plan:
            token._session.create_object({
                A.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                A.KEY_TYPE: pkcs11.KeyType.AES,
                A.VALUE: value,
                A.LABEL: label,
                A.TOKEN: True,
                A.PRIVATE: True,
                A.SENSITIVE: True,
                A.EXTRACTABLE: False,
                A.ENCRYPT: usage == A.ENCRYPT,
                A.DECRYPT: usage == A.DECRYPT,
                A.SIGN: False,
                A.VERIFY: False,
                A.WRAP: False,
                A.UNWRAP: False,
                A.DERIVE: False,
            })
            created.append(label)
    return created
