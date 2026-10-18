"""
Signed verification events — COSE_Sign1 statements for transparency logs.

Downstream systems keep append-only, third-party verifiable records of what
the engine decided (IETF SCITT, Certificate Transparency style logs). This
module turns a verification outcome into a compact, signed statement:

    COSE_Sign1 (RFC 9052, tag 18)
      protected   {1 (alg): -8 (EdDSA), 3 (content type): EVENT_CONTENT_TYPE,
                   4 (kid): b"<key name>:v<version>"}
      unprotected {}
      payload     deterministic CBOR map (RFC 8949 §4.2.1), see `SignedEvent`
      signature   Ed25519 over Sig_structure ["Signature1", protected, h'', payload]

The payload never holds key material or the tapped URL: the tag is named by
its log pseudonym (`uid_ref`), and only signal *names* are kept.

The signing key comes from a `SecretsBackend` like every other key: a 16-byte
secret (`event_signing`, versioned as `event_signing_v<N>`) from which the
Ed25519 seed is derived with HKDF-SHA256 under a dedicated label, so the
secret serves no other purpose. Verifiers only need the 32-byte public key
(`EventSigner.public_key`), published out of band or at `GET /v1/event-key`.

`EventSink` receives each signed event; `FileEventSink` appends them to a file
(one base64url line per event) for tests and simple pipelines.
"""

from __future__ import annotations

import base64
import os
import struct
import threading
from dataclasses import dataclass
from typing import Iterable, Iterator, Protocol, runtime_checkable

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from .keyring import versioned_name

EVENT_SCHEMA_VERSION = 1
EVENT_CONTENT_TYPE = "application/vnd.sphragis.verification-event+cbor"
COSE_ALG_EDDSA = -8
_COSE_SIGN1_TAG = 18
_HKDF_LABEL = b"sphragis/event-signing/ed25519/v1"


class EventError(Exception):
    """A signed event is malformed or its signature does not verify."""


# --- Deterministic CBOR (the subset the events use) -------------------------------

def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for info, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | info]) + struct.pack(fmt, n)
    raise ValueError("integer too large for CBOR")


def cbor_encode(value) -> bytes:
    """Deterministic CBOR: shortest heads, map keys in bytewise order."""
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        items = sorted((cbor_encode(k), cbor_encode(v)) for k, v in value.items())
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, _Tagged):
        return _head(6, value.tag) + cbor_encode(value.value)
    raise TypeError(f"cannot encode {type(value).__name__} as event CBOR")


@dataclass(frozen=True)
class _Tagged:
    tag: int
    value: object


def cbor_decode(data: bytes):
    """Decode one deterministic CBOR item; anything else is an EventError."""
    value, end = _decode(data, 0)
    if end != len(data):
        raise EventError("trailing bytes after CBOR item")
    return value


def _decode(data: bytes, i: int):
    if i >= len(data):
        raise EventError("truncated CBOR")
    first = data[i]
    major, info = first >> 5, first & 0x1F
    i += 1
    if major == 7:
        simple = {20: False, 21: True, 22: None}
        if info not in simple:
            raise EventError("unsupported CBOR simple value or float")
        return simple[info], i
    if info < 24:
        n = info
    elif info <= 27:
        size = 1 << (info - 24)
        if i + size > len(data):
            raise EventError("truncated CBOR")
        n = int.from_bytes(data[i:i + size], "big")
        if n < (24 if size == 1 else 1 << (4 * size)):
            raise EventError("non-canonical CBOR length")
        i += size
    else:
        raise EventError("indefinite or reserved CBOR length")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(data):
            raise EventError("truncated CBOR")
        raw = data[i:i + n]
        if major == 2:
            return bytes(raw), i + n
        try:
            return raw.decode("utf-8"), i + n
        except UnicodeDecodeError as exc:
            raise EventError("invalid UTF-8 in CBOR text") from exc
    if major == 4:
        items = []
        for _ in range(n):
            item, i = _decode(data, i)
            items.append(item)
        return items, i
    if major == 5:
        out, previous = {}, None
        for _ in range(n):
            start = i
            key, i = _decode(data, i)
            encoded = data[start:i]
            if previous is not None and encoded <= previous:
                raise EventError("CBOR map keys not in deterministic order")
            previous = encoded
            out[key], i = _decode(data, i)
        return out, i
    item, i = _decode(data, i)
    return _Tagged(n, item), i


# --- The event -------------------------------------------------------------------

@dataclass(frozen=True)
class SignedEvent:
    """
    The signed statement about one verification. CBOR keys (short, stable):

        v    schema version (1)        id   event id
        t    time, ms since the epoch  cls  classification
        rs   risk score                tag  pseudonymous tag reference or null
        ctr  read counter or null      rdr  reader id or null
        sig  signal names              al   whether an alert was raised
        be   backend or null           alg  authenticator algorithm or null
        kv   key version or null
    """

    event_id: str
    timestamp_ms: int
    classification: str
    risk_score: int
    uid_ref: str | None
    read_counter: int | None
    reader_id: str | None
    signals: tuple[str, ...]
    alerted: bool
    backend: str | None = None
    algorithm: str | None = None
    key_version: int | None = None

    def to_payload(self) -> dict:
        return {"v": EVENT_SCHEMA_VERSION, "id": self.event_id, "t": self.timestamp_ms,
                "cls": self.classification, "rs": self.risk_score, "tag": self.uid_ref,
                "ctr": self.read_counter, "rdr": self.reader_id,
                "sig": list(self.signals), "al": self.alerted, "be": self.backend,
                "alg": self.algorithm, "kv": self.key_version}

    @classmethod
    def from_payload(cls, p) -> "SignedEvent":
        try:
            if not isinstance(p, dict) or p.get("v") != EVENT_SCHEMA_VERSION:
                raise EventError("unknown event schema")
            if set(p) != set(cls("", 0, "", 0, None, None, None, (), False).to_payload()):
                raise EventError("unexpected event fields")
            return cls(p["id"], p["t"], p["cls"], p["rs"], p["tag"], p["ctr"], p["rdr"],
                       tuple(p["sig"]), p["al"], p["be"], p["alg"], p["kv"])
        except (KeyError, TypeError) as exc:
            raise EventError(f"malformed event payload: {exc}") from exc


# --- Signing and verification --------------------------------------------------------

class EventSigner:
    """Signs events as COSE_Sign1 with an Ed25519 key derived from a secret."""

    def __init__(self, secrets, name: str = "event_signing", version: int = 1) -> None:
        secret = secrets.get_key(versioned_name(name, version))
        seed = HKDF(secret, 32, salt=b"", hashmod=SHA256, context=_HKDF_LABEL)
        self._key = ECC.construct(curve="Ed25519", seed=seed)
        self.kid = f"{name}:v{version}".encode()
        self._protected = cbor_encode({1: COSE_ALG_EDDSA, 3: EVENT_CONTENT_TYPE,
                                       4: self.kid})

    @property
    def public_key(self) -> bytes:
        """The raw 32-byte Ed25519 public key verifiers need."""
        return self._key.public_key().export_key(format="raw")

    def cose_key(self) -> dict:
        """The public key as a COSE_Key map (RFC 9053: OKP, Ed25519)."""
        return {1: 1, 2: self.kid, 3: COSE_ALG_EDDSA, -1: 6, -2: self.public_key}

    def sign(self, event: SignedEvent) -> bytes:
        payload = cbor_encode(event.to_payload())
        to_sign = cbor_encode(["Signature1", self._protected, b"", payload])
        signature = eddsa.new(self._key, "rfc8032").sign(to_sign)
        return cbor_encode(_Tagged(_COSE_SIGN1_TAG,
                                   [self._protected, {}, payload, signature]))


def verify_event(signed: bytes, public_key: bytes,
                 kid: bytes | None = None) -> SignedEvent:
    """
    Verify a COSE_Sign1 event against a raw Ed25519 public key (and, if given,
    the expected key id) and return its payload. Raises EventError otherwise.
    """
    item = cbor_decode(signed)
    if isinstance(item, _Tagged):
        if item.tag != _COSE_SIGN1_TAG:
            raise EventError("not a COSE_Sign1 message")
        item = item.value
    if (not isinstance(item, list) or len(item) != 4
            or not isinstance(item[0], bytes) or not isinstance(item[1], dict)
            or not isinstance(item[2], bytes) or not isinstance(item[3], bytes)):
        raise EventError("malformed COSE_Sign1 structure")
    protected_raw, _unprotected, payload, signature = item
    protected = cbor_decode(protected_raw)
    if not isinstance(protected, dict) or protected.get(1) != COSE_ALG_EDDSA:
        raise EventError("unsupported COSE algorithm")
    if kid is not None and protected.get(4) != kid:
        raise EventError("unexpected key id")
    try:
        key = eddsa.import_public_key(public_key)
        to_sign = cbor_encode(["Signature1", protected_raw, b"", payload])
        eddsa.new(key, "rfc8032").verify(to_sign, signature)
    except ValueError as exc:
        raise EventError("signature does not verify") from exc
    return SignedEvent.from_payload(cbor_decode(payload))


# --- Sinks ------------------------------------------------------------------------------

@runtime_checkable
class EventSink(Protocol):
    def publish(self, signed: bytes, event: SignedEvent) -> None: ...


class FileEventSink:
    """Appends each signed event as one base64url line (fsync'd)."""

    def __init__(self, path: str | os.PathLike) -> None:
        self._path = os.fspath(path)
        self._lock = threading.Lock()
        if not os.path.exists(self._path):
            os.close(os.open(self._path, os.O_CREAT | os.O_WRONLY, 0o600))

    def publish(self, signed: bytes, event: SignedEvent) -> None:
        line = base64.urlsafe_b64encode(signed).rstrip(b"=") + b"\n"
        with self._lock:
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)


def read_event_file(path: str | os.PathLike) -> Iterator[bytes]:
    """The signed events of a `FileEventSink` file, in order."""
    with open(path, "rb") as f:
        for line in f:
            line = line.strip()
            if line:
                yield base64.urlsafe_b64decode(line + b"=" * (-len(line) % 4))


def publish(signed: bytes, event: SignedEvent, sinks: Iterable[EventSink], log) -> int:
    """Deliver to every sink; a failing sink is logged and skipped."""
    delivered = 0
    for sink in sinks:
        try:
            sink.publish(signed, event)
            delivered += 1
        except Exception:  # noqa: BLE001 - a broken sink must not stop the others
            log.exception("event_sink_failed", extra={"fields": {
                "event_id": event.event_id, "sink": type(sink).__name__}})
    return delivered
