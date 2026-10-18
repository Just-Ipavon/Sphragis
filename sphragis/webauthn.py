"""
FIDO2 / WebAuthn assertions as a verification backend.

A FIDO2 card answers a fresh challenge from the browser (Safari on iOS
included, over NFC) with a signed assertion that carries a signature counter.
That counter feeds the same tap ledger and clone detector as SUN counters:
challenge-response verification without an app.

The tap is the assertion as JSON, in the shape of WebAuthn's
`PublicKeyCredential.toJSON()` (binary fields base64url):

    {"type": "public-key", "id": "<credential id>", "rawId": "<credential id>",
     "response": {"clientDataJSON": "...", "authenticatorData": "...",
                  "signature": "...", "userHandle": "..." | null}}

Checks (WebAuthn Level 2 §7.2, assertion ceremony, for a known credential):
the credential is registered; `clientDataJSON.type` is `webauthn.get` and its
origin is allowed; the RP ID hash matches; user presence is set (and user
verification, when required); the signature verifies over
`authenticatorData || SHA-256(clientDataJSON)` with the registered public key
(ES256 or EdDSA); only then is the challenge consumed, so it must have been
issued by this server, be unexpired and unused.

Signature counters. Many synced passkeys keep the counter at 0. A 0 is reported
as *no counter* (`AuthenticTap.counter is None`): the analyzer then verifies
without counter-based clone detection, unless the credential reported a
non-zero counter before, in which case the drop to 0 is scored as the
regression it is.

Registration (attestation) is out of scope: credentials are registered by the
relying party and looked up here by credential id. The identity of a tap is
`fido2:<credential id, base64url>`.

Trade-off: a WebAuthn credential is bound to its relying party ID (a domain).
If the domain that verifies the cards changes, existing credentials stop
working; plan the RP ID as carefully as a key, for the whole life of the cards.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol, runtime_checkable

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS, eddsa

from .backends import AuthenticTap, ForgedTap
from .events import EventError, cbor_decode
from .sdm import SdmError

COSE_ALG_ES256 = -7
COSE_ALG_EDDSA = -8
_FLAG_UP = 0x01
_FLAG_UV = 0x04


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or any(c in value for c in "+/= \n"):
        raise SdmError("expected unpadded base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise SdmError(f"invalid base64url: {exc}") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class RegisteredCredential:
    """A credential the relying party registered: id and COSE public key."""

    credential_id: bytes
    algorithm: int          # COSE algorithm: -7 (ES256) or -8 (EdDSA)
    public_key: object      # pycryptodome key

    @classmethod
    def from_cose_key(cls, credential_id: bytes, cose_key: bytes) -> "RegisteredCredential":
        """Build from the COSE_Key the authenticator returned at registration."""
        try:
            key = cbor_decode(cose_key)
        except EventError as exc:
            raise ValueError(f"invalid COSE key: {exc}") from exc
        if not isinstance(key, dict):
            raise ValueError("invalid COSE key")
        kty, alg, crv = key.get(1), key.get(3), key.get(-1)
        if kty == 2 and alg == COSE_ALG_ES256 and crv == 1:        # EC2, P-256
            x, y = key.get(-2), key.get(-3)
            if not (isinstance(x, bytes) and isinstance(y, bytes)
                    and len(x) == 32 and len(y) == 32):
                raise ValueError("invalid P-256 coordinates")
            public = ECC.construct(curve="P-256", point_x=int.from_bytes(x, "big"),
                                   point_y=int.from_bytes(y, "big"))
        elif kty == 1 and alg == COSE_ALG_EDDSA and crv == 6:      # OKP, Ed25519
            x = key.get(-2)
            if not (isinstance(x, bytes) and len(x) == 32):
                raise ValueError("invalid Ed25519 key")
            public = eddsa.import_public_key(x)
        else:
            raise ValueError("unsupported COSE key (ES256 on P-256 or EdDSA on Ed25519)")
        return cls(bytes(credential_id), alg, public)


@runtime_checkable
class CredentialStore(Protocol):
    def get(self, credential_id: bytes) -> RegisteredCredential | None: ...


class MemoryCredentialStore:
    def __init__(self, credentials: Iterable[RegisteredCredential] = ()) -> None:
        self._creds = {c.credential_id: c for c in credentials}

    def add(self, credential: RegisteredCredential) -> None:
        self._creds[credential.credential_id] = credential

    def get(self, credential_id: bytes) -> RegisteredCredential | None:
        return self._creds.get(credential_id)


@runtime_checkable
class ChallengeStore(Protocol):
    def issue(self) -> bytes: ...

    def consume(self, challenge: bytes) -> bool:
        """True once for a challenge issued and not expired; False otherwise."""
        ...


class MemoryChallengeStore:
    """Single-use random challenges with a time to live (one process)."""

    def __init__(self, ttl_seconds: float = 120.0, size: int = 32,
                 clock: Callable[[], float] = time.monotonic,
                 max_outstanding: int = 100_000) -> None:
        self._ttl, self._size, self._clock = ttl_seconds, size, clock
        self._max = max_outstanding
        self._lock = threading.Lock()
        self._issued: dict[bytes, float] = {}

    def issue(self) -> bytes:
        challenge = secrets.token_bytes(self._size)
        now = self._clock()
        with self._lock:
            if len(self._issued) >= self._max:
                self._issued = {c: t for c, t in self._issued.items() if t > now}
                if len(self._issued) >= self._max:
                    raise RuntimeError("too many outstanding challenges")
            self._issued[challenge] = now + self._ttl
        return challenge

    def consume(self, challenge: bytes) -> bool:
        with self._lock:
            expires = self._issued.pop(challenge, None)
        return expires is not None and self._clock() <= expires


class WebAuthnBackend:
    """Verifies WebAuthn assertions from registered FIDO2 credentials."""

    name = "fido2-webauthn"

    def __init__(self, rp_id: str, origins: Iterable[str], credentials: CredentialStore,
                 challenges: ChallengeStore, *, require_user_verification: bool = False,
                 max_size: int = 4096) -> None:
        self._rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        self._origins = frozenset(origins)
        if not self._origins:
            raise ValueError("at least one allowed origin is needed")
        self._creds = credentials
        self._challenges = challenges
        self._require_uv = require_user_verification
        self._max_size = max_size

    @staticmethod
    def accepts(tap: str) -> bool:
        return tap.lstrip().startswith("{") and '"public-key"' in tap

    def authenticate(self, tap: str) -> AuthenticTap:
        if len(tap) > self._max_size:
            raise SdmError("assertion too large")
        try:
            doc = json.loads(tap)
            response = doc["response"]
            if doc["type"] != "public-key" or not isinstance(response, dict):
                raise SdmError("not a public-key credential")
            raw_id = b64url_decode(doc["rawId"])
            if doc.get("id", doc["rawId"]) != doc["rawId"]:
                raise SdmError("id and rawId differ")
            client_data_raw = b64url_decode(response["clientDataJSON"])
            auth_data = b64url_decode(response["authenticatorData"])
            signature = b64url_decode(response["signature"])
            client_data = json.loads(client_data_raw)
            challenge = b64url_decode(client_data["challenge"])
            origin, kind = client_data["origin"], client_data["type"]
        except (ValueError, KeyError, TypeError) as exc:
            raise SdmError(f"malformed WebAuthn assertion: {exc}") from exc
        if len(auth_data) < 37:
            raise SdmError("authenticatorData too short")

        credential = self._creds.get(raw_id)
        if credential is None:
            raise ForgedTap("unknown credential")
        if kind != "webauthn.get":
            raise ForgedTap("clientDataJSON is not an assertion")
        if origin not in self._origins:
            raise ForgedTap("origin not allowed")
        if auth_data[:32] != self._rp_id_hash:
            raise ForgedTap("RP ID hash mismatch")
        flags = auth_data[32]
        if not flags & _FLAG_UP or (self._require_uv and not flags & _FLAG_UV):
            raise ForgedTap("user presence or verification missing")

        signed = auth_data + hashlib.sha256(client_data_raw).digest()
        if not _signature_ok(credential, signed, signature):
            raise ForgedTap("assertion signature does not verify")
        # Consume only now: junk cannot burn a challenge issued to someone else.
        if not self._challenges.consume(challenge):
            raise ForgedTap("challenge unknown, expired or already used")

        (sign_count,) = struct.unpack(">I", auth_data[33:37])
        alg = "ES256" if credential.algorithm == COSE_ALG_ES256 else "EdDSA"
        return AuthenticTap("fido2:" + b64url_encode(raw_id),
                            sign_count or None, self.name, alg)


def _signature_ok(credential: RegisteredCredential, message: bytes,
                  signature: bytes) -> bool:
    try:
        if credential.algorithm == COSE_ALG_ES256:
            DSS.new(credential.public_key, "fips-186-3", encoding="der").verify(
                SHA256.new(message), signature)
        else:
            eddsa.new(credential.public_key, "rfc8032").verify(message, signature)
        return True
    except ValueError:
        return False
