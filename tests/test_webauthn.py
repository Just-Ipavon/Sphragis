"""
FIDO2 / WebAuthn assertions through the same ledger and clone detector.

A software authenticator built on `cryptography` and `cbor2` (independent of
the engine's own crypto and CBOR) produces the assertions.
"""

import base64
import hashlib
import json
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

cryptography = pytest.importorskip("cryptography")
cbor2 = pytest.importorskip("cbor2")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402

from sphragis import (  # noqa: E402
    CounterStore,
    Ntag424SunBackend,
    StaticKeys,
    TagAnalyzer,
    VerificationService,
)
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.webauthn import (  # noqa: E402
    MemoryChallengeStore,
    MemoryCredentialStore,
    RegisteredCredential,
    WebAuthnBackend,
)

RP_ID = "verify.example.com"
ORIGIN = "https://verify.example.com"


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    """Just enough of a FIDO2 authenticator to answer assertions."""

    def __init__(self, alg="ES256", counter=0, keeps_counter=True):
        self.alg, self.counter, self.keeps_counter = alg, counter, keeps_counter
        self.credential_id = os.urandom(16)
        if alg == "ES256":
            self._key = ec.generate_private_key(ec.SECP256R1())
            nums = self._key.public_key().public_numbers()
            self.cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"),
                                         -3: nums.y.to_bytes(32, "big")}, canonical=True)
        else:
            self._key = ed25519.Ed25519PrivateKey.generate()
            raw = self._key.public_key().public_bytes(serialization.Encoding.Raw,
                                                      serialization.PublicFormat.Raw)
            self.cose_key = cbor2.dumps({1: 1, 3: -8, -1: 6, -2: raw}, canonical=True)

    def register(self, store):
        store.add(RegisteredCredential.from_cose_key(self.credential_id, self.cose_key))

    def assert_(self, challenge, *, rp_id=RP_ID, origin=ORIGIN, flags=0x05,
                kind="webauthn.get", counter=None):
        if counter is None:
            if self.keeps_counter:
                self.counter += 1
            counter = self.counter
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + \
            struct.pack(">I", counter)
        client_data = json.dumps({"type": kind, "challenge": b64u(challenge),
                                  "origin": origin, "crossOrigin": False}).encode()
        message = auth_data + hashlib.sha256(client_data).digest()
        if self.alg == "ES256":
            sig = self._key.sign(message, ec.ECDSA(hashes.SHA256()))
        else:
            sig = self._key.sign(message)
        return json.dumps({"type": "public-key", "id": b64u(self.credential_id),
                           "rawId": b64u(self.credential_id),
                           "response": {"clientDataJSON": b64u(client_data),
                                        "authenticatorData": b64u(auth_data),
                                        "signature": b64u(sig), "userHandle": None}})


@pytest.fixture
def rig():
    creds, challenges = MemoryCredentialStore(), MemoryChallengeStore()
    backend = WebAuthnBackend(RP_ID, [ORIGIN], creds, challenges)
    clock = iter(range(1000, 10**6, 100))
    service = VerificationService(TagAnalyzer(backends=[backend], store=CounterStore()),
                                  clock=lambda: float(next(clock)))
    return creds, challenges, service


@pytest.mark.parametrize("alg", ["ES256", "EdDSA"])
def test_assertions_verify_and_feed_the_ledger(rig, alg):
    creds, challenges, service = rig
    card = SoftAuthenticator(alg)
    card.register(creds)
    r = service.verify(card.assert_(challenges.issue())).result
    assert (r.classification, r.read_counter, r.algorithm, r.backend) == \
        ("GENUINE", 1, alg, "fido2-webauthn")
    assert r.uid == "fido2:" + b64u(card.credential_id)
    assert service.verify(card.assert_(challenges.issue())).result.classification == "GENUINE"


def test_counter_regression_is_a_clone_signal(rig):
    # The card's key was extracted into a second device that lags behind.
    creds, challenges, service = rig
    card = SoftAuthenticator(counter=10)
    card.register(creds)
    for _ in range(3):
        service.verify(card.assert_(challenges.issue()))               # up to 13
    r = service.verify(card.assert_(challenges.issue(), counter=5)).result
    assert r.classification == "CLONE_LIKELY"
    assert [s.name for s in r.signals] == ["counter_regression"]
    r = service.verify(card.assert_(challenges.issue())).result        # 14: forked
    assert [s.name for s in r.signals] == ["prior_divergence"]


def test_a_counter_fixed_at_zero_means_no_counter(rig):
    creds, challenges, service = rig
    passkey = SoftAuthenticator(keeps_counter=False)
    passkey.register(creds)
    for _ in range(3):
        r = service.verify(passkey.assert_(challenges.issue())).result
        assert (r.classification, r.read_counter) == ("GENUINE", None)
        assert [s.name for s in r.signals] == ["no_counter"]


def test_a_counter_dropping_to_zero_is_a_regression(rig):
    creds, challenges, service = rig
    card = SoftAuthenticator()
    card.register(creds)
    service.verify(card.assert_(challenges.issue()))
    r = service.verify(card.assert_(challenges.issue(), counter=0)).result
    assert r.classification == "CLONE_LIKELY"


def test_challenges_are_single_use_and_server_issued(rig):
    creds, challenges, service = rig
    card = SoftAuthenticator()
    card.register(creds)
    assertion = card.assert_(challenges.issue())
    assert service.verify(assertion).result.classification == "GENUINE"
    assert service.verify(assertion).result.classification == "FORGED"   # replayed
    unissued = card.assert_(os.urandom(32))
    assert service.verify(unissued).result.classification == "FORGED"


def test_junk_does_not_burn_a_challenge(rig):
    creds, challenges, service = rig
    card = SoftAuthenticator()
    card.register(creds)
    challenge = challenges.issue()
    good = card.assert_(challenge)
    doc = json.loads(good)
    doc["response"]["signature"] = b64u(os.urandom(70))
    assert service.verify(json.dumps(doc)).result.classification == "FORGED"
    assert service.verify(good).result.classification == "GENUINE"


def test_expired_challenges_are_refused():
    now = [0.0]
    store = MemoryChallengeStore(ttl_seconds=60, clock=lambda: now[0])
    c = store.issue()
    now[0] = 61
    assert not store.consume(c)


@pytest.mark.parametrize("change", [
    {"rp_id": "evil.example.com"},
    {"origin": "https://evil.example.com"},
    {"kind": "webauthn.create"},
    {"flags": 0x04},                                   # no user presence
])
def test_ceremony_checks(rig, change):
    creds, challenges, service = rig
    card = SoftAuthenticator()
    card.register(creds)
    r = service.verify(card.assert_(challenges.issue(), **change)).result
    assert r.classification == "FORGED" and r.uid is None


def test_user_verification_can_be_required():
    creds, challenges = MemoryCredentialStore(), MemoryChallengeStore()
    backend = WebAuthnBackend(RP_ID, [ORIGIN], creds, challenges,
                              require_user_verification=True)
    card = SoftAuthenticator()
    card.register(creds)
    from sphragis import ForgedTap
    with pytest.raises(ForgedTap):
        backend.authenticate(card.assert_(challenges.issue(), flags=0x01))
    assert backend.authenticate(card.assert_(challenges.issue(), flags=0x05)).counter


def test_unknown_credentials_and_malformed_input(rig):
    _, challenges, service = rig
    stranger = SoftAuthenticator()
    assert service.verify(stranger.assert_(challenges.issue())).result.classification \
        == "FORGED"
    for junk in ('{"type": "public-key"}', '{"type": "public-key", "rawId": "a+b"}',
                 '{"type": "public-key", "response": 1, "rawId": "AA"}'):
        assert service.verify(junk).result.classification == "ERROR"


def test_sun_taps_and_assertions_share_one_pipeline():
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                      file_read_key=os.urandom(16))
    creds, challenges = MemoryCredentialStore(), MemoryChallengeStore()
    card = SoftAuthenticator()
    card.register(creds)
    analyzer = TagAnalyzer(store=CounterStore(), backends=[
        WebAuthnBackend(RP_ID, [ORIGIN], creds, challenges),
        Ntag424SunBackend(StaticKeys(tag.meta_read_key, tag.file_read_key))])
    assert analyzer.analyze(tag.tap()).backend == "ntag424-sun"
    assert analyzer.analyze(card.assert_(challenges.issue())).backend == "fido2-webauthn"


def test_cose_key_validation():
    with pytest.raises(ValueError):
        RegisteredCredential.from_cose_key(b"x", cbor2.dumps({1: 3, 3: -257}))
    with pytest.raises(ValueError):
        RegisteredCredential.from_cose_key(b"x", b"\xff")
