"""
Signed verification events (COSE_Sign1): deterministic CBOR, a known-answer
vector, round trips with an independent COSE implementation (python-cwt), and
the
wiring through the service and the API.
"""

import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis import (  # noqa: E402
    CounterStore,
    EventError,
    EventSigner,
    FileEventSink,
    SignedEvent,
    StaticKeys,
    TagAnalyzer,
    VerificationService,
    read_event_file,
    verify_event,
)
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.events import EVENT_CONTENT_TYPE, cbor_decode, cbor_encode  # noqa: E402

SECRET = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class Secrets:
    def __init__(self, **keys):
        self._keys = keys

    def get_key(self, name):
        return self._keys[name]


EVENT = SignedEvent("0123456789abcdef0123456789abcdef", 1760000000000, "CLONE_LIKELY",
                    70, "h:3f2a", 11, "gate-B", ("counter_regression",), True,
                    "ntag424-sun", "AES-128-CMAC", 1)

# Known-answer vector (Ed25519 is deterministic): secret SECRET as
# `event_signing`, version 1, signing EVENT.
KAT_PUBLIC_KEY = "58cf2f1a14d25205b00ba98605c2746ee82ca5235524984235e141e2ba495b75"
KAT_SIGNED = (
    "d2845848a301270378306170706c69636174696f6e2f766e642e73706872616769732e"
    "766572696669636174696f6e2d6576656e742b63626f7204506576656e745f7369676e"
    "696e673a7631a058a5ad61741b00000199c82cc00061760162616cf56262656b6e7461"
    "673432342d73756e62696478203031323334353637383961626364656630313233343536"
    "373839616263646566626b7601627273184663616c676c4145532d3132382d434d4143"
    "63636c736c434c4f4e455f4c494b454c59636374720b6372647266676174652d426373"
    "69678172636f756e7465725f72656772657373696f6e6374616766683a336632615840"
    "024519fe982169c4f5478bf653a66b6455ba797f8181c843cc399a9b147c5afe5271cd"
    "2ca800c74cdb7c296ded7307a231c0702a52146d3cee3612d5eaad0e02"
)


SECRET_V2 = bytes.fromhex("f0e0d0c0b0a090807060504030201000")


def _signer(version=1):
    if version == 1:
        return EventSigner(Secrets(event_signing=SECRET))
    return EventSigner(Secrets(**{f"event_signing_v{version}": SECRET_V2}), version=version)


# --- Deterministic CBOR ----------------------------------------------------------

@pytest.mark.parametrize("value,encoded", [          # RFC 8949 Appendix A
    (0, "00"), (23, "17"), (24, "1818"), (1000, "1903e8"), (1000000, "1a000f4240"),
    (-1, "20"), (-1000, "3903e7"), (b"", "40"), (b"\x01\x02\x03\x04", "4401020304"),
    ("IETF", "6449455446"), ([1, [2, 3]], "8201820203"), (None, "f6"), (True, "f5"),
    ({1: 2, 3: 4}, "a201020304"), ({"b": 1, "a": 2}, "a2616102616201"),
])
def test_cbor_encoding_matches_rfc_8949(value, encoded):
    assert cbor_encode(value).hex() == encoded
    assert cbor_decode(bytes.fromhex(encoded)) == (list(value) if isinstance(value, tuple)
                                                   else value)


@pytest.mark.parametrize("bad", [
    "1817",          # non-canonical length
    "5f4101ff",      # indefinite length
    "f93c00",        # float
    "a2616201616102",  # map keys out of order
    "0000",          # trailing bytes
    "62ff",          # truncated
])
def test_cbor_decoder_is_strict(bad):
    with pytest.raises(EventError):
        cbor_decode(bytes.fromhex(bad))


# --- Signing and verification ------------------------------------------------------

def test_known_answer_vector():
    signer = _signer()
    assert signer.public_key.hex() == KAT_PUBLIC_KEY
    assert signer.kid == b"event_signing:v1"
    assert signer.sign(EVENT).hex() == KAT_SIGNED
    assert verify_event(bytes.fromhex(KAT_SIGNED), bytes.fromhex(KAT_PUBLIC_KEY)) == EVENT


def test_verification_rejects_tampering_and_wrong_keys():
    signed = bytearray(_signer().sign(EVENT))
    pk = _signer().public_key
    assert verify_event(bytes(signed), pk, kid=b"event_signing:v1") == EVENT
    with pytest.raises(EventError):
        verify_event(bytes(signed), pk, kid=b"event_signing:v2")
    with pytest.raises(EventError):
        verify_event(bytes(signed), _signer(version=2).public_key)
    signed[-70] ^= 1                                   # inside the payload
    with pytest.raises(EventError):
        verify_event(bytes(signed), pk)


def test_key_versions_change_key_and_kid():
    v1, v2 = _signer(), _signer(version=2)
    assert v1.public_key != v2.public_key and v2.kid == b"event_signing:v2"


def test_payload_holds_no_key_material_or_raw_tap():
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                      file_read_key=os.urandom(16))
    sink = ListSink()
    service = VerificationService(
        TagAnalyzer(StaticKeys(tag.meta_read_key, tag.file_read_key), store=CounterStore()),
        event_signer=_signer(), event_sinks=[sink], clock=lambda: 1000.0)
    url = tag.tap()
    service.verify(url)
    (signed, event), = sink.events
    for secret in (tag.meta_read_key, tag.file_read_key, tag.uid, SECRET,
                   url.encode(), url.split("picc_data=")[1][:32].encode()):
        assert secret.hex().encode() not in signed and secret not in signed
    assert event.uid_ref.startswith("h:")


# --- Independent implementation (python-cwt) ---------------------------------------

def test_cwt_verifies_our_events():
    pytest.importorskip("cwt")
    from cwt import COSE, COSEKey

    x = base64.urlsafe_b64encode(bytes.fromhex(KAT_PUBLIC_KEY)).rstrip(b"=").decode()
    key = COSEKey.from_jwk({"kty": "OKP", "crv": "Ed25519", "x": x, "alg": "EdDSA",
                            "kid": "event_signing:v1"})
    payload = COSE.new().decode(bytes.fromhex(KAT_SIGNED), key)
    assert SignedEvent.from_payload(cbor_decode(payload)) == EVENT


def test_we_verify_events_signed_by_cwt():
    pytest.importorskip("cwt")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cwt import COSE, COSEKey

    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    key = COSEKey.from_pem(pem, alg="EdDSA", kid="other:v1")
    signed = COSE.new().encode_and_sign(cbor_encode(EVENT.to_payload()), key,
                                        protected={"alg": "EdDSA", "kid": "other:v1"})
    public = private.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
    assert verify_event(signed, public, kid=b"other:v1") == EVENT


# --- Service and sinks --------------------------------------------------------------

class ListSink:
    def __init__(self):
        self.events = []

    def publish(self, signed, event):
        self.events.append((signed, event))


class BrokenSink:
    def publish(self, signed, event):
        raise RuntimeError("log service down")


def _service(tmp_path=None, **kw):
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                      file_read_key=os.urandom(16))
    analyzer = TagAnalyzer(StaticKeys(tag.meta_read_key, tag.file_read_key),
                           store=CounterStore())
    return tag, VerificationService(analyzer, event_signer=_signer(), clock=lambda: 1000.5,
                                    **kw)


def test_every_verification_is_signed_by_default():
    sink = ListSink()
    tag, service = _service(event_sinks=[BrokenSink(), sink])
    withheld = tag.tap()
    first = service.verify(tag.tap())
    service.verify(withheld)
    service.verify("garbage")
    assert [e.classification for _, e in sink.events] == ["GENUINE", "CLONE_LIKELY", "ERROR"]
    signed, event = sink.events[0]
    assert verify_event(signed, _signer().public_key) == event
    assert (event.event_id, event.timestamp_ms, event.uid_ref, event.backend) == \
        (first.event_id, 1000500, first.uid_ref, "ntag424-sun")
    assert sink.events[2][1].uid_ref is None and sink.events[2][1].read_counter is None


def test_events_on_filters_classifications():
    sink = ListSink()
    tag, service = _service(event_sinks=[sink], events_on={"CLONE_LIKELY"})
    withheld = tag.tap()
    service.verify(tag.tap())
    service.verify(withheld)
    assert [e.classification for _, e in sink.events] == ["CLONE_LIKELY"]
    assert sink.events[0][1].alerted is False                # no alert sinks configured


def test_sinks_need_a_signer():
    with pytest.raises(ValueError):
        VerificationService(TagAnalyzer(StaticKeys(bytes(16), bytes(16))),
                            event_sinks=[ListSink()])


def test_file_sink_round_trip(tmp_path):
    path = tmp_path / "events.log"
    tag, service = _service(event_sinks=[FileEventSink(path)])
    for _ in range(3):
        service.verify(tag.tap())
    events = [verify_event(s, _signer().public_key) for s in read_event_file(path)]
    assert [e.read_counter for e in events] == [1, 2, 3]
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_api_publishes_the_key_and_writes_events(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sphragis import DiversifiedKeys
    from sphragis.api import create_app_from_env
    from sphragis.emulator import tag_from_provider

    master, meta = os.urandom(16), os.urandom(16)
    for name, key in (("MASTER_FILE", master), ("META_READ", meta),
                      ("LOG_PSEUDONYM", os.urandom(16)), ("EVENT_SIGNING_V2", SECRET_V2)):
        monkeypatch.setenv("SPHRAGIS_" + name, key.hex())
    events = tmp_path / "events.log"
    client = TestClient(create_app_from_env({
        "SPHRAGIS_DB_PATH": str(tmp_path / "s.db"),
        "SPHRAGIS_EVENTS_FILE": str(events),
        "SPHRAGIS_EVENT_KEY_VERSION": "2",
        "SPHRAGIS_EVENTS_ON": "genuine,clone_likely",
    }))
    key = client.get("/v1/event-key").json()
    assert key == {"kid": "event_signing:v2", "alg": "EdDSA", "crv": "Ed25519",
                   "x": _signer(version=2).public_key.hex()}
    tag = tag_from_provider(DiversifiedKeys(master, meta), uid=os.urandom(7))
    url = tag.tap()
    for _ in range(2):
        client.get("/t?" + url.partition("?")[2])           # GENUINE, then REPLAY
    (signed,) = list(read_event_file(events))
    assert verify_event(signed, bytes.fromhex(key["x"]),
                        kid=b"event_signing:v2").classification == "GENUINE"

    plain = TestClient(create_app_from_env({"SPHRAGIS_DB_PATH": str(tmp_path / "p.db")}))
    assert plain.get("/v1/event-key").status_code == 404


def test_settings_validate_event_options():
    pytest.importorskip("fastapi")
    from sphragis.api.settings import ApiSettings
    assert ApiSettings.from_env({}).events_on is None
    for name, bad in (("EVENTS_ON", "GENUIN"), ("EVENT_KEY_VERSION", "0"),
                      ("EVENT_KEY_VERSION", "x")):
        with pytest.raises(ValueError, match=name):
            ApiSettings.from_env({"SPHRAGIS_" + name: bad})


# --- Chained logs (#71) ---------------------------------------------------------------

def _chained_log(n=5, log_id="replica-a"):
    from sphragis import EventChain
    chain, signer = EventChain(log_id), _signer()
    signed = []
    for i in range(n):
        out, event = chain.seal(signer, EVENT.__class__(**{**EVENT.__dict__,
                                                           "event_id": f"e{i}"}))
        assert event.seq == i and event.log_id == log_id
        signed.append(out)
    return signed, chain


def _pub():
    return _signer().public_key


def test_a_chained_log_verifies_and_reports_its_head():
    from sphragis import verify_log
    from sphragis.events import event_digest
    signed, chain = _chained_log()
    events, head = verify_log(signed, _pub(), kid=b"event_signing:v1", log_id="replica-a")
    assert [e.seq for e in events] == list(range(5))
    assert head == chain.head == (5, event_digest(signed[-1]))
    # Each chained event still verifies on its own.
    assert verify_event(signed[2], _pub()).seq == 2


@pytest.mark.parametrize("tamper", ["remove", "reorder", "inject", "duplicate"])
def test_verify_log_detects_tampering(tamper):
    from sphragis import verify_log
    signed, _ = _chained_log()
    if tamper == "remove":
        signed = signed[:2] + signed[3:]
    elif tamper == "reorder":
        signed[1], signed[2] = signed[2], signed[1]
    elif tamper == "inject":
        stranger, _ = _chained_log(3, log_id="replica-b")
        signed.insert(2, stranger[2])
    else:
        signed.insert(3, signed[2])
    with pytest.raises(EventError):
        verify_log(signed, _pub())


def test_verify_log_refuses_a_line_from_another_log_in_the_same_position():
    from sphragis import verify_log
    signed, _ = _chained_log()
    other, _ = _chained_log(log_id="replica-b")
    with pytest.raises(EventError, match="belongs to log"):
        verify_log(signed[:2] + other[2:3] + signed[3:], _pub())


def test_verify_log_from_a_pinned_head_checks_only_the_rest():
    from sphragis import verify_log
    signed, _ = _chained_log()
    _, head = verify_log(signed[:3], _pub())
    events, _ = verify_log(signed[3:], _pub(), start=head)
    assert [e.seq for e in events] == [3, 4]
    with pytest.raises(EventError):
        verify_log(signed[4:], _pub(), start=head)          # seq 3 missing


def test_chain_resumes_after_the_last_event_of_a_file(tmp_path):
    from sphragis import EventChain, verify_log
    from sphragis.events import FileEventSink
    path = tmp_path / "events.log"
    sink = FileEventSink(path)
    first, _ = _chained_log(3)
    for s in first:
        sink.publish(s, None)
    chain = EventChain.resume("replica-a", read_event_file(path))
    more, _ = chain.seal(_signer(), EVENT)
    sink.publish(more, None)
    events, (seq, _) = verify_log(read_event_file(path), _pub())
    assert seq == 4 and events[-1].event_id == EVENT.event_id
    with pytest.raises(EventError, match="does not end with an event of this chain"):
        EventChain.resume("replica-b", read_event_file(path))


def test_unchained_events_keep_schema_1_and_the_known_answer():
    assert cbor_decode(bytes.fromhex(KAT_SIGNED)).value[2]   # payload present
    assert _signer().sign(EVENT).hex() == KAT_SIGNED
    from sphragis import verify_log
    with pytest.raises(EventError, match="not chained"):
        verify_log([bytes.fromhex(KAT_SIGNED)], _pub())


def test_service_publishes_a_chain_and_the_cli_checks_it(tmp_path, capsys):
    from sphragis import EventChain, StaticKeys
    from sphragis.analyzer import TagAnalyzer
    from sphragis.cli import main
    from sphragis.events import FileEventSink
    from sphragis.service import VerificationService
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                      file_read_key=os.urandom(16))
    path = tmp_path / "events.log"
    service = VerificationService(
        TagAnalyzer(StaticKeys(tag.meta_read_key, tag.file_read_key)),
        event_signer=_signer(), event_sinks=[FileEventSink(path)],
        event_chain=EventChain("gate-host"))
    for _ in range(3):
        service.verify(tag.tap())
    argv = ["verify-events", str(path), "--public-key", _pub().hex(), "--log-id", "gate-host"]
    assert main(argv) == 0
    assert "3 events" in capsys.readouterr().out
    lines = path.read_bytes().splitlines()
    path.write_bytes(b"\n".join([lines[0], lines[2]]) + b"\n")
    assert main(argv) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_api_chains_events_across_restarts(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sphragis import DiversifiedKeys, verify_log
    from sphragis.api import create_app_from_env
    from sphragis.emulator import tag_from_provider

    master, meta = os.urandom(16), os.urandom(16)
    for name, key in (("MASTER_FILE", master), ("META_READ", meta),
                      ("LOG_PSEUDONYM", os.urandom(16)), ("EVENT_SIGNING", SECRET)):
        monkeypatch.setenv("SPHRAGIS_" + name, key.hex())
    events = tmp_path / "events.log"
    env = {"SPHRAGIS_DB_PATH": str(tmp_path / "s.db"), "SPHRAGIS_EVENTS_FILE": str(events),
           "SPHRAGIS_EVENT_LOG_ID": "replica-a"}
    tag = tag_from_provider(DiversifiedKeys(master, meta), uid=os.urandom(7))
    for _ in range(2):                                      # two runs of the server
        with TestClient(create_app_from_env(env)) as client:
            for _ in range(2):
                client.get("/t?" + tag.tap().partition("?")[2])
    found, (seq, _) = verify_log(read_event_file(events), _pub(), log_id="replica-a")
    assert seq == 4 and [e.seq for e in found] == [0, 1, 2, 3]
