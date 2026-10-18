"""
Crypto agility: key versions and algorithms are configuration, not data
migrations. A key rotation and an algorithm switch keep the anti-replay floor
and the detector history, and every record says what produced it.
"""

import hashlib
import hmac
import os
import sys
from urllib.parse import parse_qs

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis import (  # noqa: E402
    AuthenticTap,
    DiversifiedKeys,
    ForgedTap,
    KeyRing,
    Ntag424EncBackend,
    Ntag424SunBackend,
    TagAnalyzer,
    VerificationService,
    build_keyring,
    versioned_name,
)
from sphragis.alerts import SqliteAlertSink  # noqa: E402
from sphragis.detection import CloneDetector  # noqa: E402
from sphragis.emulator import EmulatedEncTag, tag_from_provider  # noqa: E402
from sphragis.observations import SqliteObservationStore  # noqa: E402
from sphragis.sdm import SdmError  # noqa: E402
from sphragis.secrets import EnvSecretsBackend  # noqa: E402
from sphragis.sqlstore import SqliteCounterStore  # noqa: E402


def _keys():
    return DiversifiedKeys(os.urandom(16), os.urandom(16))


def _stack(tmp_path, backends):
    db = str(tmp_path / "s.db")
    analyzer = TagAnalyzer(backends=backends, store=SqliteCounterStore(db),
                           detector=CloneDetector(store=SqliteObservationStore(db)))
    sink = SqliteAlertSink(db)
    clock = iter(range(1000, 100000, 100))
    return VerificationService(analyzer, alert_sinks=[sink],
                               clock=lambda: float(next(clock))), analyzer, sink


# --- Key versions -----------------------------------------------------------------

def test_versioned_names():
    assert versioned_name("master_file", 1) == "master_file"
    assert versioned_name("master_file", 3) == "master_file_v3"
    with pytest.raises(ValueError):
        versioned_name("master_file", 0)


def test_key_ring_validates():
    k = _keys()
    assert KeyRing.of(k).versions == (1,)
    assert KeyRing([(2, k), (1, k)]).current_version == 2
    for bad in ([], [(1, k), (1, k)], [(0, k)]):
        with pytest.raises(ValueError):
            KeyRing(bad)


def test_build_keyring_reads_each_version(monkeypatch):
    v1, v2 = _keys(), _keys()
    for name, key in (("MASTER_FILE", v1._master_file), ("META_READ", v1._meta),
                      ("MASTER_FILE_V2", v2._master_file), ("META_READ_V2", v2._meta)):
        monkeypatch.setenv("SPHRAGIS_" + name, key.hex())
    ring = build_keyring(EnvSecretsBackend(), (2, 1))
    assert ring.versions == (2, 1)
    uid = os.urandom(7)
    assert dict(iter(ring))[2].file_read_key(uid) == v2.file_read_key(uid)
    assert dict(iter(ring))[1].file_read_key(uid) == v1.file_read_key(uid)


@pytest.mark.parametrize("enc", [False, True])
def test_key_rotation_keeps_floor_history_and_reports_versions(tmp_path, enc):
    v1, v2 = _keys(), _keys()
    uid = os.urandom(7)
    backend = Ntag424EncBackend if enc else Ntag424SunBackend

    def tag_on(keys, counter=0):
        if enc:
            return EmulatedEncTag(uid=uid, meta_read_key=keys.meta_read_key(),
                                  file_read_key=keys.file_read_key(uid),
                                  read_counter=counter, file_data=b"d" * 16)
        return tag_from_provider(keys, uid=uid, read_counter=counter)

    # Before the rotation: only version 1 exists.
    tag = tag_on(v1)
    service, analyzer, _ = _stack(tmp_path, [backend(KeyRing([(1, v1)]))])
    old_url = tag.tap()
    first = service.verify(old_url).result
    assert (first.classification, first.key_version) == ("GENUINE", 1)
    withheld = tag.tap()                       # counter 2, read and kept
    for _ in range(2):
        service.verify(tag.tap())

    # Rotation: both versions active, newest first; the tag is rekeyed and its
    # counter carries on.
    service, analyzer, sink = _stack(tmp_path, [backend(KeyRing([(2, v2), (1, v1)]))])
    tag = tag_on(v2, counter=tag.read_counter)
    r = service.verify(tag.tap()).result
    assert (r.classification, r.key_version, r.read_counter) == ("GENUINE", 2, 5)
    assert r.algorithm == backend.algorithm
    # The floor survived: a URL from before the rotation is still a replay.
    assert service.verify(old_url).result.classification == "REPLAY"
    # A tap kept from before the rotation still verifies under version 1: the
    # regression is caught and the alert names the version.
    assert service.verify(withheld).result.classification == "CLONE_LIKELY"
    (alert,) = sink.recent()
    assert (alert.backend, alert.algorithm, alert.key_version) == \
        (backend.name, backend.algorithm, 1)
    # The history survived, with the version of every tap.
    hist = analyzer.detector.history(uid.hex())
    assert [(o.counter, o.key_version) for o in hist] == \
        [(1, 1), (3, 1), (4, 1), (5, 2), (2, 1)]
    assert {o.backend for o in hist} == {backend.name}

    # Version 1 retired: its taps no longer verify, version 2 carries on.
    service, _, _ = _stack(tmp_path, [backend(KeyRing([(2, v2)]))])
    assert service.verify(tag_on(v1, counter=10).tap()).result.classification \
        in ("ERROR", "FORGED")
    assert service.verify(tag.tap()).result.classification == "SUSPICIOUS"   # forked UID


def test_forged_under_every_version_is_forged_not_error():
    v1, v2 = _keys(), _keys()
    uid = os.urandom(7)
    tag = tag_from_provider(v1, uid=uid)
    # Same meta key in both versions: PICCData decrypts, the MAC never verifies.
    tag.file_read_key = os.urandom(16)
    v2 = DiversifiedKeys(os.urandom(16), v1.meta_read_key())
    with pytest.raises(ForgedTap):
        Ntag424SunBackend(KeyRing([(2, v2), (1, v1)])).authenticate(tag.tap())
    with pytest.raises(SdmError):            # no version decrypts the PICCData
        Ntag424SunBackend(KeyRing([(2, _keys())])).authenticate(tag.tap())


# --- Algorithm switch ---------------------------------------------------------------

class HmacChip:
    """A made-up chip whose firmware moves from HMAC-SHA256 to HMAC-SHA3-256."""

    def __init__(self, name, algorithm, digest, key):
        self.name, self.algorithm, self._digest, self._key = name, algorithm, digest, key

    def sign(self, dev, ctr):
        mac = hmac.new(self._key, f"{dev}|{ctr}".encode(), self._digest).hexdigest()
        return f"https://example.com/x?alg={self.algorithm}&dev={dev}&ctr={ctr}&sig={mac}"

    def accepts(self, url):
        return f"alg={self.algorithm}&" in url

    def authenticate(self, url):
        q = {k: v[0] for k, v in parse_qs(url.partition("?")[2]).items()}
        try:
            dev, ctr = q["dev"], int(q["ctr"])
        except (KeyError, ValueError) as exc:
            raise SdmError("malformed") from exc
        if not hmac.compare_digest(self.sign(dev, ctr), url):
            raise ForgedTap("bad signature")
        return AuthenticTap(f"chip:{dev}", ctr, self.name, self.algorithm, key_version=1)


def test_algorithm_switch_keeps_floor_and_history(tmp_path):
    key = os.urandom(32)
    old = HmacChip("chip-v1", "HMAC-SHA256", hashlib.sha256, key)
    new = HmacChip("chip-v2", "HMAC-SHA3-256", hashlib.sha3_256, key)

    service, analyzer, _ = _stack(tmp_path, [old])
    old_url = old.sign("A", 1)
    assert service.verify(old_url).result.classification == "GENUINE"
    service.verify(old.sign("A", 2))

    # Both algorithms accepted while the fleet is updated.
    service, analyzer, _ = _stack(tmp_path, [new, old])
    r = service.verify(new.sign("A", 3)).result
    assert (r.classification, r.algorithm) == ("GENUINE", "HMAC-SHA3-256")
    assert service.verify(old_url).result.classification == "REPLAY"
    assert service.verify(old.sign("A", 2)).result.classification == "REPLAY"
    assert [(o.counter, o.algorithm) for o in analyzer.detector.history("chip:A")] == \
        [(1, "HMAC-SHA256"), (2, "HMAC-SHA256"), (3, "HMAC-SHA3-256")]

    # Old algorithm retired.
    service, _, _ = _stack(tmp_path, [new])
    assert service.verify(old.sign("A", 9)).result.classification == "ERROR"


def test_settings_validate_key_versions():
    pytest.importorskip("fastapi")
    from sphragis.api.settings import ApiSettings
    assert ApiSettings.from_env({}).key_versions == (1,)
    assert ApiSettings.from_env({"SPHRAGIS_KEY_VERSIONS": "2, 1"}).key_versions == (2, 1)
    for bad in ("0", "x", "2,2", ","):
        with pytest.raises(ValueError, match="KEY_VERSIONS"):
            ApiSettings.from_env({"SPHRAGIS_KEY_VERSIONS": bad})


def test_api_reports_provenance_to_readers(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sphragis.api import create_app_from_env, parse_reader_tokens  # noqa: F401

    v1, v2 = _keys(), _keys()
    for name, key in (("MASTER_FILE", v1._master_file), ("META_READ", v1._meta),
                      ("MASTER_FILE_V2", v2._master_file), ("META_READ_V2", v2._meta),
                      ("LOG_PSEUDONYM", os.urandom(16))):
        monkeypatch.setenv("SPHRAGIS_" + name, key.hex())
    token = "reader-token"
    client = TestClient(create_app_from_env({
        "SPHRAGIS_DB_PATH": str(tmp_path / "s.db"),
        "SPHRAGIS_KEY_VERSIONS": "2,1",
        "SPHRAGIS_READER_TOKENS": "gate-A=" + hashlib.sha256(token.encode()).hexdigest(),
    }))
    tag = tag_from_provider(v1, uid=os.urandom(7))
    body = client.post("/v1/verify", json={"url": tag.tap()},
                       headers={"Authorization": f"Bearer {token}"}).json()
    assert (body["classification"], body["backend"], body["algorithm"],
            body["key_version"]) == ("GENUINE", "ntag424-sun", "AES-128-CMAC", 1)
    public = client.get("/t?" + tag.tap().partition("?")[2]).json()
    assert "key_version" not in public and "backend" not in public
