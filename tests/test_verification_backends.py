"""
Chip-agnostic verification interface: the analyzer, the service and the API
work over any `VerificationBackend`, and the NTAG 424 DNA verifiers are the
first two backends.
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
    ForgedTap,
    Ntag424EncBackend,
    Ntag424SunBackend,
    StaticKeys,
    TagAnalyzer,
    VerificationBackend,
    VerificationService,
    select_backend,
)
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.emulator import EmulatedEncTag, EmulatedTag  # noqa: E402
from sphragis.sdm import SdmError  # noqa: E402


class HmacCounterBackend:
    """A made-up chip: `?dev=<id>&ctr=<n>&sig=<hmac(id|n)>`."""

    name = "test-hmac"

    def __init__(self, key: bytes) -> None:
        self._key = key

    def sign(self, dev: str, ctr: int) -> str:
        sig = hmac.new(self._key, f"{dev}|{ctr}".encode(), hashlib.sha256).hexdigest()
        return f"https://example.com/x?dev={dev}&ctr={ctr}&sig={sig}"

    def accepts(self, url_or_query: str) -> bool:
        return "dev=" in url_or_query

    def authenticate(self, url_or_query: str) -> AuthenticTap:
        q = parse_qs(url_or_query.partition("?")[2])
        try:
            dev, ctr, sig = q["dev"][0], int(q["ctr"][0]), q["sig"][0]
        except (KeyError, ValueError) as exc:
            raise SdmError(f"malformed: {exc}") from exc
        expected = self.sign(dev, ctr).rpartition("sig=")[2]
        if not hmac.compare_digest(expected, sig):
            raise ForgedTap("bad signature")
        return AuthenticTap(f"test:{dev}", ctr, self.name, "HMAC-SHA256")


def _tag(cls=EmulatedTag, **kw):
    return cls(uid=os.urandom(7), meta_read_key=os.urandom(16),
               file_read_key=os.urandom(16), **kw)


def _keys(tag):
    return StaticKeys(tag.meta_read_key, tag.file_read_key)


def test_shipped_backends_satisfy_the_protocol():
    keys = StaticKeys(bytes(16), bytes(16))
    for backend in (Ntag424SunBackend(keys), Ntag424EncBackend(keys),
                    HmacCounterBackend(b"k")):
        assert isinstance(backend, VerificationBackend)


def test_a_new_backend_plugs_in_without_touching_the_pipeline():
    chip = HmacCounterBackend(os.urandom(16))
    service = VerificationService(
        TagAnalyzer(backends=[chip], store=CounterStore()), clock=lambda: 1000.0)
    verdicts = [service.verify(chip.sign("A1", n)).result for n in (1, 2, 5)]
    assert [r.classification for r in verdicts] == ["GENUINE"] * 3
    assert verdicts[0].uid == "test:A1" and verdicts[0].backend == "test-hmac"
    assert verdicts[0].algorithm == "HMAC-SHA256"
    assert service.verify(chip.sign("A1", 5)).result.classification == "REPLAY"
    assert service.verify(chip.sign("A1", 3)).result.classification == "CLONE_LIKELY"
    forged = service.verify(chip.sign("A1", 9).replace("ctr=9", "ctr=10")).result
    assert forged.classification == "FORGED" and forged.uid is None
    assert service.verify("https://example.com/x?dev=A1").result.classification == "ERROR"


def test_each_tap_goes_to_the_backend_that_accepts_it():
    plain, enc = _tag(), _tag(EmulatedEncTag, file_data=b"serial-0042".ljust(16, b"\0"))
    chip = HmacCounterBackend(os.urandom(16))
    keys = _keys(enc)
    plain.meta_read_key, plain.file_read_key = enc.meta_read_key, enc.file_read_key
    analyzer = TagAnalyzer(store=CounterStore(), backends=[
        chip, Ntag424EncBackend(keys), Ntag424SunBackend(keys)])

    r = analyzer.analyze(enc.tap(), timestamp=1000)
    assert (r.classification, r.backend) == ("GENUINE", "ntag424-sun-enc")
    assert r.payload == enc.file_data
    r = analyzer.analyze(plain.tap(), timestamp=1000)
    assert (r.classification, r.backend, r.payload) == ("GENUINE", "ntag424-sun", None)
    r = analyzer.analyze(chip.sign("B", 1), timestamp=1000)
    assert (r.classification, r.backend) == ("GENUINE", "test-hmac")


def test_encrypted_payload_is_returned_for_fresh_taps_only():
    tag = _tag(EmulatedEncTag, file_data=b"x" * 16)
    analyzer = TagAnalyzer(backends=[Ntag424EncBackend(_keys(tag))], store=CounterStore())
    url = tag.tap()
    assert analyzer.analyze(url, timestamp=1000).payload == b"x" * 16
    again = analyzer.analyze(url, timestamp=1001)
    assert again.classification == "REPLAY" and again.payload is None
    withheld, later = tag.tap(), tag.tap()
    assert analyzer.analyze(later, timestamp=1002).payload == b"x" * 16
    stale = analyzer.analyze(withheld, timestamp=1003)
    assert stale.classification == "CLONE_LIKELY" and stale.payload is None


def test_an_encrypted_tap_stays_fail_closed_on_the_plain_backend():
    tag = _tag(EmulatedEncTag)
    analyzer = TagAnalyzer(_keys(tag), store=CounterStore())
    r = analyzer.analyze(tag.tap())
    assert r.classification == "ERROR" and r.uid is None
    assert "no verification backend" in r.detail


def test_selection_is_first_match():
    keys = StaticKeys(bytes(16), bytes(16))
    sun, enc = Ntag424SunBackend(keys), Ntag424EncBackend(keys)
    enc_url = "https://e.x/t?picc_data=00&enc=00&cmac=00"
    assert select_backend([sun, enc], enc_url) is enc       # sun refuses enc taps
    assert select_backend([enc, sun], "https://e.x/t?picc_data=00&cmac=00") is sun
    assert select_backend([enc], "https://e.x/t?picc_data=00&cmac=00") is None


def test_analyzer_needs_exactly_one_source_of_backends():
    keys = StaticKeys(bytes(16), bytes(16))
    with pytest.raises(TypeError):
        TagAnalyzer()
    with pytest.raises(TypeError):
        TagAnalyzer(keys, backends=[Ntag424SunBackend(keys)])
    with pytest.raises(TypeError):
        TagAnalyzer(backends=[])


def test_settings_validate_and_order_backends():
    pytest.importorskip("fastapi")
    from sphragis.api.settings import ApiSettings
    assert ApiSettings.from_env({}).backends == ("ntag424-sun",)
    s = ApiSettings.from_env({"SPHRAGIS_BACKENDS": "ntag424-sun, NTAG424-SUN-ENC"})
    assert s.backends == ("ntag424-sun-enc", "ntag424-sun")
    for bad in ("ntag-x", ",", "ntag424-sun,fido2"):
        with pytest.raises(ValueError, match="BACKENDS"):
            ApiSettings.from_env({"SPHRAGIS_BACKENDS": bad})


def test_api_serves_encrypted_taps_when_configured(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sphragis import DiversifiedKeys
    from sphragis.api import create_app_from_env
    from sphragis.emulator import tag_from_provider

    master, meta = os.urandom(16), os.urandom(16)
    monkeypatch.setenv("SPHRAGIS_MASTER_FILE", master.hex())
    monkeypatch.setenv("SPHRAGIS_META_READ", meta.hex())
    monkeypatch.setenv("SPHRAGIS_LOG_PSEUDONYM", os.urandom(16).hex())
    client = TestClient(create_app_from_env({
        "SPHRAGIS_DB_PATH": str(tmp_path / "s.db"),
        "SPHRAGIS_BACKENDS": "ntag424-sun,ntag424-sun-enc",
    }))
    plain = tag_from_provider(DiversifiedKeys(master, meta), uid=os.urandom(7))
    uid = os.urandom(7)
    enc = EmulatedEncTag(uid=uid, meta_read_key=meta,
                         file_read_key=DiversifiedKeys(master, meta).file_read_key(uid))

    def path(url):
        return "/t?" + url.partition("?")[2]

    assert client.get(path(plain.tap())).json()["verdict"] == "GENUINE"
    assert client.get(path(enc.tap())).json()["verdict"] == "GENUINE"
