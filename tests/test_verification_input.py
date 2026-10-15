"""
Unauthenticated input.

A FORGED verdict must not hand back what was decrypted before the MAC check
(otherwise anyone can decrypt blocks under the shared MetaRead key), and no
crafted input may surface as an exception (HTTP 500) instead of ERROR.
"""

import logging
import os
import sys

import pytest
from Crypto.Cipher import AES

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis import EncFileVerifier, StaticKeys, Verdict, Verifier  # noqa: E402
from sphragis.analyzer import TagAnalyzer  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.diversify import DiversifiedKeys  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.service import VerificationService  # noqa: E402

META, FILE = os.urandom(16), os.urandom(16)
KEYS = StaticKeys(META, FILE)


def _picc(tag_byte: int, uid: bytes, counter: int = 5) -> str:
    plain = bytes([tag_byte]) + uid + counter.to_bytes(3, "little")
    plain = plain.ljust(16, b"\x00")
    return AES.new(META, AES.MODE_CBC, bytes(16)).encrypt(plain).hex().upper()


def _url(picc_hex: str) -> str:
    return f"https://example.com/t?picc_data={picc_hex}&cmac={'00' * 8}"


def _enc_url(picc_hex: str) -> str:
    return (f"https://example.com/t?picc_data={picc_hex}&enc={'00' * 16}"
            f"&cmac={'00' * 8}")


# --- No decryption oracle ---------------------------------------------------------

def test_forged_verdict_hides_the_decrypted_uid_and_counter():
    # Audit reproduction: a block chosen by the attacker, any MAC.
    url = _url(_picc(0xC7, bytes.fromhex("04AABBCCDDEEFF")))
    r = Verifier(KEYS, CounterStore()).verify(url)
    assert r.verdict is Verdict.FORGED and r.uid is None and r.read_counter is None
    a = TagAnalyzer(KEYS).analyze(url)
    assert a.classification == "FORGED" and a.uid is None and a.read_counter is None
    e = EncFileVerifier(KEYS, CounterStore()).verify(_enc_url(_picc(0xC7, bytes(7))))
    assert e.verdict is Verdict.FORGED and e.uid is None and e.read_counter is None


def test_forged_taps_never_reach_the_logs_as_uids(caplog):
    caplog.set_level(logging.INFO, logger="sphragis")
    service = VerificationService(TagAnalyzer(KEYS))
    out = service.verify(_url(_picc(0xC7, bytes.fromhex("04AABBCCDDEEFF"))))
    assert out.result.classification == "FORGED" and out.uid_ref is None
    assert "04AABBCCDDEEFF" not in caplog.text


def test_genuine_taps_still_report_uid_and_counter():
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=META, file_read_key=FILE)
    r = Verifier(KEYS, CounterStore()).verify(tag.tap())
    assert r.ok and r.uid == tag.uid.hex().upper() and r.read_counter == 1


# --- Crafted input is an ERROR, never an exception ---------------------------------

CRAFTED = [
    "http://[::1/t?picc_data=00&cmac=00",          # urlparse raises ValueError
    "https://[example.com/t?x=1",
    "picc_data=" + "zz" * 16 + "&cmac=" + "00" * 8,
    "",
]


@pytest.mark.parametrize("url", CRAFTED)
def test_crafted_urls_are_errors(url):
    assert Verifier(KEYS, CounterStore()).verify(url).verdict is Verdict.ERROR
    assert EncFileVerifier(KEYS, CounterStore()).verify(url).verdict is Verdict.ERROR
    assert TagAnalyzer(KEYS).analyze(url).classification == "ERROR"


@pytest.mark.parametrize("tag_byte,uid", [
    (0x87, bytes(7)),             # no SDMReadCtr mirror: the counter would read 0
    (0xC4, bytes(4)),             # 4-byte UID
    (0xCA, bytes(10)),            # 10-byte UID
    (0xD7, bytes(7)),             # RFU bit set
    (0xE7, bytes(7)),
])
def test_only_the_standard_picc_layout_is_accepted(tag_byte, uid):
    url = _url(_picc(tag_byte, uid))
    assert Verifier(KEYS, CounterStore()).verify(url).verdict is Verdict.ERROR
    assert TagAnalyzer(KEYS).analyze(url).classification == "ERROR"
    enc = _enc_url(_picc(tag_byte, uid))
    assert EncFileVerifier(KEYS, CounterStore()).verify(enc).verdict is Verdict.ERROR


def test_random_picc_data_with_a_long_context_never_raises():
    # Audit reproduction: with a 24-byte context, random blocks decrypted to
    # long UIDs and AN10922 diversification raised (HTTP 500 on ~10 %).
    keys = DiversifiedKeys(os.urandom(16), META, context=b"x" * 24)
    analyzer, verifier = TagAnalyzer(keys), Verifier(keys, CounterStore())
    for _ in range(2000):
        url = _url(os.urandom(16).hex())
        assert analyzer.analyze(url).classification in ("ERROR", "FORGED")
        assert verifier.verify(url).verdict in (Verdict.ERROR, Verdict.FORGED)


def test_api_answers_crafted_input_without_a_500():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sphragis.api import create_app
    client = TestClient(create_app(VerificationService(TagAnalyzer(KEYS))))
    for url in CRAFTED:
        r = client.post("/v1/verify", json={"url": url or "x"})
        assert r.status_code == 200 and r.json()["verdict"] == "INVALID"


def test_key_context_is_limited_in_the_settings():
    pytest.importorskip("fastapi")
    from sphragis.api.settings import ApiSettings
    assert ApiSettings.from_env({"SPHRAGIS_KEY_CONTEXT": "x" * 23}).key_context == b"x" * 23
    with pytest.raises(ValueError, match="KEY_CONTEXT"):
        ApiSettings.from_env({"SPHRAGIS_KEY_CONTEXT": "x" * 24})


def test_backend_failures_are_logged_and_fail_closed(caplog):
    class BrokenStore(CounterStore):
        def record_tap(self, uid_hex, counter):
            raise RuntimeError("database unavailable")

    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=META, file_read_key=FILE)
    service = VerificationService(TagAnalyzer(KEYS, store=BrokenStore()))
    with pytest.raises(RuntimeError):
        service.verify(tag.tap())
    assert "verification_failed" in caplog.text and "picc_data" not in caplog.text
