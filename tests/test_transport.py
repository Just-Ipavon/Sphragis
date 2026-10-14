"""Tests for APDU helpers, NDEF encoding and the ApduTransport backends."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from fake_isodep import FakeCard  # noqa: E402

from sphragis import StaticKeys, Verdict, Verifier  # noqa: E402
from sphragis.apdu import (  # noqa: E402
    ApduError,
    build_apdu,
    parse_response,
    read_binary,
    select_file,
    select_ndef_app,
)
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.ndef import (  # noqa: E402
    NdefError,
    decode_uri_file,
    encode_uri_file,
    read_uri,
    sdm_offsets,
)
from sphragis.transport import (  # noqa: E402
    ApduTransport,
    EmulatorTransport,
    IsoDepTransport,
    ScriptedTransport,
    TransportError,
)

ZERO = bytes(16)

# --- APDU encoding ----------------------------------------------------------


def test_apdus_match_an12196_encoding():
    assert select_ndef_app().hex().upper() == "00A4040C07D276000085010100"
    assert select_file(0xE104).hex().upper() == "00A4000C02E10400"
    assert read_binary(0, 2).hex().upper() == "00B0000002"
    assert read_binary(0x0102, 256).hex().upper() == "00B0010200"


def test_build_apdu_cases():
    assert build_apdu(0x90, 0x60, 0, 0, le=0) == bytes.fromhex("9060000000")
    assert build_apdu(0, 0xA4, 4, 0, b"\x01") == bytes.fromhex("00A404000101")
    with pytest.raises(ValueError):
        build_apdu(0, 0, 0, 0, bytes(256))
    with pytest.raises(ValueError):
        build_apdu(0x100, 0, 0, 0)
    with pytest.raises(ValueError):
        read_binary(0x8000, 1)


def test_parse_response():
    r = parse_response(bytes.fromhex("AABB9000"))
    assert r.ok and r.data == b"\xAA\xBB" and r.check() == b"\xAA\xBB"
    bad = parse_response(bytes.fromhex("6A82"))
    assert not bad.ok
    with pytest.raises(ApduError) as exc:
        bad.check("select")
    assert exc.value.sw == 0x6A82
    with pytest.raises(ApduError):
        parse_response(b"\x90")


# --- NDEF -------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "https://example.com/t?picc_data=00&cmac=00",
    "http://www.example.com/x",
    "https://www.example.com/x",
    "urn:nfc:sn:foo",
    "custom-scheme:payload",
    "https://example.com/" + "a" * 400,          # long (non-SR) record
])
def test_ndef_roundtrip(url):
    assert decode_uri_file(encode_uri_file(url)) == url


def test_ndef_short_record_bytes():
    data = encode_uri_file("https://a.b")
    assert data == bytes.fromhex("0008D1010455") + b"\x04a.b"


@pytest.mark.parametrize("data", [
    b"", b"\x00", b"\x00\x00", bytes.fromhex("0010D10104"),
    bytes.fromhex("0005D1010155") + b"\x24",       # unknown prefix code
    bytes.fromhex("0006D1010254") + b"\x04x",       # type 'T', not 'U'
])
def test_ndef_decode_rejects_malformed(data):
    with pytest.raises(NdefError):
        decode_uri_file(data)


def test_sdm_offsets_errors():
    with pytest.raises(NdefError):
        sdm_offsets("https://x.example/t?cmac=00")
    with pytest.raises(NdefError):
        sdm_offsets("https://x.example/t?picc_data=0&picc_data=1&cmac=0")


# --- ScriptedTransport ------------------------------------------------------


def test_scripted_transport_enforces_script():
    t = ScriptedTransport([(select_ndef_app(), b"\x90\x00")])
    assert t.transceive(select_ndef_app()) == b"\x90\x00"
    assert t.exhausted
    with pytest.raises(TransportError):
        t.transceive(select_ndef_app())
    t = ScriptedTransport([(select_ndef_app(), b"\x90\x00")])
    with pytest.raises(TransportError):
        t.transceive(select_file(0xE104))


def test_transport_is_context_manager():
    closed = []

    class T(ApduTransport):
        def transceive(self, apdu):
            return b"\x90\x00"

        def close(self):
            closed.append(True)

    with T() as t:
        t.transceive(b"\x00")
    assert closed == [True]


# --- EmulatorTransport ------------------------------------------------------


def _emulated():
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=ZERO, file_read_key=ZERO)
    return tag, EmulatorTransport(tag)


def test_read_uri_end_to_end_with_verifier():
    tag, t = _emulated()
    verifier = Verifier(StaticKeys(ZERO, ZERO), CounterStore())
    for expected in (1, 2, 3):
        result = verifier.verify(read_uri(t))
        assert result.verdict is Verdict.AUTHENTIC
        assert result.read_counter == expected
        assert result.uid == tag.uid.hex().upper()


def test_one_tap_per_file_selection():
    tag, t = _emulated()
    read_uri(t)
    assert tag.read_counter == 1
    # Extra reads without re-selecting return the same snapshot.
    assert parse_response(t.transceive(read_binary(0, 2))).ok
    assert tag.read_counter == 1


def test_emulator_status_words():
    _, t = _emulated()
    sw = lambda apdu: parse_response(t.transceive(apdu)).sw  # noqa: E731
    assert sw(read_binary(0, 2)) == 0x6986                    # no file selected
    assert sw(select_file(0xE104)) == 0x6A82                  # app not selected
    assert sw(build_apdu(0, 0xA4, 4, 0x0C, b"\xA0\x00", le=0)) == 0x6A82
    assert sw(select_ndef_app()) == 0x9000
    assert sw(select_file(0xE105)) == 0x6A82
    assert sw(build_apdu(0x90, 0x60, 0, 0, le=0)) == 0x6E00   # native cmd, CLA 90
    assert sw(build_apdu(0, 0x84, 0, 0, le=8)) == 0x6D00
    assert sw(select_file(0xE103)) == 0x9000
    cc = parse_response(t.transceive(read_binary(0, 15)))
    assert cc.ok and cc.data[9:11] == b"\xE1\x04"
    assert sw(read_binary(0x0200, 1)) == 0x6B00


def test_read_uri_propagates_apdu_errors():
    t = ScriptedTransport([(select_ndef_app(), b"\x6A\x82")])
    with pytest.raises(ApduError):
        read_uri(t)


# --- ISO-DEP framing --------------------------------------------------------


def test_isodep_simple_exchange_and_ats():
    card = FakeCard(lambda apdu: b"\x90\x00", card_fsc_fsci=0x08)
    t = IsoDepTransport(card.exchange)
    assert t.activate()[0] == 5
    assert t.fsc == 256
    assert t.transceive(select_ndef_app()) == b"\x90\x00"
    assert t.transceive(select_ndef_app()) == b"\x90\x00"
    assert card.frames[1][0] == 0x02 and card.frames[2][0] == 0x03  # bn toggles


def test_isodep_chaining_both_directions_and_wtx():
    big = bytes(range(200))
    card = FakeCard(lambda apdu: apdu[::-1] + b"\x90\x00",
                    fsd=40, card_fsc_fsci=0x02, wtx=True)       # FSC = 32
    t = IsoDepTransport(card.exchange)
    t.activate()
    assert t.fsc == 32
    resp = t.transceive(big)
    assert resp == big[::-1] + b"\x90\x00"
    sent = [f for f in card.frames[1:] if f[0] & 0xE2 == 0x02]
    assert all(len(f) <= t.fsc - 2 for f in sent)               # frame minus CRC
    assert any(f[0] & 0xF7 == 0xF2 for f in card.frames)         # WTX answered
    # A second exchange keeps block numbers consistent.
    assert t.transceive(b"\x00\xA4") == b"\xA4\x00\x90\x00"


def test_isodep_full_stack_over_emulator():
    tag, emu = _emulated()
    card = FakeCard(emu.transceive, fsd=64, card_fsc_fsci=0x05)  # FSC = 64
    t = IsoDepTransport(card.exchange)
    t.activate()
    verifier = Verifier(StaticKeys(ZERO, ZERO), CounterStore())
    assert verifier.verify(read_uri(t)).verdict is Verdict.AUTHENTIC


def test_isodep_rejects_bad_blocks():
    t = IsoDepTransport(lambda f: b"\xC2")                       # S(DESELECT)
    with pytest.raises(TransportError):
        t.transceive(b"\x00")
    t = IsoDepTransport(lambda f: b"\x03\x90\x00")               # wrong bn
    with pytest.raises(TransportError):
        t.transceive(b"\x00")
    t = IsoDepTransport(lambda f: b"\x04\x00")                   # bad ATS length
    with pytest.raises(TransportError):
        t.activate()

