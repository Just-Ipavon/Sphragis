"""Tests for the `inspect` diagnostic (sphragis.diagnostics) and its CLI."""

import json
import os

import pytest

from sphragis.cli import main
from sphragis.diagnostics import ZERO_KEY, inspect_tap
from sphragis.emulator import EmulatedTag
from sphragis.ndef import encode_uri_file
from sphragis.sdm import SdmError, decrypt_picc_data

NXP_URL = ("https://choose.url.com/ntag424?"
           "picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086")


def _zero_tag(counter=0, uid=bytes.fromhex("04A1B2C3D4E5F6")):
    return EmulatedTag(uid=uid, meta_read_key=ZERO_KEY, file_read_key=ZERO_KEY,
                       read_counter=counter)


def test_nxp_vector_layout():
    r = inspect_tap(NXP_URL)
    assert r.mirror == "encrypted"
    assert r.picc_tag == 0xC7 and r.tag_plausible
    assert r.uid == "04DE5F1EACC040"
    assert r.read_counter == 61
    assert r.cmac_match is True
    assert r.warnings == []
    names = [(f.name, f.offset, f.length) for f in r.layout]
    assert names == [("PICCDataTag", 0, 1), ("UID", 1, 7),
                     ("SDMReadCtr", 8, 3), ("padding", 11, 5)]
    ctr = next(f for f in r.layout if f.name == "SDMReadCtr")
    assert ctr.hex == "3D0000"  # little-endian on the wire


def test_emulator_tap_matches_engine_decoding():
    tag = _zero_tag(counter=0x0102 - 1)
    url = tag.tap()
    r = inspect_tap(url)
    picc = decrypt_picc_data(bytes.fromhex(r.picc_data_enc), ZERO_KEY)
    assert r.uid == picc.uid_hex == "04A1B2C3D4E5F6"
    assert r.read_counter == picc.read_counter == 0x0102
    assert next(f for f in r.layout if f.name == "SDMReadCtr").hex == "020100"
    assert r.cmac_match is True


def test_offsets_point_at_mirrors_in_ndef_file():
    url = _zero_tag().tap()
    r = inspect_tap(url)
    data = encode_uri_file(url)
    o = r.offsets
    assert data[o.picc_data:o.picc_data + 32].decode() == r.picc_data_enc
    assert data[o.mac:o.mac + 16].decode() == r.cmac
    assert o.mac_input == o.mac
    assert o.file_length == len(data)


def test_custom_keys():
    meta, file_ = os.urandom(16), os.urandom(16)
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=meta, file_read_key=file_)
    url = tag.tap()
    r = inspect_tap(url, meta, file_)
    assert r.meta_key == "custom" and r.cmac_match is True
    assert r.uid == tag.uid.hex().upper()


def test_wrong_meta_key_is_reported_not_fatal():
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                      file_read_key=ZERO_KEY)
    url = tag.tap()
    # Retry until the random-key decryption gives an implausible tag byte
    # (3 of 256 values are plausible by chance).
    r = inspect_tap(url)
    while r.tag_plausible:
        r = inspect_tap(tag.tap())
    assert r.uid is None and r.read_counter is None
    assert r.cmac_match is None
    assert any("not a valid NTAG 424 DNA value" in w for w in r.warnings)


def test_wrong_file_key_mismatch_is_informational():
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=ZERO_KEY,
                      file_read_key=os.urandom(16))
    r = inspect_tap(tag.tap())
    assert r.uid is not None
    assert r.cmac_match is False
    assert any("CMAC does not match" in w for w in r.warnings)


def test_bare_query_string():
    r = inspect_tap(NXP_URL.split("?", 1)[1])
    assert r.uid == "04DE5F1EACC040"
    assert r.offsets is None  # no URL, no NDEF layout to compute


def test_plain_mirror_detected():
    r = inspect_tap("https://x.example/t?uid=04DE5F1EACC040&ctr=00003D&cmac=94EED9EE65337086")
    assert r.mirror == "plain"
    assert r.uid == "04DE5F1EACC040"
    assert r.cmac_match is None
    assert any("plain-text" in w for w in r.warnings)


@pytest.mark.parametrize("picc,needle", [
    ("EF963FF7828658A599F3041510671E", "15 bytes"),
    ("EF963FF7828658A599F3041510671E8800", "17 bytes"),
])
def test_wrong_picc_length_warns(picc, needle):
    r = inspect_tap(f"https://x.example/t?picc_data={picc}&cmac=94EED9EE65337086")
    assert r.picc_data_plain is None
    assert any(needle in w for w in r.warnings)


def test_short_cmac_and_missing_cmac_warn():
    r = inspect_tap("https://x.example/t?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EE")
    assert r.cmac_match is None and any("2 bytes" in w for w in r.warnings)
    r = inspect_tap("https://x.example/t?picc_data=EF963FF7828658A599F3041510671E88")
    assert any("no 'cmac'" in w for w in r.warnings)


def test_enc_file_data_flagged():
    r = inspect_tap(NXP_URL + "&enc=00112233")
    assert any("SDMENCFileData" in w for w in r.warnings)


@pytest.mark.parametrize("bad", [
    "https://x.example/t",                                       # no query
    "https://x.example/t?foo=bar",                               # no mirror params
    "https://x.example/t?picc_data=ZZ&cmac=94EED9EE65337086",    # not hex
    "https://x.example/t?picc_data=AA&picc_data=BB&cmac=00",     # duplicated
    "",
])
def test_malformed_input_raises_sdm_error(bad):
    with pytest.raises(SdmError):
        inspect_tap(bad)


def test_bad_key_length():
    with pytest.raises(SdmError):
        inspect_tap(NXP_URL, meta_key=bytes(15))


def test_cli_text_and_json(capsys):
    assert main(["inspect", NXP_URL]) == 0
    out = capsys.readouterr().out
    assert "04DE5F1EACC040" in out and "little-endian = 61" in out
    assert "PICCDataOffset" in out

    assert main(["inspect", "--json", NXP_URL]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["read_counter"] == 61 and data["cmac_match"] is True
    # Keys are never echoed back.
    assert data["meta_key"] == "all-zero"


def test_cli_malformed_exit_code(capsys):
    assert main(["inspect", "https://x.example/t?foo=1"]) == 2
    assert "ERROR" in capsys.readouterr().err
