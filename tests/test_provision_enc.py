"""
Provisioning of the SDMENCFileData layout.

The offsets are pinned to NXP AN12196 Rev. 2.0 Table 5 (same URL length as
https://www.my424dna.com/), the ChangeFileSettings payload is checked byte by
byte against NT4H2421Gx Table 69, and the flow runs against the fake PICC,
whose emitted taps must verify with EncFileVerifier.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from fake_ntag424 import FakeNtag424  # noqa: E402
from sphragis import EncFileVerifier, StaticKeys, Verdict  # noqa: E402
from sphragis.apdu import build_apdu  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.ndef import SdmOffsets, read_uri  # noqa: E402
from sphragis.provision import ProvisionError, provision_tag, update_binary_an12196  # noqa: E402
from sphragis.sdmconfig import (  # noqa: E402
    FACTORY_ACCESS,
    AccessRights,
    SdmConfigError,
    check_enc_offsets,
    enc_template_url,
    locked_access,
    sun_enc_layout,
    sun_enc_settings,
)

ZERO = bytes(16)
BASE = "https://example.com/t"
DATA = b"0123456789ABCDEF"


def _verifier():
    return EncFileVerifier(StaticKeys(ZERO, ZERO), CounterStore())


# --- Layout and file settings -----------------------------------------------

def test_offsets_match_an12196_table5():
    layout = sun_enc_layout("https://www.my424dna.com/", b"x" * 16)
    o = layout.offsets
    # Table 5: PICCENCDataOffset 1F, SDMMACInputOffset 44, ENCDataOffset 44,
    # ENCDataLength 20, SDMMACOffset 6A.
    assert (o.picc_data, o.mac_input, o.enc_data, o.enc_length, o.mac) == \
        (0x1F, 0x44, 0x44, 0x20, 0x6A)


def test_plaintext_fills_first_half_of_placeholder():
    layout = sun_enc_layout(BASE, DATA)
    o = layout.offsets
    region = layout.ndef_file[o.enc_data:o.enc_data + o.enc_length]
    assert region == DATA + b"0" * 16


def test_change_file_settings_payload():
    layout = sun_enc_layout("https://www.my424dna.com/", b"x" * 16)
    payload = sun_enc_settings(layout.offsets).encode_change()
    # FileOption 40 (SDM, plain) | AR RW=0 Change=0, Read=E Write=0
    # | SDMOptions D1 (UID, ctr, ENC, ASCII) | F1 21 (CtrRet 1, Meta 2, File 1)
    # | PICC 1F | MACInput 44 | ENC 44 | ENCLen 20 | MAC 6A (3 B LE each)
    assert payload.hex().upper() == (
        "4000E0" "D1" "F121" "1F0000" "440000" "440000" "200000" "6A0000")


def test_write_lock_key_is_configurable():
    assert locked_access(3) == AccessRights(0x3, 0x0, 0xE, 0x3)
    with pytest.raises(SdmConfigError):
        locked_access(0xE)


@pytest.mark.parametrize("data", [b"", b"x" * 15, b"x" * 17])
def test_plaintext_must_be_whole_blocks(data):
    with pytest.raises(SdmConfigError):
        sun_enc_layout(BASE, data)


def test_template_must_fit_the_file():
    assert len(sun_enc_layout(BASE, b"x" * 80).ndef_file) <= 256
    with pytest.raises(SdmConfigError):
        sun_enc_layout(BASE, b"x" * 96)
    with pytest.raises(SdmConfigError):
        enc_template_url(BASE + "?q=1", 16)


@pytest.mark.parametrize("bad", [
    dict(enc_length=48),                             # not a multiple of 32
    dict(mac_input=0x50),                            # MAC input after ENC
    dict(mac=0x60),                                  # MAC inside ENC
    dict(picc_data=0x50),                            # PICCData overlaps ENC
    dict(mac=0xF8, enc_data=0x44),                   # MAC runs past the file
])
def test_enc_offset_rules(bad):
    good = dict(picc_data=0x1F, mac_input=0x44, mac=0x6A, file_length=0x7A,
                enc_data=0x44, enc_length=0x20)
    check_enc_offsets(SdmOffsets(**good))
    with pytest.raises(SdmConfigError):
        check_enc_offsets(SdmOffsets(**{**good, **bad}))


# --- Provisioning flow against the fake PICC --------------------------------

def test_provision_factory_tag_with_encrypted_mirror():
    tag = FakeNtag424()
    report = provision_tag(tag, BASE, file_data=DATA)
    assert report.wrote_ndef and report.changed_settings
    assert report.verified, report.log
    assert tag.settings.enc_enabled
    assert tag.settings.access == locked_access(0)

    verifier = _verifier()
    seen = set()
    for _ in range(3):
        url = read_uri(tag)
        result = verifier.verify(url)
        assert result.verdict is Verdict.AUTHENTIC
        assert result.file_data == DATA
        seen.add(url.split("enc=")[1][:32])
    assert len(seen) == 3                            # fresh ciphertext per tap
    assert DATA.decode() not in url                  # plaintext never mirrored


def test_locked_tag_rejects_unauthenticated_writes():
    tag = FakeNtag424()
    provision_tag(tag, BASE, file_data=DATA)
    tag.transceive(build_apdu(0x00, 0xA4, 0x04, 0x00, bytes.fromhex("D2760000850101"), le=0))
    tag.transceive(build_apdu(0x00, 0xA4, 0x00, 0x0C, bytes.fromhex("E104")))
    # Datasheet form (no Le): reaches the access check -> security status.
    assert tag.transceive(build_apdu(0x00, 0xD6, 0x00, 0x44, b"EVIL")) == b"\x69\x82"
    # AN12196 form (trailing Le): rejected on length first, as on silicon.
    assert tag.transceive(update_binary_an12196(0x44, b"EVIL")) == b"\x67\x00"
    assert _verifier().verify(read_uri(tag)).file_data == DATA


def test_encrypted_provisioning_is_idempotent():
    tag = FakeNtag424()
    provision_tag(tag, BASE, file_data=DATA)
    writes, settings = tag.writes, tag.settings
    again = provision_tag(tag, BASE, file_data=DATA)
    assert again.already_provisioned and again.verified
    assert tag.writes == writes and tag.settings == settings


def test_longer_plaintext_writes_and_reconfigures_in_one_session():
    # WriteData (plain, CmdCtr advanced by hand) followed by ChangeFileSettings
    # (CommMode.Full) on the same session: the fake PICC rejects the second
    # command if the counter bookkeeping is off.
    tag = FakeNtag424()
    provision_tag(tag, BASE, file_data=DATA)
    settings = tag.settings
    report = provision_tag(tag, BASE, file_data=b"FEDCBA9876543210" * 2)
    assert report.wrote_ndef and report.changed_settings
    assert "WriteData" in "".join(report.log)
    assert report.verified and tag.settings != settings   # longer placeholder
    assert _verifier().verify(read_uri(tag)).file_data == b"FEDCBA9876543210" * 2


def test_same_layout_new_plaintext_keeps_settings():
    tag = FakeNtag424()
    provision_tag(tag, BASE, file_data=DATA)
    settings = tag.settings
    report = provision_tag(tag, BASE, file_data=b"Z" * 16)
    assert report.wrote_ndef and not report.changed_settings
    assert tag.settings == settings and report.verified


def test_plain_sun_tag_upgrades_to_encrypted_mirror():
    tag = FakeNtag424()
    provision_tag(tag, BASE, write_key=None)            # bench tag, writes free
    assert tag.settings.access == FACTORY_ACCESS
    report = provision_tag(tag, BASE, file_data=DATA)
    assert report.wrote_ndef and report.changed_settings and report.verified


def test_encrypted_tag_can_go_back_to_plain_sun():
    tag = FakeNtag424()
    provision_tag(tag, BASE, file_data=DATA)
    report = provision_tag(tag, BASE)
    assert report.wrote_ndef and report.changed_settings and report.verified
    assert not tag.settings.enc_enabled
    assert tag.settings.access == locked_access(0)      # plain SUN stays locked
    unlocked = provision_tag(tag, BASE, write_key=None)
    assert unlocked.changed_settings and tag.settings.access == FACTORY_ACCESS


def test_dry_run_on_factory_tag_writes_nothing():
    tag = FakeNtag424()
    report = provision_tag(tag, BASE, file_data=DATA, dry_run=True)
    assert tag.writes == 0 and not tag.settings.sdm_enabled
    log = "\n".join(report.log)
    assert "locked to key 0" in log and "ISOUpdateBinary" in log
    offline = provision_tag(None, BASE, file_data=DATA, dry_run=True)
    assert "SDMENCOffset=0x" in "\n".join(offline.log)


def test_dry_run_on_locked_tag_plans_authenticated_write():
    tag = FakeNtag424()
    provision_tag(tag, BASE, file_data=DATA)
    writes = tag.writes
    report = provision_tag(tag, BASE, file_data=b"Q" * 16, dry_run=True)
    assert not report.ndef_matches and report.settings_match
    assert "WriteData (auth with key 0)" in "\n".join(report.log)
    assert tag.writes == writes


def test_encrypted_provisioning_fails_closed_with_non_zero_key():
    tag = FakeNtag424(keys=[os.urandom(16)] + [ZERO] * 4)
    with pytest.raises(ProvisionError, match="rejects key 0"):
        provision_tag(tag, BASE, file_data=DATA)
    assert tag.writes == 0 and not tag.settings.sdm_enabled


def test_not_verified_when_file_key_differs():
    # Zero meta key but a non-zero file-read key: the tag works, the zero-key
    # check cannot verify it, and the report says so instead of passing.
    keys = [ZERO, os.urandom(16), ZERO, ZERO, ZERO]
    report = provision_tag(FakeNtag424(keys=keys), BASE, file_data=DATA)
    assert report.changed_settings and not report.verified
    assert report.enc_check.verdict is Verdict.FORGED
