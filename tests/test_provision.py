"""
Provisioning: EV2 secure messaging and SDM file settings against the NXP
AN12196 worked examples, then the full provisioning flow against a fake PICC.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from fake_ntag424 import FakeNtag424  # noqa: E402

from sphragis import StaticKeys, Verdict, Verifier  # noqa: E402
from sphragis.apdu import ApduError  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.ev2 import (  # noqa: E402
    AuthError,
    Session,
    authenticate_ev2_first,
    derive_session_keys,
    session_vectors,
)
from sphragis.ndef import encode_uri_file, read_uri, sdm_offsets  # noqa: E402
from sphragis.provision import (  # noqa: E402
    ProvisionError,
    provision_tag,
    update_binary,
    update_binary_an12196,
)
from sphragis.sdmconfig import (  # noqa: E402
    FACTORY_ACCESS,
    AccessRights,
    FileSettings,
    SdmConfigError,
    parse_file_settings,
    same_config,
    sun_layout,
    WRITE_LOCK_KEYS,
    locked_access,
    sun_settings,
    template_url,
)
from sphragis.transport import ScriptedTransport  # noqa: E402

ZERO = bytes(16)
H = bytes.fromhex

# --- AN12196 Table 14: AuthenticateEV2First with key 0x00 -------------------

AN_RND_A = H("13C5DB8A5930439FC3DEF9A4C675360F")
AN_RND_B = H("B9E2FC789B64BF237CCCAA20EC7E6E48")
AN_TI = H("9D00C4DF")
AN_K_ENC = H("1309C877509E5A215007FF0ED19CA564")
AN_K_MAC = H("4C6626F5E72EA694202139295C7A7FC7")
AN_AUTH = [
    (H("9071000002000000"), H("A04C124213C186F22399D33AC2A3021591AF")),
    (H("90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00"),
     H("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F081206639100")),
]

# --- AN12196 Table 18: ChangeFileSettings, CommMode.Full, CmdCtr = 1 --------

AN_CFS_DATA = H("4000E0C1F121200000430000430000")
AN_CFS_APDU = H("905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400")
AN_CFS_RESP = H("57BFF87B1241E93D9100")

# --- AN12196 §5.7: NDEF template --------------------------------------------

AN_URL = "https://choose.url.com/ntag424?e=" + "0" * 32 + "&c=" + "0" * 16


def test_an12196_session_vectors_and_keys():
    sv1, sv2 = session_vectors(AN_RND_A, AN_RND_B)
    assert sv1 == H("A55A0001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F")
    assert sv2 == H("5AA50001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F")
    assert derive_session_keys(ZERO, AN_RND_A, AN_RND_B) == (AN_K_ENC, AN_K_MAC)


def test_an12196_authenticate_ev2_first():
    t = ScriptedTransport(AN_AUTH)
    s = authenticate_ev2_first(t, 0, ZERO, rnd_a=AN_RND_A)
    assert t.exhausted
    assert (s.ti, s.k_enc, s.k_mac, s.cmd_ctr) == (AN_TI, AN_K_ENC, AN_K_MAC, 0)


def test_an12196_change_file_settings_full():
    t = ScriptedTransport(AN_AUTH + [(AN_CFS_APDU, AN_CFS_RESP)])
    s = authenticate_ev2_first(t, 0, ZERO, rnd_a=AN_RND_A)
    s.cmd_ctr = 1  # the AN example runs WriteData first
    assert s.send_full(0x5F, b"\x02", AN_CFS_DATA) == b""
    assert s.cmd_ctr == 2 and t.exhausted


def test_an12196_get_file_settings_mac():
    # Table 7: CommMode.MAC on GetFileSettings, response MAC verified.
    s = Session(None, H("7A21085E"), ZERO, H("8248134A386E86EB7FAF54A52E536CB6"))
    assert s.mac_command_apdu(0xF5, b"\x02") == H("90F5000009026597A457C8CD442C00")
    s.transport = ScriptedTransport([(
        H("90F5000009026597A457C8CD442C00"),
        H("0040EEEE000100D1FE001F00004400004400002000006A00002A474282E7A479869100"))])
    body = s.send_mac(0xF5, b"\x02")
    assert body == H("0040EEEE000100D1FE001F00004400004400002000006A0000")


def test_response_mac_mismatch_and_error_status():
    t = ScriptedTransport(AN_AUTH + [(AN_CFS_APDU, H("57BFF87B1241E93E9100"))])
    s = authenticate_ev2_first(t, 0, ZERO, rnd_a=AN_RND_A)
    s.cmd_ctr = 1
    with pytest.raises(AuthError):
        s.send_full(0x5F, b"\x02", AN_CFS_DATA)
    t = ScriptedTransport(AN_AUTH + [(AN_CFS_APDU, H("919D"))])
    s = authenticate_ev2_first(t, 0, ZERO, rnd_a=AN_RND_A)
    s.cmd_ctr = 1
    with pytest.raises(ApduError) as exc:
        s.send_full(0x5F, b"\x02", AN_CFS_DATA)
    assert exc.value.sw == 0x919D


def test_auth_rejects_picc_without_key():
    # Same exchange, but the PICC's proof (RndA') is garbage.
    bad = [AN_AUTH[0], (AN_AUTH[1][0], bytes(32) + H("9100"))]
    with pytest.raises(AuthError):
        authenticate_ev2_first(ScriptedTransport(bad), 0, ZERO, rnd_a=AN_RND_A)
    with pytest.raises(ApduError):
        authenticate_ev2_first(ScriptedTransport([(AN_AUTH[0][0], H("9140"))]), 0, ZERO)


# --- File settings / template ------------------------------------------------


def test_an12196_ndef_template_and_offsets():
    data = encode_uri_file(AN_URL)
    assert data[:7] == H("0051D1014D5504")
    o = sdm_offsets(AN_URL, "e", "c")
    assert (o.picc_data, o.mac_input, o.mac) == (0x20, 0x43, 0x43)


def test_an12196_change_file_settings_payload():
    o = sdm_offsets(AN_URL, "e", "c")
    fs = sun_settings(o, access=AccessRights(0x0, 0x0, 0xE, 0x0))
    assert fs.encode_change() == AN_CFS_DATA


def test_parse_file_settings():
    factory = parse_file_settings(H("0000E0EE000100"))
    assert factory.access == FACTORY_ACCESS and not factory.sdm_enabled
    assert factory.file_size == 256
    # AN12196 Table 7 response: encrypted PICCData + SDMENCFileData layout,
    # offsets as in AN12196 §3.4.4.2.2 (1F / 44 / 44 / 20 / 6A).
    enc = parse_file_settings(H("0040EEEE000100D1FE001F00004400004400002000006A0000"))
    assert (enc.meta_read, enc.file_read, enc.ctr_ret) == (0x0, 0x0, 0xE)
    assert enc.picc_offset == 0x1F
    assert (enc.mac_input_offset, enc.enc_offset, enc.enc_length, enc.mac_offset) \
        == (0x44, 0x44, 0x20, 0x6A)
    assert parse_file_settings(H("0040EEEE000100") + enc.encode_change()[3:]) == enc
    # Plain mirror (MetaRead = E): UID and counter offsets instead of PICCData.
    plain = parse_file_settings(H("0040EEEE000100C1FEE1") + H("200000430000500000500000"))
    assert (plain.uid_offset, plain.ctr_offset, plain.mac_offset) == (0x20, 0x43, 0x50)
    for bad in (H("00"), H("0100E0EE000100"), H("0040E0EE000100C1F1"),
                H("0040E0EE000100C1F12120000043"), H("0000E0EE00010000")):
        with pytest.raises(SdmConfigError):
            parse_file_settings(bad)


def test_sun_settings_refuse_plain_mirror_or_no_mac():
    o = sun_layout("https://example.com/t").offsets
    with pytest.raises(SdmConfigError):
        sun_settings(o, meta_read_key=0xE)
    with pytest.raises(SdmConfigError):
        sun_settings(o, file_read_key=0xF)
    with pytest.raises(SdmConfigError):
        template_url("https://example.com/t?x=1")
    with pytest.raises(SdmConfigError):
        sun_layout("https://example.com/" + "a" * 300)


def test_same_config():
    o = sun_layout("https://example.com/t").offsets
    assert same_config(sun_settings(o), sun_settings(o))
    assert not same_config(FileSettings(0, FACTORY_ACCESS), sun_settings(o))


def test_update_binary_an12196_matches_the_application_note():
    data = encode_uri_file(AN_URL)
    apdu = update_binary_an12196(0, data)
    assert apdu[:5] == H("00D6000053") and apdu[-1] == 0


def test_update_binary_sends_no_le():
    # Silicon (UID 04341A82161690) answers 6700 to the AN12196 form with a
    # trailing Le and writes the same bytes without it.
    data = bytes(range(48))
    assert update_binary(0x30, data) == H("00D6003030") + data


# --- Full provisioning flow against the fake PICC ---------------------------


BASE = "https://example.com/t"


def test_provision_factory_tag_then_verify():
    tag = FakeNtag424()
    report = provision_tag(tag, BASE)
    assert report.wrote_ndef and report.changed_settings
    assert report.verified, report.log
    assert report.check.uid == tag.uid.hex().upper()
    assert tag.settings.meta_read == 2 and tag.settings.file_read == 1
    assert tag.settings.access == locked_access(0)          # writes locked
    assert report.uid == tag.uid

    # The engine accepts what the provisioned tag now emits, tap after tap.
    verifier = Verifier(StaticKeys(ZERO, ZERO), CounterStore())
    for _ in range(3):
        assert verifier.verify(read_uri(tag)).verdict is Verdict.AUTHENTIC


def test_provision_is_idempotent():
    tag = FakeNtag424()
    provision_tag(tag, BASE)
    writes, settings = tag.writes, tag.settings
    again = provision_tag(tag, BASE)
    assert again.already_provisioned and again.verified
    assert not again.wrote_ndef and not again.changed_settings
    assert tag.writes == writes and tag.settings == settings


def test_provision_changes_base_url():
    tag = FakeNtag424()
    provision_tag(tag, BASE)
    report = provision_tag(tag, "https://example.org/other/path")
    assert report.wrote_ndef and report.changed_settings and report.verified


def test_dry_run_writes_nothing():
    tag = FakeNtag424()
    report = provision_tag(tag, BASE, dry_run=True)
    assert not report.settings_match and not report.ndef_matches
    assert tag.writes == 0 and not tag.settings.sdm_enabled
    assert any("would change" in line for line in report.log)
    offline = provision_tag(None, BASE, dry_run=True)
    assert offline.current is None and "dry run" in offline.log[-1]
    with pytest.raises(ProvisionError):
        provision_tag(None, BASE)


def test_provision_fails_closed_with_non_zero_key():
    tag = FakeNtag424(keys=[os.urandom(16)] + [ZERO] * 4, content=b"original")
    with pytest.raises(ProvisionError, match="nothing was written") as exc:
        provision_tag(tag, BASE)
    assert exc.value.__cause__.sw == 0x91AE    # the PICC rejects RndB'
    assert not tag.settings.sdm_enabled
    assert tag.writes == 0 and bytes(tag.file[:8]) == b"original"   # untouched


def test_free_read_write_right_allows_iso_update():
    # Write locked but ReadWrite free: ISOUpdateBinary is still granted
    # (NT4H2421Gx Table 9), so no authentication is needed.
    tag = FakeNtag424(settings=FileSettings(0x00, AccessRights(0xE, 0x0, 0xE, 0x0)))
    report = provision_tag(tag, BASE)
    assert report.wrote_ndef and report.verified
    assert "ISOUpdateBinary" in "".join(report.log)


def test_locked_ndef_file_is_written_with_authenticated_write_data():
    tag = FakeNtag424(settings=FileSettings(0x00, AccessRights(0x0, 0x0, 0xE, 0x0)))
    report = provision_tag(tag, BASE)
    assert report.wrote_ndef and report.changed_settings and report.verified
    assert "WriteData" in "".join(report.log)


def test_locked_ndef_file_with_non_zero_key_fails_closed():
    keys = [ZERO, ZERO, ZERO, os.urandom(16), ZERO]
    tag = FakeNtag424(keys=keys,
                      settings=FileSettings(0x00, AccessRights(0x3, 0x0, 0xE, 0x3)))
    with pytest.raises(ProvisionError, match="rejects key 3"):
        provision_tag(tag, BASE)
    assert tag.writes == 0 and not tag.settings.sdm_enabled


def test_unwritable_ndef_file_is_refused():
    tag = FakeNtag424(settings=FileSettings(0x00, AccessRights(0xF, 0x0, 0xE, 0xF)))
    with pytest.raises(ProvisionError):
        provision_tag(tag, BASE)


# --- Write lock and authenticate-before-write -----------------------------------

def _raw_update(tag, offset, data):
    """An unauthenticated rewrite, as any phone app would send it."""
    from sphragis.apdu import build_apdu
    tag.transceive(build_apdu(0x00, 0xA4, 0x04, 0x00, H("D2760000850101"), le=0))
    tag.transceive(build_apdu(0x00, 0xA4, 0x00, 0x0C, H("E104")))
    return tag.transceive(build_apdu(0x00, 0xD6, offset >> 8, offset & 0xFF, data))


def test_plain_layout_refuses_unauthenticated_rewrites():
    tag = FakeNtag424()
    provision_tag(tag, BASE)
    url = read_uri(tag)
    assert _raw_update(tag, 0x07, b"evilxpl.com") == b"\x69\x82"
    assert read_uri(tag).split("?")[0] == url.split("?")[0]   # host unchanged


def test_bench_tag_can_stay_writable():
    tag = FakeNtag424()
    report = provision_tag(tag, BASE, write_key=None)
    assert report.verified and tag.settings.access == FACTORY_ACCESS
    assert _raw_update(tag, 0x07, b"x") == b"\x90\x00"
    assert "FREE" in "\n".join(report.log)


@pytest.mark.parametrize("key", [1, 2, 5])
def test_write_lock_never_uses_a_verifier_key(key):
    with pytest.raises(SdmConfigError):
        locked_access(key)
    with pytest.raises(SdmConfigError):
        provision_tag(FakeNtag424(), BASE, write_key=key)


def test_write_lock_keys_are_the_admin_slots():
    assert WRITE_LOCK_KEYS == (0, 3, 4)
    o = sun_layout(BASE).offsets
    assert sun_settings(o).access == locked_access(0)              # locked by default
    for key in WRITE_LOCK_KEYS:
        assert sun_settings(o, access=locked_access(key)).access.write == key
    with pytest.raises(SdmConfigError, match="verification servers"):
        sun_settings(o, access=AccessRights(0x2, 0x0, 0xE, 0x2))   # MetaRead key


def test_write_lock_on_key_3_is_written_and_verified():
    tag = FakeNtag424()
    report = provision_tag(tag, BASE, write_key=3)
    assert report.verified and tag.settings.access == locked_access(3)
    again = provision_tag(tag, "https://example.org/x", write_key=3)
    assert again.wrote_ndef and "WriteData, authenticated with key 3" in "\n".join(again.log)


def test_dry_run_checks_the_keys_and_shows_the_uid():
    tag = FakeNtag424()
    report = provision_tag(tag, BASE, dry_run=True)
    assert report.uid == tag.uid and tag.writes == 0
    assert "auth check   : keys 0 accepted" in report.log
    locked = FakeNtag424(keys=[os.urandom(16)] + [ZERO] * 4)
    with pytest.raises(ProvisionError, match="rejects key 0"):
        provision_tag(locked, BASE, dry_run=True)


def test_operator_can_decline_provisioning():
    tag, seen = FakeNtag424(), []
    report = provision_tag(tag, BASE, confirm=lambda r: seen.append(r.uid) or False)
    assert report.aborted and seen == [tag.uid]
    assert tag.writes == 0 and not tag.settings.sdm_enabled


def test_expected_uid_must_match():
    tag = FakeNtag424(uid=H("04112233445566"))
    with pytest.raises(ProvisionError, match="differs from the expected"):
        provision_tag(tag, BASE, uid=H("04FFFFFFFFFFFF"))
    assert tag.writes == 0
    assert provision_tag(tag, BASE, uid=H("04112233445566")).verified


def test_anticollision_uid_is_cross_checked():
    tag = FakeNtag424()
    tag.anticollision_uid = H("04000000000001")
    with pytest.raises(ProvisionError, match="anticollision"):
        provision_tag(tag, BASE)
    assert tag.writes == 0
