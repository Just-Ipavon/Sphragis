"""
SDMENCFileData tests.

The known-answer tests pin the crypto to the official NXP AN12196 Rev. 2.0
vectors (Table 3: decryption of SDMENCFileData; Table 5: SDMMAC over the ASCII
mirror when SDMMACInputOffset != SDMMACOffset), including the intermediate
session keys and IV. The rest exercise EncFileVerifier end to end.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from Crypto.Cipher import AES  # noqa: E402

from sphragis import (  # noqa: E402
    EncFileVerifier,
    SdmError,
    StaticKeys,
    Verdict,
    Verifier,
    compute_sdmmac,
    decrypt_file_data,
    decrypt_picc_data,
)
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.emulator import EmulatedEncTag  # noqa: E402
from sphragis.sdm import _ZERO_IV, derive_session_mac_key  # noqa: E402
from sphragis.sdmenc import (  # noqa: E402
    derive_session_enc_key,
    encrypt_file_data,
    file_data_iv,
)

NXP_KEY = bytes(16)
NXP_UID = bytes.fromhex("04958CAA5C5E80")

# AN12196 §3.4.3, Table 3
T3_URL = ("https://my424dna.com/?picc_data=FDE4AFA99B5C820A2C1BB0F1C792D0EB"
          "&enc=94592FDE69FA06E8E3B6CA686A22842B&cmac=C48B89C17A233B2C")
T3_ENC = bytes.fromhex("94592FDE69FA06E8E3B6CA686A22842B")

# AN12196 §3.4.4.2.2, Table 5
T5_URL = ("https://www.my424dna.com/?picc_data=FD91EC264309878BE6345CBE53BADF40"
          "&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6")


def _zero_key_verifier():
    return EncFileVerifier(StaticKeys(NXP_KEY, NXP_KEY), CounterStore())


# --- Official NXP AN12196 known-answer vectors -------------------------------

def test_nxp_table3_decryption_intermediates():
    picc = decrypt_picc_data(bytes.fromhex("FDE4AFA99B5C820A2C1BB0F1C792D0EB"),
                             NXP_KEY)
    assert (picc.uid, picc.read_counter) == (NXP_UID, 1)

    kses = derive_session_enc_key(NXP_KEY, picc.uid, picc.read_counter)
    assert kses.hex().upper() == "8097D73344D53F963B09E23E03B62336"
    iv = file_data_iv(kses, picc.read_counter)
    assert iv.hex().upper() == "7B3F3CFC39D3B7FF5868636E38AF7C3A"
    plain = decrypt_file_data(NXP_KEY, picc.uid, picc.read_counter, T3_ENC)
    assert plain == b"x" * 16


def test_nxp_table5_mac_over_ascii_mirror():
    uid, ctr = NXP_UID, 8
    picc = decrypt_picc_data(bytes.fromhex("FD91EC264309878BE6345CBE53BADF40"),
                             NXP_KEY)
    assert (picc.uid, picc.read_counter) == (uid, ctr)
    kses = derive_session_mac_key(NXP_KEY, uid, ctr)
    assert kses.hex().upper() == "3ED0920E5E6A0320D823D5987FEAFBB1"
    mac_input = b"CEE9A53E3E463EF1F459635736738962&cmac="
    mac = compute_sdmmac(NXP_KEY, uid, ctr, mac_input)
    assert mac.hex().upper() == "ECC1E7F6C6C73BF6"


@pytest.mark.parametrize("url, counter", [(T3_URL, 1), (T5_URL, 8)])
def test_nxp_urls_verify_end_to_end(url, counter):
    result = _zero_key_verifier().verify(url)
    assert result.verdict is Verdict.AUTHENTIC, result.detail
    assert result.uid == "04958CAA5C5E80"
    assert result.read_counter == counter
    assert result.file_data == b"x" * 16


def test_encrypt_inverts_decrypt_on_nxp_vector():
    assert encrypt_file_data(NXP_KEY, NXP_UID, 1, b"x" * 16) == T3_ENC


def test_plain_verifier_still_refuses_enc_urls():
    # The SUN-only verifier stays fail-closed; this module is opt-in.
    result = Verifier(StaticKeys(NXP_KEY, NXP_KEY), CounterStore()).verify(T3_URL)
    assert result.verdict is Verdict.ERROR


# --- End-to-end verdicts via the emulator ------------------------------------

def _fresh(file_data=b"0123456789ABCDEF"):
    meta, file_ = os.urandom(16), os.urandom(16)
    tag = EmulatedEncTag(uid=os.urandom(7), meta_read_key=meta,
                         file_read_key=file_, file_data=file_data)
    return tag, EncFileVerifier(StaticKeys(meta, file_), CounterStore())


def test_authentic_taps_return_file_data():
    data = os.urandom(48)
    tag, verifier = _fresh(data)
    for expected in range(1, 4):
        r = verifier.verify(tag.tap())
        assert r.verdict is Verdict.AUTHENTIC
        assert r.read_counter == expected
        assert r.file_data == data


def test_ciphertext_changes_every_tap():
    tag, _ = _fresh()
    enc = {tag.tap().split("enc=")[1].split("&")[0] for _ in range(3)}
    assert len(enc) == 3


def test_replay_is_rejected_without_file_data():
    tag, verifier = _fresh()
    url = tag.tap()
    assert verifier.verify(url).verdict is Verdict.AUTHENTIC
    r = verifier.verify(url)
    assert r.verdict is Verdict.REPLAY
    assert r.file_data is None


def _swap(url, old, new):
    assert old in url
    return url.replace(old, new, 1)


def _flip_enc_nibble(url):
    head, tail = url.split("enc=")
    c = tail[0]
    return f"{head}enc={'0' if c != '0' else '1'}{tail[1:]}"


def test_tampered_enc_is_forged():
    tag, verifier = _fresh()
    r = verifier.verify(_flip_enc_nibble(tag.tap()))
    assert r.verdict is Verdict.FORGED
    assert r.file_data is None


def test_tampered_cmac_is_forged():
    tag, verifier = _fresh()
    url = tag.tap()
    mac = url.rsplit("cmac=", 1)[1]
    bad = ("0" if mac[0] != "0" else "1") + mac[1:]
    assert verifier.verify(_swap(url, mac, bad)).verdict is Verdict.FORGED


def test_wrong_file_key_is_forged():
    tag, _ = _fresh()
    verifier = EncFileVerifier(StaticKeys(tag.meta_read_key, os.urandom(16)),
                               CounterStore())
    assert verifier.verify(tag.tap()).verdict is Verdict.FORGED


def test_mac_covers_raw_bytes_so_lowercased_enc_is_forged():
    tag, verifier = _fresh()
    url = tag.tap()
    enc = url.split("enc=")[1].split("&")[0]
    assert verifier.verify(_swap(url, enc, enc.lower())).verdict is Verdict.FORGED


def _handmade_url(meta, file_, data, *, names=("picc_data", "enc", "cmac"),
                  between=""):
    """Build a tap URL by hand, with optional extra text inside the MAC input."""
    uid, ctr = os.urandom(7), 5
    p, e, m = names
    enc = encrypt_file_data(file_, uid, ctr, data).hex().upper()
    picc = bytes([0xC7]) + uid + ctr.to_bytes(3, "little") + bytes(5)
    picc = AES.new(meta, AES.MODE_CBC, _ZERO_IV).encrypt(picc).hex().upper()
    mac_input = f"{enc}{between}&{m}=".encode()
    mac = compute_sdmmac(file_, uid, ctr, mac_input).hex().upper()
    return f"https://example.com/t?{p}={picc}&{e}={enc}{between}&{m}={mac}"


def test_params_between_enc_and_cmac_are_authenticated():
    meta, file_ = os.urandom(16), os.urandom(16)
    url = _handmade_url(meta, file_, b"A" * 16, between="&v=1")

    ok = EncFileVerifier(StaticKeys(meta, file_), CounterStore()).verify(url)
    assert ok.verdict is Verdict.AUTHENTIC and ok.file_data == b"A" * 16
    bad = EncFileVerifier(StaticKeys(meta, file_), CounterStore())
    assert bad.verify(_swap(url, "v=1", "v=2")).verdict is Verdict.FORGED


@pytest.mark.parametrize("mutate", [
    lambda u: u.split("&enc=")[0] + "&cmac=" + u.rsplit("cmac=", 1)[1],  # no enc
    lambda u: u.replace("&cmac=", "&enc=00&cmac=", 1),                   # dup enc
    lambda u: u.replace("&enc=", "&%65nc=", 1),                          # encoded
    lambda u: u.replace("&enc=", "&ENC=", 1),                            # re-cased
    lambda u: u.replace("&enc=", "&enc=AB", 1),                          # 17 bytes
    lambda u: u.replace("&enc=", "&enc=A", 1),                           # odd hex
    lambda u: u.replace("&enc=", "&enc= ", 1),                           # space
    lambda u: u.replace("picc_data=", "picc_data=00", 1),                # 17 bytes
    lambda u: u + "00",                                                  # long mac
])
def test_malformed_input_is_error(mutate):
    tag, verifier = _fresh()
    r = verifier.verify(mutate(tag.tap()))
    assert r.verdict is Verdict.ERROR, r.detail
    assert r.file_data is None


def test_cmac_before_enc_is_error():
    tag, verifier = _fresh()
    url = tag.tap()
    base, query = url.split("?")
    p, e, c = query.split("&")
    assert verifier.verify(f"{base}?{p}&{c}&{e}").verdict is Verdict.ERROR


def test_bare_query_string_is_accepted():
    tag, verifier = _fresh()
    assert verifier.verify(tag.tap().split("?", 1)[1]).verdict is Verdict.AUTHENTIC


def test_piccdata_without_counter_is_error():
    meta = os.urandom(16)
    picc = bytes([0x87]) + os.urandom(7) + bytes(8)        # UID only, no ctr
    picc = AES.new(meta, AES.MODE_CBC, _ZERO_IV).encrypt(picc).hex()
    url = f"https://e/t?picc_data={picc}&enc={'00' * 16}&cmac={'00' * 8}"
    v = EncFileVerifier(StaticKeys(meta, os.urandom(16)), CounterStore())
    assert v.verify(url).verdict is Verdict.ERROR


def test_custom_parameter_names():
    meta, file_ = os.urandom(16), os.urandom(16)
    url = _handmade_url(meta, file_, b"B" * 32, names=("p", "e", "m"))
    v = EncFileVerifier(StaticKeys(meta, file_), CounterStore(),
                        picc_param="p", enc_param="e", mac_param="m")
    r = v.verify(url)
    assert r.verdict is Verdict.AUTHENTIC and r.file_data == b"B" * 32


def test_parameter_names_must_be_distinct():
    with pytest.raises(ValueError):
        EncFileVerifier(StaticKeys(NXP_KEY, NXP_KEY), enc_param="CMAC")


def test_primitives_reject_bad_lengths():
    for data in (b"", b"x" * 15, b"x" * 17):
        with pytest.raises(SdmError):
            decrypt_file_data(NXP_KEY, NXP_UID, 1, data)
        with pytest.raises(SdmError):
            encrypt_file_data(NXP_KEY, NXP_UID, 1, data)
    with pytest.raises(SdmError):
        derive_session_enc_key(NXP_KEY, NXP_UID, 1 << 24)


def test_cli_verify_enc(capsys):
    from sphragis.cli import main

    keys = ["--meta-key", NXP_KEY.hex(), "--file-key", NXP_KEY.hex()]
    assert main(["verify", "--enc", *keys, T3_URL]) == 0
    out = capsys.readouterr().out
    assert "AUTHENTIC" in out and "FileData   : " + "78" * 16 in out
    # Without --enc the plain verifier keeps refusing the URL.
    assert main(["verify", *keys, T3_URL]) == 1


# --- Physical tag, all-zero keys ---------------------------------------------
# Three consecutive taps of an NTAG 424 DNA (UID 04801A82161690) provisioned
# with tools/provision.py --enc-data 0123456789ABCDEF and read through a
# Chameleon Ultra. Pins the whole path to real silicon, not only to the NXP
# application-note vectors.

FIELD_TAPS = [
    ("https://example.com/t?picc_data=159F61C951ADA159456E05ABEBCC81FC"
     "&enc=15A911F3450D9A146B7C64559FBA32E6&cmac=71F7103244547328", 2),
    ("https://example.com/t?picc_data=6157652C70F056333C42E032DC4C5257"
     "&enc=2DBF9D0E72475941F917DB5732DB9320&cmac=6D80A272901AC2F0", 3),
    ("https://example.com/t?picc_data=51AF150B5728DF460A774206B9FA1C98"
     "&enc=93A8CAAAABB76A640D53A33190813914&cmac=DC4FB26DE23603FA", 4),
    # After the unauthenticated write attempts (6982 / 6700): content intact.
    ("https://example.com/t?picc_data=49240A8B0B0DBE89BADD23A43682B59C"
     "&enc=8D3636022199EBA7040AF2EFDF40B33B&cmac=02197F8EE72E99D1", 5),
]


def test_physical_tag_taps_verify_and_replay_is_caught():
    verifier = _zero_key_verifier()
    for url, counter in FIELD_TAPS:
        r = verifier.verify(url)
        assert r.verdict is Verdict.AUTHENTIC, r.detail
        assert (r.uid, r.read_counter) == ("04801A82161690", counter)
        assert r.file_data == b"0123456789ABCDEF"
    replay = verifier.verify(FIELD_TAPS[0][0])
    assert replay.verdict is Verdict.REPLAY and replay.file_data is None


# Same tag after the authenticated rewrite (WriteData + ChangeFileSettings in
# one EV2 session) to a 32-byte plaintext, SDMENCLength 0x40.
FIELD_TAPS_32 = [
    ("https://example.com/t?picc_data=39DDB81313481DCEE9A9B66B8442A811"
     "&enc=4FD2EA682D09ABCEFEC96CA46825F55F2DC6C6E06A32DBFDDBBA81E21B1B4760"
     "&cmac=F209BE0EF0C4369E", 11),
    ("https://example.com/t?picc_data=7E2BC9996020D84C420CA6C09AD6BF33"
     "&enc=3EE1FCDC357C9B828C8FDCDC8E9BFF510CE07C557E5EC902804CF032C273F37D"
     "&cmac=4ABFA889AAFEE2FF", 12),
]


def test_physical_tag_after_authenticated_rewrite():
    verifier = _zero_key_verifier()
    for url, counter in FIELD_TAPS_32:
        r = verifier.verify(url)
        assert r.verdict is Verdict.AUTHENTIC, r.detail
        assert (r.uid, r.read_counter) == ("04801A82161690", counter)
        assert r.file_data == b"0123456789ABCDEFFEDCBA9876543210"
