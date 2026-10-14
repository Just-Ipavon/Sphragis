"""
Test suite.

The first test is the important one: a known-answer test against the official
NXP AN12196 vector. If the crypto ever drifts, this fails immediately.
The rest exercise the end-to-end verdicts through the emulator.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis import StaticKeys, Verdict, Verifier  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.sdm import compute_sdmmac, decrypt_picc_data  # noqa: E402

# --- Official NXP AN12196 known-answer vector (all-zero keys) ----------------

NXP_KEY = bytes(16)
NXP_PICC = bytes.fromhex("EF963FF7828658A599F3041510671E88")
NXP_CMAC = "94EED9EE65337086"


def test_nxp_known_answer_vector():
    picc = decrypt_picc_data(NXP_PICC, NXP_KEY)
    mac = compute_sdmmac(NXP_KEY, picc.uid, picc.read_counter)
    assert mac.hex().upper() == NXP_CMAC


# --- End-to-end verdicts via the emulator -----------------------------------

def _fresh_verifier():
    meta = os.urandom(16)
    file_ = os.urandom(16)
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=meta, file_read_key=file_)
    verifier = Verifier(StaticKeys(meta, file_), CounterStore())
    return tag, verifier


def test_authentic_tap():
    tag, verifier = _fresh_verifier()
    result = verifier.verify(tag.tap())
    assert result.verdict is Verdict.AUTHENTIC
    assert result.read_counter == 1


def test_counter_advances_across_taps():
    tag, verifier = _fresh_verifier()
    for expected in range(1, 6):
        r = verifier.verify(tag.tap())
        assert r.verdict is Verdict.AUTHENTIC
        assert r.read_counter == expected


def test_replay_is_rejected():
    tag, verifier = _fresh_verifier()
    url = tag.tap()
    assert verifier.verify(url).verdict is Verdict.AUTHENTIC
    # Replaying the exact same URL must be caught by the counter store.
    assert verifier.verify(url).verdict is Verdict.REPLAY


def test_forged_mac_is_rejected():
    tag, verifier = _fresh_verifier()
    url = tag.tap()
    # Flip the last hex digit of the cmac -> MAC no longer matches.
    tampered = url[:-1] + ("0" if url[-1] != "0" else "1")
    assert verifier.verify(tampered).verdict is Verdict.FORGED


def test_wrong_key_is_rejected():
    tag, _ = _fresh_verifier()
    url = tag.tap()
    wrong = Verifier(StaticKeys(tag.meta_read_key, os.urandom(16)), CounterStore())
    # Right meta key (UID decrypts) but wrong file key -> FORGED, not AUTHENTIC.
    assert wrong.verify(url).verdict is Verdict.FORGED


def test_malformed_input_is_error():
    _, verifier = _fresh_verifier()
    assert verifier.verify("https://example.com/t?foo=bar").verdict is Verdict.ERROR


def test_counter_persists_to_disk(tmp_path):
    meta, file_ = os.urandom(16), os.urandom(16)
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=meta, file_read_key=file_)
    store_path = tmp_path / "counters.json"

    v1 = Verifier(StaticKeys(meta, file_), CounterStore(store_path))
    for _ in range(3):
        v1.verify(tag.tap())

    # A fresh verifier loading the same store must still reject an old tap.
    old_url = EmulatedTag(uid=tag.uid, meta_read_key=meta, file_read_key=file_,
                          read_counter=0).tap()  # counter -> 1, already seen
    v2 = Verifier(StaticKeys(meta, file_), CounterStore(store_path))
    assert v2.verify(old_url).verdict is Verdict.REPLAY
