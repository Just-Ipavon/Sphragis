"""
Adversarial test harness.

Each test mounts a concrete attack from `sphragis.adversary` and asserts the
system catches it. These are the claims the project stands behind — see
THREAT_MODEL.md for the reasoning.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis import StaticKeys  # noqa: E402
from sphragis.adversary import KeyCloner, KeylessAttacker  # noqa: E402
from sphragis.analyzer import TagAnalyzer  # noqa: E402
from sphragis.detection import CloneDetector  # noqa: E402
from sphragis.diversify import DiversifiedKeys  # noqa: E402
from sphragis.emulator import EmulatedTag, tag_from_provider  # noqa: E402
from sphragis.verifier import _consttime_eq  # noqa: E402


def _rig():
    meta, file_ = os.urandom(16), os.urandom(16)
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=meta, file_read_key=file_)
    analyzer = TagAnalyzer(StaticKeys(meta, file_))
    return tag, analyzer


# --- Key-less attacker -------------------------------------------------------

def test_genuine_sequence_is_clean():
    tag, analyzer = _rig()
    for i in range(1, 6):
        r = analyzer.analyze(tag.tap(), timestamp=1000 + i)
        assert r.classification == "GENUINE"
        assert r.risk_score == 0


def test_replay_attack_is_caught():
    tag, analyzer = _rig()
    url = tag.tap()
    assert analyzer.analyze(url, timestamp=1000).classification == "GENUINE"
    replayed = KeylessAttacker.replay(url)
    r = analyzer.analyze(replayed, timestamp=1001)
    assert r.classification == "REPLAY"
    assert any(s.name == "exact_replay" for s in r.signals)


def test_forged_mac_is_caught():
    tag, analyzer = _rig()
    forged = KeylessAttacker.forge_mac(tag.tap())
    r = analyzer.analyze(forged)
    assert r.classification == "FORGED"
    assert r.authentic_mac is False


def test_truncated_mac_is_rejected():
    tag, analyzer = _rig()
    bad = KeylessAttacker.truncate_mac(tag.tap())
    # A MAC of the wrong length is malformed input, refused before any crypto.
    assert analyzer.analyze(bad).classification == "ERROR"


def test_counter_rollback_is_caught():
    tag, analyzer = _rig()
    old = tag.tap()                       # counter 1
    for _ in range(4):                    # advance to counter 5
        analyzer.analyze(tag.tap(), timestamp=time.time())
    # Attacker resends the old, lower-counter tap.
    r = analyzer.analyze(KeylessAttacker.rollback(old))
    assert r.classification in ("REPLAY", "CLONE_LIKELY")
    assert r.authentic_mac is True        # MAC is valid; only the counter betrays it


# --- Key-extracting cloner (worst case) --------------------------------------

def test_key_clone_caught_by_counter_divergence():
    # The original tag is already in use (counter at 9) when monitoring starts,
    # so the backend observes counters 10, 11, 12 — not the low range.
    meta, file_ = os.urandom(16), os.urandom(16)
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=meta,
                      file_read_key=file_, read_counter=9)
    analyzer = TagAnalyzer(StaticKeys(meta, file_))
    for i in range(3):
        analyzer.analyze(tag.tap(), timestamp=1000 + i, reader_id="gate-A")
    # A perfect key-clone runs its own, lower counter stream. The value 3 was
    # never observed yet is below the max (12): unambiguous divergence, not a
    # replay of any captured URL.
    clone = KeyCloner.clone(tag, start_counter=2)
    r = analyzer.analyze(clone.tap(), timestamp=2000, reader_id="gate-B")
    assert r.classification == "CLONE_LIKELY"
    assert any(s.name == "counter_regression" for s in r.signals)


def test_key_clone_caught_by_impossible_velocity():
    tag, analyzer = _rig()
    # Genuine tap at gate-A, counter 5.
    for i in range(5):
        analyzer.analyze(tag.tap(), timestamp=1000 + i, reader_id="gate-A")
    # Clone that kept the counter ahead (no regression) but surfaces far away
    # just seconds later -> no single tag could travel there.
    clone = KeyCloner.clone(tag, start_counter=5)
    r = analyzer.analyze(clone.tap(), timestamp=1006, reader_id="gate-B")
    assert r.classification == "CLONE_LIKELY"
    assert any(s.name == "impossible_velocity" for s in r.signals)


def test_diversified_keys_end_to_end():
    master, meta = os.urandom(16), os.urandom(16)
    prov = DiversifiedKeys(master, meta, context=b"DEMO")
    uid = os.urandom(7)
    tag = tag_from_provider(prov, uid)
    analyzer = TagAnalyzer(prov)
    assert analyzer.analyze(tag.tap()).classification == "GENUINE"


# --- Constant-time comparison (A-1 fix) --------------------------------------

def test_mac_comparison_correctness():
    """_consttime_eq (hmac.compare_digest) must be correct for every case."""
    ref = os.urandom(8)
    assert _consttime_eq(ref, ref) is True
    # a single flipped bit at any position must be rejected
    for i in range(len(ref)):
        wrong = bytearray(ref)
        wrong[i] ^= 0x01
        assert _consttime_eq(ref, bytes(wrong)) is False
    # length mismatch must not raise and must be False
    assert _consttime_eq(ref, ref[:-1]) is False


def test_mac_comparison_uses_non_short_circuiting_primitive():
    """
    Guard against a regression to the old short-circuiting comparator. We assert
    the implementation delegates to hmac.compare_digest, whose constant-time
    property is maintained by CPython — a far more reliable check than a flaky
    wall-clock timing measurement on 8 bytes.
    """
    import inspect
    from sphragis import verifier
    src = inspect.getsource(verifier._consttime_eq)
    assert "compare_digest" in src
    assert "any(" not in src


# --- Concurrency: atomic check-and-advance (M-1 fix) -------------------------

def test_concurrent_replays_admit_only_one():
    import threading
    from sphragis import Verifier
    from sphragis.counterstore import CounterStore

    meta, file_ = os.urandom(16), os.urandom(16)
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=meta, file_read_key=file_)
    url = tag.tap()
    verifier = Verifier(StaticKeys(meta, file_), CounterStore())

    results = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        results.append(verifier.verify(url).verdict.value)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("AUTHENTIC") == 1
    assert results.count("REPLAY") == 15


# --- Persistence across restart (M-2 fix) ------------------------------------

def test_replay_caught_after_detector_history_reset(tmp_path):
    from sphragis.counterstore import CounterStore

    meta, file_ = os.urandom(16), os.urandom(16)
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=meta, file_read_key=file_)
    store_path = tmp_path / "floor.json"

    a1 = TagAnalyzer(StaticKeys(meta, file_), store=CounterStore(store_path))
    url = tag.tap()
    assert a1.analyze(url).classification == "GENUINE"

    # Simulate a process restart: brand-new analyzer (empty detector history)
    # but the same persistent store. The replayed URL must still be caught.
    a2 = TagAnalyzer(StaticKeys(meta, file_), store=CounterStore(store_path))
    assert a2.analyze(url).classification == "REPLAY"


# --- Input validation / fail-closed (M-3, B-4 fixes) -------------------------

def test_encrypted_file_data_is_refused():
    _, analyzer = _rig()
    url = ("https://example.com/t?picc_data=" + "00" * 16
           + "&enc=" + "11" * 16 + "&cmac=" + "22" * 8)
    assert analyzer.analyze(url).classification == "ERROR"


def test_duplicated_parameter_is_rejected():
    _, analyzer = _rig()
    url = ("https://example.com/t?picc_data=" + "00" * 16
           + "&picc_data=" + "11" * 16 + "&cmac=" + "22" * 8)
    assert analyzer.analyze(url).classification == "ERROR"


def test_piccdata_parser_never_crashes_on_garbage():
    """Fuzz the PICCData parser: random blocks must yield SdmError or parse,
    never an unhandled exception."""
    from sphragis.sdm import SdmError, decrypt_picc_data
    key = os.urandom(16)
    for _ in range(5000):
        block = os.urandom(16)
        try:
            decrypt_picc_data(block, key)
        except SdmError:
            pass  # expected rejection
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"unhandled exception on garbage: {exc!r}")
