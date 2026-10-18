"""
Detection over the tap ledger.

Each test reproduces an attack found in the audit and asserts the fixed
behaviour: a stale counter is never shown as authentic, replays cannot push a
clone out of view or throttle the genuine tag, a withheld URL raises at most
one alert, and concurrent copies of one tap yield exactly one GENUINE.
"""

import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis import StaticKeys  # noqa: E402
from sphragis.adversary import KeyCloner  # noqa: E402
from sphragis.analyzer import TagAnalyzer  # noqa: E402
from sphragis.counterstore import CounterStore, TapRecord  # noqa: E402
from sphragis.detection import CloneDetector  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.ratelimit import TokenBucketLimiter  # noqa: E402
from sphragis.service import VerificationService  # noqa: E402
from sphragis.sqlstore import SqliteCounterStore  # noqa: E402

STALE = {"REPLAY", "CLONE_LIKELY"}


class ListSink:
    def __init__(self):
        self.alerts = []

    def emit(self, alert):
        self.alerts.append(alert)


@pytest.fixture(params=["memory", "json", "sqlite"])
def ledger(request, tmp_path):
    if request.param == "memory":
        return CounterStore()
    if request.param == "json":
        return CounterStore(tmp_path / "counters.json")
    return SqliteCounterStore(tmp_path / "counters.db")


def _tag(counter=0):
    return EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                       file_read_key=os.urandom(16), read_counter=counter)


def _analyzer(tag, store, **detector):
    return TagAnalyzer(StaticKeys(tag.meta_read_key, tag.file_read_key),
                       detector=CloneDetector(**detector), store=store)


# --- Ledger contract ------------------------------------------------------------

def test_ledger_contract(ledger):
    assert ledger.record_tap("04aa", 5) == TapRecord(5, True, None, None)
    assert ledger.record_tap("04AA", 5) == TapRecord(5, False, 5, None)   # replay
    assert ledger.record_tap("04AA", 3) == TapRecord(3, True, 5, None)    # regression
    assert not ledger.record_tap("04AA", 3).new
    assert ledger.record_tap("04AA", 6).fresh and ledger.last_counter("04aa") == 6
    assert ledger.seen("04aa", 3) and not ledger.seen("04AA", 4)


def test_ledger_survives_a_restart(tmp_path):
    path = tmp_path / "counters.json"
    first = CounterStore(path)
    first.record_tap("04AA", 7)
    first.record_tap("04AA", 2)
    again = CounterStore(path)
    assert again.seen("04AA", 2) and again.last_counter("04AA") == 7
    assert not again.record_tap("04AA", 7).new


def test_json_store_reads_older_floor_files(tmp_path):
    path = tmp_path / "counters.json"
    path.write_text(json.dumps({"04AA": 100}))           # bare floor map
    store = CounterStore(path)
    assert store.last_counter("04AA") == 100
    old = store.record_tap("04AA", 50)
    assert old.new and old.predates_ledger                # submitted before? unknown
    assert not store.record_tap("04AA", 120).predates_ledger
    assert json.loads(path.read_text())["format"] == 2


def test_analyzer_needs_a_ledger():
    class FloorOnly:
        def last_counter(self, uid):
            return None

        def check_and_advance(self, uid, counter):
            return True

    with pytest.raises(TypeError, match="tap ledger"):
        TagAnalyzer(StaticKeys(bytes(16), bytes(16)), store=FloorOnly())


# --- A stale counter is never authentic ------------------------------------------

def test_stale_counter_with_a_gap_is_not_suspicious(ledger):
    # Audit reproduction: a weak signal on a stale counter used to yield
    # SUSPICIOUS, rendered publicly as "Authentic tag".
    tag = _tag()
    analyzer = _analyzer(tag, ledger, gap_threshold=10)
    captured = tag.tap()                                  # counter 1, withheld
    assert analyzer.analyze(tag.tap(), timestamp=999).classification == "GENUINE"
    tag.read_counter = 1500
    assert analyzer.analyze(tag.tap(), timestamp=1000).classification == "SUSPICIOUS"
    r = analyzer.analyze(captured, timestamp=1001)
    assert r.classification in STALE and r.classification != "SUSPICIOUS"


def test_every_stale_counter_is_replay_or_clone(ledger):
    tag = _tag()
    analyzer = _analyzer(tag, ledger)
    urls = [tag.tap() for _ in range(30)]
    order = urls[::3] + urls[1::3] + urls[2::3] + urls     # out of order, then again
    floor, forked = 0, False
    for i, url in enumerate(order):
        counter = urls.index(url) + 1
        r = analyzer.analyze(url, timestamp=1000 + i)
        if counter > floor:
            # Once the stream has forked, fresh taps carry the doubt (weakly).
            assert r.classification == ("SUSPICIOUS" if forked else "GENUINE")
            floor = counter
        else:
            assert r.classification in STALE, (counter, floor, r)
            forked = True


# --- Replays and anonymous taps cannot hide a clone ------------------------------

def test_replays_do_not_push_the_clone_out_of_view(ledger):
    tag = _tag(counter=9)
    analyzer = _analyzer(tag, ledger)
    first = tag.tap()
    for i in range(5):
        analyzer.analyze(tag.tap() if i else first, timestamp=1000 + i, reader_id="gate-A")
    for i in range(60):                                   # more than the history window
        assert analyzer.analyze(first, timestamp=2000 + i).classification == "REPLAY"
    clone = KeyCloner.clone(tag, start_counter=2)
    r = analyzer.analyze(clone.tap(), timestamp=3000, reader_id="gate-B")
    assert r.classification == "CLONE_LIKELY"
    assert [s.name for s in r.signals] == ["counter_regression"]


def test_stale_taps_stay_out_of_the_history(ledger):
    tag = _tag()
    analyzer = _analyzer(tag, ledger)
    url = tag.tap()
    analyzer.analyze(url, timestamp=1000)
    for i in range(10):
        analyzer.analyze(url, timestamp=1001 + i)
    assert [o.counter for o in analyzer.detector.history(tag.uid.hex())] == [1]


def test_an_anonymous_tap_in_between_hides_no_velocity(ledger):
    tag = _tag()
    analyzer = _analyzer(tag, ledger, min_travel_seconds=60)
    analyzer.analyze(tag.tap(), timestamp=1000, reader_id="gate-A")
    analyzer.analyze(tag.tap(), timestamp=1002)           # anonymous public tap
    clone = KeyCloner.clone(tag, start_counter=tag.read_counter)
    r = analyzer.analyze(clone.tap(), timestamp=1004, reader_id="gate-B")
    assert r.classification == "CLONE_LIKELY"
    assert any(s.name == "impossible_velocity" for s in r.signals)


def test_velocity_window_still_ends(ledger):
    tag = _tag()
    analyzer = _analyzer(tag, ledger, min_travel_seconds=60)
    analyzer.analyze(tag.tap(), timestamp=1000, reader_id="gate-A")
    assert analyzer.analyze(tag.tap(), timestamp=1061,
                            reader_id="gate-B").classification == "GENUINE"


# --- Replays cannot throttle the genuine tag -------------------------------------

def test_replays_do_not_consume_the_tag_budget(ledger):
    tag = _tag()
    limiter = TokenBucketLimiter(rate=0.001, burst=3, clock=lambda: 0.0)
    service = VerificationService(_analyzer(tag, ledger), uid_limiter=limiter,
                                  clock=lambda: 1000.0)
    captured = tag.tap()
    assert service.verify(captured).result.classification == "GENUINE"
    for _ in range(50):
        assert service.verify(captured).result.classification == "REPLAY"
    # The owner's next taps still get through: only fresh counters are charged.
    assert [service.verify(tag.tap()).result.classification for _ in range(2)] \
        == ["GENUINE", "GENUINE"]
    assert service.verify(tag.tap()).result.classification == "THROTTLED"


# --- A withheld URL raises at most one alert --------------------------------------

def test_withheld_urls_alert_once_each(ledger):
    tag = _tag()
    sink = ListSink()
    service = VerificationService(_analyzer(tag, ledger), alert_sinks=[sink],
                                  clock=lambda: 1000.0)
    withheld = [tag.tap() for _ in range(51)]             # read, never submitted
    assert service.verify(tag.tap()).result.classification == "GENUINE"
    for _ in range(4):                                    # the audit's four rounds
        for url in withheld:
            service.verify(url)
    assert len(sink.alerts) == 51                         # was 200
    assert {service.verify(u).result.classification for u in withheld} == {"REPLAY"}


# --- Concurrent copies of one tap ------------------------------------------------

def test_concurrent_copies_of_one_tap_yield_one_genuine(tmp_path):
    tag = _tag()
    analyzer = _analyzer(tag, SqliteCounterStore(tmp_path / "c.db"))
    url, results, barrier = tag.tap(), [], threading.Barrier(8)

    def submit():
        barrier.wait()
        results.append(analyzer.analyze(url, timestamp=1000).classification)

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["GENUINE"] + ["REPLAY"] * 7


def test_a_store_upgraded_from_a_bare_floor_raises_no_false_clone(tmp_path):
    store = SqliteCounterStore(tmp_path / "c.db")
    tag = _tag()
    old = [tag.tap() for _ in range(100)]
    store.check_and_advance(tag.uid.hex(), 100)           # floor set before the ledger
    analyzer = _analyzer(tag, store)
    r = analyzer.analyze(old[49])                         # counter 50, maybe submitted
    assert r.classification == "REPLAY" and r.signals[0].name == "stale_counter"
    tag.read_counter = 120
    assert analyzer.analyze(tag.tap()).classification == "GENUINE"
    clone = KeyCloner.clone(tag, start_counter=109)       # 110: after the ledger began
    assert analyzer.analyze(clone.tap()).classification == "CLONE_LIKELY"


# --- A forked counter stream taints the UID ----------------------------------------

def test_fresh_taps_after_a_regression_carry_prior_divergence(ledger):
    # Pre-play: the clone ran ahead (15), the genuine tag then shows 11. The
    # clone's next tap (16) is monotonic but must not read as GENUINE.
    tag = _tag(counter=9)
    analyzer = _analyzer(tag, ledger)
    assert analyzer.analyze(tag.tap(), timestamp=1000).classification == "GENUINE"
    clone = KeyCloner.clone(tag, start_counter=14)
    assert analyzer.analyze(clone.tap(), timestamp=2000).classification == "GENUINE"
    r = analyzer.analyze(tag.tap(), timestamp=3000)                  # 11 < 15
    assert r.classification == "CLONE_LIKELY"
    r = analyzer.analyze(clone.tap(), timestamp=4000)                # 16
    assert r.classification == "SUSPICIOUS"
    assert [s.name for s in r.signals] == ["prior_divergence"]


def test_prior_divergence_decays_with_the_history_window(ledger):
    tag = _tag(counter=10)
    analyzer = _analyzer(tag, ledger, history_limit=5)
    analyzer.analyze(tag.tap(), timestamp=1000)
    analyzer.analyze(KeyCloner.clone(tag, start_counter=1).tap(), timestamp=1100)
    levels = [analyzer.analyze(tag.tap(), timestamp=1200 + 100 * i).classification
              for i in range(6)]
    # The fork shows while the counter it regressed from is still in the window.
    assert levels == ["SUSPICIOUS"] * 4 + ["GENUINE"] * 2


def test_replays_do_not_taint_the_uid(ledger):
    tag = _tag()
    analyzer = _analyzer(tag, ledger)
    first = tag.tap()
    analyzer.analyze(first, timestamp=1000)
    analyzer.analyze(tag.tap(), timestamp=1100)
    assert analyzer.analyze(first, timestamp=1200).classification == "REPLAY"
    assert analyzer.analyze(tag.tap(), timestamp=1300).classification == "GENUINE"


# --- Out-of-order delivery of two quick taps ------------------------------------

def test_two_quick_taps_delivered_out_of_order_are_not_a_clone(ledger):
    tag = _tag()
    analyzer = _analyzer(tag, ledger)
    analyzer.analyze(tag.tap(), timestamp=1000, reader_id="gate-A")
    first, second = tag.tap(), tag.tap()
    assert analyzer.analyze(second, timestamp=1100.0,
                            reader_id="gate-A").classification == "GENUINE"
    r = analyzer.analyze(first, timestamp=1100.3, reader_id="gate-A")
    assert r.classification == "SUSPICIOUS"
    assert [s.name for s in r.signals] == ["counter_reordered"]
    # Not a fork: the next tap is clean, and the late URL is now a replay.
    assert analyzer.analyze(tag.tap(), timestamp=1200,
                            reader_id="gate-A").classification == "GENUINE"
    assert analyzer.analyze(first, timestamp=1201).classification == "REPLAY"


@pytest.mark.parametrize("delay, reader, behind", [
    (5.0, "gate-A", 1),      # too late
    (0.3, "gate-B", 1),      # another reader
    (0.3, None, 1),          # anonymous: nothing ties it to the floor tap
    (0.3, "gate-A", 3),      # too far below the floor
])
def test_reorder_tolerance_is_narrow(ledger, delay, reader, behind):
    tag = _tag()
    analyzer = _analyzer(tag, ledger)
    urls = [tag.tap() for _ in range(4)]
    analyzer.analyze(urls[3], timestamp=1000.0, reader_id="gate-A")   # floor 4
    r = analyzer.analyze(urls[3 - behind], timestamp=1000.0 + delay, reader_id=reader)
    assert r.classification == "CLONE_LIKELY"


# --- Counter advancing faster than a tag can be read ------------------------------

def test_counter_racing_ahead_of_any_reader_is_flagged(ledger):
    tag = _tag()
    analyzer = _analyzer(tag, ledger)
    analyzer.analyze(tag.tap(), timestamp=1000)
    tag.read_counter += 500                               # +500 in 10 s
    r = analyzer.analyze(tag.tap(), timestamp=1010)
    assert r.classification == "SUSPICIOUS"
    assert [s.name for s in r.signals] == ["counter_rate"]


def test_offline_taps_over_time_are_not_a_rate_anomaly(ledger):
    tag = _tag()
    analyzer = _analyzer(tag, ledger)
    analyzer.analyze(tag.tap(), timestamp=1000)
    tag.read_counter += 500                               # +500 over an hour
    assert analyzer.analyze(tag.tap(), timestamp=4600).classification == "GENUINE"
