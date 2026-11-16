"""A history write lost after the ledger write is completed on the next tap (#86)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from test_backends import needs_pg, pg_dsn  # noqa: E402, F401

from sphragis.analyzer import TagAnalyzer  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.detection import CloneDetector  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.observations import MemoryObservationStore, SqliteObservationStore  # noqa: E402
from sphragis.service import VerificationService  # noqa: E402
from sphragis.sqlstore import SqliteCounterStore  # noqa: E402
from sphragis.verifier import StaticKeys  # noqa: E402


class FlakyHistory:
    """An observation store whose next `observe` fails (store down, lock timeout)."""

    def __init__(self, inner):
        self.inner, self.fail_next = inner, False

    def history(self, uid):
        return self.inner.history(uid)

    def observe(self, uid, obs, limit):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("database is locked")
        return self.inner.observe(uid, obs, limit)


@pytest.fixture(params=["memory", "json", "sqlite", pytest.param("pg", marks=needs_pg)])
def stores(request, tmp_path):
    """(make_ledger, make_history): factories, so a 'restart' reopens the same data."""
    if request.param == "memory":
        ledger = CounterStore()
        history = MemoryObservationStore()
        return (lambda: ledger), (lambda: history)
    if request.param == "json":
        path = tmp_path / "counters.json"
        history = MemoryObservationStore()
        return (lambda: CounterStore(path)), (lambda: history)
    if request.param == "sqlite":
        db = tmp_path / "s.db"
        return (lambda: SqliteCounterStore(db)), (lambda: SqliteObservationStore(db))
    from sphragis.pgstore import PostgresCounterStore, PostgresObservationStore
    dsn = request.getfixturevalue("pg_dsn")
    opened = []

    def track(store):
        opened.append(store)
        return store

    request.addfinalizer(lambda: [store.close() for store in opened])
    return ((lambda: track(PostgresCounterStore(dsn))),
            (lambda: track(PostgresObservationStore(dsn))))


def _rig(stores, tag):
    make_ledger, make_history = stores
    history = FlakyHistory(make_history())
    analyzer = TagAnalyzer(StaticKeys(tag.meta_read_key, tag.file_read_key),
                           detector=CloneDetector(store=history), store=make_ledger())
    return analyzer, history


def _tag(counter=0):
    return EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                       file_read_key=os.urandom(16), read_counter=counter)


def test_lost_fresh_observation_is_completed_on_the_next_tap(stores):
    tag = _tag()
    analyzer, history = _rig(stores, tag)
    assert analyzer.analyze(tag.tap(), timestamp=1000.0).classification == "GENUINE"
    lost = tag.tap()                                         # counter 2
    history.fail_next = True
    with pytest.raises(RuntimeError):
        analyzer.analyze(lost, timestamp=1100.0)
    uid = tag.uid.hex().upper()
    assert [o.counter for o in history.history(uid)] == [1]   # the gap #86 is about
    assert analyzer.analyze(lost, timestamp=1150.0).classification == "REPLAY"
    assert [o.counter for o in history.history(uid)] == [1, 2]   # completed by the retry
    analyzer.analyze(tag.tap(), timestamp=1200.0)
    counters = [o.counter for o in history.history(uid)]
    assert counters == [1, 2, 3]                               # once, in order
    assert history.history(uid)[1].timestamp == 1100.0         # with its own time


def test_lost_regression_still_raises_its_alert(stores):
    genuine = _tag(counter=9)
    analyzer, history = _rig(stores, genuine)
    sink = []

    class Sink:
        def emit(self, alert):
            sink.append(alert)

    service = VerificationService(analyzer, alert_sinks=[Sink()])
    service.verify(genuine.tap())                              # floor 10
    clone = EmulatedTag(uid=genuine.uid, meta_read_key=genuine.meta_read_key,
                        file_read_key=genuine.file_read_key, read_counter=4)
    history.fail_next = True
    with pytest.raises(RuntimeError):
        service.verify(clone.tap())                            # counter 5: lost
    assert sink == []
    outcome = service.verify(genuine.tap())                    # counter 11
    assert outcome.result.classification == "CLONE_LIKELY"
    assert "counter_regression" in [s.name for s in outcome.result.signals]
    assert len(sink) == 1 and "counter_regression" in sink[0].signals
    uid = genuine.uid.hex().upper()
    regressions = [o for o in history.history(uid) if o.counter == 5]
    assert len(regressions) == 1 and regressions[0].regression is True
    # Settled: the next tap is clean again.
    assert service.verify(genuine.tap()).result.classification != "CLONE_LIKELY"


def test_pending_note_survives_a_restart(stores):
    """A crash right after the ledger write: the note is on disk, the next
    process completes it."""
    make_ledger, make_history = stores
    tag = _tag()
    analyzer, _ = _rig(stores, tag)
    analyzer.analyze(tag.tap(), timestamp=1000.0)
    uid = tag.uid.hex().upper()
    ledger = make_ledger()
    ledger.record_tap(uid, 7, {"timestamp": 1050.0, "reader_id": "gate"})   # then "crash"
    restarted, history = _rig(stores, tag)
    tag.read_counter = 7
    restarted.analyze(tag.tap(), timestamp=1100.0)               # counter 8
    observed = {o.counter: o for o in history.history(uid)}
    assert set(observed) == {1, 7, 8} and observed[7].reader_id == "gate"


def test_written_but_unsettled_is_not_written_twice(stores):
    """A crash between the history write and the settle: no duplicate row."""
    make_ledger, make_history = stores
    tag = _tag()
    analyzer, history = _rig(stores, tag)
    analyzer.analyze(tag.tap(), timestamp=1000.0)
    uid = tag.uid.hex().upper()
    make_ledger().record_tap(uid, 2, {"timestamp": 1010.0})
    history.observe(uid, history.history(uid)[0].__class__(2, 1010.0), 100)
    analyzer.analyze(tag.tap(), timestamp=1100.0)                # counter 2 is a replay
    analyzer.analyze(tag.tap(), timestamp=1200.0)                # counter 3
    assert [o.counter for o in history.history(uid)] == [1, 2, 3]
