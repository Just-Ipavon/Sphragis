"""Tag lifecycle (#73): revocation list, counter-rollover policy, alert throttling."""

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from test_backends import needs_pg, pg_dsn  # noqa: E402, F401

from sphragis.alerts import Alert, AlertThrottle, BackgroundAlertSink  # noqa: E402
from sphragis.analyzer import CounterPolicy, TagAnalyzer  # noqa: E402
from sphragis.cli import main as cli  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.revocation import (  # noqa: E402
    MemoryRevocationList,
    RevocationStatus,
)
from sphragis.service import VerificationService  # noqa: E402
from sphragis.sqlstore import SqliteRevocationList  # noqa: E402
from sphragis.verifier import StaticKeys  # noqa: E402

LIMIT = 0xFFFFFF


class ListSink:
    def __init__(self):
        self.alerts = []

    def emit(self, alert):
        self.alerts.append(alert)


def _tag(counter=0):
    return EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                       file_read_key=os.urandom(16), read_counter=counter)


def _analyzer(tag, **kw):
    return TagAnalyzer(StaticKeys(tag.meta_read_key, tag.file_read_key),
                       store=kw.pop("store", CounterStore()), **kw)


# --- revocation list --------------------------------------------------------------

@pytest.fixture(params=["memory", "sqlite", pytest.param("pg", marks=needs_pg)])
def revocations(request, tmp_path):
    if request.param == "memory":
        store = MemoryRevocationList()
    elif request.param == "sqlite":
        store = SqliteRevocationList(tmp_path / "sphragis.db")
    else:
        from sphragis.pgstore import PostgresRevocationList
        store = PostgresRevocationList(request.getfixturevalue("pg_dsn"))
    yield store
    store.close()


def test_revocation_list_round_trip(revocations):
    uid = "04de5f1eacc040"
    assert revocations.get(uid) is None
    entry = revocations.revoke(uid, RevocationStatus.RETIRED, "returned by customer")
    assert entry.identity == uid.upper() and entry.status is RevocationStatus.RETIRED
    got = revocations.get(uid.upper())
    assert (got.status, got.reason) == (RevocationStatus.RETIRED, "returned by customer")
    revocations.revoke(uid, "revoked", "stolen")             # status can change
    assert revocations.get(uid).status is RevocationStatus.REVOKED
    assert [e.identity for e in revocations.entries()] == [uid.upper()]
    assert revocations.reinstate(uid) is True
    assert revocations.reinstate(uid) is False
    assert revocations.get(uid) is None


@pytest.mark.parametrize("identity,reason", [("", ""), ("04AA", "two\nlines"),
                                             ("04AA", "x" * 201)])
def test_revocation_entries_are_validated(identity, reason):
    with pytest.raises(ValueError):
        MemoryRevocationList().revoke(identity, "revoked", reason)


def test_revoked_tag_answers_revoked_and_touches_no_state(revocations):
    tag = _tag()
    store = CounterStore()
    analyzer = _analyzer(tag, store=store, revocations=revocations)
    assert analyzer.analyze(tag.tap()).classification == "GENUINE"
    uid = tag.uid.hex().upper()
    revocations.revoke(uid, RevocationStatus.REVOKED, "reported stolen")
    r = analyzer.analyze(tag.tap())
    assert r.classification == "REVOKED" and r.authentic_mac
    assert [s.name for s in r.signals] == ["revoked"] and "reported stolen" in r.detail
    assert store.last_counter(uid) == 1                       # ledger untouched
    revocations.revoke(uid, RevocationStatus.RETIRED)
    assert analyzer.analyze(tag.tap()).signals[0].name == "retired"
    revocations.reinstate(uid)
    assert analyzer.analyze(tag.tap()).classification == "GENUINE"


def test_forged_tap_of_a_revoked_uid_stays_forged():
    tag = _tag()
    revocations = MemoryRevocationList()
    revocations.revoke(tag.uid.hex(), "revoked")
    forger = EmulatedTag(uid=tag.uid, meta_read_key=tag.meta_read_key,
                         file_read_key=os.urandom(16))
    r = _analyzer(tag, revocations=revocations).analyze(forger.tap())
    assert r.classification == "FORGED" and r.uid is None


def test_revoked_tap_alerts_by_default():
    tag = _tag()
    revocations = MemoryRevocationList()
    revocations.revoke(tag.uid.hex(), "revoked", "lost")
    sink = ListSink()
    service = VerificationService(_analyzer(tag, revocations=revocations),
                                  alert_sinks=[sink])
    assert service.verify(tag.tap()).alerted
    assert sink.alerts[0].classification == "REVOKED"


# --- counter rollover -------------------------------------------------------------

def test_counter_policy_is_validated():
    with pytest.raises(ValueError):
        CounterPolicy(warn_at=0)
    with pytest.raises(ValueError):
        CounterPolicy(refuse_at=LIMIT + 1)
    with pytest.raises(ValueError):
        CounterPolicy(warn_at=100, refuse_at=100)


def test_counter_near_the_limit_raises_a_single_alert():
    policy = CounterPolicy(warn_at=LIMIT - 10)
    tag = _tag(counter=LIMIT - 13)
    sink = ListSink()
    service = VerificationService(_analyzer(tag, counter_policy=policy),
                                  alert_sinks=[sink])
    outcomes = [service.verify(tag.tap()) for _ in range(6)]   # counters -12 .. -7
    near = [o for o in outcomes if "counter_near_limit" in
            [s.name for s in o.result.signals]]
    assert len(near) == 1 and near[0].result.read_counter == LIMIT - 10
    assert all(o.result.classification == "GENUINE" for o in outcomes)
    assert len(sink.alerts) == 1 and "counter_near_limit" in sink.alerts[0].signals


def test_first_tap_already_past_the_threshold_warns():
    tag = _tag(counter=LIMIT - 5)
    r = _analyzer(tag, counter_policy=CounterPolicy(warn_at=LIMIT - 10)).analyze(tag.tap())
    assert "counter_near_limit" in [s.name for s in r.signals]


def test_refuse_at_keeps_the_floor_below_the_limit():
    policy = CounterPolicy(warn_at=None, refuse_at=1000)
    genuine = _tag(counter=10)
    store = CounterStore()
    analyzer = _analyzer(genuine, store=store, counter_policy=policy)
    assert analyzer.analyze(genuine.tap()).classification == "GENUINE"
    # A clone holding the keys jumps to the limit: refused, the floor stays.
    clone = EmulatedTag(uid=genuine.uid, meta_read_key=genuine.meta_read_key,
                        file_read_key=genuine.file_read_key, read_counter=LIMIT - 1)
    r = analyzer.analyze(clone.tap())
    assert r.classification == "COUNTER_LIMIT" and r.authentic_mac
    assert store.last_counter(genuine.uid.hex().upper()) == 11
    assert analyzer.analyze(genuine.tap()).classification == "GENUINE"


def test_warning_is_on_by_default():
    tag = _tag(counter=LIMIT - 0xFFFF - 1)
    r = _analyzer(tag).analyze(tag.tap())
    assert "counter_near_limit" in [s.name for s in r.signals]


# --- alert throttling -------------------------------------------------------------

def _alert(uid, classification="REPLAY", signals=("exact_replay",), n=0):
    return Alert(f"e{uid}{n}", 0.0, classification, 65, uid, n, None, signals, "")


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_throttle_deduplicates_and_rate_limits_per_uid():
    clock = Clock()
    throttle = AlertThrottle(per_uid_burst=3, per_uid_window=300, dedup_seconds=60,
                             clock=clock)
    assert throttle.allow(_alert("A"))
    assert not throttle.allow(_alert("A", n=1))               # same fingerprint
    assert throttle.allow(_alert("A", "CLONE_LIKELY", ("counter_regression",)))
    assert throttle.allow(_alert("A", "REVOKED", ("revoked",)))
    assert not throttle.allow(_alert("A", "SUSPICIOUS", ("gap",)))   # budget spent
    assert throttle.suppressed == {"duplicate": 1, "rate": 1}
    clock.now = 100.0                                          # one token back
    assert throttle.allow(_alert("A", n=2))


def test_flood_from_one_uid_does_not_evict_alerts_for_others():
    tag_a, tag_b = _tag(), _tag()
    sink = ListSink()
    # Two tags under the same (static) keys.
    tag_b.meta_read_key, tag_b.file_read_key = tag_a.meta_read_key, tag_a.file_read_key
    analyzer = _analyzer(tag_a)
    background = BackgroundAlertSink(sink, maxsize=10)
    service = VerificationService(
        analyzer, alert_sinks=[background], alert_on={"REPLAY", "CLONE_LIKELY"},
        alert_throttle=AlertThrottle(per_uid_burst=3, dedup_seconds=0))
    urls = [tag_a.tap() for _ in range(50)]
    for url in urls:
        service.verify(url)
    for url in urls * 3:                         # the holder replays them all
        service.verify(url)
    assert service.verify(tag_b.tap()).result.classification == "GENUINE"
    b_url = tag_b.tap()
    service.verify(b_url)
    assert service.verify(b_url).alerted          # tag B's replay still gets through
    assert background.flush(5)
    background.close()
    by_uid = {}
    for alert in sink.alerts:
        by_uid[alert.uid_ref] = by_uid.get(alert.uid_ref, 0) + 1
    assert sorted(by_uid.values()) == [1, 3]
    stats = service.alert_stats()
    assert stats["suppressed"]["rate"] == 147 and stats["dropped"] == 0


def test_background_sink_counts_dropped_alerts():
    import threading
    gate = threading.Event()

    class Slow:
        def emit(self, alert):
            gate.wait(5)

    background = BackgroundAlertSink(Slow(), maxsize=1)
    background.emit(_alert("A"))
    import time
    deadline = time.monotonic() + 5
    while background.pending and time.monotonic() < deadline:   # worker took it
        time.sleep(0.01)
    background.emit(_alert("A", n=1))                           # fills the queue
    with pytest.raises(RuntimeError):
        background.emit(_alert("A", n=2))
    assert background.dropped == 1
    gate.set()
    background.close()


# --- API and CLI ------------------------------------------------------------------

def test_api_answers_revoked_and_serves_alert_stats(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sphragis.api import create_app

    tag = _tag()
    revocations = MemoryRevocationList()
    revocations.revoke(tag.uid.hex(), "revoked")
    service = VerificationService(_analyzer(tag, revocations=revocations),
                                  alert_throttle=AlertThrottle())
    token = "reader-token"
    app = create_app(service, reader_tokens={
        hashlib.sha256(token.encode()).hexdigest(): "gate"})
    client = TestClient(app)
    body = client.post("/v1/verify", json={"url": tag.tap()}).json()
    assert body["verdict"] == "REVOKED" and body["risk_score"] == 100
    assert client.get("/v1/alert-stats").status_code == 401
    stats = client.get("/v1/alert-stats",
                       headers={"Authorization": f"Bearer {token}"}).json()
    assert stats == {"suppressed": {"duplicate": 0, "rate": 0}, "dropped": 0}


@pytest.mark.parametrize("env", [
    {"SPHRAGIS_COUNTER_WARN_AT": "0"},
    {"SPHRAGIS_COUNTER_REFUSE_AT": "nope"},
    {"SPHRAGIS_COUNTER_WARN_AT": "2000", "SPHRAGIS_COUNTER_REFUSE_AT": "1000"},
    {"SPHRAGIS_ALERT_UID_BURST": "0"},
    {"SPHRAGIS_ALERT_DEDUP_SECONDS": "-1"},
])
def test_lifecycle_settings_are_validated(env):
    from sphragis.api.settings import ApiSettings
    with pytest.raises(ValueError):
        ApiSettings.from_env(env)


def test_lifecycle_settings_defaults_and_off():
    from sphragis.api.settings import ApiSettings
    s = ApiSettings.from_env({})
    assert s.alert_on == {"CLONE_LIKELY", "REVOKED"}
    assert (s.counter_warn_at, s.counter_refuse_at) == (LIMIT - 0xFFFF, None)
    s = ApiSettings.from_env({"SPHRAGIS_COUNTER_WARN_AT": "off",
                              "SPHRAGIS_COUNTER_REFUSE_AT": "0xFFF000"})
    assert (s.counter_warn_at, s.counter_refuse_at) == (None, 0xFFF000)


def test_cli_revoke_list_reinstate(tmp_path, capsys):
    db = str(tmp_path / "sphragis.db")
    SqliteRevocationList(db).close()
    assert cli(["revoke", "04de5f1eacc040", "--sqlite", db, "--reason", "stolen"]) == 0
    assert "REVOKED : 04DE5F1EACC040  (stolen)" in capsys.readouterr().out
    assert cli(["revoke", "04AABBCCDDEEFF", "--sqlite", db, "--retire"]) == 0
    capsys.readouterr()
    assert cli(["revocations", "--sqlite", db, "--json"]) == 0
    listed = {e["identity"]: e["status"] for e in json.loads(capsys.readouterr().out)}
    assert listed == {"04DE5F1EACC040": "revoked", "04AABBCCDDEEFF": "retired"}
    assert cli(["reinstate", "04de5f1eacc040", "--sqlite", db]) == 0
    assert cli(["reinstate", "04de5f1eacc040", "--sqlite", db]) == 1
    with pytest.raises(SystemExit):
        cli(["revoke", "04AA", "--sqlite", str(tmp_path / "missing.db")])
    with pytest.raises(SystemExit):
        cli(["revoke", "04AA"])                                # a database is required
