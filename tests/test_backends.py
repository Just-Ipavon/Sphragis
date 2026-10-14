"""
Storage backends: one conformance suite for SQLite and Postgres.

The Postgres half runs when SPHRAGIS_TEST_PG_DSN points at a database (CI
starts one as a service); each test gets its own schema, dropped afterwards.
The concurrency tests are the point: many threads and several processes race
on one UID, and the anti-replay floor must accept every counter value at most
once while the detector history serializes concurrent taps.
"""

import multiprocessing as mp
import os
import sys
import threading
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis.alerts import Alert, SqliteAlertSink  # noqa: E402
from sphragis.observations import Observation, SqliteObservationStore  # noqa: E402
from sphragis.sqlstore import SqliteCounterStore  # noqa: E402

PG_DSN = os.environ.get("SPHRAGIS_TEST_PG_DSN")

try:
    import psycopg
    from psycopg.conninfo import make_conninfo
except ImportError:
    psycopg = None

needs_pg = pytest.mark.skipif(
    not (PG_DSN and psycopg), reason="set SPHRAGIS_TEST_PG_DSN and install sphragis[pg]")


@pytest.fixture
def pg_dsn():
    """A DSN whose search_path is a fresh schema, dropped after the test."""
    schema = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(PG_DSN, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    yield make_conninfo(PG_DSN, options=f"-c search_path={schema}")
    with psycopg.connect(PG_DSN, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA {schema} CASCADE")


def _factories(kind, tmp_path, request):
    if kind == "sqlite":
        db = str(tmp_path / "sphragis.db")
        return (lambda: SqliteCounterStore(db), lambda: SqliteObservationStore(db),
                lambda: SqliteAlertSink(db), ("sqlite", db))
    from sphragis.pgstore import PostgresAlertSink, PostgresCounterStore, PostgresObservationStore
    dsn = request.getfixturevalue("pg_dsn")
    return (lambda: PostgresCounterStore(dsn), lambda: PostgresObservationStore(dsn),
            lambda: PostgresAlertSink(dsn), ("pg", dsn))


@pytest.fixture(params=["sqlite", pytest.param("pg", marks=needs_pg)])
def backend(request, tmp_path):
    counters, history, alerts, spec = _factories(request.param, tmp_path, request)
    opened = []

    def make(factory):
        store = factory()
        opened.append(store)
        return store

    yield {"counters": lambda: make(counters), "history": lambda: make(history),
           "alerts": lambda: make(alerts), "spec": spec}
    for store in opened:
        getattr(store, "close", lambda: None)()


# --- Counter floor ------------------------------------------------------------

def test_counter_floor_contract(backend):
    s = backend["counters"]()
    assert s.last_counter("04AA") is None
    assert s.check_and_advance("04aa", 5)
    assert not s.check_and_advance("04AA", 5)      # replay (case-insensitive UID)
    assert not s.check_and_advance("04AA", 3)      # rollback
    assert s.check_and_advance("04AA", 6)
    assert s.last_counter("04aa") == 6
    assert s.check_and_advance("04BB", 1)          # independent UIDs


def test_counter_floor_is_shared_and_durable(backend):
    first = backend["counters"]()
    assert first.check_and_advance("04CC", 10)
    first.close()
    again = backend["counters"]()
    assert again.last_counter("04CC") == 10
    assert not again.check_and_advance("04CC", 10)


def test_counter_handles_full_24_bit_range(backend):
    s = backend["counters"]()
    assert s.check_and_advance("04DD", 0xFFFFFF)
    assert s.last_counter("04DD") == 0xFFFFFF


def test_same_counter_from_many_threads_is_accepted_once(backend):
    s = backend["counters"]()
    for value in range(1, 6):
        results, barrier = [], threading.Barrier(16)

        def tap():
            barrier.wait()
            results.append(s.check_and_advance("04EE", value))

        threads = [threading.Thread(target=tap) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count(True) == 1, (value, results)
    assert s.last_counter("04EE") == 5


def test_interleaved_counters_never_move_the_floor_back(backend):
    s = backend["counters"]()
    accepted: list[int] = []
    lock = threading.Lock()

    def worker(values):
        for v in values:
            if s.check_and_advance("04FF", v):
                with lock:
                    accepted.append(v)

    values = list(range(1, 201))
    threads = [threading.Thread(target=worker, args=(values[i::8][::-1],)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(accepted) == len(set(accepted))     # no value accepted twice
    assert s.last_counter("04FF") == 200
    assert not any(s.check_and_advance("04FF", v) for v in values)


def _process_tap(spec, uid, value, start):
    kind, target = spec
    if kind == "sqlite":
        store = SqliteCounterStore(target)
    else:
        from sphragis.pgstore import PostgresCounterStore
        store = PostgresCounterStore(target)
    start.wait()
    try:
        return store.check_and_advance(uid, value)
    finally:
        store.close()


def test_same_counter_from_many_processes_is_accepted_once(backend):
    backend["counters"]()                          # create the schema first
    ctx = mp.get_context("spawn")
    with ctx.Manager() as manager:
        start = manager.Event()
        with ctx.Pool(6) as pool:
            pending = [pool.apply_async(_process_tap, (backend["spec"], "04AB", 7, start))
                       for _ in range(6)]
            start.set()
            results = [p.get(timeout=60) for p in pending]
    assert results.count(True) == 1, results


# --- Detector history ---------------------------------------------------------

def test_history_contract(backend):
    h = backend["history"]()
    assert h.observe("04aa", Observation(1, 1.0, "gate-A"), limit=2) == []
    assert h.observe("04AA", Observation(2, 2.0), limit=2) == [Observation(1, 1.0, "gate-A")]
    h.observe("04AA", Observation(3, 3.0), limit=2)
    assert [o.counter for o in h.history("04aa")] == [2, 3]   # trimmed to limit
    assert h.history("04BB") == []


def test_concurrent_taps_are_serialized_per_uid(backend):
    h = backend["history"]()
    priors, barrier = [], threading.Barrier(12)

    def tap(n):
        barrier.wait()
        priors.append(len(h.observe("04CD", Observation(n, float(n)), limit=100)))

    threads = [threading.Thread(target=tap, args=(n,)) for n in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Serialized: each tap saw a different number of earlier taps.
    assert sorted(priors) == list(range(12))
    assert len(h.history("04CD")) == 12


# --- Alert audit trail --------------------------------------------------------

def _alert(event_id, ts, uid_ref="u1"):
    return Alert(event_id, ts, "CLONE_LIKELY", 90, uid_ref, 7, "gate-A",
                 ("counter_regression", "impossible_velocity"), "detail")


def test_alert_audit_trail(backend):
    a = backend["alerts"]()
    a.emit(_alert("e1", 1.0))
    a.emit(_alert("e2", 2.0, uid_ref="u2"))
    a.emit(_alert("e3", 3.0))
    assert [x.event_id for x in a.recent()] == ["e3", "e2", "e1"]
    assert [x.event_id for x in a.recent(uid_ref="u1")] == ["e3", "e1"]
    assert a.recent(limit=1)[0] == _alert("e3", 3.0)          # round-trips intact


def test_alert_event_ids_are_unique(backend):
    a = backend["alerts"]()
    a.emit(_alert("dup", 1.0))
    with pytest.raises(Exception):
        a.emit(_alert("dup", 2.0))


# --- API wiring ---------------------------------------------------------------

def test_settings_accept_only_postgres_urls():
    from sphragis.api.settings import ApiSettings

    assert ApiSettings.from_env({}).db_url is None
    url = "postgresql://sphragis@db.internal/sphragis"
    assert ApiSettings.from_env({"SPHRAGIS_DB_URL": url}).db_url == url
    with pytest.raises(ValueError):
        ApiSettings.from_env({"SPHRAGIS_DB_URL": "sqlite:///x.db"})


def _as_url(dsn):
    """libpq keyword DSN -> postgresql:// URL, as SPHRAGIS_DB_URL expects."""
    from urllib.parse import quote, urlencode

    from psycopg.conninfo import conninfo_to_dict

    d = conninfo_to_dict(dsn)
    auth = quote(d.pop("user", "")) + (":" + quote(d.pop("password")) if "password" in d else "")
    host = d.pop("host", "localhost") + (":" + str(d.pop("port")) if "port" in d else "")
    path = quote(d.pop("dbname", ""))
    query = ("?" + urlencode(d, quote_via=quote)) if d else ""
    return f"postgresql://{auth + '@' if auth else ''}{host}/{path}{query}"


@needs_pg
def test_api_on_postgres_shares_state_across_app_instances(pg_dsn):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sphragis.api import create_app_from_env
    from sphragis.emulator import tag_from_provider
    from sphragis.secrets import build_diversified_keys

    keys_hex = {"master_file": "11" * 16, "meta_read": "22" * 16}

    class Secrets:
        def get_key(self, name):
            return bytes.fromhex(keys_hex[name])

    env = {"SPHRAGIS_DB_URL": _as_url(pg_dsn), "SPHRAGIS_LOG_UID": "plain"}
    tag = tag_from_provider(build_diversified_keys(Secrets()), bytes.fromhex("04112233445566"))
    url = tag.tap()
    # Two app instances stand for two replicas: the second sees the first's floor.
    first = TestClient(create_app_from_env(env, secrets=Secrets()))
    second = TestClient(create_app_from_env(env, secrets=Secrets()))
    assert first.post("/v1/verify", json={"url": url}).json()["verdict"] == "GENUINE"
    assert second.post("/v1/verify", json={"url": url}).json()["verdict"] == "REPLAY"
