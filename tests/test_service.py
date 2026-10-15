"""
Service-layer tests: shared observation history, rate limiting, structured
logging, pseudonymization and alerting. No web framework required.
"""

import http.server
import json
import logging
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest  # noqa: E402

from sphragis import StaticKeys  # noqa: E402
from sphragis.adversary import KeyCloner, KeylessAttacker  # noqa: E402
from sphragis.alerts import (  # noqa: E402
    Alert,
    LogAlertSink,
    SqliteAlertSink,
    WebhookAlertSink,
    dispatch,
    sign_webhook,
)
from sphragis.analyzer import TagAnalyzer  # noqa: E402
from sphragis.detection import CloneDetector  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.logs import JsonFormatter, UidPseudonymizer  # noqa: E402
from sphragis.observations import (  # noqa: E402
    MemoryObservationStore,
    Observation,
    SqliteObservationStore,
)
from sphragis.ratelimit import TokenBucketLimiter  # noqa: E402
from sphragis.service import VerificationService  # noqa: E402
from sphragis.sqlstore import SqliteCounterStore  # noqa: E402


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class ListSink:
    def __init__(self):
        self.alerts = []

    def emit(self, alert):
        self.alerts.append(alert)


class BrokenSink:
    def emit(self, alert):
        raise RuntimeError("sink down")


def _tag(counter=0):
    meta, file_ = os.urandom(16), os.urandom(16)
    return EmulatedTag(uid=os.urandom(7), meta_read_key=meta,
                       file_read_key=file_, read_counter=counter)


def _keys(tag):
    return StaticKeys(tag.meta_read_key, tag.file_read_key)


# --- Observation stores ------------------------------------------------------

@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_observe_returns_prior_history_and_trims(kind, tmp_path):
    store = (MemoryObservationStore() if kind == "memory"
             else SqliteObservationStore(tmp_path / "o.db"))
    assert store.observe("aa", Observation(1, 1.0, "r"), limit=3) == []
    for c in range(2, 6):
        prior = store.observe("AA", Observation(c, float(c), "r"), limit=3)
        assert [o.counter for o in prior] == list(range(max(1, c - 3), c))
    assert [o.counter for o in store.history("AA")] == [3, 4, 5]


def test_sqlite_observations_persist_across_reopen(tmp_path):
    db = tmp_path / "o.db"
    s = SqliteObservationStore(db)
    s.observe("CAFE", Observation(7, 1.0, "gate-A"), limit=10)
    s.close()
    s2 = SqliteObservationStore(db)
    assert s2.history("cafe") == [Observation(7, 1.0, "gate-A")]
    s2.close()


def test_sqlite_observe_is_atomic_under_concurrency(tmp_path):
    store = SqliteObservationStore(tmp_path / "o.db")
    seen_lengths = []
    lock = threading.Lock()

    def worker(i):
        prior = store.observe("UID", Observation(i, float(i)), limit=1000)
        with lock:
            seen_lengths.append(len(prior))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Serialized: every tap saw a distinct prefix of the history.
    assert sorted(seen_lengths) == list(range(40))
    store.close()


def test_clone_caught_across_workers_sharing_history(tmp_path):
    """Two analyzers (= two API workers) sharing the DB see one stream."""
    db = tmp_path / "s.db"
    tag = _tag(counter=9)

    def worker():
        return TagAnalyzer(
            _keys(tag),
            detector=CloneDetector(store=SqliteObservationStore(db)),
            store=SqliteCounterStore(db),
        )

    w1, w2 = worker(), worker()
    for i in range(3):
        assert w1.analyze(tag.tap(), timestamp=1000 + i,
                          reader_id="gate-A").classification == "GENUINE"
    clone = KeyCloner.clone(tag, start_counter=2)
    r = w2.analyze(clone.tap(), timestamp=2000, reader_id="gate-B")
    assert r.classification == "CLONE_LIKELY"
    assert any(s.name == "counter_regression" for s in r.signals)


# --- Admission hook ----------------------------------------------------------

def test_throttled_tap_leaves_state_untouched():
    tag = _tag()
    analyzer = TagAnalyzer(_keys(tag))
    url = tag.tap()
    r = analyzer.analyze(url, timestamp=1000, admit=lambda uid: False)
    assert r.classification == "THROTTLED"
    assert analyzer.detector.history(r.uid) == []
    # The same (genuine) tap is still accepted once admitted.
    assert analyzer.analyze(url, timestamp=1001).classification == "GENUINE"


def test_admission_is_not_consulted_for_forged_taps():
    tag = _tag()
    analyzer = TagAnalyzer(_keys(tag))
    calls = []
    analyzer.analyze(KeylessAttacker.forge_mac(tag.tap()),
                     admit=lambda uid: calls.append(uid) or True)
    assert calls == []


# --- Rate limiter ------------------------------------------------------------

def test_token_bucket_burst_then_refill():
    clock = FakeClock(0.0)
    rl = TokenBucketLimiter(rate=1.0, burst=3, clock=clock)
    assert [rl.check("k").allowed for _ in range(3)] == [True, True, True]
    denied = rl.check("k")
    assert not denied.allowed and denied.retry_after == pytest.approx(1.0)
    assert rl.check("other").allowed          # buckets are per key
    clock.t = 1.0
    assert rl.check("k").allowed
    assert not rl.check("k").allowed


def test_token_bucket_bounds_memory():
    rl = TokenBucketLimiter(rate=1.0, burst=1, max_keys=10)
    for i in range(100):
        rl.check(f"ip-{i}")
    assert len(rl) == 10


# --- Logging & pseudonymization ----------------------------------------------

def test_pseudonymizer_is_stable_keyed_and_not_raw():
    p1, p2 = UidPseudonymizer(b"k" * 16), UidPseudonymizer(b"j" * 16)
    assert p1.ref("04aabb") == p1.ref("04AABB")
    assert p1.ref("04AABB") != p2.ref("04AABB")
    assert "04AABB" not in p1.ref("04AABB")
    assert UidPseudonymizer(None).ref("04aabb") == "04AABB"
    with pytest.raises(ValueError):
        UidPseudonymizer(b"short")


def test_json_formatter_emits_one_object_per_line():
    rec = logging.LogRecord("sphragis.verify", logging.INFO, __file__, 1,
                            "verification", None, None)
    rec.fields = {"classification": "GENUINE", "risk_score": 0, "event": "x"}
    line = JsonFormatter().format(rec)
    assert "\n" not in line
    obj = json.loads(line)
    assert obj["event"] == "verification" and obj["field_event"] == "x"
    assert obj["classification"] == "GENUINE" and obj["level"] == "INFO"


def _service(tag, **kw):
    analyzer = TagAnalyzer(_keys(tag))
    return VerificationService(analyzer, **kw)


def test_verification_log_has_no_raw_uid_or_sdm_params(caplog):
    tag = _tag()
    svc = _service(tag, pseudonymizer=UidPseudonymizer(os.urandom(16)))
    url = tag.tap()
    with caplog.at_level(logging.INFO, logger="sphragis.verify"):
        out = svc.verify(url)
    assert out.result.classification == "GENUINE"
    rendered = JsonFormatter().format(caplog.records[-1])
    fields = json.loads(rendered)
    assert fields["uid_ref"] == out.uid_ref and fields["uid_ref"].startswith("h:")
    query = url.split("?", 1)[1]
    for secret_ish in [tag.uid.hex().upper(), *(v.split("=")[1] for v in query.split("&"))]:
        assert secret_ish not in rendered


def test_service_uses_server_clock_not_client_time():
    tag = _tag()
    clock = FakeClock(1000.0)
    sink = ListSink()
    svc = _service(tag, clock=clock, alert_sinks=[sink])
    svc.verify(tag.tap(), reader_id="gate-A")
    clock.t = 1005.0                      # 5 s later, another reader
    clone = KeyCloner.clone(tag, start_counter=tag.read_counter)
    out = svc.verify(clone.tap(), reader_id="gate-B")
    assert out.timestamp == 1005.0
    assert out.result.classification == "CLONE_LIKELY"
    assert any(s.name == "impossible_velocity" for s in out.result.signals)


# --- Alerts ------------------------------------------------------------------

def test_clone_raises_alert_genuine_does_not(tmp_path):
    tag = _tag(counter=9)
    sink, audit = ListSink(), SqliteAlertSink(tmp_path / "a.db")
    svc = _service(tag, alert_sinks=[sink, audit])
    for _ in range(3):
        assert svc.verify(tag.tap()).alerted is False
    clone = KeyCloner.clone(tag, start_counter=2)
    out = svc.verify(clone.tap())
    assert out.alerted is True
    assert [a.classification for a in sink.alerts] == ["CLONE_LIKELY"]
    stored = audit.recent()
    assert len(stored) == 1 and stored[0].event_id == out.event_id
    assert stored[0].signals == ("counter_regression",)
    assert audit.recent(uid_ref=out.uid_ref)[0].uid_ref == out.uid_ref


def test_replay_alert_is_opt_in():
    tag = _tag()
    url = tag.tap()
    default, opted = ListSink(), ListSink()
    svc_default = _service(tag, alert_sinks=[default])
    svc_opted = _service(tag, alert_sinks=[opted],
                         alert_on={"CLONE_LIKELY", "REPLAY"})
    for svc in (svc_default, svc_opted):
        svc.verify(url)
        assert svc.verify(url).result.classification == "REPLAY"
    assert default.alerts == []
    assert [a.classification for a in opted.alerts] == ["REPLAY"]


def test_broken_sink_does_not_break_verification_or_other_sinks(caplog):
    tag = _tag(counter=9)
    good = ListSink()
    svc = _service(tag, alert_sinks=[BrokenSink(), good])
    for _ in range(2):
        svc.verify(tag.tap())
    with caplog.at_level(logging.ERROR, logger="sphragis.alert"):
        out = svc.verify(KeyCloner.clone(tag, start_counter=2).tap())
    assert out.result.classification == "CLONE_LIKELY" and out.alerted
    assert len(good.alerts) == 1
    assert any(r.getMessage() == "alert_sink_failed" for r in caplog.records)


def test_log_alert_sink_is_critical(caplog):
    alert = Alert("e1", 1.0, "CLONE_LIKELY", 70, "h:x", 3, "gate-B",
                  ("counter_regression",), "d")
    with caplog.at_level(logging.CRITICAL, logger="sphragis.alert"):
        assert dispatch(alert, [LogAlertSink()]) == 1
    assert caplog.records[-1].levelno == logging.CRITICAL


def test_webhook_sink_posts_signed_json():
    received = {}
    secret = os.urandom(32)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.update(body=body, ts=self.headers["X-Sphragis-Timestamp"],
                            sig=self.headers["X-Sphragis-Signature"])
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/hook"
    alert = Alert("e1", 1.0, "CLONE_LIKELY", 70, "h:x", 3, None,
                  ("counter_regression",), "d")
    WebhookAlertSink(url, secret, allow_insecure=True).emit(alert)
    server.server_close()
    assert json.loads(received["body"])["event_id"] == "e1"
    assert received["sig"] == sign_webhook(secret, received["ts"], received["body"])


def test_webhook_sink_requires_https_and_real_secret():
    with pytest.raises(ValueError):
        WebhookAlertSink("http://example.com/hook", os.urandom(32))
    with pytest.raises(ValueError):
        WebhookAlertSink("https://example.com/hook", b"short")


# --- Webhook hardening (#25) ------------------------------------------------------

def _one_shot_server(status, location=None):
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            hits.append((self.command, self.path))
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_POST = do_GET = _answer  # noqa: N815

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hits


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_webhook_refuses_redirects(status):
    target, target_hits = _one_shot_server(204)
    hook, hook_hits = _one_shot_server(status, f"http://127.0.0.1:{target.server_port}/x")
    alert = Alert("e1", 1.0, "CLONE_LIKELY", 70, "h:x", 3, None, (), "d")
    sink = WebhookAlertSink(f"http://127.0.0.1:{hook.server_port}/hook", os.urandom(32),
                            allow_insecure=True)
    with pytest.raises(Exception):
        sink.emit(alert)
    assert dispatch(alert, [sink]) == 0                # not counted as delivered
    hook.shutdown()
    target.shutdown()
    assert hook_hits and not target_hits               # never followed


def test_verify_webhook():
    from sphragis.alerts import verify_webhook
    secret, body = os.urandom(32), b'{"event_id":"e1"}'
    sig = sign_webhook(secret, "1000", body)
    assert verify_webhook(secret, "1000", sig, body, now=1100)
    assert not verify_webhook(secret, "1000", sig, body + b" ", now=1100)
    assert not verify_webhook(secret, "1000", sig, body, now=1000 + 301)   # stale
    assert not verify_webhook(secret, "1000", sig.replace("a", "b"), body, now=1000)
    assert not verify_webhook(secret, "x", sig, body, now=1000)


def test_background_sink_does_not_block_and_delivers():
    from sphragis.alerts import BackgroundAlertSink
    gate, got = threading.Event(), []

    class Slow:
        def emit(self, alert):
            gate.wait(5)
            got.append(alert.event_id)

    sink = BackgroundAlertSink(Slow(), maxsize=2)
    alert = Alert("e1", 1.0, "CLONE_LIKELY", 70, None, 1, None, (), "d")
    assert dispatch(alert, [sink]) == 1                # returned before delivery
    assert got == []
    gate.set()
    sink.flush()
    assert got == ["e1"]
    sink.close()


def test_background_sink_drops_when_full(caplog):
    from sphragis.alerts import BackgroundAlertSink
    gate, busy = threading.Event(), threading.Event()

    class Stuck:
        def emit(self, alert):
            busy.set()
            gate.wait(5)

    sink = BackgroundAlertSink(Stuck(), maxsize=1)
    alerts = [Alert(f"e{i}", 1.0, "CLONE_LIKELY", 70, None, 1, None, (), "d")
              for i in range(3)]
    assert dispatch(alerts[0], [sink]) == 1
    assert busy.wait(5)                                # worker holds e0
    assert dispatch(alerts[1], [sink]) == 1            # fills the one slot
    assert dispatch(alerts[2], [sink]) == 0            # dropped, never blocks
    assert "queue full" in caplog.text
    gate.set()
    sink.flush()
    sink.close()
