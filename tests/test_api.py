"""
REST API tests: response tiers (no oracle), reader authentication, alerting on
a real key-clone, rate limiting and proxy handling.
"""

import hashlib
import os
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest  # noqa: E402

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from sphragis import DiversifiedKeys, StaticKeys  # noqa: E402
from sphragis.adversary import KeyCloner, KeylessAttacker  # noqa: E402
from sphragis.alerts import SqliteAlertSink  # noqa: E402
from sphragis.analyzer import TagAnalyzer  # noqa: E402
from sphragis.api import create_app, create_app_from_env, parse_reader_tokens  # noqa: E402
from sphragis.emulator import EmulatedTag, tag_from_provider  # noqa: E402
from sphragis.ratelimit import TokenBucketLimiter  # noqa: E402
from sphragis.service import VerificationService  # noqa: E402

TOKEN_A, TOKEN_B = "token-gate-a", "token-gate-b"
READERS = {
    hashlib.sha256(TOKEN_A.encode()).hexdigest(): "gate-A",
    hashlib.sha256(TOKEN_B.encode()).hexdigest(): "gate-B",
}
PUBLIC_KEYS = {"event_id", "verdict", "risk_score", "message"}


class ListSink:
    def __init__(self):
        self.alerts = []

    def emit(self, alert):
        self.alerts.append(alert)


def _rig(counter=0, ip_limiter=None, uid_limiter=None, peer=("testclient", 50000),
         **app_kw):
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=os.urandom(16),
                      file_read_key=os.urandom(16), read_counter=counter)
    sink = ListSink()
    service = VerificationService(
        TagAnalyzer(StaticKeys(tag.meta_read_key, tag.file_read_key)),
        alert_sinks=[sink], uid_limiter=uid_limiter,
    )
    app = create_app(service, ip_limiter=ip_limiter, reader_tokens=READERS, **app_kw)
    return tag, TestClient(app, client=peer), sink


def _path(url):
    parts = urlsplit(url)
    return f"/t?{parts.query}"


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# --- Public tier -------------------------------------------------------------

def test_get_tap_genuine_minimal_response():
    tag, client, _ = _rig()
    r = client.get(_path(tag.tap()))
    assert r.status_code == 200
    body = r.json()
    assert set(body) == PUBLIC_KEYS
    assert body["verdict"] == "GENUINE" and body["risk_score"] == 0
    assert tag.uid.hex().upper() not in r.text
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_forged_and_malformed_are_indistinguishable_publicly():
    tag, client, _ = _rig()
    forged = client.get(_path(KeylessAttacker.forge_mac(tag.tap()))).json()
    garbage = client.get("/t?picc_data=zz&cmac=00").json()
    missing = client.get("/t").json()
    for body in (forged, garbage, missing):
        assert set(body) == PUBLIC_KEYS
        assert body["verdict"] == "INVALID" and body["risk_score"] == 100
        body.pop("event_id")
    assert forged == garbage == missing


def test_post_verify_public_and_replay():
    tag, client, _ = _rig()
    url = tag.tap()
    assert client.post("/v1/verify", json={"url": url}).json()["verdict"] == "GENUINE"
    again = client.post("/v1/verify", json={"url": url}).json()
    assert again["verdict"] == "REPLAY" and set(again) == PUBLIC_KEYS


def test_post_rejects_client_supplied_reader_and_oversized_url():
    tag, client, _ = _rig()
    r = client.post("/v1/verify", json={"url": tag.tap(), "reader_id": "gate-A"})
    assert r.status_code == 422
    r = client.post("/v1/verify", json={"url": "x" * 5000})
    assert r.status_code == 422


def test_query_reader_id_cannot_fake_velocity():
    """A reader_id smuggled in the query string is ignored."""
    tag, client, _ = _rig()
    client.get(_path(tag.tap()) + "&reader_id=gate-A")
    clone = KeyCloner.clone(tag, start_counter=tag.read_counter)
    r = client.get(_path(clone.tap()) + "&reader_id=gate-B")
    assert r.json()["verdict"] == "GENUINE"


def test_duplicated_params_and_encrypted_file_data_stay_fail_closed():
    tag, client, _ = _rig()
    path = _path(tag.tap())
    assert client.get(path + "&cmac=0000000000000000").json()["verdict"] == "INVALID"
    assert client.get(path + "&enc=00").json()["verdict"] == "INVALID"


# --- Detailed tier (authenticated readers) -----------------------------------

def test_detailed_response_for_authenticated_reader():
    tag, client, _ = _rig()
    r = client.post("/v1/verify", json={"url": tag.tap()}, headers=_auth(TOKEN_A))
    body = r.json()
    assert body["classification"] == "GENUINE"
    assert body["reader_id"] == "gate-A"
    assert body["uid"] == tag.uid.hex().upper()
    assert body["read_counter"] == 1


def test_detailed_forged_reports_real_classification():
    tag, client, _ = _rig()
    body = client.get(_path(KeylessAttacker.forge_mac(tag.tap())),
                      headers=_auth(TOKEN_A)).json()
    assert body["verdict"] == "INVALID" and body["classification"] == "FORGED"


@pytest.mark.parametrize("header", ["Bearer wrong", "Basic abc", "Bearer ", "token"])
def test_bad_credentials_are_rejected_not_downgraded(header):
    tag, client, _ = _rig()
    r = client.post("/v1/verify", json={"url": tag.tap()},
                    headers={"Authorization": header})
    assert r.status_code == 401


def test_key_clone_via_api_raises_alert():
    tag, client, sink = _rig(counter=9)
    for _ in range(3):
        client.post("/v1/verify", json={"url": tag.tap()}, headers=_auth(TOKEN_A))
    clone = KeyCloner.clone(tag, start_counter=2)
    body = client.post("/v1/verify", json={"url": clone.tap()},
                       headers=_auth(TOKEN_B)).json()
    assert body["verdict"] == "CLONE_LIKELY" and body["alerted"] is True
    # Real clock: the two readers are also seconds apart, so velocity fires too.
    assert "counter_regression" in [s["name"] for s in body["signals"]]
    assert len(sink.alerts) == 1
    alert = sink.alerts[0]
    assert alert.event_id == body["event_id"] and alert.reader_id == "gate-B"
    assert alert.uid_ref != tag.uid.hex().upper()


def test_impossible_velocity_between_authenticated_readers():
    tag, client, sink = _rig()
    client.post("/v1/verify", json={"url": tag.tap()}, headers=_auth(TOKEN_A))
    clone = KeyCloner.clone(tag, start_counter=tag.read_counter)
    body = client.post("/v1/verify", json={"url": clone.tap()},
                       headers=_auth(TOKEN_B)).json()
    assert body["verdict"] == "CLONE_LIKELY"
    assert "impossible_velocity" in [s["name"] for s in body["signals"]]
    assert len(sink.alerts) == 1


# --- Rate limiting -----------------------------------------------------------

def test_ip_rate_limit_returns_429_with_retry_after():
    tag, client, _ = _rig(ip_limiter=TokenBucketLimiter(rate=0.01, burst=2))
    assert client.get(_path(tag.tap())).status_code == 200
    assert client.get(_path(tag.tap())).status_code == 200
    r = client.get(_path(tag.tap()))
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert client.get("/healthz").status_code == 200   # probes not limited


def test_uid_rate_limit_throttles_authentic_taps():
    tag, client, _ = _rig(uid_limiter=TokenBucketLimiter(rate=0.01, burst=1),
                          throttle_retry_after=7)
    assert client.get(_path(tag.tap())).json()["verdict"] == "GENUINE"
    url = tag.tap()
    r = client.get(_path(url))
    assert r.status_code == 429 and r.headers["retry-after"] == "7"


def test_forwarded_for_ignored_unless_peer_is_trusted_proxy():
    limiter = TokenBucketLimiter(rate=0.01, burst=1)
    tag, client, _ = _rig(ip_limiter=limiter)
    # Untrusted peer: rotating X-Forwarded-For must not buy fresh buckets.
    assert client.get("/t", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert client.get("/t", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 429

    # A trusted proxy in front of the API.
    limiter2 = TokenBucketLimiter(rate=0.01, burst=1)
    tag, client, _ = _rig(ip_limiter=limiter2, peer=("10.0.0.2", 50000),
                          trusted_proxies=frozenset({"10.0.0.2"}))
    assert client.get("/t", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert client.get("/t", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200
    # Left-most (client-controlled) hops are ignored: the right-most decides.
    assert client.get("/t", headers={"X-Forwarded-For": "9.9.9.9, 1.1.1.1"}).status_code == 429


def test_docs_disabled_by_default():
    _, client, _ = _rig()
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


# --- Settings / factory ------------------------------------------------------

def test_parse_reader_tokens_validates():
    digest = "a" * 64
    assert parse_reader_tokens(f"gate-A={digest.upper()}") == {digest: "gate-A"}
    for bad in ("gate-A", "gate-A=zz", f"={digest}",
                f"a={digest},b={digest}"):
        with pytest.raises(ValueError):
            parse_reader_tokens(bad)


def test_create_app_from_env_end_to_end(tmp_path, monkeypatch):
    master, meta, pseudo = os.urandom(16), os.urandom(16), os.urandom(16)
    for name, key in (("MASTER_FILE", master), ("META_READ", meta),
                      ("LOG_PSEUDONYM", pseudo)):
        monkeypatch.setenv("SPHRAGIS_" + name, key.hex())
    db = tmp_path / "sphragis.db"
    env = {
        "SPHRAGIS_DB_PATH": str(db),
        "SPHRAGIS_KEY_CONTEXT": "DEMO",
        "SPHRAGIS_READER_TOKENS": ",".join(f"{r}={d}" for d, r in READERS.items()),
    }
    client = TestClient(create_app_from_env(env))
    tag = tag_from_provider(DiversifiedKeys(master, meta, context=b"DEMO"),
                            uid=os.urandom(7), read_counter=9)
    for _ in range(2):
        assert client.get(_path(tag.tap())).json()["verdict"] == "GENUINE"
    body = client.post("/v1/verify", json={"url": KeyCloner.clone(tag, 2).tap()},
                       headers=_auth(TOKEN_B)).json()
    assert body["verdict"] == "CLONE_LIKELY"
    # The durable audit trail lives in the same database.
    stored = SqliteAlertSink(db).recent()
    assert [a.event_id for a in stored] == [body["event_id"]]


# --- Client address, request guard, logs (#21, #22, #25) -----------------------

def test_duplicate_forwarded_for_lines_cannot_mint_buckets():
    # HAProxy-style proxies append their own X-Forwarded-For line: the
    # attacker's line comes first and must not win.
    from sphragis.api.app import client_address, parse_trusted_proxies
    proxy = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_address("10.0.0.2", ["6.6.6.6", "1.1.1.1"], proxy) == "1.1.1.1"
    assert client_address("10.0.0.2", ["6.6.6.6, 1.1.1.1", "10.0.0.9"], proxy) == "1.1.1.1"
    assert client_address("10.0.0.2", ["not-an-ip"], proxy) == "10.0.0.2"
    assert client_address("8.8.8.8", ["1.1.1.1"], proxy) == "8.8.8.8"   # untrusted peer


def test_duplicate_forwarded_for_header_end_to_end():
    limiter = TokenBucketLimiter(rate=0.01, burst=1)
    tag, client, _ = _rig(ip_limiter=limiter, peer=("10.0.0.2", 50000),
                          trusted_proxies=["10.0.0.0/8"])
    headers = [("X-Forwarded-For", "6.6.6.1"), ("X-Forwarded-For", "1.1.1.1")]
    assert client.get("/t", headers=headers).status_code == 200
    headers = [("X-Forwarded-For", "6.6.6.2"), ("X-Forwarded-For", "1.1.1.1")]
    assert client.get("/t", headers=headers).status_code == 429


def test_ipv6_clients_share_a_bucket_per_64():
    from sphragis.api.app import bucket_key, client_address
    a = client_address("2001:db8:1:2::1", [], ())
    b = client_address("2001:db8:1:2:ffff::9", [], ())
    assert a == b == "2001:db8:1:2::/64"
    assert client_address("2001:db8:1:3::1", [], ()) != a
    assert client_address("::ffff:1.2.3.4", [], ()) == "1.2.3.4"     # IPv4-mapped
    import ipaddress
    assert bucket_key(ipaddress.ip_address("192.0.2.7")) == "192.0.2.7"


def test_invalid_trusted_proxy_is_a_configuration_error():
    with pytest.raises(ValueError, match="trusted proxy"):
        _rig(trusted_proxies=["10.0.0.0/33"])


def test_oversized_body_is_refused_before_parsing():
    _, client, _ = _rig()
    r = client.post("/v1/verify", content=b"{" + b" " * 9000 + b"}",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.headers["cache-control"] == "no-store"

    def chunks():                                   # no Content-Length: streamed
        for _ in range(10):
            yield b" " * 1024
    r = client.post("/v1/verify", content=chunks(),
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_invalid_json_counts_against_the_ip_limit():
    limiter = TokenBucketLimiter(rate=0.01, burst=2)
    _, client, _ = _rig(ip_limiter=limiter)
    for _ in range(2):
        assert client.post("/v1/verify", content=b"not json",
                           headers={"Content-Type": "application/json"}).status_code == 422
    r = client.post("/v1/verify", content=b"not json",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 429 and "retry-after" in r.headers


def test_normal_body_still_reaches_the_endpoint():
    tag, client, _ = _rig()
    assert client.post("/v1/verify", json={"url": tag.tap()}).json()["verdict"] == "GENUINE"


def test_access_log_lines_lose_the_query_string():
    import logging
    from sphragis.api.app import QueryRedactingFilter
    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1,
                               '%s - "%s %s HTTP/%s" %d',
                               ("1.2.3.4:5", "GET", "/t?picc_data=AA&cmac=BB", "1.1", 200),
                               None)
    assert QueryRedactingFilter().filter(record)
    assert "picc_data" not in record.getMessage() and "/t" in record.getMessage()
    _rig()
    assert any(isinstance(f, QueryRedactingFilter)
               for f in logging.getLogger("uvicorn.access").filters)


@pytest.mark.parametrize("name,value", [
    ("IP_RATE", "nan"), ("IP_RATE", "-1"), ("UID_RATE", "0"), ("UID_RATE", "inf"),
    ("IP_BURST", "0"), ("UID_BURST", "x"), ("MIN_TRAVEL_SECONDS", "nan"),
    ("MIN_TRAVEL_SECONDS", "-5"), ("ALERT_ON", "CLONE_LIKLEY"), ("ALERT_ON", ","),
    ("LOG_LEVEL", "VERBOSE"), ("TRUSTED_PROXIES", "10.0.0.0/40"),
    ("MAX_BODY_BYTES", "0"),
])
def test_settings_refuse_values_that_would_disable_protections(name, value):
    from sphragis.api.settings import ApiSettings
    with pytest.raises(ValueError, match=name):
        ApiSettings.from_env({"SPHRAGIS_" + name: value})


def test_settings_accept_valid_values():
    from sphragis.api.settings import ApiSettings
    s = ApiSettings.from_env({"SPHRAGIS_ALERT_ON": "clone_likely,replay",
                              "SPHRAGIS_TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.1",
                              "SPHRAGIS_MAX_BODY_BYTES": "4096"})
    assert s.alert_on == {"CLONE_LIKELY", "REPLAY"} and s.max_body_bytes == 4096


def test_declared_oversized_body_is_refused_without_reading_it():
    import asyncio
    from sphragis.api.app import RequestGuard

    async def app(scope, receive, send):           # must never be reached
        raise AssertionError("app called")

    async def receive():                           # must never be read
        raise AssertionError("body read")

    sent = []

    async def send(message):
        sent.append(message)

    guard = RequestGuard(app, ip_limiter=None, trusted_proxies=(), max_body_bytes=8192)
    scope = {"type": "http", "method": "POST", "path": "/v1/verify",
             "headers": [(b"content-length", b"1000000000")], "client": ("1.2.3.4", 1)}
    asyncio.run(guard(scope, receive, send))
    assert sent[0]["status"] == 413
