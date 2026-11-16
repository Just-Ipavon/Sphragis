"""WebAuthn through the REST API (#57): durable credentials, shared challenges."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")
pytest.importorskip("cbor2")

from fastapi.testclient import TestClient  # noqa: E402
from test_backends import _as_url, needs_pg, pg_dsn  # noqa: E402, F401
from test_webauthn import ORIGIN, RP_ID, SoftAuthenticator, b64u  # noqa: E402

from sphragis.api import create_app_from_env  # noqa: E402
from sphragis.api.settings import ApiSettings  # noqa: E402
from sphragis.cli import main as cli  # noqa: E402
from sphragis.sqlstore import SqliteChallengeStore, SqliteCredentialStore  # noqa: E402
from sphragis.webauthn import b64url_decode, check_rp_id  # noqa: E402


class Secrets:
    def get_key(self, name):
        return bytes.fromhex({"master_file": "11" * 16, "meta_read": "22" * 16}[name])


def _env(db):
    env = {"SPHRAGIS_LOG_UID": "plain", "SPHRAGIS_BACKENDS": "fido2-webauthn,ntag424-sun",
           "SPHRAGIS_WEBAUTHN_RP_ID": RP_ID, "SPHRAGIS_WEBAUTHN_ORIGINS": ORIGIN}
    kind, target = db
    env["SPHRAGIS_DB_URL" if kind == "pg" else "SPHRAGIS_DB_PATH"] = target
    return env


def _credentials(db):
    kind, target = db
    if kind == "pg":
        from sphragis.pgstore import PostgresCredentialStore
        return PostgresCredentialStore(target)
    return SqliteCredentialStore(target)


@pytest.fixture(params=["sqlite", pytest.param("pg", marks=needs_pg)])
def db(request, tmp_path):
    if request.param == "sqlite":
        return ("sqlite", str(tmp_path / "sphragis.db"))
    return ("pg", _as_url(request.getfixturevalue("pg_dsn")))


def _replicas(db, n=2):
    return [TestClient(create_app_from_env(_env(db), secrets=Secrets())) for _ in range(n)]


def _challenge(client):
    r = client.post("/v1/webauthn/challenge")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    options = r.json()
    assert set(options) == {"challenge", "rpId", "timeout", "userVerification"}
    assert options["rpId"] == RP_ID and options["timeout"] == 120_000
    return b64url_decode(options["challenge"])


@pytest.mark.parametrize("alg", ["ES256", "EdDSA"])
def test_assertion_verifies_end_to_end_across_replicas(db, alg):
    first, second = _replicas(db)
    auth = SoftAuthenticator(alg=alg, counter=7)
    store = _credentials(db)
    store.add(auth.credential_id, auth.cose_key, RP_ID)
    store.close()

    assertion = auth.assert_(_challenge(first))               # issued by replica 1
    body = second.post("/v1/verify", json={"assertion": json.loads(assertion)}).json()
    assert body["verdict"] == "GENUINE"                       # consumed by replica 2
    # The same assertion again: its challenge is spent, on every replica.
    for client in (first, second):
        again = client.post("/v1/verify", json={"url": assertion}).json()
        assert again["verdict"] == "INVALID"
    # A fresh challenge, the counter going backwards: the shared ledger sees it.
    stale = auth.assert_(_challenge(second), counter=3)
    body = first.post("/v1/verify", json={"url": stale}).json()
    assert body["verdict"] in ("SUSPICIOUS", "CLONE_LIKELY")


def test_revoked_or_foreign_credentials_are_refused(db):
    client, = _replicas(db, 1)
    auth, other = SoftAuthenticator(), SoftAuthenticator()
    store = _credentials(db)
    store.add(auth.credential_id, auth.cose_key, RP_ID)
    store.add(other.credential_id, other.cose_key, "elsewhere.example.org")
    with pytest.raises(ValueError):
        store.add(auth.credential_id, auth.cose_key, RP_ID)   # imported once only
    assert store.revoke(auth.credential_id) and not store.revoke(auth.credential_id)
    states = {r.credential_id: r.revoked is not None for r in store.entries()}
    assert states == {auth.credential_id: True, other.credential_id: False}
    store.close()
    for a in (auth, other):
        body = client.post("/v1/verify", json={"url": a.assert_(_challenge(client))}).json()
        assert body["verdict"] == "INVALID"


def test_challenge_endpoint_is_rate_limited_and_bounded(tmp_path):
    env = _env(("sqlite", str(tmp_path / "s.db"))) | {
        "SPHRAGIS_IP_RATE": "0.001", "SPHRAGIS_IP_BURST": "3",
        "SPHRAGIS_WEBAUTHN_MAX_CHALLENGES": "2"}
    client = TestClient(create_app_from_env(env, secrets=Secrets()))
    codes = [client.post("/v1/webauthn/challenge").status_code for _ in range(4)]
    assert codes == [200, 200, 503, 429]


def test_challenge_endpoint_absent_without_the_backend(tmp_path):
    env = {"SPHRAGIS_DB_PATH": str(tmp_path / "s.db"), "SPHRAGIS_LOG_UID": "plain"}
    client = TestClient(create_app_from_env(env, secrets=Secrets()))
    assert client.post("/v1/webauthn/challenge").status_code in (404, 405)


@pytest.mark.parametrize("body", [{}, {"url": "x", "assertion": {"a": 1}}])
def test_verify_takes_exactly_one_input(tmp_path, body):
    client, = _replicas(("sqlite", str(tmp_path / "s.db")), 1)
    assert client.post("/v1/verify", json=body).status_code == 422


def test_user_verification_required_is_enforced(tmp_path):
    db = ("sqlite", str(tmp_path / "s.db"))
    env = _env(db) | {"SPHRAGIS_WEBAUTHN_USER_VERIFICATION": "required"}
    client = TestClient(create_app_from_env(env, secrets=Secrets()))
    auth = SoftAuthenticator()
    store = _credentials(db)
    store.add(auth.credential_id, auth.cose_key, RP_ID)
    store.close()
    assert client.post("/v1/webauthn/challenge").json()["userVerification"] == "required"
    up_only = auth.assert_(_challenge(client), flags=0x01)
    assert client.post("/v1/verify", json={"url": up_only}).json()["verdict"] == "INVALID"
    with_uv = auth.assert_(_challenge(client), flags=0x05)
    assert client.post("/v1/verify", json={"url": with_uv}).json()["verdict"] == "GENUINE"


@pytest.mark.parametrize("env", [
    {"SPHRAGIS_BACKENDS": "fido2-webauthn"},                               # no RP ID
    {"SPHRAGIS_BACKENDS": "fido2-webauthn", "SPHRAGIS_WEBAUTHN_RP_ID": RP_ID},
    {"SPHRAGIS_BACKENDS": "fido2-webauthn", "SPHRAGIS_WEBAUTHN_RP_ID": RP_ID,
     "SPHRAGIS_WEBAUTHN_ORIGINS": "https://other.example.org"},
    {"SPHRAGIS_BACKENDS": "fido2-webauthn", "SPHRAGIS_WEBAUTHN_RP_ID": RP_ID,
     "SPHRAGIS_WEBAUTHN_ORIGINS": "http://verify.example.com"},
    {"SPHRAGIS_WEBAUTHN_USER_VERIFICATION": "maybe"},
    {"SPHRAGIS_WEBAUTHN_CHALLENGE_TTL": "0"},
])
def test_webauthn_settings_are_validated(env):
    with pytest.raises(ValueError):
        ApiSettings.from_env(env)


def test_rp_id_check():
    check_rp_id("example.com", ["https://verify.example.com", "https://example.com:8443"])
    check_rp_id("localhost", ["http://localhost:8000"])
    for rp_id, origins in [("example.com", ["https://notexample.com"]),
                           ("example.com", ["https://example.com/path"]),
                           ("https://example.com", ["https://example.com"])]:
        with pytest.raises(ValueError):
            check_rp_id(rp_id, origins)


def test_challenge_stores_bound_outstanding_challenges(tmp_path):
    clock = [1000.0]
    store = SqliteChallengeStore(tmp_path / "c.db", ttl_seconds=10, max_outstanding=2,
                                 clock=lambda: clock[0])
    first = store.issue()
    store.issue()
    with pytest.raises(RuntimeError):
        store.issue()
    assert store.consume(first)
    store.issue()                                              # room again
    clock[0] += 11                                             # all expired
    store.issue()
    store.close()


def test_cli_takes_a_credential_id_starting_with_a_dash(tmp_path, capsys):
    """base64url ids can start with '-': the documented --credential-id=ID form reads them."""
    db = str(tmp_path / "s.db")
    SqliteCredentialStore(db).close()
    auth = SoftAuthenticator()
    auth.credential_id = b"\xfb" + auth.credential_id[1:]        # base64url "-..."
    cid = b64u(auth.credential_id)
    assert cid.startswith("-")
    assert cli(["credentials", "import", "--sqlite", db, f"--credential-id={cid}",
                f"--cose-key={b64u(auth.cose_key)}"]) == 0
    assert cli(["credentials", "revoke", "--sqlite", db, f"--credential-id={cid}"]) == 0


def test_cli_credentials_import_list_revoke(tmp_path, capsys):
    db = str(tmp_path / "s.db")
    SqliteCredentialStore(db).close()
    auth = SoftAuthenticator()
    cid = b64u(auth.credential_id)
    assert cli(["credentials", "import", "--sqlite", db, f"--credential-id={cid}",
                f"--cose-key={b64u(auth.cose_key)}", "--rp-id", RP_ID]) == 0
    assert f"IMPORTED  : {cid}" in capsys.readouterr().out
    with pytest.raises(SystemExit):                            # already imported
        cli(["credentials", "import", "--sqlite", db, f"--credential-id={cid}",
             f"--cose-key={b64u(auth.cose_key)}"])
    with pytest.raises(SystemExit):                            # not a COSE key
        cli(["credentials", "import", "--sqlite", db, "--credential-id=AAAA",
             "--cose-key=AAAA"])
    capsys.readouterr()
    assert cli(["credentials", "list", "--sqlite", db, "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert [(c["credential_id"], c["rp_id"], c["revoked"]) for c in listed] == [
        (cid, RP_ID, None)]
    assert cli(["credentials", "revoke", "--sqlite", db, f"--credential-id={cid}"]) == 0
    assert cli(["credentials", "revoke", "--sqlite", db, f"--credential-id={cid}"]) == 1
