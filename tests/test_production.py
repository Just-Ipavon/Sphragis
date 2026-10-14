"""
Production-layer tests: SQLite anti-replay floor and secrets backends.
"""

import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest  # noqa: E402

from sphragis import StaticKeys, Verifier  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.secrets import (  # noqa: E402
    EnvSecretsBackend,
    FileSecretsBackend,
    KmsSecretsBackend,
    SecretsError,
    build_diversified_keys,
)
from sphragis.sqlstore import SqliteCounterStore  # noqa: E402


# --- SQLite counter store ----------------------------------------------------

def test_sqlite_store_monotonic(tmp_path):
    s = SqliteCounterStore(tmp_path / "c.db")
    assert s.check_and_advance("AABB", 5) is True    # fresh
    assert s.check_and_advance("AABB", 5) is False   # replay
    assert s.check_and_advance("AABB", 3) is False   # rollback
    assert s.check_and_advance("AABB", 6) is True    # advance
    assert s.last_counter("AABB") == 6
    s.close()


def test_sqlite_store_persists_across_reopen(tmp_path):
    db = tmp_path / "c.db"
    s = SqliteCounterStore(db)
    s.check_and_advance("CAFE", 10)
    s.close()
    s2 = SqliteCounterStore(db)
    assert s2.last_counter("CAFE") == 10
    assert s2.check_and_advance("CAFE", 10) is False  # replay survives restart
    s2.close()


def test_sqlite_concurrent_replays_admit_one(tmp_path):
    meta, file_ = os.urandom(16), os.urandom(16)
    tag = EmulatedTag(uid=os.urandom(7), meta_read_key=meta, file_read_key=file_)
    url = tag.tap()
    store = SqliteCounterStore(tmp_path / "v.db")
    verifier = Verifier(StaticKeys(meta, file_), store)

    results = []
    barrier = threading.Barrier(32)

    def worker():
        barrier.wait()
        results.append(verifier.verify(url).verdict.value)

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("AUTHENTIC") == 1
    assert results.count("REPLAY") == 31
    store.close()


# --- Secrets backends --------------------------------------------------------

def test_env_secrets_backend(monkeypatch):
    master = os.urandom(16)
    meta = os.urandom(16)
    monkeypatch.setenv("SPHRAGIS_MASTER_FILE", master.hex())
    monkeypatch.setenv("SPHRAGIS_META_READ", meta.hex())

    keys = build_diversified_keys(EnvSecretsBackend())
    # End-to-end: emulate with these keys, verify AUTHENTIC.
    from sphragis.emulator import tag_from_provider
    tag = tag_from_provider(keys, uid=os.urandom(7))
    assert Verifier(keys).verify(tag.tap()).verdict.value == "AUTHENTIC"


def test_env_secrets_missing_var():
    with pytest.raises(SecretsError):
        EnvSecretsBackend(prefix="NOPE_").get_key("master_file")


def test_env_secrets_bad_length(monkeypatch):
    monkeypatch.setenv("SPHRAGIS_SHORT", "00112233")  # 4 bytes
    with pytest.raises(SecretsError):
        EnvSecretsBackend().get_key("short")


def test_file_secrets_rejects_insecure_perms(tmp_path):
    p = tmp_path / "master_file"
    p.write_text(os.urandom(16).hex())
    os.chmod(p, 0o644)  # group/world readable
    with pytest.raises(SecretsError):
        FileSecretsBackend(tmp_path).get_key("master_file")


def test_file_secrets_accepts_secure_perms(tmp_path):
    p = tmp_path / "meta_read"
    p.write_text(os.urandom(16).hex())
    os.chmod(p, 0o600)
    key = FileSecretsBackend(tmp_path).get_key("meta_read")
    assert len(key) == 16


def test_kms_backend_is_extension_point():
    with pytest.raises(NotImplementedError):
        KmsSecretsBackend().get_key("master_file")
