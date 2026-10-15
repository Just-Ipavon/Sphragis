"""
Counter-file durability and secrets handling.
"""

import json
import multiprocessing as mp
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis.counterstore import CounterStore, CounterStoreError  # noqa: E402
from sphragis.diversify import DiversifiedKeys  # noqa: E402
from sphragis.emulator import EmulatedTag  # noqa: E402
from sphragis.keyprov import DiversifiedTagKeys  # noqa: E402
from sphragis.secrets import FileSecretsBackend, SecretsError  # noqa: E402
from sphragis.sqlstore import SqliteCounterStore  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
K1, K2, K3 = bytes([1]) * 16, bytes([2]) * 16, bytes([3]) * 16


# --- The JSON counter file --------------------------------------------------------

@pytest.mark.parametrize("content,why", [
    ("", "empty"), ("   \n", "empty"),            # a truncated write: say so
    ("not json", "not a valid"), ("[1, 2]", "not a valid"), ('{"04AA": "x"}', "not a valid"),
])
def test_empty_or_corrupt_file_is_refused(tmp_path, content, why):
    path = tmp_path / "counters.json"
    path.write_text(content)
    with pytest.raises(CounterStoreError, match=why):
        CounterStore(path)


def test_uids_are_normalised_when_loaded(tmp_path):
    path = tmp_path / "counters.json"
    path.write_text(json.dumps({"04aabbccddeeff": 9}))
    store = CounterStore(path)
    assert store.last_counter("04AABBCCDDEEFF") == 9
    assert not store.check_and_advance("04AABBCCDDEEFF", 9)


def test_two_handles_on_one_file_do_not_lose_the_floor(tmp_path):
    # Audit reproduction: each process kept its own copy and overwrote the
    # other's floor, letting a replay through.
    path = tmp_path / "counters.json"
    a, b = CounterStore(path), CounterStore(path)
    assert a.check_and_advance("04AA", 5)
    assert not b.check_and_advance("04AA", 5)          # b re-reads before writing
    assert b.check_and_advance("04BB", 1)
    assert CounterStore(path).last_counter("04AA") == 5  # a's floor survived b's write


def _process_advance(path, value, start):
    start.wait()
    return CounterStore(path).check_and_advance("04CD", value)


@pytest.mark.skipif(os.name != "posix", reason="flock is POSIX")
def test_processes_sharing_the_file_accept_a_counter_once(tmp_path):
    path = str(tmp_path / "counters.json")
    ctx = mp.get_context("spawn")
    with ctx.Manager() as manager:
        start = manager.Event()
        with ctx.Pool(6) as pool:
            pending = [pool.apply_async(_process_advance, (path, 7, start)) for _ in range(6)]
            start.set()
            results = [p.get(timeout=60) for p in pending]
    assert results.count(True) == 1, results


def test_a_failed_write_leaves_the_floor_where_it_was(tmp_path, monkeypatch):
    path = tmp_path / "counters.json"
    store = CounterStore(path)
    assert store.check_and_advance("04AA", 5)

    def broken(*args):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken)
    with pytest.raises(OSError):
        store.check_and_advance("04AA", 6)
    monkeypatch.undo()
    assert store.last_counter("04AA") == 5                 # memory did not move first
    assert CounterStore(path).last_counter("04AA") == 5
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("tmp")]


def test_writes_are_fsynced(tmp_path, monkeypatch):
    calls = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd) or real(fd))
    CounterStore(tmp_path / "counters.json").check_and_advance("04AA", 1)
    assert len(calls) >= 2                                 # the file and its directory


@posix_only
def test_counter_file_is_owner_only(tmp_path):
    path = tmp_path / "counters.json"
    CounterStore(path).check_and_advance("04AA", 1)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@posix_only
def test_sqlite_store_is_owner_only_and_fully_synchronous(tmp_path):
    path = tmp_path / "c.db"
    store = SqliteCounterStore(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert store._connection().execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


# --- Secrets --------------------------------------------------------------------------

def _secrets(tmp_path, **files):
    d = tmp_path / "keys"
    d.mkdir(mode=0o700)
    for name, value in files.items():
        p = d / name
        p.write_text(value)
        p.chmod(0o600)
    return d


def test_all_zero_keys_are_refused(tmp_path):
    d = _secrets(tmp_path, meta_read="00" * 16)
    with pytest.raises(SecretsError, match="all zero"):
        FileSecretsBackend(d).get_key("meta_read")


@posix_only
def test_symlinked_key_files_are_refused(tmp_path):
    d = _secrets(tmp_path, real="11" * 16)
    (d / "meta_read").symlink_to(d / "real")
    with pytest.raises(SecretsError, match="safely"):
        FileSecretsBackend(d).get_key("meta_read")


@posix_only
def test_a_writable_directory_is_refused(tmp_path):
    d = _secrets(tmp_path, meta_read="11" * 16)
    d.chmod(0o777)
    with pytest.raises(SecretsError, match="writable"):
        FileSecretsBackend(d).get_key("meta_read")


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_readable_key_files_are_refused(tmp_path, mode):
    d = _secrets(tmp_path, meta_read="11" * 16)
    (d / "meta_read").chmod(mode)
    with pytest.raises(SecretsError, match="permissions"):
        FileSecretsBackend(d).get_key("meta_read")


@posix_only
def test_non_regular_files_and_odd_names_are_refused(tmp_path):
    d = _secrets(tmp_path)
    (d / "meta_read").mkdir(mode=0o700)
    with pytest.raises(SecretsError):
        FileSecretsBackend(d).get_key("meta_read")
    for name in ("", "..", "a/b"):
        with pytest.raises(SecretsError, match="invalid key name"):
            FileSecretsBackend(d).get_key(name)


def test_a_good_key_file_still_loads(tmp_path):
    d = _secrets(tmp_path, meta_read="11" * 16)
    assert FileSecretsBackend(d).get_key("meta_read") == bytes([0x11]) * 16


def test_equal_or_zero_master_keys_are_refused():
    with pytest.raises(ValueError, match="different"):
        DiversifiedKeys(K1, K1)
    for args in [(K1, K1, K2), (K1, K2, K2), (K1, K2, K1), (bytes(16), K2, K3)]:
        with pytest.raises(ValueError):
            DiversifiedTagKeys(*args)
    DiversifiedTagKeys(K1, K2, K3)                         # distinct, non-zero: fine


def test_settings_repr_hides_the_database_url():
    pytest.importorskip("fastapi")
    from sphragis.api.settings import ApiSettings
    s = ApiSettings.from_env({"SPHRAGIS_DB_URL": "postgresql://u:s3cret@db/x"})
    assert "s3cret" not in repr(s) and s.db_url.endswith("@db/x")


# --- CLI keys ------------------------------------------------------------------------

def _tap(meta, file_):
    return EmulatedTag(uid=bytes.fromhex("04112233445566"), meta_read_key=meta,
                       file_read_key=file_).tap()


def test_cli_reads_keys_from_a_secrets_directory(tmp_path, capsys):
    from sphragis.cli import main
    d = _secrets(tmp_path, master_file="11" * 16, meta_read="22" * 16)
    keys = DiversifiedKeys(bytes([0x11]) * 16, bytes([0x22]) * 16, context=b"DEMO")
    url = _tap(keys.meta_read_key(), keys.file_read_key(bytes.fromhex("04112233445566")))
    assert main(["verify", "--secrets-dir", str(d), "--context", "DEMO", url]) == 0
    captured = capsys.readouterr()
    assert "AUTHENTIC" in captured.out and "warning" not in captured.err


def test_cli_warns_about_keys_on_the_command_line(capsys):
    from sphragis.cli import main
    url = _tap(K1, K2)
    assert main(["verify", "--meta-key", K1.hex(), "--file-key", K2.hex(), url]) == 0
    assert "visible to other users" in capsys.readouterr().err


def test_cli_reads_keys_from_the_environment(monkeypatch, capsys):
    from sphragis.cli import main
    monkeypatch.setenv("SPHRAGIS_CLI_META_KEY", K1.hex())
    monkeypatch.setenv("SPHRAGIS_CLI_FILE_KEY", K2.hex())
    assert main(["verify", _tap(K1, K2)]) == 0
    assert "warning" not in capsys.readouterr().err


def test_cli_without_keys_or_terminal_refuses(monkeypatch):
    from sphragis.cli import main
    monkeypatch.delenv("SPHRAGIS_CLI_META_KEY", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit, match="no keys"):
        main(["verify", _tap(K1, K2)])


def test_ev2_session_repr_hides_the_session_keys():
    from sphragis.ev2 import Session
    k_enc, k_mac = bytes([0xAB]) * 16, bytes([0xCD]) * 16
    text = repr(Session(transport=None, ti=bytes(4), k_enc=k_enc, k_mac=k_mac))
    assert k_enc.hex() not in text.lower() and k_mac.hex() not in text.lower()
    assert "cmd_ctr" in text
