"""End to end on the packaged simulator: provision -> tap -> rekey -> reset, no hardware."""

import importlib.util
import json
import os
import stat

import pytest

from sphragis.simulator import (
    MAX_READ_COUNTER,
    PersistentSimulatorTransport,
    SimulatedNtag424,
)

TOOLS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")
URL = "https://example.com/t"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"tool_{name}",
                                                  os.path.join(TOOLS, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bench(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    for name in ("master_admin", "master_file", "meta_read"):
        path = keys / name
        path.write_text(os.urandom(16).hex() + "\n")
        path.chmod(0o600)
    state = tmp_path / "tag.json"
    tag = SimulatedNtag424.load_or_create(state)
    return dict(state=str(state), keys=str(keys), inventory=str(tmp_path / "inv.db"),
                uid=tag.uid.hex(), sim=["--reader", "emulator", "--emulator-state", str(state)])


def _tag(bench):
    return SimulatedNtag424.load(bench["state"])


def test_state_file_is_private_and_round_trips(bench):
    assert stat.S_IMODE(os.stat(bench["state"]).st_mode) == 0o600
    tag = _tag(bench)
    tag.counter = 41
    again = SimulatedNtag424.from_state(json.loads(json.dumps(tag.to_state())))
    assert again.to_state() == tag.to_state()


@pytest.mark.parametrize("change", [
    {"version": 2},
    {"counter": MAX_READ_COUNTER + 1},
    {"keys": ["00" * 16] * 4},
])
def test_corrupt_state_is_refused(bench, change):
    state = _tag(bench).to_state() | change
    with pytest.raises(ValueError):
        SimulatedNtag424.from_state(state)


def test_full_lifecycle_through_the_tools(bench, capsys):
    sim, uid = bench["sim"], bench["uid"]
    key_args = ["--secrets-dir", bench["keys"], "--inventory", bench["inventory"],
                "--context", "CI", "--uid", uid]

    assert _load("provision").main([*sim, "--base-url", URL, "--yes", "--uid", uid]) == 0
    assert "provisioned and verified" in capsys.readouterr().out
    assert _load("tap_verify").main([*sim, "--taps", "2"]) == 0
    assert capsys.readouterr().out.count("GENUINE") == 2

    assert _load("rekey").main([*sim, *key_args, "--yes"]) == 0
    assert "keys changed and verified" in capsys.readouterr().out
    assert all(k != bytes(16) for k in _tag(bench).keys)
    assert _load("tap_verify").main([*sim, "--secrets-dir", bench["keys"],
                                     "--context", "CI"]) == 0
    assert "GENUINE" in capsys.readouterr().out
    assert _load("tap_verify").main(sim) == 1          # factory keys no longer verify

    assert _load("rekey").main([*sim, *key_args, "--to-factory", "--yes"]) == 0
    assert all(k == bytes(16) for k in _tag(bench).keys)
    capsys.readouterr()
    assert _load("tap_verify").main(sim) == 0
    assert "GENUINE" in capsys.readouterr().out


def test_encrypted_file_data_lifecycle(bench, capsys):
    sim, uid = bench["sim"], bench["uid"]
    assert _load("provision").main([*sim, "--base-url", URL, "--yes", "--uid", uid,
                                    "--enc-data", "0123456789ABCDEF"]) == 0
    capsys.readouterr()
    assert _load("tap_verify").main([*sim, "--enc", "--taps", "2"]) == 0
    assert capsys.readouterr().out.count(b"0123456789ABCDEF".hex().upper()) == 2


def test_rekey_refuses_a_clone_of_a_keyed_uid(bench, tmp_path, capsys):
    sim, uid = bench["sim"], bench["uid"]
    key_args = ["--secrets-dir", bench["keys"], "--inventory", bench["inventory"],
                "--uid", uid]
    assert _load("rekey").main([*sim, *key_args, "--yes"]) == 0
    # A second, factory-fresh tag answering with the same UID.
    clone = SimulatedNtag424(uid=bytes.fromhex(uid))
    clone_state = tmp_path / "clone.json"
    clone.save(clone_state)
    clone_sim = ["--reader", "emulator", "--emulator-state", str(clone_state)]
    capsys.readouterr()
    assert _load("rekey").main([*clone_sim, *key_args, "--yes"]) == 2
    assert "REFUSED" in capsys.readouterr().out
    assert SimulatedNtag424.load(clone_state).key_changes == 0


def test_rekey_checks_the_simulator_signature(bench, capsys):
    tag = _tag(bench)
    tag.signature = bytes(56)                      # not signed by the test key
    tag.save(bench["state"])
    assert _load("rekey").main([*bench["sim"], "--secrets-dir", bench["keys"],
                                "--inventory", bench["inventory"], "--uid",
                                bench["uid"], "--yes"]) == 2
    assert "REFUSED" in capsys.readouterr().out
    assert all(k == bytes(16) for k in _tag(bench).keys)


@pytest.mark.parametrize("name,argv", [
    ("provision", ["--reader", "emulator", "--base-url", URL, "--yes"]),
    ("rekey", ["--reader", "emulator", "--secrets-dir", "k", "--inventory", "i", "--yes"]),
    ("tap_verify", ["--reader", "chameleon", "--emulator-state", "x.json"]),
])
def test_read_only_emulator_and_stray_state_are_refused(name, argv):
    with pytest.raises(SystemExit):
        _load(name).main(argv)


def test_unreadable_tag_is_reported_without_a_traceback(bench, capsys):
    assert _load("tap_verify").main(bench["sim"]) == 2      # factory tag: empty NDEF
    assert "ERROR" in capsys.readouterr().out


def test_status_words_match_the_chip(bench):
    with PersistentSimulatorTransport(bench["state"]) as t:
        assert t.transceive(bytes.fromhex("80A4040000"))[-2:] == b"\x6E\x00"
        assert t.transceive(bytes.fromhex("00840000"))[-2:] == b"\x6D\x00"
        assert t.transceive(bytes.fromhex("9060000000"))[-2:] == b"\x91\x1C"
        assert t.transceive(b"\x00")[-2:] == b"\x67\x00"


def test_counter_stops_at_the_24_bit_limit(bench):
    from sphragis.provision import provision_tag
    tag = _tag(bench)
    provision_tag(tag, URL)
    tag.counter = MAX_READ_COUNTER
    from sphragis.ndef import read_uri
    read_uri(tag)
    assert tag.counter == MAX_READ_COUNTER
