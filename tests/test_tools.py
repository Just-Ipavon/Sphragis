"""Smoke tests for tools/*.py, run against the emulator / fake PICC (no hardware)."""

import importlib.util
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from fake_ntag424 import FakeNtag424  # noqa: E402

from sphragis.transport import ApduTransport  # noqa: E402

TOOLS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")


def _load(name):
    spec = importlib.util.spec_from_file_location(f"tool_{name}", os.path.join(TOOLS, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Wrapped(ApduTransport):
    def __init__(self, tag):
        self.tag = tag

    def transceive(self, apdu):
        return self.tag.transceive(apdu)


def test_sdm_probe_emulator(capsys):
    assert _load("sdm_probe").main(["--reader", "emulator"]) == 0
    out = capsys.readouterr().out
    assert "00 A4 04 0C 07 D2 76 00 00 85 01 01 00" in out and "SW     : 9000" in out


def test_tap_verify_emulator(capsys):
    assert _load("tap_verify").main(["--reader", "emulator", "--taps", "3"]) == 0
    out = capsys.readouterr().out
    assert out.count("GENUINE") == 3 and "ctr 3" in out


def test_provision_offline_dry_run(capsys):
    tool = _load("provision")
    assert tool.main(["--dry-run", "--base-url", "https://example.com/t"]) == 0
    out = capsys.readouterr().out
    assert "4000E0C1F121" in out and "locked to key 0" in out     # writes locked
    assert tool.main(["--dry-run", "--base-url", "https://example.com/t",
                      "--leave-writable"]) == 0
    assert "40E0EEC1F121" in capsys.readouterr().out           # factory access kept


@pytest.mark.parametrize("argv", [
    ["--base-url", "https://example.com/t"],                         # no reader
    ["--reader", "emulator", "--base-url", "https://example.com/t"],  # cannot provision
    ["--reader", "chameleon", "--base-url", "https://example.com/t"],     # no --yes
])
def test_provision_refuses_unsafe_invocations(argv):
    with pytest.raises(SystemExit):
        _load("provision").main(argv)


def test_provision_with_fake_picc(capsys):
    tool = _load("provision")
    tag = FakeNtag424()
    tool.reader_factory = lambda args: (lambda: _Wrapped(tag))
    argv = ["--reader", "chameleon", "--base-url", "https://example.com/t", "--yes",
            "--uid", tag.uid.hex()]
    assert tool.main(argv) == 0
    assert "provisioned and verified" in capsys.readouterr().out
    assert tool.main(argv) == 0
    assert "already provisioned" in capsys.readouterr().out


def test_provision_asks_to_type_the_uid(capsys, monkeypatch):
    tool = _load("provision")
    tag = FakeNtag424()
    tool.reader_factory = lambda args: (lambda: _Wrapped(tag))
    argv = ["--reader", "chameleon", "--base-url", "https://example.com/t", "--yes"]
    monkeypatch.setattr("builtins.input", lambda prompt: "04")
    assert tool.main(argv) == 1 and tag.writes == 0
    assert "aborted" in capsys.readouterr().out
    monkeypatch.setattr("builtins.input", lambda prompt: tag.uid.hex())
    assert tool.main(argv) == 0 and tag.settings.sdm_enabled


def test_provision_refuses_a_tag_whose_keys_it_lacks(capsys):
    import os as _os
    tool = _load("provision")
    tag = FakeNtag424(keys=[_os.urandom(16)] + [bytes(16)] * 4)
    tool.reader_factory = lambda args: (lambda: _Wrapped(tag))
    argv = ["--reader", "chameleon", "--base-url", "https://example.com/t", "--yes",
            "--uid", tag.uid.hex()]
    assert tool.main(argv) == 2 and tag.writes == 0
    assert "REFUSED" in capsys.readouterr().out


def test_provision_enc_offline_dry_run(capsys):
    tool = _load("provision")
    argv = ["--dry-run", "--base-url", "https://example.com/t",
            "--enc-data", "0123456789ABCDEF"]
    assert tool.main(argv) == 0
    out = capsys.readouterr().out
    assert "4000E0D1F121" in out and "locked to key 0" in out


@pytest.mark.parametrize("extra", [
    ["--enc-data", "short"],                                   # not 16 bytes
    ["--enc-data-hex", "zz" * 16],                             # not hex
    ["--enc-data", "0123456789ABCDEF", "--enc-data-hex", "00" * 16],
    ["--enc-data", "0123456789ABCDEF", "--write-key", "14"],   # not a key
    ["--write-key", "2"],                                      # verifier-held key
    ["--write-key", "1"],
    ["--enc-data", "0123456789ABCDEF", "--leave-writable"],
    ["--write-key", "3", "--leave-writable"],
])
def test_provision_enc_rejects_bad_arguments(extra):
    with pytest.raises(SystemExit):
        _load("provision").main(["--dry-run", "--base-url", "https://example.com/t",
                                 *extra])


def test_provision_enc_with_fake_picc(capsys):
    tool = _load("provision")
    tag = FakeNtag424()
    tool.reader_factory = lambda args: (lambda: _Wrapped(tag))
    argv = ["--reader", "chameleon", "--base-url", "https://example.com/t", "--yes",
            "--uid", tag.uid.hex(), "--enc-data-hex", "00112233445566778899AABBCCDDEEFF"]
    assert tool.main(argv) == 0
    out = capsys.readouterr().out
    assert "provisioned and verified" in out and "file data match" in out
    assert tag.settings.enc_enabled


def test_tap_verify_enc_with_fake_picc(capsys):
    from sphragis.provision import provision_tag

    tag = FakeNtag424()
    provision_tag(tag, "https://example.com/t", file_data=b"0123456789ABCDEF")
    tool = _load("tap_verify")
    tool.reader_factory = lambda args: (lambda: _Wrapped(tag))
    assert tool.main(["--reader", "chameleon", "--taps", "2", "--enc"]) == 0
    out = capsys.readouterr().out
    assert out.count("AUTHENTIC") == 2
    assert out.count(b"0123456789ABCDEF".hex().upper()) == 2


def test_tap_verify_enc_refuses_emulator():
    with pytest.raises(SystemExit):
        _load("tap_verify").main(["--reader", "emulator", "--enc"])
