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
    assert "40E0EEC1F121" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [
    ["--base-url", "https://example.com/t"],                         # no reader
    ["--reader", "emulator", "--base-url", "https://example.com/t"],  # cannot provision
    ["--reader", "pn532", "--base-url", "https://example.com/t"],     # no --yes
])
def test_provision_refuses_unsafe_invocations(argv):
    with pytest.raises(SystemExit):
        _load("provision").main(argv)


def test_provision_with_fake_picc(capsys):
    tool = _load("provision")
    tag = FakeNtag424()
    tool.reader_factory = lambda args: (lambda: _Wrapped(tag))
    argv = ["--reader", "pn532", "--base-url", "https://example.com/t", "--yes"]
    assert tool.main(argv) == 0
    assert "provisioned and verified" in capsys.readouterr().out
    assert tool.main(argv) == 0
    assert "already provisioned" in capsys.readouterr().out
