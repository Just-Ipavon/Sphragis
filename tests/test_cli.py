"""
Command line and emulator edge cases (#68): bad arguments are usage errors,
library errors become one-line messages, and no traceback reaches the user.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sphragis import StaticKeys, Verifier  # noqa: E402
from sphragis.cli import main  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.emulator import (  # noqa: E402
    MAX_READ_COUNTER,
    EmulatedEncTag,
    EmulatedTag,
)

KEY = "00" * 16
KEYS = ("--meta-key", KEY, "--file-key", KEY)
UID = "04DE5F1EACC040"


@pytest.mark.parametrize("extra", [
    ("--uid", "04DE5F"), ("--uid", "zz"),
    ("--uid", UID, "--counter", "-5"), ("--uid", UID, "--counter", str(MAX_READ_COUNTER)),
    ("--uid", UID, "--counter", "x"), ("--uid", UID, "--taps", "0"),
])
def test_emulate_bad_arguments_are_usage_errors(extra, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["emulate", *KEYS, *extra])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and "error:" in err


def test_emulate_refuses_taps_past_the_counter_limit():
    with pytest.raises(SystemExit, match="24-bit limit"):
        main(["emulate", *KEYS, "--uid", UID, "--counter", str(MAX_READ_COUNTER - 1),
              "--taps", "2"])


def test_emulate_reaches_the_last_counter(capsys):
    assert main(["emulate", *KEYS, "--uid", UID, "--counter",
                 str(MAX_READ_COUNTER - 1)]) == 0
    assert "picc_data=" in capsys.readouterr().out


def test_verify_with_an_empty_store_is_an_error_message(tmp_path):
    store = tmp_path / "counters.json"
    store.write_text("")
    with pytest.raises(SystemExit) as exc:
        main(["verify", *KEYS, "--store", str(store), "https://example.com/t?x=1"])
    assert str(exc.value).startswith("error:") and "empty" in str(exc.value)


def _tag(**kw):
    return EmulatedTag(uid=bytes.fromhex(UID), meta_read_key=bytes(16),
                       file_read_key=bytes(16), **kw)


@pytest.mark.parametrize("counter", [-1, MAX_READ_COUNTER + 1])
def test_emulator_refuses_an_out_of_range_counter(counter):
    with pytest.raises(ValueError, match="read_counter"):
        _tag(read_counter=counter)


def test_emulator_stops_at_the_counter_limit():
    tag = _tag(read_counter=MAX_READ_COUNTER - 1)
    tag.tap()
    with pytest.raises(ValueError, match="24-bit limit"):
        tag.tap()
    assert tag.read_counter == MAX_READ_COUNTER


def test_base_url_with_a_query_keeps_it_and_verifies():
    tag = _tag(base_url="https://x.io/t?id=7")
    url = tag.tap()
    assert url.startswith("https://x.io/t?id=7&picc_data=") and url.count("?") == 1
    assert Verifier(StaticKeys(bytes(16), bytes(16)), CounterStore()).verify(url).ok
    enc = EmulatedEncTag(uid=bytes.fromhex(UID), meta_read_key=bytes(16),
                         file_read_key=bytes(16), base_url="https://x.io/t?id=7")
    assert enc.tap().startswith("https://x.io/t?id=7&picc_data=")


def test_velocity_ignores_history_recorded_after_the_tap():
    from sphragis.detection import CloneDetector
    detector = CloneDetector()
    detector.analyze("04AA", 1, timestamp=2000.0, reader_id="gate-B")
    later = detector.analyze("04AA", 2, timestamp=1000.0, reader_id="gate-A")
    assert "impossible_velocity" not in {s.name for s in later.signals}
