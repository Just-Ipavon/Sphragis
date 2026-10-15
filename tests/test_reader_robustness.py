"""
The reader side against a malicious or broken tag (#27): every exchange is
bounded, and a failure leaves the reader in a clean state.
"""

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fake_ntag424 import TEST_ORIGINALITY_KEY, FakeNtag424  # noqa: E402
from sphragis.keyprov import (  # noqa: E402
    DiversifiedTagKeys,
    KeyProvisionError,
    MemoryKeyInventory,
    rekey_tag,
)
from sphragis.ndef import NdefError, read_uri  # noqa: E402
from sphragis.transport import TransportError  # noqa: E402
from sphragis.transport import isodep as isodep_mod  # noqa: E402
from sphragis.transport.isodep import IsoDepTransport  # noqa: E402

APDU = bytes.fromhex("00A4040007D276000085010100")


def test_endless_waiting_time_extensions_are_cut_off():
    calls = []

    def tag(frame):
        calls.append(frame)
        return b"\xF2\x01"                       # S(WTX) forever

    with pytest.raises(TransportError, match="waiting-time extensions"):
        IsoDepTransport(tag, max_wtx=5).transceive(APDU)
    assert len(calls) == 6


def test_endless_response_chaining_is_cut_off():
    state = {"bn": 0}

    def tag(frame):
        bn = state["bn"]
        state["bn"] ^= 1
        return bytes([0x12 | bn]) + b"A" * 60   # chained I-block, never the last

    with pytest.raises(TransportError, match="longer than"):
        IsoDepTransport(tag, max_response=1000).transceive(APDU)


def test_a_slow_tag_hits_the_deadline(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(isodep_mod.time, "monotonic", lambda: now[0])

    def tag(frame):
        now[0] += 3.0                            # each answer takes 3 s
        return b"\xF2\x01"

    with pytest.raises(TransportError, match="exceeded"):
        IsoDepTransport(tag, deadline_s=10.0).transceive(APDU)


@pytest.mark.parametrize("pcb", [0x0A, 0x06, 0x0E])   # CID, NAD, both
def test_blocks_with_cid_or_nad_are_refused(pcb):
    with pytest.raises(TransportError, match="CID/NAD"):
        IsoDepTransport(lambda frame: bytes([pcb, 0x90, 0x00])).transceive(APDU)


def test_a_normal_exchange_still_works():
    assert IsoDepTransport(lambda frame: b"\x02\x90\x00").transceive(APDU) == b"\x90\x00"


@pytest.mark.parametrize("nlen", [0x0100, 0x7FFF, 0xFFFF])
def test_an_oversized_nlen_is_refused_before_reading(nlen):
    reads = []

    class Tag:
        def transceive(self, apdu):
            if apdu[1] == 0xB0:
                reads.append(apdu)
                return nlen.to_bytes(2, "big") + b"\x90\x00"
            return b"\x90\x00"

    with pytest.raises(NdefError, match="exceeds"):
        read_uri(Tag())
    assert len(reads) == 1                       # only the NLEN itself


def test_get_card_uid_must_be_seven_bytes():
    tag = FakeNtag424(uid=bytes.fromhex("04112233"))
    scheme = DiversifiedTagKeys(bytes([1]) * 16, bytes([2]) * 16, bytes([3]) * 16)
    with pytest.raises(KeyProvisionError, match="7 bytes"):
        rekey_tag(tag, scheme, inventory=MemoryKeyInventory(),
                  originality_key=TEST_ORIGINALITY_KEY, uid=None)
    assert tag.key_changes == 0


# --- Reader drivers --------------------------------------------------------------

def test_chameleon_turns_the_field_off_when_setup_fails():
    from sphragis.transport.chameleon import ChameleonTransport
    events = []

    class Link:
        def ensure_reader_mode(self):
            events.append("mode")

        def select(self):
            raise TransportError("no tag in the field")

        def field_off(self):
            events.append("field_off")

        def close(self):
            events.append("close")

    with pytest.raises(TransportError):
        ChameleonTransport.over_link(Link())
    assert events == ["mode", "field_off", "close"]


def test_chameleon_opens_the_serial_port_exclusively(monkeypatch):
    from sphragis.transport import chameleon
    opened = {}

    class Serial:
        def __init__(self, **kwargs):
            opened.update(kwargs)
            self.dtr = False

    fake = types.SimpleNamespace(Serial=Serial, SerialException=OSError)
    monkeypatch.setitem(sys.modules, "serial", fake)
    chameleon.ChameleonLink.open_serial("/dev/ttyACM0")
    assert opened["exclusive"] is True and opened["port"] == "/dev/ttyACM0"
