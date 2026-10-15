"""
Chameleon Ultra backend: serial framing against reference frames produced by
the official client, and the full stack (serial -> ISO-DEP -> NTAG 424 DNA
model) through a fake device. No hardware needed.
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from fake_isodep import FakeCard  # noqa: E402
from fake_ntag424 import FakeNtag424  # noqa: E402

from sphragis.apdu import select_ndef_app  # noqa: E402
from sphragis.provision import provision_tag  # noqa: E402
from sphragis.transport import ChameleonTransport, TransportError  # noqa: E402
from sphragis.transport.chameleon import (  # noqa: E402
    CMD_CHANGE_DEVICE_MODE,
    CMD_GET_DEVICE_MODE,
    CMD_HF14A_RAW,
    CMD_HF14A_SCAN_KEEP,
    DEVICE_MAX_FSC,
    OPT_FIELD_OFF,
    OPT_ISODEP_FRAME,
    STATUS_HF_TAG_NO,
    STATUS_HF_TAG_OK,
    STATUS_SUCCESS,
    ChameleonLink,
    encode_frame,
    parse_scan,
)

UID = bytes.fromhex("04084582161690")
ATS = bytes.fromhex("067777710280")          # NTAG 424 DNA: FSCI 7 -> FSC 128


# --- Framing ----------------------------------------------------------------


@pytest.mark.parametrize("cmd, data, frame", [
    # Produced by ChameleonCom.make_data_frame_bytes of the official client.
    (1002, b"", "11ef03ea000000001300"),
    (2016, b"", "11ef07e0000000001900"),
    (2010, bytes([0x6C]) + struct.pack("!HH", 500, 16) + bytes.fromhex("0290"),
     "11ef07da00000007186c01f400100290fd"),
])
def test_encode_frame_matches_official_client(cmd, data, frame):
    assert encode_frame(cmd, data).hex() == frame


def test_parse_scan():
    data = bytes([7]) + UID + bytes.fromhex("4403") + b"\x20" + bytes([len(ATS)]) + ATS
    tag = parse_scan(data)
    assert (tag.uid, tag.atqa, tag.sak, tag.ats) == (UID, b"\x44\x03", 0x20, ATS)
    with pytest.raises(TransportError):
        parse_scan(data[:-1])


# --- Fake device ------------------------------------------------------------


class FakeChameleon:
    """Serial-port stand-in that decodes host frames and answers like the device."""

    def __init__(self, card=None, mode=1, garbage=b""):
        self.card = card
        self.mode = mode
        self.rx = bytearray(garbage)        # bytes waiting for the host
        self.commands = []
        self.raw_frames = []
        self.field_on = False
        self.closed = False
        self.corrupt_next = False

    def write(self, data):
        cmd, status, length = struct.unpack("!HHH", data[2:8])
        payload = bytes(data[9 : 9 + length])
        assert encode_frame(cmd, payload, status) == bytes(data)
        self.commands.append(cmd)
        reply = encode_frame(cmd, *self._handle(cmd, payload)[::-1])
        if self.corrupt_next:
            reply = reply[:-1] + bytes([reply[-1] ^ 0xFF])
            self.corrupt_next = False
        self.rx += reply
        return len(data)

    def _handle(self, cmd, payload):
        if cmd == CMD_GET_DEVICE_MODE:
            return STATUS_SUCCESS, bytes([self.mode])
        if cmd == CMD_CHANGE_DEVICE_MODE:
            self.mode = payload[0]
            return STATUS_SUCCESS, b""
        if cmd == CMD_HF14A_SCAN_KEEP:
            if self.mode != 1:
                return 0x66, b""
            if self.card is None:
                return STATUS_HF_TAG_NO, b""
            self.field_on = True
            return STATUS_HF_TAG_OK, (bytes([7]) + UID + b"\x44\x03\x20"
                                      + bytes([len(ATS)]) + ATS)
        if cmd == CMD_HF14A_RAW:
            options, _timeout, bits = struct.unpack("!BHH", payload[:5])
            frame = payload[5:]
            assert bits == len(frame) * 8
            if options == OPT_FIELD_OFF:
                self.field_on = False
                return STATUS_HF_TAG_OK, b""
            assert options == OPT_ISODEP_FRAME and self.field_on
            if len(frame) > DEVICE_MAX_FSC - 2:             # firmware FIFO limit
                return 0x60, b""
            self.raw_frames.append(frame)
            return STATUS_HF_TAG_OK, self.card.exchange(frame)
        return 0x67, b""

    def read(self, size=1):
        out = bytes(self.rx[:size])
        del self.rx[:size]
        return out

    def close(self):
        self.closed = True


def _open(dev):
    return ChameleonTransport.over_link(ChameleonLink(dev, timeout_s=0.2))


# --- Transport --------------------------------------------------------------


def test_select_takes_fsc_from_scan_ats_and_never_resends_rats():
    card = FakeCard(lambda apdu: b"\x90\x00")
    dev = FakeChameleon(card)
    t = _open(dev)
    assert t.tag.uid == UID and t.ats == ATS
    assert t.fsc == DEVICE_MAX_FSC                    # ATS says 128, device caps
    assert t.transceive(select_ndef_app()) == b"\x90\x00"
    assert b"\xE0\x80" not in dev.raw_frames          # card already in ISO-DEP
    assert CMD_CHANGE_DEVICE_MODE not in dev.commands  # already a reader
    t.close()
    assert not dev.field_on and dev.closed
    t.close()                                          # idempotent


def test_switches_to_reader_mode_when_emulating():
    dev = FakeChameleon(FakeCard(lambda apdu: b"\x90\x00"), mode=0)
    with _open(dev):
        pass
    assert CMD_CHANGE_DEVICE_MODE in dev.commands and dev.mode == 1


def test_no_tag_fails_and_releases_port():
    dev = FakeChameleon(card=None)
    with pytest.raises(TransportError, match="no tag"):
        _open(dev)
    assert dev.closed


def test_resyncs_on_garbage_and_rejects_bad_lrc():
    dev = FakeChameleon(FakeCard(lambda apdu: b"\x90\x00"), garbage=b"\x00\xFF\x42")
    t = _open(dev)
    dev.corrupt_next = True
    with pytest.raises(TransportError, match="LRC"):
        t.transceive(select_ndef_app())


def test_silent_device_times_out():
    class Mute(FakeChameleon):
        def read(self, size=1):
            return b""

    with pytest.raises(TransportError, match="timeout"):
        _open(Mute())


def test_provisioning_end_to_end_over_serial_stack():
    tag = FakeNtag424(uid=UID)              # the UID the fake Chameleon reports
    dev = FakeChameleon(FakeCard(tag.transceive, fsd=64))   # forces PICC chaining
    with _open(dev) as t:
        report = provision_tag(t, "https://example.com/t")
    assert report.wrote_ndef and report.changed_settings and report.verified
    assert all(len(f) <= DEVICE_MAX_FSC - 2 for f in dev.raw_frames)
    # The template goes out in single-frame ISOUpdateBinary pieces, each one
    # written atomically by the tag, never as chained I-blocks.
    updates = [f for f in dev.raw_frames if f[1:3] == b"\x00\xD6"]
    assert len(updates) >= 2 and not any(f[0] & 0x10 for f in updates)
    assert not any(f[0] & 0xE2 == 0x02 and f[0] & 0x10 for f in dev.raw_frames)
