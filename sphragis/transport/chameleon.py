"""
Chameleon Ultra backend (hardware host; needs `sphragis[hw]` for pyserial).

The Chameleon Ultra, in reader mode, is used purely as a raw ISO 14443-A frame
pipe: it selects the tag (anticollision, CRC_A, RATS), and Sphragis does
everything above that in Python — ISO-DEP framing (IsoDepTransport) and, on
top, NTAG 424 DNA secure messaging (AES session keys, CMAC). No key ever
touches the device.

The device speaks a small binary protocol over USB CDC serial (115200 8N1,
DTR on). Every frame, in both directions, is

    SOF(0x11) LRC1 | CMD u16 | STATUS u16 | LEN u16 | LRC2 | DATA[LEN] | LRC3

big-endian, where each LRC is the two's complement of the byte sum of
everything before it. Only four commands are used:

    GET_DEVICE_MODE / CHANGE_DEVICE_MODE   make sure the device is a reader
    HF14A_SCAN_KEEP    select + RATS, RF field kept on; returns UID/ATQA/SAK/ATS
    HF14A_RAW          one 14443-A frame out, one back (CRC_A added/checked)

Note: the device's selection already performs RATS, so the card is in ISO-DEP
state when it returns; sending RATS again gets no answer. The FSC is therefore
taken from the ATS the scan returns, never from a second RATS, and capped at
the device's own 64-byte frame limit (longer APDUs go out chained).

Verified against firmware v2.1 (RfidResearchGroup/ChameleonUltra) and an
NTAG 424 DNA; see docs/hardware.md.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Protocol

from . import TransportError
from .isodep import IsoDepTransport, RawExchange

SOF = 0x11
_HEAD = struct.Struct("!BBHHHB")  # SOF, LRC1, cmd, status, len, LRC2

CMD_GET_DEVICE_MODE = 1002
CMD_CHANGE_DEVICE_MODE = 1001
CMD_HF14A_RAW = 2010
CMD_HF14A_SCAN_KEEP = 2016

STATUS_HF_TAG_OK = 0x00
STATUS_HF_TAG_NO = 0x01
STATUS_SUCCESS = 0x68

MODE_READER = 1

# HF14A_RAW option bits (first payload byte, MSB first).
_OPT_ACTIVATE_RF = 0x80
_OPT_WAIT_RESPONSE = 0x40
_OPT_APPEND_CRC = 0x20
_OPT_AUTO_SELECT = 0x10
_OPT_KEEP_RF = 0x08
_OPT_CHECK_CRC = 0x04

# One ISO-DEP block: CRC appended and checked, field kept on for the next one.
OPT_ISODEP_FRAME = _OPT_WAIT_RESPONSE | _OPT_APPEND_CRC | _OPT_KEEP_RF | _OPT_CHECK_CRC
OPT_FIELD_OFF = 0x00

FRAME_TIMEOUT_MS = 500

# The reader chip FIFO is 64 bytes and the firmware rejects (STATUS_PAR_ERR)
# any frame longer than 62 bytes plus CRC_A, whatever FSC the card announces.
DEVICE_MAX_FSC = 64


class SerialPort(Protocol):
    """The subset of pyserial's Serial used here (lets tests plug a fake)."""

    def write(self, data: bytes) -> int | None: ...
    def read(self, size: int = 1) -> bytes: ...
    def close(self) -> None: ...


def lrc(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def encode_frame(cmd: int, data: bytes = b"", status: int = 0) -> bytes:
    head = bytearray(_HEAD.pack(SOF, 0, cmd, status, len(data), 0))
    head[1] = lrc(head[:1])
    head[8] = lrc(head[:8])
    body = bytes(head) + data
    return body + bytes([lrc(body)])


@dataclass(frozen=True)
class Tag14a:
    uid: bytes
    atqa: bytes
    sak: int
    ats: bytes


def parse_scan(data: bytes) -> Tag14a:
    """First tag of a HF14A_SCAN(_KEEP) reply: uidlen|uid|atqa[2]|sak|atslen|ats."""
    try:
        n = data[0]
        uid, atqa, sak = data[1 : 1 + n], data[1 + n : 3 + n], data[3 + n]
        ats_len = data[4 + n]
        ats = data[5 + n : 5 + n + ats_len]
    except IndexError as exc:
        raise TransportError(f"truncated scan reply {data.hex().upper()}") from exc
    if len(ats) != ats_len or len(uid) != n:
        raise TransportError(f"truncated scan reply {data.hex().upper()}")
    return Tag14a(bytes(uid), bytes(atqa), sak, bytes(ats))


class ChameleonLink:
    """Synchronous command/response over the Chameleon Ultra serial protocol."""

    def __init__(self, port: SerialPort, timeout_s: float = 3.0) -> None:
        self._port = port
        self.timeout_s = timeout_s

    @classmethod
    def open_serial(cls, device: str) -> "ChameleonLink":
        try:
            import serial  # type: ignore[import-untyped]
        except ImportError as exc:
            raise TransportError("pyserial is not installed (pip install 'sphragis[hw]')") from exc
        try:
            port = serial.Serial(port=device, baudrate=115200, timeout=0.1)
            port.dtr = True
        except serial.SerialException as exc:
            raise TransportError(f"cannot open {device}: {exc}") from exc
        return cls(port)

    def command(self, cmd: int, data: bytes = b"") -> tuple[int, bytes]:
        """Send one command, return (status, data) of its reply."""
        self._port.write(encode_frame(cmd, data))
        deadline = time.monotonic() + self.timeout_s
        while True:
            rcmd, status, payload = self._read_frame(deadline)
            if rcmd == cmd:
                return status, payload
            # A stray reply to some earlier command: skip it.

    def _read_exact(self, n: int, deadline: float) -> bytes:
        buf = b""
        while len(buf) < n:
            if time.monotonic() > deadline:
                raise TransportError("Chameleon Ultra: no reply (timeout)")
            buf += self._port.read(n - len(buf))
        return buf

    def _read_frame(self, deadline: float) -> tuple[int, int, bytes]:
        while self._read_exact(1, deadline)[0] != SOF:
            pass                                # resynchronise on SOF
        head = bytes([SOF]) + self._read_exact(_HEAD.size - 1, deadline)
        _, lrc1, cmd, status, length, lrc2 = _HEAD.unpack(head)
        if lrc1 != lrc(head[:1]) or lrc2 != lrc(head[:8]):
            raise TransportError("Chameleon Ultra: corrupt frame header")
        rest = self._read_exact(length + 1, deadline)
        if rest[-1] != lrc(head + rest[:-1]):
            raise TransportError("Chameleon Ultra: corrupt frame (LRC)")
        return cmd, status, rest[:-1]

    def ensure_reader_mode(self) -> None:
        status, data = self.command(CMD_GET_DEVICE_MODE)
        if status == STATUS_SUCCESS and data[:1] == bytes([MODE_READER]):
            return
        status, _ = self.command(CMD_CHANGE_DEVICE_MODE, bytes([MODE_READER]))
        if status != STATUS_SUCCESS:
            raise TransportError(f"Chameleon Ultra: cannot enter reader mode (status {status:#x})")

    def select(self) -> Tag14a:
        """Select the tag in the field and send RATS, keeping the field on."""
        status, data = self.command(CMD_HF14A_SCAN_KEEP)
        if status == STATUS_HF_TAG_NO:
            raise TransportError("no tag in the field")
        if status != STATUS_HF_TAG_OK or not data:
            raise TransportError(f"Chameleon Ultra: tag selection failed (status {status:#x})")
        return parse_scan(data)

    def raw(self, options: int, frame: bytes = b"", timeout_ms: int = FRAME_TIMEOUT_MS) -> bytes:
        payload = struct.pack("!BHH", options, timeout_ms, len(frame) * 8) + frame
        status, data = self.command(CMD_HF14A_RAW, payload)
        if status != STATUS_HF_TAG_OK:
            raise TransportError(f"Chameleon Ultra: 14443-A exchange failed (status {status:#x})")
        return data

    def exchange(self, frame: bytes) -> bytes:
        """RawExchange: one block out with CRC_A, the reply with CRC_A checked."""
        reply = self.raw(OPT_ISODEP_FRAME, frame)
        if not reply:
            raise TransportError("no reply from the tag")
        return reply

    def field_off(self) -> None:
        self.raw(OPT_FIELD_OFF, timeout_ms=0)

    def close(self) -> None:
        self._port.close()


class ChameleonTransport(IsoDepTransport):
    """ISO-DEP over a Chameleon Ultra raw 14443-A link."""

    def __init__(self, exchange: RawExchange, fsc: int = 32,
                 link: ChameleonLink | None = None) -> None:
        super().__init__(exchange, fsc=fsc)
        self._link = link
        self.tag: Tag14a | None = None

    @classmethod
    def open(cls, port: str) -> "ChameleonTransport":
        """Connect to the device on `port` and select the tag (RATS included)."""
        return cls.over_link(ChameleonLink.open_serial(port))

    @classmethod
    def over_link(cls, link: ChameleonLink) -> "ChameleonTransport":
        try:
            link.ensure_reader_mode()
            tag = link.select()
            if not tag.ats:
                raise TransportError("tag is not ISO 14443-4 (no ATS)")
            transport = cls(link.exchange, link=link)
            transport.use_ats(tag.ats)
            transport.fsc = min(transport.fsc, DEVICE_MAX_FSC)
            transport.tag = tag
        except BaseException:
            link.close()
            raise
        return transport

    def close(self) -> None:
        if self._link is None:
            return
        link, self._link = self._link, None
        try:
            link.field_off()
        except TransportError:
            pass
        finally:
            link.close()
