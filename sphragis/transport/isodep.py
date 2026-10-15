"""
ISO/IEC 14443-4 (ISO-DEP) block framing over a raw 14443-A frame link.

Some readers (notably the Chameleon Ultra) only expose "send this 14443-A frame,
give me the reply": they handle anticollision and CRC but not the T=CL block
protocol. This class adds the missing layer in pure Python:

  - RATS / ATS (FSC negotiation),
  - I-blocks with block-number toggling and chaining in both directions,
  - R(ACK) during chaining, S(WTX) waiting-time extensions.

No CID/NAD, no error recovery by retransmission: an unexpected block raises
TransportError and the caller restarts the session (re-select the tag).

A tag is untrusted input: an exchange is bounded in waiting-time extensions
(`max_wtx`), in response size (`max_response`) and in wall-clock time
(`deadline_s`), so a malicious or broken tag cannot hang the station or make
it buffer without limit. Blocks carrying CID or NAD (never requested) are
refused.

The raw link is any callable `exchange(frame: bytes) -> bytes` that sends a
frame with CRC_A appended and returns the reply with CRC_A checked and removed.
"""

from __future__ import annotations

import time
from typing import Callable

from . import ApduTransport, TransportError

RawExchange = Callable[[bytes], bytes]

# FSCI -> FSC (bytes, including PCB and CRC); values above 8 are RFU -> 256.
_FSC_TABLE = (16, 24, 32, 40, 48, 64, 96, 128, 256)

_PCB_I = 0x02
_PCB_CHAIN = 0x10
_PCB_R_ACK = 0xA2
_PCB_S_WTX = 0xF2
_PCB_CID = 0x08
_PCB_NAD = 0x04
_RATS = bytes([0xE0, 0x80])  # FSDI=8 (256 B), CID=0


def _fsc_from_fsci(fsci: int) -> int:
    return _FSC_TABLE[min(fsci, len(_FSC_TABLE) - 1)]


class IsoDepTransport(ApduTransport):
    def __init__(self, exchange: RawExchange, fsc: int = 32, *, max_wtx: int = 32,
                 max_response: int = 4096, deadline_s: float = 10.0) -> None:
        self._raw = exchange
        self.fsc = fsc
        self._bn = 0
        self.ats: bytes | None = None
        self.max_wtx = max_wtx
        self.max_response = max_response
        self.deadline_s = deadline_s
        self._deadline = 0.0

    def activate(self) -> bytes:
        """Send RATS on an already-selected tag; returns the ATS."""
        return self.use_ats(self._raw(_RATS))

    def use_ats(self, ats: bytes) -> bytes:
        """
        Adopt an ATS obtained elsewhere (e.g. a reader that sends RATS itself
        during selection): take the FSC from it and reset the block number.
        """
        if not ats or ats[0] != len(ats):
            raise TransportError(f"invalid ATS {ats.hex().upper()}")
        self.ats = ats
        if len(ats) > 1:
            self.fsc = _fsc_from_fsci(ats[1] & 0x0F)
        self._bn = 0
        return ats

    def _check_time(self) -> None:
        if time.monotonic() > self._deadline:
            raise TransportError(f"tag exchange exceeded {self.deadline_s:g} s")

    def _exchange(self, frame: bytes) -> bytes:
        self._check_time()
        resp = self._raw(frame)
        # Honour waiting-time extensions transparently, within limits.
        extensions = 0
        while resp and (resp[0] & 0xF7) == _PCB_S_WTX:
            if len(resp) < 2:
                raise TransportError("truncated S(WTX) block")
            extensions += 1
            if extensions > self.max_wtx:
                raise TransportError(f"more than {self.max_wtx} waiting-time extensions")
            self._check_time()
            resp = self._raw(bytes([_PCB_S_WTX, resp[1] & 0x3F]))
        if not resp:
            raise TransportError("empty response block")
        return resp

    def transceive(self, apdu: bytes) -> bytes:
        self._deadline = time.monotonic() + self.deadline_s
        max_inf = self.fsc - 3  # PCB + CRC_A
        chunks = [apdu[i : i + max_inf] for i in range(0, len(apdu), max_inf)] or [b""]

        # Send, chaining when the APDU exceeds the card's frame size.
        resp = b""
        for i, chunk in enumerate(chunks):
            last = i == len(chunks) - 1
            pcb = _PCB_I | self._bn | (0 if last else _PCB_CHAIN)
            resp = self._exchange(bytes([pcb]) + chunk)
            if not last:
                if (resp[0] & 0xF6) != _PCB_R_ACK or (resp[0] & 1) != self._bn:
                    raise TransportError(f"expected R(ACK), got {resp.hex().upper()}")
                self._bn ^= 1

        # Receive, acknowledging chained I-blocks.
        out = b""
        while True:
            if (resp[0] & 0xE2) != _PCB_I:
                raise TransportError(f"expected I-block, got {resp.hex().upper()}")
            if resp[0] & (_PCB_CID | _PCB_NAD):
                raise TransportError("I-block with CID/NAD, which were not requested")
            if (resp[0] & 1) != self._bn:
                raise TransportError("I-block with wrong block number")
            self._bn ^= 1
            out += resp[1:]
            if len(out) > self.max_response:
                raise TransportError(f"response longer than {self.max_response} bytes")
            if not resp[0] & _PCB_CHAIN:
                return out
            resp = self._exchange(bytes([_PCB_R_ACK | self._bn]))
