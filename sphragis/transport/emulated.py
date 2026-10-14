"""
In-memory Type 4 tag backed by the software emulator.

Answers the unauthenticated ISO 7816-4 subset a reader uses to fetch a SUN URL:
ISOSelectFile (NDEF application by DF name, CC / NDEF file by ID) and
ISOReadBinary. Nothing else is modelled: anything outside that subset returns
6D00 (instruction not supported), so tools that need secure messaging can only
be tested here against a ScriptedTransport.

SDM model: the first ISOReadBinary after the NDEF file is selected triggers one
tap of the underlying EmulatedTag (counter +1, fresh PICCData/SDMMAC); further
reads return the same snapshot until the file is selected again.
"""

from __future__ import annotations

from ..apdu import CC_FILE_ID, NDEF_APP_AID, NDEF_FILE_ID
from ..emulator import EmulatedTag
from ..ndef import encode_uri_file
from . import ApduTransport

_SW_OK = b"\x90\x00"
_SW_WRONG_LENGTH = b"\x67\x00"
_SW_NO_CURRENT_EF = b"\x69\x86"
_SW_FILE_NOT_FOUND = b"\x6A\x82"
_SW_WRONG_P1P2 = b"\x6B\x00"
_SW_INS_NOT_SUPPORTED = b"\x6D\x00"
_SW_CLA_NOT_SUPPORTED = b"\x6E\x00"

_FILE_SIZE = 256

# Capability Container: CCLEN=15, mapping v2.0, MLe=256, MLc=255, then the NDEF
# File Control TLV (E104, 256 B, free read, free write).
_CC_FILE = bytes.fromhex("000F20010000FF0406E10401000000")


class EmulatorTransport(ApduTransport):
    def __init__(self, tag: EmulatedTag) -> None:
        self.tag = tag
        self._app_selected = False
        self._current: int | None = None
        self._snapshot: bytes | None = None
        self.log: list[tuple[bytes, bytes]] = []

    def transceive(self, apdu: bytes) -> bytes:
        response = self._handle(bytes(apdu))
        self.log.append((bytes(apdu), response))
        return response

    def _handle(self, apdu: bytes) -> bytes:
        if len(apdu) < 4:
            return _SW_WRONG_LENGTH
        cla, ins, p1, p2 = apdu[:4]
        if cla != 0x00:
            return _SW_CLA_NOT_SUPPORTED
        if ins == 0xA4:
            return self._select(p1, apdu[4:])
        if ins == 0xB0:
            return self._read_binary(p1, p2, apdu[4:])
        return _SW_INS_NOT_SUPPORTED

    def _select(self, p1: int, body: bytes) -> bytes:
        if not body or len(body) < 1 + body[0]:
            return _SW_WRONG_LENGTH
        target = body[1 : 1 + body[0]]
        if p1 == 0x04:
            if target != NDEF_APP_AID:
                return _SW_FILE_NOT_FOUND
            self._app_selected = True
            self._current = None
            return _SW_OK
        if p1 == 0x00 and len(target) == 2 and self._app_selected:
            fid = int.from_bytes(target, "big")
            if fid not in (CC_FILE_ID, NDEF_FILE_ID):
                return _SW_FILE_NOT_FOUND
            self._current = fid
            self._snapshot = None
            return _SW_OK
        return _SW_FILE_NOT_FOUND

    def _file_content(self) -> bytes:
        if self._current == CC_FILE_ID:
            return _CC_FILE
        if self._snapshot is None:
            self._snapshot = encode_uri_file(self.tag.tap()).ljust(_FILE_SIZE, b"\x00")
        return self._snapshot

    def _read_binary(self, p1: int, p2: int, body: bytes) -> bytes:
        if self._current is None:
            return _SW_NO_CURRENT_EF
        if p1 & 0x80 or len(body) != 1:
            return _SW_WRONG_P1P2 if p1 & 0x80 else _SW_WRONG_LENGTH
        offset = (p1 << 8) | p2
        le = body[0] or 0x100
        content = self._file_content()
        if offset > len(content):
            return _SW_WRONG_P1P2
        return content[offset : offset + le] + _SW_OK
