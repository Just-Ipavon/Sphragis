"""
ISO 7816-4 APDU helpers (pure, no I/O).

Builds the short command APDUs Sphragis needs to talk to an NTAG 424 DNA and
splits responses into data + status word. The transport that actually carries
the bytes lives in `sphragis.transport`.
"""

from __future__ import annotations

from dataclasses import dataclass

# NFC Forum Type 4 NDEF application (DF name) and its standard files.
NDEF_APP_AID = bytes.fromhex("D2760000850101")
CC_FILE_ID = 0xE103
NDEF_FILE_ID = 0xE104

SW_OK = 0x9000


class ApduError(Exception):
    """A command completed at transport level but returned a non-9000 status."""

    def __init__(self, sw: int, message: str = "") -> None:
        self.sw = sw
        super().__init__(f"SW={sw:04X}" + (f": {message}" if message else ""))


@dataclass(frozen=True)
class Response:
    data: bytes
    sw: int

    @property
    def ok(self) -> bool:
        return self.sw == SW_OK

    def check(self, what: str = "") -> bytes:
        """Return the data, raising ApduError unless SW is 9000."""
        if not self.ok:
            raise ApduError(self.sw, what)
        return self.data


def parse_response(raw: bytes) -> Response:
    if len(raw) < 2:
        raise ApduError(0, f"response too short ({len(raw)} B), no status word")
    return Response(data=bytes(raw[:-2]), sw=int.from_bytes(raw[-2:], "big"))


def build_apdu(cla: int, ins: int, p1: int, p2: int,
               data: bytes = b"", le: int | None = None) -> bytes:
    """
    Encode a short APDU. `le=0` means "up to 256 bytes" (encoded 0x00);
    `le=None` omits the Le field.
    """
    for name, v in (("cla", cla), ("ins", ins), ("p1", p1), ("p2", p2)):
        if not 0 <= v <= 0xFF:
            raise ValueError(f"{name} out of range: {v}")
    if len(data) > 0xFF:
        raise ValueError("data too long for a short APDU (max 255 B)")
    apdu = bytes([cla, ins, p1, p2])
    if data:
        apdu += bytes([len(data)]) + data
    if le is not None:
        if not 0 <= le <= 0x100:
            raise ValueError(f"le out of range: {le}")
        apdu += bytes([le & 0xFF])
    return apdu


def select_ndef_app() -> bytes:
    """ISOSelectFile by DF name of the NDEF application (as in AN12196)."""
    return build_apdu(0x00, 0xA4, 0x04, 0x0C, NDEF_APP_AID, le=0)


def select_file(file_id: int) -> bytes:
    """ISOSelectFile of an EF under the current DF, by 2-byte file ID."""
    return build_apdu(0x00, 0xA4, 0x00, 0x0C, file_id.to_bytes(2, "big"), le=0)


def read_binary(offset: int, length: int) -> bytes:
    """ISOReadBinary of `length` (1..256) bytes at `offset` (0..0x7FFF)."""
    if not 0 <= offset <= 0x7FFF:
        raise ValueError(f"offset out of range: {offset}")
    if not 1 <= length <= 0x100:
        raise ValueError(f"length out of range: {length}")
    return build_apdu(0x00, 0xB0, offset >> 8, offset & 0xFF, le=length)
