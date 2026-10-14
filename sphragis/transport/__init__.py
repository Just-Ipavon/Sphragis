"""
APDU transport abstraction.

Every tool that talks to a physical NTAG 424 DNA goes through one tiny
interface:

    transceive(apdu: bytes) -> bytes      # response data || SW1 SW2

Secure messaging (AuthenticateEV2First, AES session keys, CMAC'd commands) is
done by Sphragis in Python on top of this interface; a transport is only a pipe
for raw ISO 7816-4 APDUs. That keeps all protocol logic testable in software:

    ScriptedTransport   in-memory, replays an expected command/response script
    EmulatorTransport   in-memory, a Type 4 NDEF tag backed by EmulatedTag
    IsoDepTransport     ISO 14443-4 block framing over a raw 14443-A link (pure)

Hardware backends (run ONLY on a host with the reader attached; not exercised
by the test suite):

    ChameleonTransport  Chameleon Ultra used as a raw 14443-A frame pipe
    Pn532Transport      PN532 via nfcpy
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable


class TransportError(Exception):
    """The APDU could not be exchanged (link, framing or script failure)."""


class ApduTransport(ABC):
    """A pipe for raw APDUs. Implementations must be usable as context managers."""

    @abstractmethod
    def transceive(self, apdu: bytes) -> bytes:
        """Send one command APDU, return the response (data || SW1 SW2)."""

    def close(self) -> None:
        """Release the underlying link. Default: nothing to release."""

    def __enter__(self) -> "ApduTransport":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class ScriptedTransport(ApduTransport):
    """
    In-memory transport that expects an exact sequence of commands and returns
    the scripted responses. Any deviation raises TransportError, which makes it
    a precise oracle for testing command construction.
    """

    def __init__(self, script: Iterable[tuple[bytes, bytes]]) -> None:
        self._script = list(script)
        self._pos = 0
        self.log: list[tuple[bytes, bytes]] = []

    def transceive(self, apdu: bytes) -> bytes:
        if self._pos >= len(self._script):
            raise TransportError(f"unexpected extra command {apdu.hex().upper()}")
        expected, response = self._script[self._pos]
        if bytes(apdu) != expected:
            raise TransportError(
                f"command #{self._pos}: expected {expected.hex().upper()}, "
                f"got {bytes(apdu).hex().upper()}"
            )
        self._pos += 1
        self.log.append((bytes(apdu), response))
        return response

    @property
    def exhausted(self) -> bool:
        return self._pos == len(self._script)


from .emulated import EmulatorTransport  # noqa: E402
from .isodep import IsoDepTransport  # noqa: E402
from .chameleon import ChameleonTransport  # noqa: E402
from .pn532 import Pn532Transport  # noqa: E402

__all__ = [
    "ApduTransport",
    "TransportError",
    "ScriptedTransport",
    "EmulatorTransport",
    "IsoDepTransport",
    "ChameleonTransport",
    "Pn532Transport",
]
