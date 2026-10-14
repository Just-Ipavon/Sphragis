"""
Chameleon Ultra backend — HARDWARE ONLY, NOT EXERCISED BY THE TEST SUITE.

The Chameleon Ultra, in reader mode, is used purely as a raw ISO 14443-A frame
pipe: it selects the tag (anticollision, CRC_A), and Sphragis does everything
above that in Python — ISO-DEP framing (IsoDepTransport) and, on top, NTAG 424
DNA secure messaging (AES session keys, CMAC). No key ever touches the device.

What the host has to provide is one callable:

    exchange(frame: bytes) -> bytes
        send `frame` with CRC_A appended by the device, keep the RF field on,
        wait for the reply, check and strip its CRC_A, return the bytes.

With the official ChameleonUltra Python client (software/script in the
RfidResearchGroup/ChameleonUltra repository) that is one `hf14a_raw` call with
the options activate_rf_field / wait_response / append_crc / check_response_crc
/ keep_rf_field enabled, preceded by a single call with auto_select to select
the tag. The client is not on PyPI and its call signatures have changed across
firmware releases, so the binding is deliberately left to `_open_link` on the
host and verified there against a real tag.
"""

from __future__ import annotations

from .isodep import IsoDepTransport, RawExchange


class ChameleonTransport(IsoDepTransport):
    """ISO-DEP over a Chameleon Ultra raw 14443-A link (run on the hardware host)."""

    def __init__(self, exchange: RawExchange, fsc: int = 32) -> None:
        super().__init__(exchange, fsc=fsc)

    @classmethod
    def open(cls, port: str) -> "ChameleonTransport":
        """Connect to the device on `port`, select the tag and send RATS."""
        transport = cls(_open_link(port))
        transport.activate()
        return transport


def _open_link(port: str) -> RawExchange:
    """
    HARDWARE HOST ONLY: bind the ChameleonUltra client to a RawExchange.

    Steps to implement against the installed client version:
      1. open the serial port (`port`, e.g. /dev/ttyACM0) and switch the
         device to reader mode;
      2. select the tag: hf14a_raw with activate_rf_field + auto_select +
         keep_rf_field, no data;
      3. return a function that, for each frame, calls hf14a_raw with
         append_crc + check_response_crc + wait_response + keep_rf_field and
         returns the reply bytes (CRC stripped), raising TransportError on a
         timeout or CRC error.
    """
    raise NotImplementedError(
        "ChameleonTransport needs the ChameleonUltra client on the hardware "
        f"host (port {port!r}); see sphragis/transport/chameleon.py"
    )
