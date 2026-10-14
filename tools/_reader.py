"""
Shared reader selection for the hardware tools.

    --reader chameleon --port /dev/ttyACM0   Chameleon Ultra (hardware host)
    --reader pn532 --port usb                PN532 via nfcpy (hardware host)
    --reader emulator                        software tag, all-zero keys (no hardware)

The emulator backend only answers the read-only ISO subset, so it can drive
sdm_probe.py and tap_verify.py but not a real provisioning run.
"""

from __future__ import annotations

import argparse
import os

from sphragis.emulator import EmulatedTag
from sphragis.transport import ApduTransport, ChameleonTransport, EmulatorTransport, Pn532Transport


def add_reader_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reader", choices=("chameleon", "pn532", "emulator"),
                        default="emulator", help="APDU transport backend")
    parser.add_argument("--port", default=None,
                        help="serial port (chameleon) or nfcpy path (pn532, default 'usb')")


def reader_factory(args: argparse.Namespace):
    """Return a zero-argument callable that opens a fresh transport per tap."""
    if args.reader == "emulator":
        tag = EmulatedTag(uid=bytes.fromhex("04") + os.urandom(6),
                          meta_read_key=bytes(16), file_read_key=bytes(16))
        return lambda: EmulatorTransport(tag)
    if args.reader == "chameleon":
        if not args.port:
            raise SystemExit("--port is required for --reader chameleon")
        return lambda: ChameleonTransport.open(args.port)
    return lambda: Pn532Transport.open(args.port or "usb")


def hexdump(b: bytes) -> str:
    return b.hex(" ").upper() if b else "(empty)"


__all__ = ["ApduTransport", "add_reader_args", "reader_factory", "hexdump"]
