"""
Shared reader selection for the hardware tools.

    --reader chameleon --port /dev/ttyACM0   Chameleon Ultra (hardware host)
    --reader emulator                        software tag, all-zero keys (no hardware)

The emulator backend only answers the read-only ISO subset, so it can drive
sdm_probe.py and tap_verify.py but not a real provisioning run.
"""

from __future__ import annotations

import argparse
import os

from sphragis.emulator import EmulatedTag
from sphragis.transport import ApduTransport, ChameleonTransport, EmulatorTransport


def add_reader_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reader", choices=("chameleon", "emulator"),
                        default="emulator", help="APDU transport backend")
    parser.add_argument("--port", default=None,
                        help="serial port of the Chameleon Ultra, e.g. /dev/ttyACM0")


def reader_factory(args: argparse.Namespace):
    """Return a zero-argument callable that opens a fresh transport per tap."""
    if args.reader == "emulator":
        tag = EmulatedTag(uid=bytes.fromhex("04") + os.urandom(6),
                          meta_read_key=bytes(16), file_read_key=bytes(16))
        return lambda: EmulatorTransport(tag)
    if not args.port:
        raise SystemExit("--port is required for --reader chameleon")
    return lambda: ChameleonTransport.open(args.port)


def hexdump(b: bytes) -> str:
    return b.hex(" ").upper() if b else "(empty)"


__all__ = ["ApduTransport", "add_reader_args", "reader_factory", "hexdump"]
