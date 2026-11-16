"""
Shared reader selection for the hardware tools.

    --reader chameleon --port /dev/ttyACM0   Chameleon Ultra (hardware host)
    --reader emulator                        software tag, all-zero keys (no hardware)
    --reader emulator --emulator-state FILE  simulated NTAG 424 DNA kept in FILE

Without --emulator-state the emulator is a tag already provisioned with the
factory keys that only answers the read-only ISO subset: enough for
sdm_probe.py and tap_verify.py. With it, the tag is the full simulator
(sphragis.simulator, EV2 secure messaging), created factory-fresh if FILE does
not exist and saved back after each connection, so provision.py, rekey.py and
tap_verify.py act on the same tag across runs.
"""

from __future__ import annotations

import argparse
import os

from sphragis.emulator import EmulatedTag
from sphragis.simulator import TEST_ORIGINALITY_KEY, PersistentSimulatorTransport
from sphragis.transport import ApduTransport, ChameleonTransport, EmulatorTransport


def add_reader_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reader", choices=("chameleon", "emulator"),
                        default="emulator", help="APDU transport backend")
    parser.add_argument("--port", default=None,
                        help="serial port of the Chameleon Ultra, e.g. /dev/ttyACM0")
    parser.add_argument("--emulator-state", default=None, metavar="FILE",
                        help="with --reader emulator: a simulated tag with secure "
                             "messaging, kept in FILE (created if missing)")


def simulated(args: argparse.Namespace) -> bool:
    """The reader is the full simulator (provisioning and key changes work)."""
    return args.reader == "emulator" and bool(getattr(args, "emulator_state", None))


def reader_factory(args: argparse.Namespace):
    """Return a zero-argument callable that opens a fresh transport per tap."""
    if getattr(args, "emulator_state", None) and args.reader != "emulator":
        raise SystemExit("--emulator-state needs --reader emulator")
    if simulated(args):
        path = os.path.expanduser(args.emulator_state)
        return lambda: PersistentSimulatorTransport(path)
    if args.reader == "emulator":
        tag = EmulatedTag(uid=bytes.fromhex("04") + os.urandom(6),
                          meta_read_key=bytes(16), file_read_key=bytes(16))
        return lambda: EmulatorTransport(tag)
    if not args.port:
        raise SystemExit("--port is required for --reader chameleon")
    return lambda: ChameleonTransport.open(args.port)


def hexdump(b: bytes) -> str:
    return b.hex(" ").upper() if b else "(empty)"


__all__ = ["TEST_ORIGINALITY_KEY", "ApduTransport", "add_reader_args", "hexdump",
           "reader_factory", "simulated"]
