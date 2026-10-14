#!/usr/bin/env python3
"""
Smoke test of the APDU path: ISOSelect the NDEF application and print the
exchange. Runs on the host with the reader; `--reader emulator` needs nothing.

    python tools/sdm_probe.py --reader pn532
    python tools/sdm_probe.py --reader chameleon --port /dev/ttyACM0
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reader import add_reader_args, hexdump, reader_factory  # noqa: E402

from sphragis.apdu import parse_response, select_ndef_app  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_reader_args(parser)
    args = parser.parse_args(argv)

    with reader_factory(args)() as transport:
        apdu = select_ndef_app()
        raw = transport.transceive(apdu)
    resp = parse_response(raw)
    print(f"C-APDU : {hexdump(apdu)}")
    print(f"R-APDU : {hexdump(raw)}")
    print(f"SW     : {resp.sw:04X} ({'OK, NDEF application present' if resp.ok else 'error'})")
    return 0 if resp.ok else 1


if __name__ == "__main__":
    sys.exit(main())
