#!/usr/bin/env python3
"""
Provision an NTAG 424 DNA for SUN with the factory all-zero keys.

Writes the NDEF template, enables SDM with an encrypted PICCData mirror and a
CMAC (AuthenticateEV2First + ChangeFileSettings), then reads back one tap to
check it. Idempotent: a tag already in this layout is left untouched. Never
changes keys. Real runs need --yes; --dry-run only reads (or, without a
reader, just prints the plan).

    python tools/provision.py --dry-run --base-url https://example.com/t
    python tools/provision.py --reader pn532 --base-url https://example.com/t --yes
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reader import add_reader_args, reader_factory  # noqa: E402

from sphragis.provision import provision_tag  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_reader_args(parser)
    parser.set_defaults(reader=None)
    parser.add_argument("--base-url", required=True,
                        help="URL before the SUN query string, e.g. https://example.com/t")
    parser.add_argument("--dry-run", action="store_true", help="read and plan, write nothing")
    parser.add_argument("--yes", action="store_true", help="confirm writing to the tag")
    args = parser.parse_args(argv)

    if args.reader is None:
        if not args.dry_run:
            parser.error("--reader is required unless --dry-run is given")
        provision_tag(None, args.base_url, dry_run=True, log=print)
        return 0
    if args.reader == "emulator":
        parser.error("the emulator backend cannot provision (no secure messaging); "
                     "use --dry-run without --reader for the offline plan")
    if not args.dry_run and not args.yes:
        parser.error("refusing to write without --yes (or use --dry-run)")

    with reader_factory(args)() as transport:
        report = provision_tag(transport, args.base_url, dry_run=args.dry_run, log=print)
    if args.dry_run:
        return 0
    print("RESULT       : " + ("provisioned and verified" if report.verified else "NOT VERIFIED"))
    return 0 if report.verified else 1


if __name__ == "__main__":
    sys.exit(main())
