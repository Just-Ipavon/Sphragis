#!/usr/bin/env python3
"""
Replace the five application keys of an NTAG 424 DNA with per-UID keys.

Keys come from a secrets directory (FileSecretsBackend: one hex file per key,
`master_admin`, `master_file`, `meta_read`; permissions must be 0600), never
from the command line, so they can always be derived again. The run is
resumable: key versions record which slots changed. --to-factory puts the
all-zero keys back. Real runs need --yes; --dry-run only authenticates and
reads (UID, key versions) and prints the plan.

    python tools/rekey.py --reader chameleon --port /dev/ttyACM0 \\
        --secrets-dir ~/.sphragis/keys --context DEMO --dry-run
    python tools/rekey.py ... --yes
    python tools/rekey.py ... --to-factory --yes
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reader import add_reader_args, reader_factory  # noqa: E402

from sphragis.keyprov import DiversifiedTagKeys, FactoryKeys, rekey_tag  # noqa: E402
from sphragis.secrets import FileSecretsBackend  # noqa: E402


def add_key_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--secrets-dir", required=True,
                        help="directory with master_admin, master_file, meta_read (hex, 0600)")
    parser.add_argument("--context", default="",
                        help="diversification context (same as SPHRAGIS_KEY_CONTEXT)")
    parser.add_argument("--key-version", type=lambda v: int(v, 0), default=0x01,
                        help="version stored with the diversified keys (01h..FFh)")


def scheme_from_args(args: argparse.Namespace) -> DiversifiedTagKeys:
    return DiversifiedTagKeys.from_secrets(FileSecretsBackend(args.secrets_dir),
                                           context=args.context.encode(),
                                           version=args.key_version)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_reader_args(parser)
    parser.set_defaults(reader=None)
    add_key_args(parser)
    parser.add_argument("--uid", help="expected UID (hex); otherwise read from the tag")
    parser.add_argument("--to-factory", action="store_true",
                        help="put the all-zero factory keys back")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="read and plan, change nothing")
    mode.add_argument("--yes", action="store_true", help="confirm changing the keys")
    args = parser.parse_args(argv)

    if args.reader in (None, "emulator"):
        parser.error("a hardware reader is required (--reader chameleon|pn532)")
    try:
        uid = bytes.fromhex(args.uid) if args.uid else None
    except ValueError:
        parser.error("--uid must be hex")
    diversified = scheme_from_args(args)
    target, known = ((FactoryKeys(), [diversified]) if args.to_factory
                     else (diversified, []))

    with reader_factory(args)() as transport:
        report = rekey_tag(transport, target, known, uid=uid,
                           dry_run=args.dry_run, log=print)
    if args.dry_run:
        return 0
    print("RESULT       : " + ("keys changed and verified" if report.verified
                               else "NOT VERIFIED"))
    return 0 if report.verified else 1


if __name__ == "__main__":
    sys.exit(main())
