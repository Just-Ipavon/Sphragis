#!/usr/bin/env python3
"""
Provision an NTAG 424 DNA for SUN with the factory all-zero keys.

Writes the NDEF template, enables SDM with an encrypted PICCData mirror and a
CMAC (AuthenticateEV2First + ChangeFileSettings), then reads back one tap to
check it. Idempotent: a tag already in this layout is left untouched. Never
changes keys. Real runs need --yes; --dry-run only reads and authenticates
(or, without a reader, just prints the plan).

The NDEF file ends up writable only after authenticating with --write-key
(0, 3 or 4; default 0), so nobody can point the tag at another URL;
--leave-writable keeps the factory free write access on a bench tag. Every
key the writes need is checked before anything is written. Without --uid, a
real run asks you to type the UID shown.

With --enc-data / --enc-data-hex the tag also mirrors that plaintext as
encrypted file data (SDMENCFileData, a multiple of 16 bytes).

    python tools/provision.py --dry-run --base-url https://example.com/t
    python tools/provision.py --reader pn532 --base-url https://example.com/t --yes
    python tools/provision.py --reader chameleon --base-url https://example.com/t \\
        --enc-data 0123456789ABCDEF --dry-run
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reader import add_reader_args, reader_factory  # noqa: E402

from sphragis.keyprov import DiversifiedTagKeys, current_tag_keys  # noqa: E402
from sphragis.provision import ProvisionError, provision_tag  # noqa: E402
from sphragis.sdmconfig import WRITE_LOCK_KEYS  # noqa: E402
from sphragis.secrets import FileSecretsBackend  # noqa: E402


def confirm_by_typing(report) -> bool:
    """Ask the operator to type the UID shown, so the right tag is written."""
    uid = report.uid.hex().upper()
    try:
        answer = input(f"About to write tag {uid}. Type the UID to confirm: ")
    except EOFError:
        return False
    return answer.strip().upper() == uid


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_reader_args(parser)
    parser.set_defaults(reader=None)
    parser.add_argument("--base-url", required=True,
                        help="URL before the SUN query string, e.g. https://example.com/t")
    enc = parser.add_mutually_exclusive_group()
    enc.add_argument("--enc-data", help="plaintext (ASCII) to mirror encrypted, "
                                        "a multiple of 16 bytes")
    enc.add_argument("--enc-data-hex", help="plaintext as hex, a multiple of 16 bytes")
    lock = parser.add_mutually_exclusive_group()
    lock.add_argument("--write-key", type=int, default=0, choices=WRITE_LOCK_KEYS,
                      help="key NDEF writes are locked to (default 0)")
    lock.add_argument("--leave-writable", action="store_true",
                      help="keep the factory free write access (bench tags, "
                           "plain layout only)")
    parser.add_argument("--uid", help="expected UID (hex); otherwise confirmed by "
                                      "typing it")
    parser.add_argument("--secrets-dir",
                        help="tag keys already replaced with tools/rekey.py: directory "
                             "with master_admin, master_file, meta_read (hex, 0600)")
    parser.add_argument("--context", default="", help="diversification context")
    parser.add_argument("--key-version", type=lambda v: int(v, 0), default=0x01,
                        help="version of the diversified keys (default 01h)")
    parser.add_argument("--dry-run", action="store_true", help="read and plan, write nothing")
    parser.add_argument("--yes", action="store_true", help="confirm writing to the tag")
    args = parser.parse_args(argv)

    file_data = None
    try:
        if args.enc_data is not None:
            file_data = args.enc_data.encode("ascii")
        elif args.enc_data_hex is not None:
            file_data = bytes.fromhex(args.enc_data_hex)
    except (UnicodeEncodeError, ValueError) as exc:
        parser.error(f"invalid file data: {exc}")
    if file_data is not None and (not file_data or len(file_data) % 16):
        parser.error(f"file data must be a non-empty multiple of 16 bytes, "
                     f"got {len(file_data)}")
    if args.leave_writable and file_data is not None:
        parser.error("--leave-writable cannot be combined with --enc-data*")
    try:
        uid = bytes.fromhex(args.uid) if args.uid else None
    except ValueError:
        parser.error("--uid must be hex")
    options = dict(file_data=file_data,
                   write_key=None if args.leave_writable else args.write_key)

    if args.reader is None:
        if not args.dry_run:
            parser.error("--reader is required unless --dry-run is given")
        provision_tag(None, args.base_url, dry_run=True, log=print, **options)
        return 0
    if args.reader == "emulator":
        parser.error("the emulator backend cannot provision (no secure messaging); "
                     "use --dry-run without --reader for the offline plan")
    if not args.dry_run and not args.yes:
        parser.error("refusing to write without --yes (or use --dry-run)")

    try:
        with reader_factory(args)() as transport:
            if args.secrets_dir:
                scheme = DiversifiedTagKeys.from_secrets(
                    FileSecretsBackend(args.secrets_dir), context=args.context.encode(),
                    version=args.key_version)
                options["tag_keys"] = current_tag_keys(transport, [scheme], log=print)
            report = provision_tag(transport, args.base_url, dry_run=args.dry_run,
                                   log=print, uid=uid,
                                   confirm=None if uid else confirm_by_typing, **options)
    except ProvisionError as exc:
        print(f"REFUSED      : {exc}")
        return 2
    if args.dry_run:
        return 0
    if report.aborted:
        print("RESULT       : aborted, nothing written")
        return 1
    print("RESULT       : " + ("provisioned and verified" if report.verified else "NOT VERIFIED"))
    return 0 if report.verified else 1


if __name__ == "__main__":
    sys.exit(main())
