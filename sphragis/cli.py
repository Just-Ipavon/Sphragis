"""
Command-line verifier.

Examples:
    # Verify a tapped URL with hex keys
    python -m sphragis.cli verify \\
        --meta-key 00000000000000000000000000000000 \\
        --file-key 00000000000000000000000000000000 \\
        "https://example.com/t?picc_data=...&cmac=..."

    # Generate a demo tap from an emulated tag (no hardware needed)
    python -m sphragis.cli emulate --meta-key <hex> --file-key <hex> --uid 04DE5F1EACC040
"""

from __future__ import annotations

import argparse
import sys

from .counterstore import CounterStore
from .emulator import EmulatedTag
from .verifier import StaticKeys, Verdict, Verifier

_VERDICT_LABEL = {
    Verdict.AUTHENTIC: "AUTHENTIC  - genuine tag, fresh tap",
    Verdict.REPLAY: "REPLAY     - valid MAC but stale counter (replay/clone)",
    Verdict.FORGED: "FORGED     - MAC mismatch, not a genuine tag",
    Verdict.ERROR: "ERROR      - malformed input",
}


def _hexkey(value: str) -> bytes:
    key = bytes.fromhex(value)
    if len(key) != 16:
        raise argparse.ArgumentTypeError("key must be 16 bytes (32 hex chars)")
    return key


def _cmd_verify(args: argparse.Namespace) -> int:
    keys = StaticKeys(args.meta_key, args.file_key)
    verifier = Verifier(keys, CounterStore(args.store))
    result = verifier.verify(args.url)
    print(_VERDICT_LABEL[result.verdict])
    if result.uid:
        print(f"UID        : {result.uid}")
    if result.read_counter is not None:
        print(f"ReadCounter: {result.read_counter}")
    print(f"Detail     : {result.detail}")
    return 0 if result.ok else 1


def _cmd_emulate(args: argparse.Namespace) -> int:
    tag = EmulatedTag(
        uid=bytes.fromhex(args.uid),
        meta_read_key=args.meta_key,
        file_read_key=args.file_key,
        read_counter=args.counter,
    )
    for _ in range(args.taps):
        print(tag.tap())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sphragis",
        description="NTAG 424 DNA SUN/SDM verification toolkit",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="verify a tapped SUN URL")
    v.add_argument("url", help="the full URL (or query string) emitted by the tag")
    v.add_argument("--meta-key", type=_hexkey, required=True, help="K_SDMMetaReadKey (hex)")
    v.add_argument("--file-key", type=_hexkey, required=True, help="K_SDMFileReadKey (hex)")
    v.add_argument("--store", default=None, help="path to the JSON counter store")
    v.set_defaults(func=_cmd_verify)

    e = sub.add_parser("emulate", help="emit SUN URL(s) from a virtual tag")
    e.add_argument("--meta-key", type=_hexkey, required=True, help="K_SDMMetaReadKey (hex)")
    e.add_argument("--file-key", type=_hexkey, required=True, help="K_SDMFileReadKey (hex)")
    e.add_argument("--uid", required=True, help="7-byte UID (hex)")
    e.add_argument("--counter", type=int, default=0, help="starting read counter")
    e.add_argument("--taps", type=int, default=1, help="number of taps to emit")
    e.set_defaults(func=_cmd_emulate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
