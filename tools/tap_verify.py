#!/usr/bin/env python3
"""
Read SUN taps from a tag and run them through the engine with all-zero keys.

Each tap is read with a fresh connection and analysed by TagAnalyzer (MAC,
counter floor, scored clone detection), printing verdict, UID, counter and
signals. Use --wait to swap tags between taps, e.g. genuine tag then a
Chameleon emulating a clone, within one detector history.

    python tools/tap_verify.py --reader pn532 --taps 3 --wait
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reader import add_reader_args, reader_factory  # noqa: E402

from sphragis import StaticKeys, TagAnalyzer  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.ndef import read_uri  # noqa: E402

ZERO = bytes(16)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    add_reader_args(parser)
    parser.add_argument("--taps", type=int, default=1, help="number of taps to read")
    parser.add_argument("--wait", action="store_true", help="press Enter before each tap")
    parser.add_argument("--store", default=None,
                        help="JSON counter store, to keep the anti-replay floor across runs")
    parser.add_argument("--reader-id", default="bench", help="reader id for velocity signals")
    args = parser.parse_args(argv)

    analyzer = TagAnalyzer(StaticKeys(ZERO, ZERO), store=CounterStore(args.store))
    open_reader = reader_factory(args)
    genuine = True
    for n in range(1, args.taps + 1):
        if args.wait:
            input(f"[tap {n}/{args.taps}] place the tag and press Enter... ")
        with open_reader() as transport:
            url = read_uri(transport)
        r = analyzer.analyze(url, reader_id=args.reader_id)
        print(f"tap {n}: {r.classification:<12} UID {r.uid}  ctr {r.read_counter}  "
              f"score {r.risk_score}")
        print(f"        {url}")
        for s in r.signals:
            print(f"        signal {s.name} (+{s.weight}): {s.detail}")
        genuine = genuine and r.is_genuine
    return 0 if genuine else 1


if __name__ == "__main__":
    sys.exit(main())
