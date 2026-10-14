"""
Clone-detection demo: the worst case.

Shows that even a *perfect* clone — one built after extracting the tag's secret
keys, so its MACs are all valid — is caught the moment it is used, by the
behaviour of the read counter. No hardware required.

Run:  python examples/clone_demo.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sphragis import StaticKeys, TagAnalyzer
from sphragis.adversary import KeyCloner
from sphragis.emulator import EmulatedTag


def show(label, r):
    sig = ", ".join(s.name for s in r.signals) or "-"
    print(f"{label:28s} {r.classification:13s} score={r.risk_score:3d}  [{sig}]")


def main() -> None:
    meta, file_ = os.urandom(16), os.urandom(16)
    # Genuine tag already in service (counter at 9) when monitoring begins.
    tag = EmulatedTag(uid=bytes.fromhex("04DE5F1EACC040"),
                      meta_read_key=meta, file_read_key=file_, read_counter=9)
    analyzer = TagAnalyzer(StaticKeys(meta, file_))

    print("Genuine tag in the field (reader = gate-A):")
    for i in range(3):
        show(f"  authentic tap", analyzer.analyze(
            tag.tap(), timestamp=1000 + i, reader_id="gate-A"))

    print("\nAttacker extracts the keys and builds a perfect clone.")
    print("The clone's MACs are all cryptographically VALID — yet:\n")

    clone = KeyCloner.clone(tag, start_counter=2)
    show("  clone, divergent counter", analyzer.analyze(
        clone.tap(), timestamp=1100, reader_id="gate-A"))

    clone2 = KeyCloner.clone(tag, start_counter=20)
    show("  clone, far away seconds later", analyzer.analyze(
        clone2.tap(), timestamp=1103, reader_id="gate-B"))

    print("\n-> A valid MAC proves key possession, not physical uniqueness.")
    print("   The read counter is what unmasks the clone.")


if __name__ == "__main__":
    main()
