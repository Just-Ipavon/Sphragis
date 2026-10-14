"""
End-to-end demo with no physical tag.

Creates a virtual tag, taps it a few times (all accepted), then shows the two
attack cases being caught: a replayed URL and a tampered (forged) URL.

Run:  python examples/demo.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sphragis import StaticKeys, Verifier
from sphragis.counterstore import CounterStore
from sphragis.emulator import EmulatedTag


def main() -> None:
    meta_key = os.urandom(16)
    file_key = os.urandom(16)
    uid = bytes.fromhex("04DE5F1EACC040")

    tag = EmulatedTag(uid=uid, meta_read_key=meta_key, file_read_key=file_key)
    verifier = Verifier(StaticKeys(meta_key, file_key), CounterStore())

    print("=== Genuine taps ===")
    first_url = None
    for i in range(3):
        url = tag.tap()
        if first_url is None:
            first_url = url
        r = verifier.verify(url)
        print(f"tap {i + 1}: {r.verdict.value:10s} counter={r.read_counter}")

    print("\n=== Replay attack (resend tap #1) ===")
    r = verifier.verify(first_url)
    print(f"{r.verdict.value}: {r.detail}")

    print("\n=== Forgery (tamper the MAC) ===")
    url = tag.tap()
    tampered = url[:-1] + ("0" if url[-1] != "0" else "1")
    r = verifier.verify(tampered)
    print(f"{r.verdict.value}: {r.detail}")


if __name__ == "__main__":
    main()
