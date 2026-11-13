"""
The key under which every per-tag store files an identity.

NTAG 424 DNA identities are bare UIDs in hex; callers have always been free
to pass them in either case, so they are upper-cased. Every other identity is
opaque: backends prefix theirs (`fido2:<credential id, base64url>`), and
base64url is case-sensitive, so folding its case would make two credentials
share one counter and one history.
"""

from __future__ import annotations

import string

_HEX = frozenset(string.hexdigits)


def store_key(identity: str) -> str:
    """Upper-case a bare hex UID; return any other identity unchanged."""
    if identity and _HEX.issuperset(identity):
        return identity.upper()
    return identity
