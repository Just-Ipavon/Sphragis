"""
Refuse to run on the abandoned PyCrypto.

pycryptodome and the unmaintained PyCrypto (last release 2013, known CVEs)
both install a top-level `Crypto` package. If both end up in an environment,
whichever was installed last wins, and every primitive here would silently run
on the wrong library. pycryptodome exposes `Crypto.version_info` (3.x and
later); PyCrypto does not. Imported first by `sphragis/__init__.py`.
"""

import Crypto

_version = getattr(Crypto, "version_info", None)
if not (isinstance(_version, tuple) and _version and int(_version[0]) >= 3):
    raise ImportError(
        "the 'Crypto' package is not pycryptodome (found version "
        f"{getattr(Crypto, '__version__', 'unknown')}): uninstall pycrypto and "
        "reinstall pycryptodome")
