"""
Master keys in a PKCS#11 token (#58), against SoftHSM2.

Runs when python-pkcs11 is installed and SoftHSM2 is found (the module path
comes from SPHRAGIS_TEST_PKCS11_MODULE, or the usual Debian/Ubuntu location).
"""

import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(__file__))

pkcs11 = pytest.importorskip("pkcs11")

from test_diversify import AN_M, AN_MASTER  # noqa: E402
from test_sdm import NXP_CMAC, NXP_KEY, NXP_PICC  # noqa: E402

from sphragis.analyzer import TagAnalyzer  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.diversify import DiversifiedKeys, diversify_key  # noqa: E402
from sphragis.emulator import tag_from_provider  # noqa: E402
from sphragis.hsm import (  # noqa: E402
    Pkcs11KeyProvider,
    build_pkcs11_keyring,
    import_keys,
)
from sphragis.keyring import KeyRing  # noqa: E402
from sphragis.sdm import compute_sdmmac, parse_picc_plain  # noqa: E402

from conftest import softhsm_available  # noqa: E402

pytestmark = pytest.mark.skipif(not softhsm_available(),
                                reason="SoftHSM2 not installed (set SPHRAGIS_TEST_PKCS11_MODULE)")


class Secrets:
    def __init__(self, **keys):
        self.keys = keys

    def get_key(self, name):
        return self.keys[name]


@pytest.fixture
def imported(token):
    prefix = f"t{uuid.uuid4().hex[:8]}."
    secrets = Secrets(master_file=os.urandom(16), meta_read=os.urandom(16),
                      master_file_v2=os.urandom(16), meta_read_v2=os.urandom(16))
    labels = import_keys(token, secrets, versions=(1, 2), prefix=prefix)
    assert labels == [prefix + n for n in ("master_file", "meta_read",
                                           "master_file_v2", "meta_read_v2")]
    return prefix, secrets


def test_an10922_vector_through_the_token(token):
    prefix = f"v{uuid.uuid4().hex[:8]}."
    import_keys(token, Secrets(master_file=AN_MASTER, meta_read=bytes(16)), prefix=prefix)
    provider = Pkcs11KeyProvider(token, prefix + "master_file", prefix + "meta_read")
    assert provider.diversify(AN_M).hex().upper() == "A8DD63A3B89D54B37CA802473FDA9175"


def test_nxp_sun_vector_through_the_token(token):
    prefix = f"n{uuid.uuid4().hex[:8]}."
    import_keys(token, Secrets(master_file=os.urandom(16), meta_read=NXP_KEY),
                prefix=prefix)
    provider = Pkcs11KeyProvider(token, prefix + "master_file", prefix + "meta_read")
    picc = parse_picc_plain(provider.decrypt_picc(NXP_PICC))
    assert compute_sdmmac(NXP_KEY, picc.uid, picc.read_counter).hex().upper() == NXP_CMAC


@pytest.mark.parametrize("context", [b"", b"DEMO", b"x" * 23])
def test_per_uid_keys_match_the_software_derivation(imported, token, context):
    prefix, secrets = imported
    provider = Pkcs11KeyProvider(token, prefix + "master_file", prefix + "meta_read",
                                 context=context)
    software = DiversifiedKeys(secrets.keys["master_file"], secrets.keys["meta_read"],
                               context=context)
    for _ in range(5):
        uid = os.urandom(7)
        assert provider.file_read_key(uid) == software.file_read_key(uid)
    assert provider.diversify(b"\x04" * 20) == diversify_key(secrets.keys["master_file"],
                                                            b"\x04" * 20)


def test_taps_verify_with_the_masters_in_the_token(imported, token):
    prefix, secrets = imported
    ring = build_pkcs11_keyring(token, versions=(2, 1), context=b"DEMO", prefix=prefix)
    analyzer = TagAnalyzer(ring, store=CounterStore())
    for version in (1, 2):
        suffix = "" if version == 1 else "_v2"
        software = DiversifiedKeys(secrets.keys["master_file" + suffix],
                                   secrets.keys["meta_read" + suffix], context=b"DEMO")
        tag = tag_from_provider(software, os.urandom(7))
        for _ in range(2):
            r = analyzer.analyze(tag.tap())
            assert r.classification == "GENUINE" and r.key_version == version
    stranger = tag_from_provider(DiversifiedKeys(os.urandom(16), os.urandom(16)),
                                 os.urandom(7))
    assert analyzer.analyze(stranger.tap()).classification in ("ERROR", "FORGED")


def test_the_masters_never_leave_the_token(imported, token):
    prefix, _ = imported
    provider = Pkcs11KeyProvider(token, prefix + "master_file", prefix + "meta_read")
    with pytest.raises(RuntimeError):
        provider.meta_read_key()
    for name in ("master_file", "meta_read"):
        key = token.key(prefix + name)
        assert key[pkcs11.Attribute.SENSITIVE] and not key[pkcs11.Attribute.EXTRACTABLE]
        with pytest.raises(pkcs11.PKCS11Error):
            key[pkcs11.Attribute.VALUE]
    # Each key does only its own job (python-pkcs11 does not even offer the
    # method a key's attributes forbid).
    refused = (pkcs11.PKCS11Error, AttributeError)
    with pytest.raises(refused):
        token.cbc(token.key(prefix + "meta_read"), bytes(16))
    with pytest.raises(refused):
        token.cbc(token.key(prefix + "master_file"), bytes(16), decrypt=True)


def test_import_refuses_to_overwrite(imported, token):
    prefix, secrets = imported
    with pytest.raises(ValueError):
        import_keys(token, secrets, versions=(1,), prefix=prefix)


def test_per_uid_cache_expires(imported, token):
    prefix, _ = imported
    now = [0.0]
    provider = Pkcs11KeyProvider(token, prefix + "master_file", prefix + "meta_read",
                                 cache_seconds=10, cache_size=2, clock=lambda: now[0])
    calls = []
    real = provider.diversify
    provider.diversify = lambda m: calls.append(m) or real(m)
    a, b, c = (os.urandom(7) for _ in range(3))
    provider.file_read_key(a)
    provider.file_read_key(a)
    assert len(calls) == 1                        # cached
    provider.file_read_key(b)
    provider.file_read_key(c)                     # evicts a (size 2)
    provider.file_read_key(a)
    assert len(calls) == 4
    now[0] = 11.0                                 # expired
    provider.file_read_key(a)
    assert len(calls) == 5


def test_missing_label_is_a_clear_error(token):
    with pytest.raises(KeyError):
        Pkcs11KeyProvider(token, "nope.master_file", "nope.meta_read")


def test_keyring_type(imported, token):
    prefix, _ = imported
    assert isinstance(build_pkcs11_keyring(token, prefix=prefix), KeyRing)
