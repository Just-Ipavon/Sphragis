"""
Key provisioning: ChangeKey, GetKeyVersion, GetCardUID and the rekey flow.

The primitives are pinned byte for byte to NXP AN12196 (Table 25: ChangeKey of
another key; Table 26: ChangeKey of the session key; Table 28: GetCardUID).
The flow runs against the fake PICC, which implements the PICC side of those
commands independently, including the CRC32 check and the end of the session
after the session key changes.
"""

import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from fake_ntag424 import TEST_ORIGINALITY_KEY, FakeNtag424, sign_uid  # noqa: E402
from sphragis import EncFileVerifier, StaticKeys, Verdict, Verifier  # noqa: E402
from sphragis.apdu import ApduError  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.diversify import DiversifiedKeys  # noqa: E402
from sphragis.ev2 import Session  # noqa: E402
from sphragis.keyprov import (  # noqa: E402
    DiversifiedTagKeys,
    FactoryKeys,
    INVENTORY_FACTORY,
    INVENTORY_KEYED,
    INVENTORY_KEYING,
    NXP_NTAG424_ORIGINALITY_KEY,
    KeyProvisionError,
    MemoryKeyInventory,
    SqliteKeyInventory,
    TagKeys,
    change_key,
    crc32nk,
    current_tag_keys,
    get_card_uid,
    key_check_value,
    read_signature,
    rekey_tag,
    verify_originality,
)
from sphragis.ndef import read_uri  # noqa: E402
from sphragis.provision import provision_tag  # noqa: E402
from sphragis.transport import ScriptedTransport  # noqa: E402

H = bytes.fromhex
ZERO = bytes(16)
BASE = "https://example.com/t"
UID = H("04112233445566")

# --- AN12196 §5.16 / §6.3 known-answer vectors ----------------------------------

AN_TI = H("7614281A")
AN_K_ENC = H("4CF3CB41A22583A61E89B158D252FC53")
AN_K_MAC = H("5529860B2FC5FB6154B7F28361D30BF9")


def _an_session(transport, ctr):
    return Session(transport=transport, ti=AN_TI, k_enc=AN_K_ENC, k_mac=AN_K_MAC,
                   cmd_ctr=ctr)


def test_crc32nk_matches_an12196():
    assert crc32nk(H("F3847D627727ED3BC9C4CC050489B966")).hex().upper() == "789DFADC"


def test_change_key_other_than_session_key_table25():
    apdu = H("90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1"
             "FAC75D0CE20BCD1D06E600")
    t = ScriptedTransport([(apdu, H("203BB55D1089D5879100"))])
    s = _an_session(t, 2)
    alive = change_key(s, 2, H("F3847D627727ED3BC9C4CC050489B966"), 0x01,
                       auth_key_no=0, old_key=ZERO)
    assert alive and t.exhausted and s.cmd_ctr == 3        # response MAC verified


def test_change_key_of_session_key_table26():
    apdu = H("90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A0"
             "1D6FDA6610234BDED643200")
    t = ScriptedTransport([(apdu, H("9100"))])
    alive = change_key(_an_session(t, 3), 0, H("5004BF991F408672B1EF00F08F9E8647"),
                       0x01, auth_key_no=0)
    assert not alive and t.exhausted                        # session is gone


def test_get_card_uid_table28():
    t = ScriptedTransport([(H("90510000088E2C155ADDA99BE300"),
                            H("70756055688505B52A5E26E59E329CD6595F672298EA41B79100"))])
    s = Session(transport=t, ti=H("DF055522"), k_enc=H("2B4D963C014DC36F24F69A50A394F875"),
                k_mac=H("379D32130CE61705DD5FD8C36B95D764"))
    assert get_card_uid(s) == H("04958CAA5C5E80") and s.cmd_ctr == 1


def test_change_key_needs_the_old_key_for_other_slots():
    with pytest.raises(ValueError):
        change_key(_an_session(None, 0), 2, os.urandom(16), 1, auth_key_no=0)


# --- Key schemes ----------------------------------------------------------------

def _scheme(version=0x01, context=b"DEMO"):
    return DiversifiedTagKeys(H("A0" * 16), H("B1" * 16), H("C2" * 16),
                              context=context, version=version)


def test_diversified_slots():
    keys = _scheme().keys_for(UID)
    assert keys[1] == DiversifiedKeys(H("B1" * 16), H("C2" * 16),
                                      context=b"DEMO").file_read_key(UID)
    assert keys[2] == H("C2" * 16)                      # shared MetaRead key
    assert len({keys[0], keys[1], keys[3], keys[4]}) == 4
    assert _scheme().keys_for(H("04112233445567"))[0] != keys[0]   # per UID
    assert keys.version == 0x01


def test_keys_never_appear_in_reprs():
    keys = _scheme().keys_for(UID)
    for text in (repr(keys), repr(_scheme())):
        assert all(k.hex() not in text.lower() for k in keys.keys)
    assert key_check_value(ZERO) in repr(FactoryKeys().keys_for(UID))


@pytest.mark.parametrize("kwargs", [dict(version=0), dict(version=256),
                                    dict(context=b"x" * 24)])
def test_scheme_rejects_bad_parameters(kwargs):
    with pytest.raises(ValueError):
        _scheme(**kwargs)


def test_tag_keys_validation():
    with pytest.raises(ValueError):
        TagKeys((ZERO,) * 4, 0, "short")


def test_scheme_from_secrets():
    class Secrets:
        values = {"master_admin": H("A0" * 16), "master_file": H("B1" * 16),
                  "meta_read": H("C2" * 16)}

        def get_key(self, name):
            return self.values[name]

    loaded = DiversifiedTagKeys.from_secrets(Secrets(), context=b"DEMO")
    assert loaded.keys_for(UID) == _scheme().keys_for(UID)


# --- Flow against the fake PICC --------------------------------------------------

def _inventory(tag):
    """One inventory per physical (fake) tag, shared across runs on it."""
    return vars(getattr(tag, "tag", tag)).setdefault("_inventory", MemoryKeyInventory())


def _rekey(tag, target, known=(), **kwargs):
    kwargs.setdefault("originality_key", TEST_ORIGINALITY_KEY)
    kwargs.setdefault("inventory", _inventory(tag))
    return rekey_tag(tag, target, known, **kwargs)


def _sun_tag(uid=UID):
    tag = FakeNtag424(uid=uid)
    provision_tag(tag, BASE)
    return tag


def test_rekey_from_factory_and_verify_taps():
    tag, scheme = _sun_tag(), _scheme()
    report = _rekey(tag, scheme)
    assert report.verified and report.changed == [1, 2, 3, 4, 0]
    assert tag.keys == list(scheme.keys_for(UID).keys)
    assert tag.key_versions == [0x01] * 5

    # The verifier side (master_file + meta_read only) accepts the tag's taps.
    server = DiversifiedKeys(H("B1" * 16), H("C2" * 16), context=b"DEMO")
    assert Verifier(server, CounterStore()).verify(read_uri(tag)).verdict is Verdict.AUTHENTIC
    zero = Verifier(StaticKeys(ZERO, ZERO), CounterStore()).verify(read_uri(tag))
    assert zero.verdict is not Verdict.AUTHENTIC


def test_dry_run_changes_nothing():
    tag = _sun_tag()
    report = _rekey(tag, _scheme(), dry_run=True)
    assert report.planned == [1, 2, 3, 4, 0] and not report.changed
    assert tag.key_changes == 0 and tag.keys == [ZERO] * 5


def test_rekey_is_idempotent():
    tag, scheme = _sun_tag(), _scheme()
    _rekey(tag, scheme)
    changes = tag.key_changes
    again = _rekey(tag, scheme)
    assert again.already_done and again.verified and tag.key_changes == changes


def test_back_to_factory():
    tag, scheme = _sun_tag(), _scheme()
    _rekey(tag, scheme)
    report = _rekey(tag, FactoryKeys(), known=[scheme])
    assert report.verified and tag.keys == [ZERO] * 5 and tag.key_versions == [0] * 5


class _CutAfter:
    """Transport that loses the tag after `n` ChangeKey commands went through."""

    def __init__(self, tag, n):
        self.tag, self.left = tag, n

    def transceive(self, apdu):
        if apdu[:2] == b"\x90\xC4":
            if self.left == 0:
                raise ConnectionError("tag removed")
            self.left -= 1
        return self.tag.transceive(apdu)


@pytest.mark.parametrize("cut", [1, 2, 4])
def test_interrupted_rekey_resumes(cut):
    tag, scheme = _sun_tag(), _scheme()
    with pytest.raises(ConnectionError):
        _rekey(_CutAfter(tag, cut), scheme)
    assert tag.key_versions[0] == 0 and sum(tag.key_versions) == cut
    report = _rekey(tag, scheme)
    assert report.verified and len(report.changed) == 5 - cut
    assert tag.keys == list(scheme.keys_for(UID).keys)


@pytest.mark.parametrize("cut", [1, 2, 4])
def test_interrupted_reset_resumes(cut):
    # cut=1 leaves MetaRead diversified but FileRead factory: the UID must
    # still come from a tap verified under mixed slot schemes.
    tag, scheme = _sun_tag(), _scheme()
    _rekey(tag, scheme)
    with pytest.raises(ConnectionError):
        _rekey(_CutAfter(tag, cut), FactoryKeys(), known=[scheme])
    report = _rekey(tag, FactoryKeys(), known=[scheme])
    assert report.verified and tag.keys == [ZERO] * 5


class _WrongVersionTag(FakeNtag424):
    """A PICC that stores a different key version from the one sent."""

    def _change_key(self, data):
        result = self._change_key_real(data)
        self.key_versions = [v and 0x09 for v in self.key_versions]
        return result


_WrongVersionTag._change_key_real = FakeNtag424._change_key


def test_verification_checks_the_stored_versions():
    tag = _WrongVersionTag(uid=UID)
    report = _rekey(tag, _scheme())
    assert report.changed == [1, 2, 3, 4, 0] and not report.verified


def test_unknown_key_version_stops_before_writing():
    tag = _sun_tag()
    tag.key_versions[3] = 0x42
    with pytest.raises(KeyProvisionError, match="slot 3"):
        _rekey(tag, _scheme())
    assert tag.key_changes == 0


def test_unknown_slot0_key_is_refused():
    tag = FakeNtag424(uid=UID, keys=[os.urandom(16)] + [ZERO] * 4)
    with pytest.raises(KeyProvisionError, match="slot 0"):
        _rekey(tag, _scheme())
    assert tag.key_changes == 0


def test_expected_uid_mismatch_is_refused():
    tag = _sun_tag()
    with pytest.raises(KeyProvisionError, match="differs"):
        _rekey(tag, _scheme(), uid=H("04FFFFFFFFFFFF"))
    assert tag.key_changes == 0


def test_tag_without_sdm_needs_the_uid_once_keyed():
    tag, scheme = FakeNtag424(uid=UID), _scheme()      # factory, no SUN template
    assert _rekey(tag, scheme).verified              # UID via GetCardUID
    with pytest.raises(KeyProvisionError, match="pass it"):
        _rekey(tag, FactoryKeys(), known=[scheme])   # no tap to read a UID from
    assert _rekey(tag, FactoryKeys(), known=[scheme], uid=UID).verified


def test_versions_must_identify_schemes():
    with pytest.raises(ValueError):
        _rekey(_sun_tag(), _scheme(), known=[_scheme(context=b"OTHER")])


def test_current_tag_keys():
    tag, scheme = _sun_tag(), _scheme()
    assert current_tag_keys(tag, [scheme]) == FactoryKeys().keys_for(UID)
    _rekey(tag, scheme)
    assert current_tag_keys(tag, [scheme]) == scheme.keys_for(UID)
    tag.key_versions[4] = 0x00                          # half-done run
    with pytest.raises(KeyProvisionError, match="different schemes"):
        current_tag_keys(tag, [scheme])


def test_provisioning_after_rekey_uses_the_real_keys():
    tag, scheme = _sun_tag(), _scheme()
    _rekey(tag, scheme)
    keys = current_tag_keys(tag, [scheme])
    data = b"0123456789ABCDEF"
    # ChangeFileSettings and the write lock now need the diversified slot 0.
    report = provision_tag(tag, BASE, file_data=data, tag_keys=keys)
    assert report.verified and report.changed_settings
    again = provision_tag(tag, BASE, file_data=b"FEDCBA9876543210", tag_keys=keys)
    assert again.verified and "WriteData" in "".join(again.log)
    server = DiversifiedKeys(H("B1" * 16), H("C2" * 16), context=b"DEMO")
    r = EncFileVerifier(server, CounterStore()).verify(read_uri(tag))
    assert r.ok and r.file_data == b"FEDCBA9876543210"
    with pytest.raises(Exception):                      # factory keys no longer work
        provision_tag(tag, BASE)


# --- Originality signature -------------------------------------------------------

def test_nxp_originality_key_is_a_p224_point():
    from Crypto.PublicKey import ECC
    key = NXP_NTAG424_ORIGINALITY_KEY
    assert len(key) == 57 and key[0] == 0x04
    ECC.EccPoint(int.from_bytes(key[1:29], "big"), int.from_bytes(key[29:], "big"),
                 curve="P-224")                         # raises if off the curve


def test_originality_signature_verifies_only_for_its_uid():
    sig = sign_uid(UID)
    assert verify_originality(UID, sig, TEST_ORIGINALITY_KEY)
    assert not verify_originality(H("04112233445567"), sig, TEST_ORIGINALITY_KEY)
    assert not verify_originality(UID, sig)             # under the NXP key
    tampered = bytearray(sig)
    tampered[40] ^= 1
    assert not verify_originality(UID, bytes(tampered), TEST_ORIGINALITY_KEY)


@pytest.mark.parametrize("sig", [bytes(56), b"\xff" * 56, bytes(55)])
def test_originality_rejects_malformed_signatures(sig):
    assert not verify_originality(UID, sig, TEST_ORIGINALITY_KEY)


def test_originality_rejects_a_key_off_the_curve():
    bad = TEST_ORIGINALITY_KEY[:-1] + bytes([TEST_ORIGINALITY_KEY[-1] ^ 1])
    assert not verify_originality(UID, sign_uid(UID), bad)


def test_read_signature_apdu():
    sig = sign_uid(UID)
    t = ScriptedTransport([(H("903C0000010000"), sig + H("9100"))])
    assert read_signature(t) == sig and t.exhausted
    chained = ScriptedTransport([(H("903C0000010000"), sig[:40] + H("91AF")),
                                 (H("90AF000000"), sig[40:] + H("9100"))])
    assert read_signature(chained) == sig
    with pytest.raises(KeyProvisionError):
        read_signature(ScriptedTransport([(H("903C0000010000"), sig[:50] + H("9100"))]))


# --- Identity checks before keys leave the station (issue: rekey to an emulator) ---

def _clone_of(tag):
    """A factory-state device answering with the UID and signature of `tag`."""
    clone = FakeNtag424(uid=tag.uid)
    clone.signature = tag.signature                    # the signature is static
    provision_tag(clone, BASE)
    return clone


def test_clone_of_a_keyed_uid_receives_no_key():
    genuine, scheme = _sun_tag(), _scheme()
    inventory = MemoryKeyInventory()
    assert _rekey(genuine, scheme, inventory=inventory).verified
    assert inventory.state(UID) == INVENTORY_KEYED
    clone = _clone_of(genuine)
    with pytest.raises(KeyProvisionError, match="already in the inventory"):
        _rekey(clone, scheme, inventory=inventory)
    assert clone.key_changes == 0 and clone.keys == [ZERO] * 5


def test_clone_with_a_made_up_uid_fails_the_signature():
    fake = FakeNtag424(uid=H("04AABBCCDDEEFF"))
    fake.signature = sign_uid(UID)                     # a real signature, other UID
    with pytest.raises(KeyProvisionError, match="originality"):
        _rekey(fake, _scheme())
    assert fake.key_changes == 0


def test_tag_without_read_sig_is_refused():
    class NoSig(FakeNtag424):
        def _native(self, ins, data):
            return b"\x91\x1C" if ins == 0x3C else super()._native(ins, data)

    tag = NoSig(uid=UID)
    with pytest.raises(ApduError):
        _rekey(tag, _scheme())
    assert tag.key_changes == 0
    assert _rekey(tag, _scheme(), originality_key=None).verified   # explicit opt-out


def test_claimed_keys_must_authenticate():
    # A clone claiming slot 1 is already keyed (version 01h) cannot prove it.
    genuine = _sun_tag()
    _rekey(genuine, _scheme())
    clone = _clone_of(genuine)
    clone.key_versions[1] = 0x01
    with pytest.raises(KeyProvisionError, match="slot 1 claims"):
        _rekey(clone, _scheme(), inventory=_inventory(genuine))
    assert clone.key_changes == 0


def test_shared_meta_key_is_no_proof_of_identity():
    # Slot 2 holds the shared MetaRead key, which a reader-side leak exposes:
    # a clone holding it there still proves nothing about its UID.
    genuine, scheme = _sun_tag(), _scheme()
    _rekey(genuine, scheme)
    clone = _clone_of(genuine)
    clone.keys[2], clone.key_versions[2] = scheme.meta_read_key, 0x01
    with pytest.raises(KeyProvisionError, match="already in the inventory"):
        _rekey(clone, scheme, inventory=_inventory(genuine))
    assert clone.key_changes == 0


def test_interrupted_run_is_resumed_on_proof_of_possession():
    tag, scheme = _sun_tag(), _scheme()
    with pytest.raises(ConnectionError):
        _rekey(_CutAfter(tag, 1), scheme)
    assert _inventory(tag).state(UID) == INVENTORY_KEYING
    report = _rekey(tag, scheme)
    assert report.proven == [1] and report.verified
    assert _inventory(tag).state(UID) == INVENTORY_KEYED


def test_known_uid_back_on_factory_keys():
    tag, scheme = _sun_tag(), _scheme()
    _rekey(tag, scheme)
    _rekey(tag, FactoryKeys(), known=[scheme])          # reset by this tool: recorded
    assert _inventory(tag).state(UID) == INVENTORY_FACTORY
    assert _rekey(tag, scheme).verified                 # so keying again is fine

    other = MemoryKeyInventory()                        # reset outside the tool
    other.record(UID, INVENTORY_KEYED, 0x01)
    fresh = _sun_tag()
    with pytest.raises(KeyProvisionError):
        _rekey(fresh, scheme, inventory=other)
    report = _rekey(fresh, scheme, inventory=other, allow_known_uid=True)
    assert report.verified and any("WARNING" in line for line in report.log)


def test_anticollision_uid_must_match():
    tag = _sun_tag()
    tag.anticollision_uid = H("04000000000001")
    with pytest.raises(KeyProvisionError, match="anticollision"):
        _rekey(tag, _scheme())
    assert tag.key_changes == 0
    tag.anticollision_uid = UID
    assert _rekey(tag, _scheme()).verified


def test_operator_can_decline():
    tag, seen = _sun_tag(), []

    def confirm(report):
        seen.append((report.uid, list(report.planned), report.signature_ok))
        return False

    report = _rekey(tag, _scheme(), confirm=confirm)
    assert report.aborted and not report.changed and tag.key_changes == 0
    assert seen == [(UID, [1, 2, 3, 4, 0], True)]
    assert _inventory(tag).state(UID) is None           # nothing sent, nothing recorded


def test_keying_needs_an_inventory():
    tag = _sun_tag()
    with pytest.raises(ValueError, match="inventory"):
        rekey_tag(tag, _scheme(), originality_key=TEST_ORIGINALITY_KEY)
    assert rekey_tag(tag, _scheme(), originality_key=TEST_ORIGINALITY_KEY,
                     dry_run=True).planned


def test_sqlite_inventory(tmp_path):
    path = str(tmp_path / "inventory.db")
    first = SqliteKeyInventory(path)
    assert first.state(UID) is None
    first.record(UID, INVENTORY_KEYING, 1)
    first.record(UID, INVENTORY_KEYED, 1)
    assert SqliteKeyInventory(path).state(UID) == INVENTORY_KEYED
    with pytest.raises(ValueError):
        first.record(UID, "whatever", 1)


# --- tools/rekey.py ----------------------------------------------------------------

def _secrets_dir(tmp_path):
    for name, value in (("master_admin", "A0"), ("master_file", "B1"), ("meta_read", "C2")):
        path = tmp_path / name
        path.write_text(value * 16)
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return str(tmp_path)


def _tool():
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools", "rekey.py")
    spec = importlib.util.spec_from_file_location("tool_rekey", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Wrapped:
    def __init__(self, tag):
        self.tag = tag

    def transceive(self, apdu):
        return self.tag.transceive(apdu)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


def _tool_args(tmp_path, *extra):
    secrets = tmp_path / "keys"
    secrets.mkdir(exist_ok=True)
    return ["--reader", "pn532", "--secrets-dir", _secrets_dir(secrets),
            "--inventory", str(tmp_path / "inventory.db"), "--context", "DEMO", *extra]


def _tool_on(tag):
    tool = _tool()
    tool.reader_factory = lambda args: (lambda: _Wrapped(tag))
    tool.ORIGINALITY_KEY = TEST_ORIGINALITY_KEY
    return tool


def test_rekey_tool(tmp_path, capsys):
    tag = _sun_tag()
    tool = _tool_on(tag)
    assert tool.main(_tool_args(tmp_path, "--dry-run")) == 0 and tag.key_changes == 0
    out = capsys.readouterr().out
    assert "would change" in out and "NXP signature verifies" in out
    assert tool.main(_tool_args(tmp_path, "--yes", "--uid", UID.hex())) == 0
    assert "keys changed and verified" in capsys.readouterr().out
    assert tag.keys == list(_scheme().keys_for(UID).keys)
    assert SqliteKeyInventory(str(tmp_path / "inventory.db")).state(UID) == INVENTORY_KEYED
    assert tool.main(_tool_args(tmp_path, "--to-factory", "--yes", "--uid", UID.hex())) == 0
    assert tag.keys == [ZERO] * 5
    assert SqliteKeyInventory(str(tmp_path / "inventory.db")).state(UID) == INVENTORY_FACTORY


def test_rekey_tool_asks_to_type_the_uid(tmp_path, monkeypatch, capsys):
    tag = _sun_tag()
    tool = _tool_on(tag)
    monkeypatch.setattr("builtins.input", lambda prompt: "04 11 22")
    assert tool.main(_tool_args(tmp_path, "--yes")) == 1
    assert "aborted" in capsys.readouterr().out and tag.key_changes == 0
    monkeypatch.setattr("builtins.input", lambda prompt: UID.hex().lower())
    assert tool.main(_tool_args(tmp_path, "--yes")) == 0
    assert tag.key_versions == [0x01] * 5


def test_rekey_tool_refuses_a_clone_of_a_keyed_uid(tmp_path, capsys):
    genuine = _sun_tag()
    assert _tool_on(genuine).main(_tool_args(tmp_path, "--yes", "--uid", UID.hex())) == 0
    clone = _clone_of(genuine)
    assert _tool_on(clone).main(_tool_args(tmp_path, "--yes", "--uid", UID.hex())) == 2
    assert "REFUSED" in capsys.readouterr().out and clone.key_changes == 0


@pytest.mark.parametrize("extra", [
    [],                                         # neither --dry-run nor --yes
    ["--dry-run", "--yes"],
    ["--yes", "--uid", "zz"],
])
# (and --inventory is mandatory: see test_rekey_tool_needs_an_inventory)
def test_rekey_tool_refuses_unsafe_invocations(tmp_path, extra):
    argv = ["--reader", "pn532", "--secrets-dir", _secrets_dir(tmp_path),
            "--inventory", str(tmp_path / "inv.db"), *extra]
    with pytest.raises(SystemExit):
        _tool().main(argv)


def test_rekey_tool_refuses_emulator(tmp_path):
    with pytest.raises(SystemExit):
        _tool().main(["--reader", "emulator", "--secrets-dir", _secrets_dir(tmp_path),
                      "--inventory", str(tmp_path / "inv.db"), "--dry-run"])


def test_rekey_tool_needs_an_inventory(tmp_path):
    with pytest.raises(SystemExit):
        _tool().main(["--reader", "pn532", "--secrets-dir", _secrets_dir(tmp_path),
                      "--dry-run"])
