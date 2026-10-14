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

from fake_ntag424 import FakeNtag424  # noqa: E402
from sphragis import EncFileVerifier, StaticKeys, Verdict, Verifier  # noqa: E402
from sphragis.counterstore import CounterStore  # noqa: E402
from sphragis.diversify import DiversifiedKeys  # noqa: E402
from sphragis.ev2 import Session  # noqa: E402
from sphragis.keyprov import (  # noqa: E402
    DiversifiedTagKeys,
    FactoryKeys,
    KeyProvisionError,
    TagKeys,
    change_key,
    crc32nk,
    current_tag_keys,
    get_card_uid,
    key_check_value,
    rekey_tag,
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

def _sun_tag(uid=UID):
    tag = FakeNtag424(uid=uid)
    provision_tag(tag, BASE)
    return tag


def test_rekey_from_factory_and_verify_taps():
    tag, scheme = _sun_tag(), _scheme()
    report = rekey_tag(tag, scheme)
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
    report = rekey_tag(tag, _scheme(), dry_run=True)
    assert report.planned == [1, 2, 3, 4, 0] and not report.changed
    assert tag.key_changes == 0 and tag.keys == [ZERO] * 5


def test_rekey_is_idempotent():
    tag, scheme = _sun_tag(), _scheme()
    rekey_tag(tag, scheme)
    changes = tag.key_changes
    again = rekey_tag(tag, scheme)
    assert again.already_done and again.verified and tag.key_changes == changes


def test_back_to_factory():
    tag, scheme = _sun_tag(), _scheme()
    rekey_tag(tag, scheme)
    report = rekey_tag(tag, FactoryKeys(), known=[scheme])
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
        rekey_tag(_CutAfter(tag, cut), scheme)
    assert tag.key_versions[0] == 0 and sum(tag.key_versions) == cut
    report = rekey_tag(tag, scheme)
    assert report.verified and len(report.changed) == 5 - cut
    assert tag.keys == list(scheme.keys_for(UID).keys)


@pytest.mark.parametrize("cut", [1, 2, 4])
def test_interrupted_reset_resumes(cut):
    # cut=1 leaves MetaRead diversified but FileRead factory: the UID must
    # still come from a tap verified under mixed slot schemes.
    tag, scheme = _sun_tag(), _scheme()
    rekey_tag(tag, scheme)
    with pytest.raises(ConnectionError):
        rekey_tag(_CutAfter(tag, cut), FactoryKeys(), known=[scheme])
    report = rekey_tag(tag, FactoryKeys(), known=[scheme])
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
    report = rekey_tag(tag, _scheme())
    assert report.changed == [1, 2, 3, 4, 0] and not report.verified


def test_unknown_key_version_stops_before_writing():
    tag = _sun_tag()
    tag.key_versions[3] = 0x42
    with pytest.raises(KeyProvisionError, match="slot 3"):
        rekey_tag(tag, _scheme())
    assert tag.key_changes == 0


def test_unknown_slot0_key_is_refused():
    tag = FakeNtag424(uid=UID, keys=[os.urandom(16)] + [ZERO] * 4)
    with pytest.raises(KeyProvisionError, match="slot 0"):
        rekey_tag(tag, _scheme())
    assert tag.key_changes == 0


def test_expected_uid_mismatch_is_refused():
    tag = _sun_tag()
    with pytest.raises(KeyProvisionError, match="differs"):
        rekey_tag(tag, _scheme(), uid=H("04FFFFFFFFFFFF"))
    assert tag.key_changes == 0


def test_tag_without_sdm_needs_the_uid_once_keyed():
    tag, scheme = FakeNtag424(uid=UID), _scheme()      # factory, no SUN template
    assert rekey_tag(tag, scheme).verified              # UID via GetCardUID
    with pytest.raises(KeyProvisionError, match="pass it"):
        rekey_tag(tag, FactoryKeys(), known=[scheme])   # no tap to read a UID from
    assert rekey_tag(tag, FactoryKeys(), known=[scheme], uid=UID).verified


def test_versions_must_identify_schemes():
    with pytest.raises(ValueError):
        rekey_tag(_sun_tag(), _scheme(), known=[_scheme(context=b"OTHER")])


def test_current_tag_keys():
    tag, scheme = _sun_tag(), _scheme()
    assert current_tag_keys(tag, [scheme]) == FactoryKeys().keys_for(UID)
    rekey_tag(tag, scheme)
    assert current_tag_keys(tag, [scheme]) == scheme.keys_for(UID)
    tag.key_versions[4] = 0x00                          # half-done run
    with pytest.raises(KeyProvisionError, match="different schemes"):
        current_tag_keys(tag, [scheme])


def test_provisioning_after_rekey_uses_the_real_keys():
    tag, scheme = _sun_tag(), _scheme()
    rekey_tag(tag, scheme)
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


def test_rekey_tool(tmp_path, capsys):
    tag, tool = _sun_tag(), _tool()
    tool.reader_factory = lambda args: (lambda: _Wrapped(tag))
    base = ["--reader", "pn532", "--secrets-dir", _secrets_dir(tmp_path), "--context", "DEMO"]
    assert tool.main(base + ["--dry-run"]) == 0 and tag.key_changes == 0
    assert "would change" in capsys.readouterr().out
    assert tool.main(base + ["--yes"]) == 0
    assert "keys changed and verified" in capsys.readouterr().out
    assert tag.keys == list(_scheme().keys_for(UID).keys)
    assert tool.main(base + ["--to-factory", "--yes"]) == 0
    assert tag.keys == [ZERO] * 5


@pytest.mark.parametrize("extra", [
    [],                                         # neither --dry-run nor --yes
    ["--dry-run", "--yes"],
    ["--yes", "--uid", "zz"],
])
def test_rekey_tool_refuses_unsafe_invocations(tmp_path, extra):
    argv = ["--reader", "pn532", "--secrets-dir", _secrets_dir(tmp_path), *extra]
    with pytest.raises(SystemExit):
        _tool().main(argv)


def test_rekey_tool_refuses_emulator(tmp_path):
    with pytest.raises(SystemExit):
        _tool().main(["--reader", "emulator", "--secrets-dir", _secrets_dir(tmp_path),
                      "--dry-run"])
