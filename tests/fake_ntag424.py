"""
Test-only model of the NTAG 424 DNA PICC side, enough to exercise provisioning:

  ISOSelect (NDEF app / CC / NDEF file), ISOReadBinary with SDM mirroring
  (PICCData, SDMENCFileData, SDMMAC over the dynamic MAC input),
  ISOUpdateBinary and WriteData under the file's access rights,
  GetFileSettings (plain), AuthenticateEV2First, ChangeFileSettings and
  ChangeKey (both cases) in CommMode.Full, GetKeyVersion (MAC),
  GetCardUID (Full, encrypted response) and Read_Sig (plain, unauthenticated).

The originality signature is made with a test key (`TEST_ORIGINALITY_KEY` is
its public half) by a small affine secp224r1 implementation written here,
independent of the pycryptodome point arithmetic the verifier uses.

It reuses Sphragis' own primitives for SDM (compute_sdmmac) and file settings
parsing, but implements the PICC half of EV2 independently so that the
reader-side code in sphragis.ev2 is checked against a counterpart.
"""

import os
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from sphragis.apdu import CC_FILE_ID, NDEF_APP_AID, NDEF_FILE_ID
from sphragis.sdm import compute_sdmmac
from sphragis.sdmenc import encrypt_file_data
from sphragis.sdmconfig import FACTORY_ACCESS, KEY_FREE, FileSettings, parse_file_settings

ZERO_IV = bytes(16)

# --- secp224r1, affine coordinates (test signer only) ---------------------------
_P = 2**224 - 2**96 + 1
_A = _P - 3
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
_G = (0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
      0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _ec_mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _ec_add(result, point)
        point = _ec_add(point, point)
        k >>= 1
    return result


_TEST_D = int.from_bytes(bytes.fromhex("5A17" * 14), "big") % _N
_TEST_Q = _ec_mul(_TEST_D, _G)
TEST_ORIGINALITY_KEY = (b"\x04" + _TEST_Q[0].to_bytes(28, "big")
                        + _TEST_Q[1].to_bytes(28, "big"))


def sign_uid(uid, d=_TEST_D):
    """ECDSA over the raw UID (no hash), as the NXP originality signature."""
    e = int.from_bytes(uid, "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % _N
        if not k:
            continue
        r = _ec_mul(k, _G)[0] % _N
        s = pow(k, -1, _N) * (e + r * d) % _N
        if r and s:
            return r.to_bytes(28, "big") + s.to_bytes(28, "big")


def _cmac(key, msg):
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg)
    return c.digest()


class FakeNtag424:
    def __init__(self, uid=None, keys=None, settings=None, content=b""):
        self.uid = uid or bytes.fromhex("04") + os.urandom(6)
        self.keys = list(keys or [bytes(16)] * 5)
        self.key_versions = [0x00] * 5
        self.key_changes = 0
        self.settings = settings or FileSettings(0x00, FACTORY_ACCESS)
        self.file = bytearray(content.ljust(256, b"\x00"))
        self.counter = 0
        self.writes = 0
        self.app = False
        self.current = None
        self.snapshot = None
        self._auth = None       # (key_no, rnd_b) during part 1
        self.signature = sign_uid(self.uid)
        self.session = None     # dict(ti, k_enc, k_mac, ctr)

    # -- transport interface -------------------------------------------------
    def transceive(self, apdu):
        cla, ins = apdu[0], apdu[1]
        if cla == 0x00:
            return self._iso(ins, apdu)
        if cla == 0x90:
            data = apdu[5:5 + apdu[4]] if len(apdu) > 5 else b""
            return self._native(ins, data)
        return b"\x6E\x00"

    # -- ISO 7816-4 ----------------------------------------------------------
    def _iso(self, ins, apdu):
        p1, p2 = apdu[2], apdu[3]
        if ins == 0xA4:
            target = apdu[5:5 + apdu[4]]
            if p1 == 0x04 and target == NDEF_APP_AID:
                self.app, self.current, self.session = True, None, None
                return b"\x90\x00"
            if p1 == 0x00 and self.app and int.from_bytes(target, "big") in (CC_FILE_ID, NDEF_FILE_ID):
                self.current = int.from_bytes(target, "big")
                self.snapshot = None
                return b"\x90\x00"
            return b"\x6A\x82"
        if self.current != NDEF_FILE_ID:
            return b"\x69\x86"
        offset = (p1 << 8) | p2
        if ins == 0xB0:
            le = apdu[4] or 256
            return self._content()[offset:offset + le] + b"\x90\x00"
        if ins == 0xD6:
            # Observed on silicon: a trailing Le (the AN12196 Table 16 form) is
            # rejected as a length error on a single-frame write, whatever the
            # access rights: 6700 on 48 bytes to a free file (UID
            # 04341A82161690), and before the access check when writes are
            # locked (UID 04801A82161690). Only a chained 122-byte write with
            # Le got through. The fake sees APDUs, not frames, so it refuses
            # Le on every write; the datasheet form without Le is accepted, or
            # reaches the access check and gets 6982.
            if len(apdu) == 5 + apdu[4] + 1:
                return b"\x67\x00"
            access = self.settings.access
            if KEY_FREE not in (access.write, access.read_write):
                return b"\x69\x82"
            data = apdu[5:5 + apdu[4]]
            self.file[offset:offset + len(data)] = data
            self.writes += 1
            return b"\x90\x00"
        return b"\x6D\x00"

    def _content(self):
        if self.snapshot is None:
            data = bytearray(self.file)
            s = self.settings
            if s.sdm_enabled:
                self.counter += 1
                plain = bytes([0xC7]) + self.uid + self.counter.to_bytes(3, "little")
                plain += os.urandom(16 - len(plain))
                picc = AES.new(self.keys[s.meta_read], AES.MODE_CBC, ZERO_IV).encrypt(plain)
                data[s.picc_offset:s.picc_offset + 32] = picc.hex().upper().encode()
                file_key = self.keys[s.file_read]
                if s.enc_enabled:
                    # Only the first half of the placeholder is plaintext.
                    start, n = s.enc_offset, s.enc_length
                    enc = encrypt_file_data(file_key, self.uid, self.counter,
                                            bytes(self.file[start:start + n // 2]))
                    data[start:start + n] = enc.hex().upper().encode()
                mac_input = bytes(data[s.mac_input_offset:s.mac_offset])
                mac = compute_sdmmac(file_key, self.uid, self.counter, mac_input)
                data[s.mac_offset:s.mac_offset + 16] = mac.hex().upper().encode()
            self.snapshot = bytes(data)
        return self.snapshot

    # -- native commands -----------------------------------------------------
    def _native(self, ins, data):
        if ins == 0xF5:
            enc = self.settings.encode_change()
            return bytes([0x00]) + enc[:3] + (256).to_bytes(3, "little") + enc[3:] + b"\x91\x00"
        if ins == 0x71:
            key_no = data[0]
            rnd_b = os.urandom(16)
            self.session = None          # a new authentication drops the old session
            self._auth = (key_no, rnd_b)
            return AES.new(self.keys[key_no], AES.MODE_CBC, ZERO_IV).encrypt(rnd_b) + b"\x91\xAF"
        if ins == 0xAF and self._auth:
            key_no, rnd_b = self._auth
            self._auth = None
            key = self.keys[key_no]
            plain = AES.new(key, AES.MODE_CBC, ZERO_IV).decrypt(data)
            rnd_a, rnd_b_rot = plain[:16], plain[16:]
            if rnd_b_rot != rnd_b[1:] + rnd_b[:1]:
                return b"\x91\xAE"
            ti = os.urandom(4)
            tail = (rnd_a[0:2] + bytes(x ^ y for x, y in zip(rnd_a[2:8], rnd_b[0:6]))
                    + rnd_b[6:16] + rnd_a[8:16])
            self.session = dict(
                key_no=key_no, ti=ti, ctr=0,
                k_enc=_cmac(key, bytes.fromhex("A55A00010080") + tail),
                k_mac=_cmac(key, bytes.fromhex("5AA500010080") + tail))
            resp = ti + rnd_a[1:] + rnd_a[:1] + bytes(12)
            return AES.new(key, AES.MODE_CBC, ZERO_IV).encrypt(resp) + b"\x91\x00"
        if ins == 0x3C:
            if data != b"\x00" or self.session:
                return b"\x91\x7E"        # only the plain, unauthenticated form is modelled
            return self.signature + b"\x91\x90"     # as on silicon
        if ins == 0x5F:
            return self._change_file_settings(data)
        if ins == 0x8D:
            return self._write_data(data)
        if ins == 0xC4:
            return self._change_key(data)
        if ins == 0x64:
            return self._get_key_version(data)
        if ins == 0x51:
            return self._get_card_uid(data)
        return b"\x91\x1C"

    # -- secure messaging helpers (PICC side) -------------------------------
    def _verify_cmd(self, ins, header, payload, mac):
        s = self.session
        ctr = s["ctr"].to_bytes(2, "little")
        expect = _cmac(s["k_mac"], bytes([ins]) + ctr + s["ti"] + header + payload)[1::2]
        return mac == expect

    def _decrypt_cmd(self, enc):
        s = self.session
        ctr = s["ctr"].to_bytes(2, "little")
        iv = AES.new(s["k_enc"], AES.MODE_ECB).encrypt(b"\xA5\x5A" + s["ti"] + ctr + bytes(8))
        plain = AES.new(s["k_enc"], AES.MODE_CBC, iv).decrypt(enc)
        return plain[:plain.rindex(b"\x80")]

    def _respond(self, body=b""):
        """Advance CmdCtr and answer 9100 with body || MACt (CommMode.MAC/Full)."""
        s = self.session
        s["ctr"] += 1
        ctr = s["ctr"].to_bytes(2, "little")
        mac = _cmac(s["k_mac"], b"\x00" + ctr + s["ti"] + body)[1::2]
        return body + mac + b"\x91\x00"

    def _encrypt_resp(self, plain):
        s = self.session
        ctr = (s["ctr"] + 1).to_bytes(2, "little")
        iv = AES.new(s["k_enc"], AES.MODE_ECB).encrypt(b"\x5A\xA5" + s["ti"] + ctr + bytes(8))
        plain += b"\x80" + bytes(-(len(plain) + 1) % 16)
        return AES.new(s["k_enc"], AES.MODE_CBC, iv).encrypt(plain)

    def _change_key(self, data):
        s = self.session
        if s is None or s["key_no"] != 0:        # only the AppMasterKey changes keys
            return b"\x91\xAE"
        header, enc, mac = data[:1], data[1:-8], data[-8:]
        key_no = header[0]
        if not self._verify_cmd(0xC4, header, enc, mac) or key_no > 4:
            self.session = None
            return b"\x91\x1E"
        plain = self._decrypt_cmd(enc)
        if key_no == s["key_no"]:
            new, version = plain[:16], plain[16]
            self.keys[key_no], self.key_versions[key_no] = new, version
            self.key_changes += 1
            self.session = None                     # session key gone
            return b"\x91\x00"
        new = bytes(a ^ b for a, b in zip(plain[:16], self.keys[key_no]))
        version, crc = plain[16], plain[17:21]
        if crc != (zlib.crc32(new) ^ 0xFFFFFFFF).to_bytes(4, "little"):
            self.session = None
            return b"\x91\x1E"
        self.keys[key_no], self.key_versions[key_no] = new, version
        self.key_changes += 1
        return self._respond()

    def _get_key_version(self, data):
        if self.session is None:
            return bytes([self.key_versions[data[0]]]) + b"\x91\x00"
        header, mac = data[:1], data[1:]
        if not self._verify_cmd(0x64, header, b"", mac):
            self.session = None
            return b"\x91\x1E"
        return self._respond(bytes([self.key_versions[header[0]]]))

    def _get_card_uid(self, data):
        if self.session is None:
            return b"\x91\xAE"
        if not self._verify_cmd(0x51, b"", b"", data):
            self.session = None
            return b"\x91\x1E"
        return self._respond(self._encrypt_resp(self.uid))

    def _write_data(self, data):
        """WriteData, CommMode.Plain (the only mode the provisioning flow uses)."""
        access, s = self.settings.access, self.session
        free = KEY_FREE in (access.write, access.read_write)
        if not free and (s is None or s["key_no"] not in (access.write, access.read_write)):
            return b"\x91\x9D"
        if self.settings.file_option & 0x03:
            return b"\x91\x9E"            # model covers CommMode.Plain files only
        file_no, offset = data[0], int.from_bytes(data[1:4], "little")
        length, payload = int.from_bytes(data[4:7], "little"), data[7:]
        if file_no != 0x02 or length != len(payload) or offset + length > 256:
            return b"\x91\x7E"
        self.file[offset:offset + length] = payload
        self.writes += 1
        if s is not None:
            s["ctr"] += 1                    # CmdCtr advances in plain mode too
        return b"\x91\x00"

    @staticmethod
    def _enc_rules_ok(st):
        """The SDMENCFileData checks of NT4H2421Gx Table 69 / Table 71."""
        if not st.enc_enabled:
            return True
        o = st.sdm_options
        return bool(
            o & 0x80 and o & 0x40 and st.file_read != 0xF
            and st.enc_length >= 32 and st.enc_length % 32 == 0
            and st.mac_input_offset <= st.enc_offset <= st.mac_offset - 32
            and st.mac_offset >= st.enc_offset + st.enc_length
            and (st.enc_offset >= st.picc_offset + 32
                 or st.picc_offset >= st.enc_offset + st.enc_length)
            and st.mac_offset + 16 <= 256)

    def _change_file_settings(self, data):
        s = self.session
        if s is None or s["key_no"] != self.settings.access.change:
            return b"\x91\xAE"
        header, enc, mac = data[:1], data[1:-8], data[-8:]
        ctr = s["ctr"].to_bytes(2, "little")
        expect = _cmac(s["k_mac"], b"\x5F" + ctr + s["ti"] + header + enc)[1::2]
        if mac != expect or header != b"\x02":
            self.session = None
            return b"\x91\x1E"
        iv = AES.new(s["k_enc"], AES.MODE_ECB).encrypt(b"\xA5\x5A" + s["ti"] + ctr + bytes(8))
        plain = AES.new(s["k_enc"], AES.MODE_CBC, iv).decrypt(enc)
        plain = plain[:plain.rindex(b"\x80")]
        body = plain[:3] + (256).to_bytes(3, "little") + plain[3:]
        new_settings = parse_file_settings(b"\x00" + body)
        if not self._enc_rules_ok(new_settings):
            self.session = None
            return b"\x91\x9E"
        self.settings = new_settings
        s["ctr"] += 1
        rmac = _cmac(s["k_mac"], b"\x00" + s["ctr"].to_bytes(2, "little") + s["ti"])[1::2]
        return rmac + b"\x91\x00"
