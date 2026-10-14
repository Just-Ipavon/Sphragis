"""
Test-only model of the NTAG 424 DNA PICC side, enough to exercise provisioning:

  ISOSelect (NDEF app / CC / NDEF file), ISOReadBinary with SDM mirroring,
  ISOUpdateBinary, GetFileSettings (plain), AuthenticateEV2First and
  ChangeFileSettings in CommMode.Full.

It reuses Sphragis' own primitives for SDM (compute_sdmmac) and file settings
parsing, but implements the PICC half of EV2 independently so that the
reader-side code in sphragis.ev2 is checked against a counterpart.
"""

import os

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from sphragis.apdu import CC_FILE_ID, NDEF_APP_AID, NDEF_FILE_ID
from sphragis.sdm import compute_sdmmac
from sphragis.sdmconfig import FACTORY_ACCESS, KEY_FREE, FileSettings, parse_file_settings

ZERO_IV = bytes(16)


def _cmac(key, msg):
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg)
    return c.digest()


class FakeNtag424:
    def __init__(self, uid=None, keys=None, settings=None, content=b""):
        self.uid = uid or bytes.fromhex("04") + os.urandom(6)
        self.keys = keys or [bytes(16)] * 5
        self.settings = settings or FileSettings(0x00, FACTORY_ACCESS)
        self.file = bytearray(content.ljust(256, b"\x00"))
        self.counter = 0
        self.writes = 0
        self.app = False
        self.current = None
        self.snapshot = None
        self._auth = None       # (key_no, rnd_b) during part 1
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
            if self.settings.access.write != KEY_FREE:
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
                mac = compute_sdmmac(self.keys[s.file_read], self.uid, self.counter)
                data[s.picc_offset:s.picc_offset + 32] = picc.hex().upper().encode()
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
        if ins == 0x5F:
            return self._change_file_settings(data)
        return b"\x91\x1C"

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
        self.settings = parse_file_settings(b"\x00" + body)
        s["ctr"] += 1
        rmac = _cmac(s["k_mac"], b"\x00" + s["ctr"].to_bytes(2, "little") + s["ti"])[1::2]
        return rmac + b"\x91\x00"
