"""
NTAG 424 DNA secure messaging: AuthenticateEV2First + CommMode.Full / MAC.

Pure protocol logic on top of an ApduTransport (AN12196 §4, §5.6, §5.9). The
reader is only a pipe for APDUs; every AES/CMAC operation happens here.

    session = authenticate_ev2_first(transport, key_no=0, key=bytes(16))
    session.send_full(0x5F, header=b"\\x02", data=settings)   # ChangeFileSettings

Only the AES (not LRP) secure channel is implemented, and only what
provisioning needs. Validated against the AN12196 worked examples in the tests.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from .apdu import ApduError, build_apdu, parse_response

_ZERO_IV = bytes(16)

SW_OK = 0x9100
SW_ADDITIONAL_FRAME = 0x91AF

INS_AUTH_EV2_FIRST = 0x71
INS_ADDITIONAL_FRAME = 0xAF
INS_GET_FILE_SETTINGS = 0xF5
INS_CHANGE_FILE_SETTINGS = 0x5F

_NATIVE_SW = {
    0x917E: "length error",
    0x919D: "permission denied",
    0x919E: "parameter error",
    0x9140: "no such key",
    0x91AE: "authentication error",
    0x91BE: "boundary error",
    0x911E: "integrity error",
    0x91F0: "file not found",
    0x91CA: "command aborted",
}


class AuthError(Exception):
    """Mutual authentication or response MAC verification failed."""


def native_apdu(ins: int, data: bytes = b"") -> bytes:
    """Wrap a native NTAG 424 DNA command in an ISO 7816-4 APDU (CLA 0x90)."""
    return build_apdu(0x90, ins, 0x00, 0x00, data, le=0)


def native_exchange(transport, ins: int, data: bytes, expect: int = SW_OK) -> bytes:
    resp = parse_response(transport.transceive(native_apdu(ins, data)))
    if resp.sw != expect:
        raise ApduError(resp.sw, _NATIVE_SW.get(resp.sw, f"INS {ins:02X}"))
    return resp.data


def _aes_cmac(key: bytes, message: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(message)
    return c.digest()


def _mac_t(mac16: bytes) -> bytes:
    """Truncate a CMAC to the 8 bytes at odd indices (MACt)."""
    return mac16[1::2]


def _rotl(b: bytes) -> bytes:
    return b[1:] + b[:1]


def _pad(data: bytes) -> bytes:
    """ISO/IEC 9797-1 padding method 2 (always pads, 0x80 then zeros)."""
    padded = data + b"\x80"
    return padded + bytes(-len(padded) % 16)


def session_vectors(rnd_a: bytes, rnd_b: bytes) -> tuple[bytes, bytes]:
    """SV1 / SV2 for the AES session keys (AN12196 Table 14, steps 25-26)."""
    tail = (rnd_a[0:2]
            + bytes(x ^ y for x, y in zip(rnd_a[2:8], rnd_b[0:6]))
            + rnd_b[6:16]
            + rnd_a[8:16])
    return (bytes.fromhex("A55A00010080") + tail,
            bytes.fromhex("5AA500010080") + tail)


def derive_session_keys(key: bytes, rnd_a: bytes, rnd_b: bytes) -> tuple[bytes, bytes]:
    """(KSesAuthENC, KSesAuthMAC) = (CMAC(K, SV1), CMAC(K, SV2))."""
    sv1, sv2 = session_vectors(rnd_a, rnd_b)
    return _aes_cmac(key, sv1), _aes_cmac(key, sv2)


@dataclass
class Session:
    """An authenticated EV2 secure channel (transaction ID + command counter)."""

    transport: object
    ti: bytes
    k_enc: bytes = field(repr=False)     # session keys never appear in a repr
    k_mac: bytes = field(repr=False)
    cmd_ctr: int = 0

    def _ctr(self, value: int) -> bytes:
        return value.to_bytes(2, "little")

    def _iv(self, label: bytes, ctr: int) -> bytes:
        block = label + self.ti + self._ctr(ctr) + bytes(8)
        return AES.new(self.k_enc, AES.MODE_ECB).encrypt(block)

    def command_mac(self, ins: int, header: bytes, payload: bytes) -> bytes:
        msg = bytes([ins]) + self._ctr(self.cmd_ctr) + self.ti + header + payload
        return _mac_t(_aes_cmac(self.k_mac, msg))

    def encrypt_command_data(self, data: bytes) -> bytes:
        iv = self._iv(b"\xA5\x5A", self.cmd_ctr)
        return AES.new(self.k_enc, AES.MODE_CBC, iv).encrypt(_pad(data))

    def full_command_apdu(self, ins: int, header: bytes, data: bytes) -> bytes:
        """C-APDU for a CommMode.Full command at the current counter."""
        enc = self.encrypt_command_data(data) if data else b""
        return native_apdu(ins, header + enc + self.command_mac(ins, header, enc))

    def mac_command_apdu(self, ins: int, header: bytes, data: bytes = b"") -> bytes:
        """C-APDU for a CommMode.MAC command at the current counter."""
        return native_apdu(ins, header + data + self.command_mac(ins, header, data))

    def _verify_response(self, raw: bytes) -> bytes:
        resp = parse_response(raw)
        if resp.sw != SW_OK:
            # Any error status invalidates the session on the PICC side.
            raise ApduError(resp.sw, _NATIVE_SW.get(resp.sw, "command failed"))
        if len(resp.data) < 8:
            raise AuthError("response too short to carry a MAC")
        body, mac = resp.data[:-8], resp.data[-8:]
        self.cmd_ctr += 1
        msg = bytes([resp.sw & 0xFF]) + self._ctr(self.cmd_ctr) + self.ti + body
        if not hmac.compare_digest(_mac_t(_aes_cmac(self.k_mac, msg)), mac):
            raise AuthError("response MAC mismatch")
        return body

    def send_full(self, ins: int, header: bytes, data: bytes) -> bytes:
        """Send a CommMode.Full command; returns the still-encrypted response body."""
        return self._verify_response(
            self.transport.transceive(self.full_command_apdu(ins, header, data)))

    def send_mac(self, ins: int, header: bytes, data: bytes = b"") -> bytes:
        """Send a CommMode.MAC command; returns the (plain) response body."""
        return self._verify_response(
            self.transport.transceive(self.mac_command_apdu(ins, header, data)))


def authenticate_ev2_first(transport, key_no: int, key: bytes,
                           rnd_a: bytes | None = None) -> Session:
    """
    AuthenticateEV2First with application key `key_no`. `rnd_a` is only for
    reproducing known-answer vectors; leave it None to draw it from os.urandom.
    """
    if len(key) != 16:
        raise ValueError("key must be 16 bytes (AES-128)")
    if not 0 <= key_no <= 4:
        raise ValueError("NTAG 424 DNA application keys are 0..4")

    enc_rnd_b = native_exchange(transport, INS_AUTH_EV2_FIRST, bytes([key_no, 0x00]),
                          expect=SW_ADDITIONAL_FRAME)
    if len(enc_rnd_b) != 16:
        raise AuthError(f"unexpected RndB length {len(enc_rnd_b)}")
    rnd_b = AES.new(key, AES.MODE_CBC, _ZERO_IV).decrypt(enc_rnd_b)

    rnd_a = os.urandom(16) if rnd_a is None else rnd_a
    part2 = AES.new(key, AES.MODE_CBC, _ZERO_IV).encrypt(rnd_a + _rotl(rnd_b))
    enc = native_exchange(transport, INS_ADDITIONAL_FRAME, part2)
    if len(enc) != 32:
        raise AuthError(f"unexpected AuthenticatePart2 response length {len(enc)}")
    plain = AES.new(key, AES.MODE_CBC, _ZERO_IV).decrypt(enc)
    ti, rnd_a_rot = plain[0:4], plain[4:20]
    if not hmac.compare_digest(rnd_a_rot, _rotl(rnd_a)):
        raise AuthError("PICC failed to prove knowledge of the key (RndA' mismatch)")

    k_enc, k_mac = derive_session_keys(key, rnd_a, rnd_b)
    return Session(transport=transport, ti=ti, k_enc=k_enc, k_mac=k_mac)
