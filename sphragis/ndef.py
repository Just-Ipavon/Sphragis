"""
NDEF URI file encoding/decoding and SDM offset arithmetic.

An NTAG 424 DNA emits its SUN URL from the NDEF file (file ID E104) of the
NFC Forum Type 4 application. The file content is:

    NLEN (2 bytes, big-endian) || NDEF message

and for SUN the message is a single URI record whose payload starts with a
one-byte URI identifier code (e.g. 0x04 = "https://") followed by the rest of
the URL. SDM mirrors (PICCData, SDMMAC) are configured as *byte offsets into
this file*, so knowing exactly where each query value lands is what makes the
tag configuration line up with the URL the verifier expects.

Everything here is pure (no I/O) so it can be tested against the emulator and
reused by the provisioning / probing tools that run on hardware hosts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# NFC Forum URI Record Type Definition, identifier codes 0x00..0x23.
URI_PREFIXES: tuple[str, ...] = (
    "", "http://www.", "https://www.", "http://", "https://", "tel:",
    "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://",
    "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:", "telnet://",
    "imap:", "rtsp://", "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://",
    "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://", "file://",
    "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:",
    "urn:nfc:",
)

_TNF_WELL_KNOWN = 0x01
_FLAG_MB = 0x80
_FLAG_ME = 0x40
_FLAG_SR = 0x10
_FLAG_IL = 0x08
_TYPE_URI = b"U"


class NdefError(ValueError):
    """Raised when NDEF file content is malformed or not a URI record."""


def _prefix_code(url: str) -> int:
    """Longest matching URI identifier code for `url` (0 if none matches)."""
    best = 0
    for code, prefix in enumerate(URI_PREFIXES):
        if prefix and url.startswith(prefix) and len(prefix) > len(URI_PREFIXES[best]):
            best = code
    return best


def _record_header(payload_len: int) -> bytes:
    """Header of a single (MB|ME) well-known 'U' record, short form if possible."""
    if payload_len <= 0xFF:
        flags = _FLAG_MB | _FLAG_ME | _FLAG_SR | _TNF_WELL_KNOWN
        return bytes([flags, len(_TYPE_URI), payload_len]) + _TYPE_URI
    flags = _FLAG_MB | _FLAG_ME | _TNF_WELL_KNOWN
    return bytes([flags, len(_TYPE_URI)]) + payload_len.to_bytes(4, "big") + _TYPE_URI


def encode_uri_file(url: str) -> bytes:
    """Encode `url` as NDEF file content: NLEN || single URI record."""
    code = _prefix_code(url)
    payload = bytes([code]) + url[len(URI_PREFIXES[code]):].encode("utf-8")
    message = _record_header(len(payload)) + payload
    if len(message) > 0xFFFF:
        raise NdefError("NDEF message too long")
    return len(message).to_bytes(2, "big") + message


def decode_uri_file(data: bytes) -> str:
    """Decode NDEF file content (NLEN || message) whose first record is a URI."""
    if len(data) < 2:
        raise NdefError("NDEF file shorter than its NLEN field")
    nlen = int.from_bytes(data[:2], "big")
    if nlen == 0:
        raise NdefError("NDEF file is empty (NLEN = 0)")
    msg = data[2 : 2 + nlen]
    if len(msg) < nlen:
        raise NdefError(f"NDEF message truncated: NLEN={nlen}, have {len(msg)} B")

    if len(msg) < 3:
        raise NdefError("NDEF record header truncated")
    flags, type_len = msg[0], msg[1]
    pos = 2
    if flags & _FLAG_SR:
        payload_len = msg[pos]
        pos += 1
    else:
        if len(msg) < pos + 4:
            raise NdefError("NDEF record header truncated")
        payload_len = int.from_bytes(msg[pos : pos + 4], "big")
        pos += 4
    id_len = 0
    if flags & _FLAG_IL:
        if len(msg) <= pos:
            raise NdefError("NDEF record header truncated")
        id_len = msg[pos]
        pos += 1
    rtype = msg[pos : pos + type_len]
    pos += type_len + id_len
    if flags & 0x07 != _TNF_WELL_KNOWN or rtype != _TYPE_URI:
        raise NdefError(f"first NDEF record is not a URI record (TNF={flags & 7}, type={rtype!r})")
    payload = msg[pos : pos + payload_len]
    if len(payload) < payload_len or payload_len < 1:
        raise NdefError("NDEF URI payload truncated")
    code = payload[0]
    if code >= len(URI_PREFIXES):
        raise NdefError(f"unknown URI identifier code 0x{code:02X}")
    try:
        rest = payload[1:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NdefError(f"URI is not valid UTF-8: {exc}") from exc
    return URI_PREFIXES[code] + rest


@dataclass(frozen=True)
class SdmOffsets:
    """
    SDM offsets (bytes into the NDEF file) as they must be written with
    ChangeFileSettings for this URL layout.

    For plain SUN `mac_input` equals `mac`: the MAC is over an empty message,
    i.e. SDMMACInputOffset == SDMMACOffset. With an SDMENCFileData mirror the
    MAC input starts at the encrypted data (SDMMACInputOffset ==
    SDMENCOffset) and `enc_data` / `enc_length` describe its placeholder.
    """

    picc_data: int
    mac_input: int
    mac: int
    file_length: int
    enc_data: int | None = None
    enc_length: int | None = None


def _value_index(url: str, param: str) -> int:
    """Index in `url` of the first character of query parameter `param`'s value."""
    matches = list(re.finditer(rf"[?&]{re.escape(param)}=", url))
    if not matches:
        raise NdefError(f"parameter '{param}' not found in URL")
    if len(matches) > 1:
        raise NdefError(f"parameter '{param}' appears more than once")
    return matches[0].end()


def sdm_offsets(url: str, picc_param: str = "picc_data",
                mac_param: str = "cmac", enc_param: str | None = None) -> SdmOffsets:
    """
    Compute PICCDataOffset / SDMMACInputOffset / SDMMACOffset for `url`
    encoded with `encode_uri_file`. Works on a template or on a real tap
    (mirrors have the same length as their placeholders). With `enc_param`
    also SDMENCOffset / SDMENCLength, the length being that of the parameter
    value (up to the next '&' or the end of the URL).
    """
    data = encode_uri_file(url)
    code = _prefix_code(url)
    stripped = len(URI_PREFIXES[code])
    # URI text starts right after NLEN, the record header and the code byte.
    uri_start = len(data) - (len(url.encode("utf-8")) - stripped)

    def to_file(index: int) -> int:
        if index < stripped:
            raise NdefError("parameter value falls inside the abbreviated prefix")
        # Byte (not character) offset, in case the URL holds non-ASCII text.
        return uri_start + len(url[stripped:index].encode("utf-8"))

    picc = to_file(_value_index(url, picc_param))
    mac = to_file(_value_index(url, mac_param))
    if enc_param is None:
        return SdmOffsets(picc_data=picc, mac_input=mac, mac=mac, file_length=len(data))

    enc_index = _value_index(url, enc_param)
    end = url.find("&", enc_index)
    value = url[enc_index:] if end < 0 else url[enc_index:end]
    enc = to_file(enc_index)
    return SdmOffsets(picc_data=picc, mac_input=enc, mac=mac, file_length=len(data),
                      enc_data=enc, enc_length=len(value.encode("utf-8")))


def read_uri(transport) -> str:
    """
    Read the SUN URL from a Type 4 tag over an ApduTransport: select the NDEF
    application and file, read NLEN, then the message (unauthenticated, so SDM
    mirroring applies and the tag emits a fresh tap).
    """
    from .apdu import NDEF_FILE_ID, parse_response, read_binary, select_file, select_ndef_app

    def run(apdu: bytes, what: str) -> bytes:
        return parse_response(transport.transceive(apdu)).check(what)

    run(select_ndef_app(), "select NDEF application")
    run(select_file(NDEF_FILE_ID), "select NDEF file")
    head = run(read_binary(0, 2), "read NLEN")
    if len(head) != 2:
        raise NdefError(f"short NLEN read ({len(head)} B)")
    nlen = int.from_bytes(head, "big")
    body = b""
    while len(body) < nlen:
        chunk = run(read_binary(2 + len(body), min(0xFF, nlen - len(body))), "read NDEF")
        if not chunk:
            raise NdefError("tag returned no data before the end of the NDEF message")
        body += chunk
    return decode_uri_file(head + body[:nlen])
