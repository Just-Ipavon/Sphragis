"""
Tap inspection: decode what a tag actually emitted, without judging it.

`Verifier` answers "is this tap genuine?". This module answers the question
that comes first when bringing up a physical tag: "what is this tag sending?"
It parses the query string, decrypts the PICCData with the given (default
all-zero, factory) meta-read key and lays out every byte — PICCDataTag flags,
UID, SDMReadCtr (little-endian), padding — plus the NDEF offsets this URL
layout implies for ChangeFileSettings. The CMAC is recomputed only as
information; a mismatch is reported, never fatal.

Typical findings it makes visible:
  - the mirror is in plain text (uid=/ctr= parameters), not encrypted;
  - the PICCData decrypts to an implausible PICCDataTag (wrong meta key, or the
    value is not an encrypted PICCData at all);
  - parameter values have the wrong length (offsets misconfigured, so the
    mirror overwrites the wrong bytes of the template).

Structurally unusable input raises SdmError, like the verifier.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import AES

from .ndef import NdefError, SdmOffsets, sdm_offsets
from .sdm import (
    _TAG_CTR_MIRROR,
    _TAG_UID_LEN_MASK,
    _TAG_UID_MIRROR,
    _ZERO_IV,
    SdmError,
    compute_sdmmac,
)

ZERO_KEY = bytes(16)

PICC_PARAM = "picc_data"
MAC_PARAM = "cmac"
_PLAIN_UID_PARAMS = ("uid",)
_PLAIN_CTR_PARAMS = ("ctr",)
_ENC_FILE_PARAMS = {"enc", "encfiledata", "encdata"}

# Valid PICCDataTag values on NTAG 424 DNA (7-byte UID): UID+ctr, UID only, ctr only.
_PLAUSIBLE_TAGS = {0xC7, 0x87, 0x40}
_TAG_RFU_MASK = 0x30


@dataclass(frozen=True)
class ByteField:
    """One field of the decrypted PICCData block."""

    name: str
    offset: int
    length: int
    hex: str
    note: str = ""


@dataclass
class TapInspection:
    url: str
    params: dict[str, list[str]]
    mirror: str                     # "encrypted" | "plain" | "none"
    meta_key: str                   # "all-zero" | "custom"
    file_key: str
    picc_data_enc: str | None = None
    picc_data_plain: str | None = None
    picc_tag: int | None = None
    tag_plausible: bool | None = None
    uid: str | None = None
    read_counter: int | None = None
    layout: list[ByteField] = field(default_factory=list)
    cmac: str | None = None
    cmac_match: bool | None = None
    offsets: SdmOffsets | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def render(self) -> str:
        lines = ["Sphragis tap inspection (diagnostic only - not a verdict)"]
        add = lines.append
        add("Parameters   : " + ", ".join(
            f"{k} ({len(v[0])} chars)" for k, v in self.params.items()))
        add(f"Mirror       : {self.mirror}")
        if self.picc_data_enc is not None:
            add(f"Meta key     : {self.meta_key}")
            add(f"PICCData enc : {self.picc_data_enc}")
        if self.picc_data_plain is not None:
            add(f"PICCData dec : {self.picc_data_plain}")
            for f in self.layout:
                span = f"[{f.offset}]" if f.length == 1 else f"[{f.offset}..{f.offset + f.length - 1}]"
                note = f"  {f.note}" if f.note else ""
                add(f"  {span:<9} {f.name:<12}: {f.hex}{note}")
        if self.uid is not None:
            add(f"UID          : {self.uid}")
        if self.read_counter is not None:
            add(f"SDMReadCtr   : {self.read_counter}")
        if self.cmac is not None:
            add(f"CMAC         : {self.cmac} ({len(self.cmac) // 2} bytes)")
        if self.cmac_match is not None:
            verdict = "match" if self.cmac_match else "MISMATCH"
            add(f"CMAC check   : {verdict} with {self.file_key} file key (informational)")
        if self.offsets is not None:
            o = self.offsets
            add("NDEF offsets : (single URI record, standard prefix abbreviation)")
            add(f"  PICCDataOffset    : 0x{o.picc_data:06X} ({o.picc_data})")
            add(f"  SDMMACInputOffset : 0x{o.mac_input:06X} ({o.mac_input})")
            add(f"  SDMMACOffset      : 0x{o.mac:06X} ({o.mac})")
            add(f"  NDEF file length  : {o.file_length} bytes")
        add("Warnings     :" + ("" if self.warnings else " none"))
        for w in self.warnings:
            add(f"  - {w}")
        return "\n".join(lines)


def _key_label(key: bytes) -> str:
    return "all-zero" if key == ZERO_KEY else "custom"


def _parse_params(url_or_query: str) -> dict[str, list[str]]:
    parsed = urlparse(url_or_query)
    query = parsed.query or (url_or_query if "=" in url_or_query and not parsed.scheme else "")
    if not query:
        raise SdmError("no query string to inspect")
    params = parse_qs(query, keep_blank_values=True)
    if not params:
        raise SdmError("no query parameters to inspect")
    for name, values in params.items():
        if len(values) > 1:
            raise SdmError(f"duplicated parameter '{name}'")
    return params


def _hex_param(params: dict[str, list[str]], name: str) -> bytes:
    value = params[name][0]
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise SdmError(f"parameter '{name}' is not hex: {value!r}") from exc


def _find(params: dict[str, list[str]], names: tuple[str, ...]) -> str | None:
    lower = {k.lower(): k for k in params}
    for n in names:
        if n in lower:
            return lower[n]
    return None


def _inspect_encrypted(report: TapInspection, enc: bytes, meta_key: bytes) -> None:
    report.picc_data_enc = enc.hex().upper()
    if len(enc) != 16:
        report.warnings.append(
            f"picc_data is {len(enc)} bytes, an encrypted PICCData is exactly 16 "
            f"(32 hex chars): check PICCDataOffset and the template placeholder"
        )
        return
    plain = AES.new(meta_key, AES.MODE_CBC, _ZERO_IV).decrypt(enc)
    report.picc_data_plain = plain.hex().upper()
    tag = plain[0]
    report.picc_tag = tag
    uid_on = bool(tag & _TAG_UID_MIRROR)
    ctr_on = bool(tag & _TAG_CTR_MIRROR)
    uid_len = tag & _TAG_UID_LEN_MASK
    report.tag_plausible = tag in _PLAUSIBLE_TAGS

    report.layout.append(ByteField(
        "PICCDataTag", 0, 1, f"{tag:02X}",
        f"UID mirror={int(uid_on)}, SDMReadCtr mirror={int(ctr_on)}, "
        f"UID length={uid_len}" + ("" if not tag & _TAG_RFU_MASK else ", RFU bits set"),
    ))
    if not report.tag_plausible:
        report.warnings.append(
            f"PICCDataTag 0x{tag:02X} is not a valid NTAG 424 DNA value "
            f"(expected C7, 87 or 40): wrong meta key, or picc_data is not an "
            f"encrypted PICCData; field layout below is not meaningful"
        )
        return

    offset = 1
    if uid_on:
        uid = plain[offset : offset + uid_len]
        report.uid = uid.hex().upper()
        report.layout.append(ByteField("UID", offset, uid_len, report.uid))
        offset += uid_len
    if ctr_on:
        ctr = plain[offset : offset + 3]
        report.read_counter = int.from_bytes(ctr, "little")
        report.layout.append(ByteField(
            "SDMReadCtr", offset, 3, ctr.hex().upper(),
            f"little-endian = {report.read_counter}",
        ))
        offset += 3
    if offset < 16:
        report.layout.append(ByteField(
            "padding", offset, 16 - offset, plain[offset:].hex().upper(), "random fill",
        ))
    if not uid_on:
        report.warnings.append("UID is not mirrored: the verifier requires the UID mirror")


def inspect_tap(url_or_query: str, meta_key: bytes = ZERO_KEY,
                file_key: bytes = ZERO_KEY) -> TapInspection:
    """Decode a tapped URL (or bare query string) into a TapInspection."""
    for name, key in (("meta_key", meta_key), ("file_key", file_key)):
        if len(key) != 16:
            raise SdmError(f"{name} must be 16 bytes")
    params = _parse_params(url_or_query)
    report = TapInspection(
        url=url_or_query, params=params, mirror="none",
        meta_key=_key_label(meta_key), file_key=_key_label(file_key),
    )

    if {k.lower() for k in params} & _ENC_FILE_PARAMS:
        report.warnings.append(
            "encrypted file data (SDMENCFileData) present: not supported, the "
            "verifier refuses such taps (fail-closed)"
        )

    uid_param = _find(params, _PLAIN_UID_PARAMS)
    ctr_param = _find(params, _PLAIN_CTR_PARAMS)

    if PICC_PARAM in params:
        report.mirror = "encrypted"
        _inspect_encrypted(report, _hex_param(params, PICC_PARAM), meta_key)
    elif uid_param or ctr_param:
        report.mirror = "plain"
        report.warnings.append(
            "plain-text UID/counter mirror: the engine only verifies the "
            "encrypted PICCData layout; reconfigure the tag with an encrypted mirror"
        )
        if uid_param:
            report.uid = _hex_param(params, uid_param).hex().upper()
        if ctr_param:
            raw = _hex_param(params, ctr_param)
            report.warnings.append(
                f"plain counter '{raw.hex().upper()}' reads "
                f"{int.from_bytes(raw, 'big')} MSB-first, "
                f"{int.from_bytes(raw, 'little')} LSB-first"
            )
    else:
        raise SdmError(
            f"no '{PICC_PARAM}' (encrypted) nor uid/ctr (plain) mirror parameter found"
        )

    if MAC_PARAM in params:
        mac = _hex_param(params, MAC_PARAM)
        report.cmac = mac.hex().upper()
        if len(mac) != 8:
            report.warnings.append(
                f"cmac is {len(mac)} bytes, the truncated SDMMAC is 8 (16 hex chars)"
            )
        elif report.uid is not None and report.read_counter is not None \
                and report.mirror == "encrypted":
            expected = compute_sdmmac(file_key, bytes.fromhex(report.uid), report.read_counter)
            report.cmac_match = expected == mac
            if not report.cmac_match:
                report.warnings.append(
                    "CMAC does not match: wrong file key, or SDMMACInputOffset != "
                    "SDMMACOffset (MAC computed over mirrored data, not supported)"
                )
    else:
        report.warnings.append(f"no '{MAC_PARAM}' parameter: SDM MAC mirror not configured")

    if report.mirror == "encrypted" and MAC_PARAM in params and urlparse(url_or_query).scheme:
        try:
            report.offsets = sdm_offsets(url_or_query, PICC_PARAM, MAC_PARAM)
        except NdefError as exc:
            report.warnings.append(f"cannot compute NDEF offsets: {exc}")
    return report
