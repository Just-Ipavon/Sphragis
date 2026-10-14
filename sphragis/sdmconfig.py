"""
SDM file-settings model for the NDEF file (pure, no I/O).

Builds the ChangeFileSettings payload that turns on Secure Dynamic Messaging
in the layout the engine verifies, and parses GetFileSettings responses so a
provisioning run can tell whether a tag is already configured:

  - encrypted PICCData mirror (SDMMetaRead = a key, never 0xE/plain),
  - UID + SDMReadCtr inside the PICCData, ASCII encoding,
  - SDMMAC over an empty message (SDMMACInputOffset == SDMMACOffset),
  - no SDMENCFileData, no read-counter limit.

Byte layout follows NT4H2421Gx / AN12196 §5.4 and §5.9: access-right nibbles
are packed (RW|Change)(Read|Write) and (RFU|CtrRet)(MetaRead|FileRead);
offsets are 3 bytes little-endian.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ndef import SdmOffsets, encode_uri_file, sdm_offsets

NDEF_FILE_NO = 0x02
FILE_TYPE_STANDARD = 0x00

_FILE_OPT_SDM = 0x40

_SDM_UID = 0x80
_SDM_CTR = 0x40
_SDM_CTR_LIMIT = 0x20
_SDM_ENC_FILE = 0x10
_SDM_ASCII = 0x01

KEY_FREE = 0xE
KEY_NONE = 0xF

PICC_PLACEHOLDER = "0" * 32   # 16-byte encrypted PICCData as ASCII hex
MAC_PLACEHOLDER = "0" * 16    # 8-byte SDMMAC as ASCII hex
NDEF_FILE_SIZE = 256


class SdmConfigError(ValueError):
    """Invalid SDM configuration or unparsable file settings."""


@dataclass(frozen=True)
class AccessRights:
    read_write: int
    change: int
    read: int
    write: int

    def encode(self) -> bytes:
        return bytes([(self.read_write << 4) | self.change, (self.read << 4) | self.write])

    @classmethod
    def decode(cls, b: bytes) -> "AccessRights":
        return cls(b[0] >> 4, b[0] & 0xF, b[1] >> 4, b[1] & 0xF)


# Factory default of the NDEF file: RW free, Change key 0, Read free, Write free.
FACTORY_ACCESS = AccessRights(KEY_FREE, 0x0, KEY_FREE, KEY_FREE)


@dataclass(frozen=True)
class FileSettings:
    file_option: int
    access: AccessRights
    file_size: int | None = None          # only in GetFileSettings responses
    sdm_options: int | None = None
    ctr_ret: int = KEY_NONE
    meta_read: int = KEY_NONE
    file_read: int = KEY_NONE
    uid_offset: int | None = None
    ctr_offset: int | None = None
    picc_offset: int | None = None
    mac_input_offset: int | None = None
    enc_offset: int | None = None
    enc_length: int | None = None
    mac_offset: int | None = None
    ctr_limit: int | None = None

    @property
    def sdm_enabled(self) -> bool:
        return bool(self.file_option & _FILE_OPT_SDM)

    def encode_change(self) -> bytes:
        """CmdData of ChangeFileSettings (everything after the file number)."""
        out = bytes([self.file_option]) + self.access.encode()
        if not self.sdm_enabled:
            return out
        out += bytes([self.sdm_options, (0xF << 4) | self.ctr_ret,
                      (self.meta_read << 4) | self.file_read])
        for value in self._sdm_offset_fields():
            if value is None:
                raise SdmConfigError("an SDM offset required by these options is missing")
            out += value.to_bytes(3, "little")
        return out

    def _sdm_offset_fields(self) -> list[int | None]:
        """The offsets present for these options, in on-the-wire order."""
        opts = self.sdm_options or 0
        fields: list[int | None] = []
        if self.meta_read == KEY_FREE:
            if opts & _SDM_UID:
                fields.append(self.uid_offset)
            if opts & _SDM_CTR:
                fields.append(self.ctr_offset)
        elif self.meta_read != KEY_NONE:
            fields.append(self.picc_offset)
        if self.file_read != KEY_NONE:
            fields.append(self.mac_input_offset)
            if opts & _SDM_ENC_FILE:
                fields += [self.enc_offset, self.enc_length]
            fields.append(self.mac_offset)
        if opts & _SDM_CTR_LIMIT:
            fields.append(self.ctr_limit)
        return fields


def parse_file_settings(data: bytes) -> FileSettings:
    """Parse a plain GetFileSettings response body (without SW)."""
    if len(data) < 7:
        raise SdmConfigError(f"file settings too short ({len(data)} B)")
    if data[0] != FILE_TYPE_STANDARD:
        raise SdmConfigError(f"not a StandardData file (type {data[0]:02X})")
    file_option = data[1]
    access = AccessRights.decode(data[2:4])
    size = int.from_bytes(data[4:7], "little")
    if not file_option & _FILE_OPT_SDM:
        if len(data) != 7:
            raise SdmConfigError(f"{len(data) - 7} unexpected trailing bytes in file settings")
        return FileSettings(file_option, access, size)
    if len(data) < 10:
        raise SdmConfigError("SDM enabled but SDM options truncated")
    opts, ar0, ar1 = data[7], data[8], data[9]
    meta, file_ = ar1 >> 4, ar1 & 0xF
    pos = 10

    def take() -> int:
        nonlocal pos
        if len(data) < pos + 3:
            raise SdmConfigError("SDM offsets truncated")
        value = int.from_bytes(data[pos : pos + 3], "little")
        pos += 3
        return value

    kw: dict[str, int] = {}
    if meta == KEY_FREE:
        if opts & _SDM_UID:
            kw["uid_offset"] = take()
        if opts & _SDM_CTR:
            kw["ctr_offset"] = take()
    elif meta != KEY_NONE:
        kw["picc_offset"] = take()
    if file_ != KEY_NONE:
        kw["mac_input_offset"] = take()
        if opts & _SDM_ENC_FILE:
            kw["enc_offset"] = take()
            kw["enc_length"] = take()
        kw["mac_offset"] = take()
    if opts & _SDM_CTR_LIMIT:
        kw["ctr_limit"] = take()
    if pos != len(data):
        raise SdmConfigError(f"{len(data) - pos} unexpected trailing bytes in file settings")
    return FileSettings(file_option, access, size, opts, ar0 & 0xF, meta, file_, **kw)


def template_url(base_url: str) -> str:
    """The SUN template written to the tag: placeholders the tag overwrites."""
    if "?" in base_url or "#" in base_url:
        raise SdmConfigError("base URL must not carry a query string or fragment")
    return f"{base_url}?picc_data={PICC_PLACEHOLDER}&cmac={MAC_PLACEHOLDER}"


def sun_settings(offsets: SdmOffsets, meta_read_key: int = 2, file_read_key: int = 1,
                 ctr_ret_key: int = 1, access: AccessRights = FACTORY_ACCESS) -> FileSettings:
    """
    File settings for the engine's layout. Defaults mirror AN12196 §5.9
    (MetaRead = key 2, FileRead = key 1, CtrRet = key 1) while keeping the
    factory access rights, so the NDEF file stays freely writable.
    """
    for name, k in (("meta_read_key", meta_read_key), ("file_read_key", file_read_key)):
        if not 0 <= k <= 4:
            raise SdmConfigError(f"{name} must be an application key 0..4 "
                                 f"(encrypted mirror + MAC are mandatory)")
    if not (0 <= ctr_ret_key <= 4 or ctr_ret_key in (KEY_FREE, KEY_NONE)):
        raise SdmConfigError("ctr_ret_key must be 0..4, 0xE or 0xF")
    return FileSettings(
        file_option=_FILE_OPT_SDM,          # SDM on, CommMode.Plain
        access=access,
        sdm_options=_SDM_UID | _SDM_CTR | _SDM_ASCII,
        ctr_ret=ctr_ret_key,
        meta_read=meta_read_key,
        file_read=file_read_key,
        picc_offset=offsets.picc_data,
        mac_input_offset=offsets.mac_input,
        mac_offset=offsets.mac,
    )


def same_config(current: FileSettings, desired: FileSettings) -> bool:
    """True when `current` (from GetFileSettings) already equals `desired`."""
    return current.encode_change() == desired.encode_change()


@dataclass(frozen=True)
class SunLayout:
    """Everything provisioning needs for one base URL."""

    url: str
    ndef_file: bytes
    offsets: SdmOffsets

    def mask_mirrors(self, data: bytes) -> bytes:
        """Replace mirrored regions with the template's placeholders, for comparison."""
        if len(data) < len(self.ndef_file):
            return bytes(data)
        out = bytearray(data[: len(self.ndef_file)])
        for start, n in ((self.offsets.picc_data, len(PICC_PLACEHOLDER)),
                         (self.offsets.mac, len(MAC_PLACEHOLDER))):
            out[start : start + n] = self.ndef_file[start : start + n]
        return bytes(out)


def sun_layout(base_url: str) -> SunLayout:
    url = template_url(base_url)
    data = encode_uri_file(url)
    if len(data) > NDEF_FILE_SIZE:
        raise SdmConfigError(f"NDEF template is {len(data)} B, file holds {NDEF_FILE_SIZE}")
    return SunLayout(url=url, ndef_file=data, offsets=sdm_offsets(url))
