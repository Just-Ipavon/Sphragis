"""
Provision an NTAG 424 DNA for SUN in the layout the engine verifies.

Steps (idempotent; nothing is written when the tag already matches):

  1. ISOSelect NDEF application, GetFileSettings(02) in plain, read the NDEF file.
  2. If the NDEF content (mirrors masked) differs from the template:
     ISOUpdateBinary the template (requires the factory free write access).
  3. If the file settings differ: AuthenticateEV2First with the file's Change
     key, then ChangeFileSettings in CommMode.Full (encrypted PICCData + MAC).
  4. Re-read one tap and decode it with `inspect_tap` (all-zero keys) to
     confirm the mirror is encrypted, the CMAC matches and offsets line up.

Validation scope: keys stay at the all-zero factory value. This module never
issues ChangeKey and accepts no other key material.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .apdu import (
    NDEF_FILE_ID,
    build_apdu,
    parse_response,
    read_binary,
    select_file,
    select_ndef_app,
)
from .diagnostics import ZERO_KEY, TapInspection, inspect_tap
from .ev2 import (
    INS_CHANGE_FILE_SETTINGS,
    INS_GET_FILE_SETTINGS,
    authenticate_ev2_first,
    native_exchange,
)
from .ndef import read_uri
from .sdmconfig import (
    KEY_FREE,
    NDEF_FILE_NO,
    FileSettings,
    SunLayout,
    parse_file_settings,
    same_config,
    sun_layout,
    sun_settings,
)

_WRITE_CHUNK = 0xF0


class ProvisionError(Exception):
    """The tag cannot be brought to the target configuration."""


@dataclass
class ProvisionReport:
    layout: SunLayout
    desired: FileSettings
    current: FileSettings | None = None
    ndef_matches: bool | None = None
    settings_match: bool | None = None
    wrote_ndef: bool = False
    changed_settings: bool = False
    dry_run: bool = False
    check: TapInspection | None = None
    log: list[str] = field(default_factory=list)

    @property
    def already_provisioned(self) -> bool:
        return bool(self.ndef_matches and self.settings_match)

    @property
    def verified(self) -> bool:
        """The post-provisioning tap decodes, MAC matches and offsets line up."""
        c = self.check
        return bool(c and c.cmac_match and not c.warnings
                    and c.offsets == self.layout.offsets)


def update_binary(offset: int, data: bytes) -> bytes:
    """ISOUpdateBinary at `offset` (encoded as in AN12196 Table 16)."""
    return build_apdu(0x00, 0xD6, offset >> 8, offset & 0xFF, data, le=0)


def _iso(transport, apdu: bytes, what: str) -> bytes:
    return parse_response(transport.transceive(apdu)).check(what)


def _read_file(transport, length: int) -> bytes:
    _iso(transport, select_ndef_app(), "select NDEF application")
    _iso(transport, select_file(NDEF_FILE_ID), "select NDEF file")
    data = b""
    while len(data) < length:
        chunk = _iso(transport, read_binary(len(data), min(0xFF, length - len(data))),
                     "read NDEF file")
        if not chunk:
            break
        data += chunk
    return data


def provision_tag(transport, base_url: str, *, dry_run: bool = False,
                  log: Callable[[str], None] | None = None) -> ProvisionReport:
    """
    Bring the tag behind `transport` to the SUN layout for `base_url`.
    With `transport=None` (and `dry_run=True`) only the offline plan is built.
    """
    layout = sun_layout(base_url)
    desired = sun_settings(layout.offsets)
    report = ProvisionReport(layout=layout, desired=desired, dry_run=dry_run)

    def say(msg: str) -> None:
        report.log.append(msg)
        if log:
            log(msg)

    o = layout.offsets
    say(f"template      : {layout.url}")
    say(f"NDEF file     : {len(layout.ndef_file)} B, PICCDataOffset=0x{o.picc_data:02X}, "
        f"SDMMACInputOffset=SDMMACOffset=0x{o.mac:02X}")
    say(f"file settings : {desired.encode_change().hex().upper()} "
        f"(SDM on, encrypted PICCData key {desired.meta_read}, MAC key {desired.file_read})")

    if transport is None:
        if not dry_run:
            raise ProvisionError("a transport is required unless dry_run is set")
        say("dry run, no reader: plan only")
        return report

    # 1. Read the current state (plain, unauthenticated).
    _iso(transport, select_ndef_app(), "select NDEF application")
    report.current = current = parse_file_settings(
        native_exchange(transport, INS_GET_FILE_SETTINGS, bytes([NDEF_FILE_NO])))
    content = _read_file(transport, len(layout.ndef_file))
    report.ndef_matches = layout.mask_mirrors(content) == layout.ndef_file
    report.settings_match = same_config(current, desired)
    say(f"current       : settings {'match' if report.settings_match else 'differ'}, "
        f"NDEF {'matches' if report.ndef_matches else 'differs'}")

    if report.already_provisioned:
        say("already provisioned: nothing to write")
    elif dry_run:
        if not report.ndef_matches:
            say("would write  : NDEF template via ISOUpdateBinary")
        if not report.settings_match:
            say(f"would change : file settings (auth with key {current.access.change}, "
                f"CommMode.Full)")
        return report
    else:
        # 2. NDEF template.
        if not report.ndef_matches:
            if current.access.write != KEY_FREE:
                raise ProvisionError(
                    f"NDEF file write needs key {current.access.write}; only the "
                    f"factory free write access is supported")
            _iso(transport, select_file(NDEF_FILE_ID), "select NDEF file")
            data = layout.ndef_file
            for off in range(0, len(data), _WRITE_CHUNK):
                _iso(transport, update_binary(off, data[off : off + _WRITE_CHUNK]),
                     "write NDEF template")
            report.wrote_ndef = True
            say("wrote        : NDEF template")
        # 3. File settings.
        if not report.settings_match:
            change_key = current.access.change
            if not 0 <= change_key <= 4:
                raise ProvisionError(f"unsupported Change access right 0x{change_key:X}")
            _iso(transport, select_ndef_app(), "select NDEF application")
            session = authenticate_ev2_first(transport, change_key, ZERO_KEY)
            session.send_full(INS_CHANGE_FILE_SETTINGS, bytes([NDEF_FILE_NO]),
                              desired.encode_change())
            report.changed_settings = True
            say(f"changed      : file settings (authenticated with key {change_key})")

    # 4. Confirm with a fresh tap (re-selecting drops the authenticated state).
    report.check = inspect_tap(read_uri(transport), ZERO_KEY, ZERO_KEY)
    say(f"check        : UID {report.check.uid}, SDMReadCtr {report.check.read_counter}, "
        f"CMAC {'match' if report.check.cmac_match else 'MISMATCH'}"
        + ("" if report.verified else " -> NOT VERIFIED"))
    return report
