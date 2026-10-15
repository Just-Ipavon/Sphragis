"""
Provision an NTAG 424 DNA for SUN in the layout the engine verifies.

Steps (idempotent; nothing is written when the tag already matches):

  1. ISOSelect NDEF application, GetFileSettings(02) in plain, read the NDEF file.
  2. Before anything is written, authenticate with every key the writes will
     need (the file's Change key, and its write key when writes are locked):
     a tag whose keys we do not hold is left exactly as it was. The UID is
     read here (anticollision, or GetCardUID) and the caller may confirm it.
  3. If the NDEF content (mirrors masked) differs from the template: write it,
     with ISOUpdateBinary when writes are free, else authenticated WriteData.
  4. If the file settings differ: AuthenticateEV2First with the file's Change
     key, then ChangeFileSettings in CommMode.Full (encrypted PICCData + MAC).
  5. Re-read one tap and decode it with `inspect_tap` (all-zero keys) to
     confirm the mirror is encrypted, the CMAC matches and offsets line up.

NDEF writes end up locked to `write_key` (0, 3 or 4) in both layouts, so the
URL cannot be rewritten without that key; `write_key=None` keeps the factory
free write access, for bench tags of the plain layout only.

With `file_data` the tag gets the SDMENCFileData layout instead: the NDEF
template carries an `enc` placeholder holding the plaintext, SDM encrypts and
MACs it on every tap, and the NDEF file's Write/ReadWrite rights are locked to
an application key. Writing a file whose write access is locked uses
AuthenticateEV2First + WriteData (the file stays in CommMode.Plain, so the
frames are plain but the session command counter still advances).

Keys: by default the tag is assumed to hold the all-zero factory keys. Pass
`tag_keys` (a `keyprov.TagKeys`) once its keys have been replaced with
`keyprov.rekey_tag`: authentication then uses the real key of each slot and
the final check verifies the tap with the real MetaRead / FileRead keys. This
module never changes keys itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .apdu import (
    NDEF_FILE_ID,
    ApduError,
    build_apdu,
    parse_response,
    read_binary,
    select_file,
    select_ndef_app,
)
from .counterstore import CounterStore
from .diagnostics import TapInspection, inspect_tap
from .encverifier import EncFileVerifier, EncVerificationResult
from .ev2 import (
    INS_CHANGE_FILE_SETTINGS,
    INS_GET_FILE_SETTINGS,
    Session,
    authenticate_ev2_first,
    native_exchange,
)
from .keyprov import FactoryKeys, TagKeys, get_card_uid
from .ndef import NdefError, decode_uri_file, read_uri
from .sdmconfig import (
    FACTORY_ACCESS,
    KEY_FREE,
    NDEF_FILE_NO,
    FileSettings,
    SunLayout,
    parse_file_settings,
    same_config,
    sun_enc_layout,
    sun_enc_settings,
    sun_layout,
    locked_access,
    sun_settings,
)
from .verifier import StaticKeys

# ISOUpdateBinary chunks small enough for one ISO-DEP frame on every reader in
# use (5 B header + data + Le + PCB + CRC within the Chameleon's 62 bytes), so
# each piece is written atomically rather than across chained frames.
_WRITE_CHUNK = 48
INS_WRITE_DATA = 0x8D
# WriteData payload per command: 5 B header + 7 B FileNo/Offset/Length + data
# + Le fits one 64-byte ISO-DEP frame, so every chunk is tearing protected
# (NT4H2421Gx §10.8.2) without relying on chaining.
_WRITE_DATA_CHUNK = 48


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
    uid: bytes | None = None
    aborted: bool = False
    check: TapInspection | None = None
    enc_check: EncVerificationResult | None = None
    log: list[str] = field(default_factory=list)

    @property
    def already_provisioned(self) -> bool:
        return bool(self.ndef_matches and self.settings_match)

    @property
    def verified(self) -> bool:
        """
        The post-provisioning tap verifies: for plain SUN it decodes, the MAC
        matches and offsets line up; for SDMENCFileData it is AUTHENTIC under
        the zero keys and decrypts to the plaintext that was written.
        """
        if self.layout.file_data is not None:
            e = self.enc_check
            return bool(e and e.ok and e.file_data == self.layout.file_data)
        c = self.check
        return bool(c and c.cmac_match and not c.warnings
                    and c.offsets == self.layout.offsets)


def update_binary(offset: int, data: bytes) -> bytes:
    """
    ISOUpdateBinary at `offset` in the datasheet form (NT4H2421Gx: no Le).
    The AN12196 Table 16 form with a trailing Le (`update_binary_an12196`) is
    refused on silicon: 6700 for a single-frame write to a freely writable
    file (UID 04341A82161690), and before the access check when writes are
    locked (UID 04801A82161690). The same bytes without Le are written.
    """
    return build_apdu(0x00, 0xD6, offset >> 8, offset & 0xFF, data)


def update_binary_an12196(offset: int, data: bytes) -> bytes:
    """ISOUpdateBinary encoded as in AN12196 Table 16 (trailing Le); kept to
    pin that encoding, never sent by provisioning."""
    return build_apdu(0x00, 0xD6, offset >> 8, offset & 0xFF, data, le=0)


def _iso(transport, apdu: bytes, what: str) -> bytes:
    return parse_response(transport.transceive(apdu)).check(what)


def write_data(offset: int, data: bytes) -> bytes:
    """CmdHeader + CmdData of a plain WriteData to the NDEF file."""
    return (bytes([NDEF_FILE_NO]) + offset.to_bytes(3, "little")
            + len(data).to_bytes(3, "little") + data)


def _write_key(access) -> int | None:
    """None when writes are free, else the key granting them (Write or RW)."""
    if KEY_FREE in (access.write, access.read_write):
        return None
    for key in (access.write, access.read_write):
        if 0 <= key <= 4:
            return key
    raise ProvisionError("NDEF file is not writable (Write and ReadWrite disabled)")


def _enc_tap(url: str, meta_key: bytes, file_key: bytes) -> EncVerificationResult:
    """Verify one SDMENCFileData tap with the given keys, with no history."""
    return EncFileVerifier(StaticKeys(meta_key, file_key), CounterStore()).verify(url)


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


def provision_tag(transport, base_url: str, *, file_data: bytes | None = None,
                  write_key: int | None = 0, tag_keys: TagKeys | None = None,
                  uid: bytes | None = None, dry_run: bool = False,
                  confirm: Callable[[ProvisionReport], bool] | None = None,
                  log: Callable[[str], None] | None = None) -> ProvisionReport:
    """
    Bring the tag behind `transport` to the SUN layout for `base_url`, or,
    with `file_data`, to the SDMENCFileData layout mirroring that plaintext.
    NDEF writes are locked to `write_key` (None leaves them free, plain layout
    only). `uid`, if given, must match the tag. `confirm` sees the report
    (UID and plan) before anything is written and returns whether to go on.
    With `transport=None` (and `dry_run=True`) only the offline plan is built.
    """
    if file_data is None:
        layout = sun_layout(base_url)
        access = FACTORY_ACCESS if write_key is None else locked_access(write_key)
        desired = sun_settings(layout.offsets, access=access)
    else:
        if write_key is None:
            raise ProvisionError("the encrypted mirror needs locked NDEF writes")
        layout = sun_enc_layout(base_url, file_data)
        desired = sun_enc_settings(layout.offsets, write_key=write_key)
    report = ProvisionReport(layout=layout, desired=desired, dry_run=dry_run)
    keys = tag_keys or FactoryKeys().keys_for(b"")
    meta_key, file_key = keys[desired.meta_read], keys[desired.file_read]

    def say(msg: str) -> None:
        report.log.append(msg)
        if log:
            log(msg)

    o = layout.offsets
    say(f"template      : {layout.url}")
    if file_data is None:
        say(f"NDEF file     : {len(layout.ndef_file)} B, PICCDataOffset=0x{o.picc_data:02X}, "
            f"SDMMACInputOffset=SDMMACOffset=0x{o.mac:02X}")
    else:
        say(f"NDEF file     : {len(layout.ndef_file)} B, PICCDataOffset=0x{o.picc_data:02X}, "
            f"SDMMACInputOffset=SDMENCOffset=0x{o.enc_data:02X}, "
            f"SDMENCLength=0x{o.enc_length:02X}, SDMMACOffset=0x{o.mac:02X}")
        say(f"file data     : {len(file_data)} B plaintext")
    say("NDEF writes   : " + ("FREE (bench tag)" if write_key is None
                              else f"locked to key {write_key}"))
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
    report.settings_match = same_config(current, desired)
    if file_data is None or not current.enc_enabled:
        # Plain SUN, or the plaintext is still readable as static data.
        report.ndef_matches = layout.mask_mirrors(content, enc_mirrored=False) \
            == layout.ndef_file
    elif report.settings_match:
        # The tag already encrypts the mirror: decrypt this read to compare.
        report.ndef_matches = layout.mask_mirrors(content) == layout.ndef_file \
            and _current_plaintext(content, meta_key, file_key) == file_data
    else:
        # Encrypted under other settings: the plaintext cannot be checked.
        report.ndef_matches = False
    say(f"current       : settings {'match' if report.settings_match else 'differ'}, "
        f"NDEF {'matches' if report.ndef_matches else 'differs'}")

    # 2. Prove every key the writes need before writing anything.
    if not report.already_provisioned:
        _preflight(transport, report, current, keys, uid, say)

    if report.already_provisioned:
        say("already provisioned: nothing to write")
    elif dry_run:
        if not report.ndef_matches:
            key = _write_key(current.access)
            say("would write  : NDEF template via "
                + ("ISOUpdateBinary" if key is None
                   else f"WriteData (auth with key {key})"))
        if not report.settings_match:
            say(f"would change : file settings (auth with key {current.access.change}, "
                f"CommMode.Full)")
        return report
    else:
        if confirm is not None and not confirm(report):
            report.aborted = True
            say("aborted      : not confirmed, nothing written")
            return report
        session: Session | None = None
        session_key: int | None = None
        # 3. NDEF template.
        if not report.ndef_matches:
            key = _write_key(current.access)
            if key is None:
                _iso(transport, select_file(NDEF_FILE_ID), "select NDEF file")
                data = layout.ndef_file
                for off in range(0, len(data), _WRITE_CHUNK):
                    _iso(transport, update_binary(off, data[off : off + _WRITE_CHUNK]),
                         "write NDEF template")
                say("wrote        : NDEF template (ISOUpdateBinary)")
            else:
                _iso(transport, select_ndef_app(), "select NDEF application")
                session, session_key = authenticate_ev2_first(transport, key, keys[key]), key
                _write_data(transport, session, layout.ndef_file)
                say(f"wrote        : NDEF template (WriteData, authenticated with key {key})")
            report.wrote_ndef = True
        # 4. File settings.
        if not report.settings_match:
            change_key = current.access.change
            if not 0 <= change_key <= 4:
                raise ProvisionError(f"unsupported Change access right 0x{change_key:X}")
            if session is None or session_key != change_key:
                _iso(transport, select_ndef_app(), "select NDEF application")
                session = authenticate_ev2_first(transport, change_key, keys[change_key])
            session.send_full(INS_CHANGE_FILE_SETTINGS, bytes([NDEF_FILE_NO]),
                              desired.encode_change())
            report.changed_settings = True
            say(f"changed      : file settings (authenticated with key {change_key})")

    # 5. Confirm with a fresh tap (re-selecting drops the authenticated state).
    tap = read_uri(transport)
    if file_data is None:
        report.check = inspect_tap(tap, meta_key, file_key)
        say(f"check        : UID {report.check.uid}, SDMReadCtr {report.check.read_counter}, "
            f"CMAC {'match' if report.check.cmac_match else 'MISMATCH'}"
            + ("" if report.verified else " -> NOT VERIFIED"))
    else:
        e = report.enc_check = _enc_tap(tap, meta_key, file_key)
        say(f"check        : {e.verdict.value}, UID {e.uid}, SDMReadCtr {e.read_counter}, "
            f"file data {'match' if e.file_data == file_data else 'MISMATCH'}"
            + ("" if report.verified else f" -> NOT VERIFIED ({e.detail})"))
    return report


def _preflight(transport, report: ProvisionReport, current: FileSettings,
               keys: TagKeys, uid: bytes | None, say: Callable[[str], None]) -> None:
    """
    Authenticate with each key the planned writes need and read the UID, so a
    missing key or a different tag stops the run before the tag is touched.
    """
    needed: list[int] = []
    if not report.ndef_matches:
        key = _write_key(current.access)
        if key is not None:
            needed.append(key)
    change_key = current.access.change
    if not 0 <= change_key <= 4:
        raise ProvisionError(f"unsupported Change access right 0x{change_key:X}")
    anticollision = getattr(transport, "anticollision_uid", None)
    report.uid = None if anticollision is None else bytes(anticollision)
    if (not report.settings_match or report.uid is None) and change_key not in needed:
        needed.append(change_key)
    for key in needed:
        _iso(transport, select_ndef_app(), "select NDEF application")
        try:
            session = authenticate_ev2_first(transport, key, keys[key])
        except ApduError as exc:
            if exc.sw != 0x91AE:
                raise
            raise ProvisionError(
                f"the tag rejects key {key}: nothing was written. If its keys were "
                "replaced, pass them (tools/provision.py --secrets-dir)") from exc
        card_uid = get_card_uid(session)
        if report.uid is None:
            report.uid = card_uid
        elif card_uid != report.uid:
            raise ProvisionError("GetCardUID differs from the anticollision UID: refusing")
    if uid is not None and report.uid != uid:
        raise ProvisionError(f"tag UID {report.uid.hex().upper()} differs from the "
                             f"expected {uid.hex().upper()}: nothing was written")
    say(f"UID          : {report.uid.hex().upper()}")
    if needed:
        say("auth check   : keys " + ", ".join(map(str, needed)) + " accepted")
        # Leave the authenticated state, so the writes run exactly as before.
        _iso(transport, select_ndef_app(), "select NDEF application")


def _write_data(transport, session: Session, data: bytes) -> None:
    """
    WriteData to the NDEF file in CommMode.Plain within an authenticated
    session: frames carry no MAC, but the PICC still advances CmdCtr
    (NT4H2421Gx §9.1.8), so the session counter is kept in step for any
    MAC'd or encrypted command that follows.
    """
    session._require_open()
    for off in range(0, len(data), _WRITE_DATA_CHUNK):
        try:
            native_exchange(transport, INS_WRITE_DATA,
                            write_data(off, data[off : off + _WRITE_DATA_CHUNK]))
        except Exception:
            session.close()
            raise
        session.cmd_ctr += 1


def _current_plaintext(content: bytes, meta_key: bytes, file_key: bytes) -> bytes | None:
    """Plaintext mirrored in an SDMENCFileData read, or None if it does not verify."""
    try:
        result = _enc_tap(decode_uri_file(content), meta_key, file_key)
    except NdefError:
        return None
    return result.file_data if result.ok else None
