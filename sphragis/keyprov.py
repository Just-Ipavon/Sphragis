"""
Key provisioning for NTAG 424 DNA: replace the application keys of a tag.

Primitives (on top of an EV2 session from `ev2.py`, AN12196 §5.16 and §6.3):

  - `change_key`      ChangeKey (C4h) in CommMode.Full, both cases: a key other
                      than the session key (new XOR old || version || CRC32NK),
                      and the session key itself (new || version; the PICC then
                      drops the session and returns no MAC);
  - `get_key_version` GetKeyVersion (64h) in CommMode.MAC;
  - `get_card_uid`    GetCardUID (51h) in CommMode.Full, response decrypted.

Key schemes say which key sits in each of the five slots of a given tag:

  - `FactoryKeys`     all-zero keys, version 00h (delivery state);
  - `DiversifiedTagKeys`
        slot 0 (AppMasterKey), 3, 4: AN10922-diversified from `master_admin`
                                     with M = UID || slot || context;
        slot 1 (SDMFileRead):        `diversify(master_file, context || UID)`,
                                     i.e. exactly `DiversifiedKeys.file_read_key`;
        slot 2 (SDMMetaRead):        `meta_read`, shared, since the UID is only
                                     known after decrypting PICCData with it.
    `master_admin` is a separate secret, so verification servers (which need
    `master_file` and `meta_read` only) never hold the key that reconfigures
    tags.

`rekey_tag` moves a tag from whatever known scheme each slot is in to a target
scheme. Key versions record the scheme of every slot (factory 00h, Sphragis
01h by default), so an interrupted run resumes where it stopped; a slot whose
version matches no known scheme stops the run before anything is written.
Slots 1-4 change first and slot 0 last, because changing the session key ends
the session. The result is verified by authenticating with every new key and
reading the version of every slot.

Keys never appear in logs or reprs: only key check values (KCV, the first
three bytes of AES-ECB(key, 0^16)).
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from typing import Callable, Protocol, Sequence
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import AES

from .apdu import ApduError, parse_response, select_ndef_app
from .counterstore import CounterStore
from .diversify import DiversifiedKeys, diversify_key
from .encverifier import EncFileVerifier
from .ev2 import SW_OK, Session, authenticate_ev2_first
from .ndef import NdefError, read_uri
from .sdm import SdmError, decrypt_picc_data
from .verifier import StaticKeys, Verifier

INS_CHANGE_KEY = 0xC4
INS_GET_KEY_VERSION = 0x64
INS_GET_CARD_UID = 0x51

KEY_SLOTS = 5
FACTORY_VERSION = 0x00
SPHRAGIS_VERSION = 0x01


class KeyProvisionError(Exception):
    """The tag cannot be brought to the target keys safely."""


# --- Primitives -----------------------------------------------------------------

def crc32nk(data: bytes) -> bytes:
    """CRC32 as used by ChangeKey (JAMCRC: no final XOR), little-endian."""
    return (zlib.crc32(data) ^ 0xFFFFFFFF).to_bytes(4, "little")


def key_check_value(key: bytes) -> str:
    """KCV for logs: first three bytes of AES-ECB(key, 0^16), as hex."""
    return AES.new(key, AES.MODE_ECB).encrypt(bytes(16))[:3].hex().upper()


def change_key(session: Session, key_no: int, new_key: bytes, version: int, *,
               auth_key_no: int, old_key: bytes | None = None) -> bool:
    """
    ChangeKey for `key_no` within `session` (authenticated with `auth_key_no`).
    Returns True if the session is still usable afterwards, False when the
    session key itself was changed (the PICC ends the session).
    """
    if len(new_key) != 16 or not 0 <= version <= 0xFF:
        raise ValueError("new_key must be 16 bytes and version a byte")
    header = bytes([key_no])
    if key_no != auth_key_no:
        if old_key is None or len(old_key) != 16:
            raise ValueError("changing another key needs its current value")
        data = (bytes(a ^ b for a, b in zip(new_key, old_key))
                + bytes([version]) + crc32nk(new_key))
        session.send_full(INS_CHANGE_KEY, header, data)
        return True
    apdu = session.full_command_apdu(INS_CHANGE_KEY, header, new_key + bytes([version]))
    resp = parse_response(session.transport.transceive(apdu))
    if resp.sw != SW_OK:
        raise ApduError(resp.sw, "ChangeKey of the session key failed")
    if resp.data:
        raise KeyProvisionError("unexpected response data after changing the session key")
    return False


def get_key_version(session: Session, key_no: int) -> int:
    body = session.send_mac(INS_GET_KEY_VERSION, bytes([key_no]))
    if len(body) != 1:
        raise KeyProvisionError(f"GetKeyVersion returned {len(body)} bytes")
    return body[0]


def get_card_uid(session: Session) -> bytes:
    """GetCardUID; the response is encrypted under the session ENC key."""
    enc = session.send_mac(INS_GET_CARD_UID, b"")
    if not enc or len(enc) % 16:
        raise KeyProvisionError("GetCardUID response is not whole AES blocks")
    # send_mac has advanced the counter: the response IV uses CmdCtr + 1.
    iv = session._iv(b"\x5A\xA5", session.cmd_ctr)
    plain = AES.new(session.k_enc, AES.MODE_CBC, iv).decrypt(enc).rstrip(b"\x00")
    if not plain.endswith(b"\x80"):
        raise KeyProvisionError("GetCardUID response padding is invalid")
    return plain[:-1]


# --- Key schemes ----------------------------------------------------------------

@dataclass(frozen=True)
class TagKeys:
    """The five application keys of one tag, plus the version they carry."""

    keys: tuple[bytes, ...]
    version: int
    label: str

    def __post_init__(self) -> None:
        if len(self.keys) != KEY_SLOTS or any(len(k) != 16 for k in self.keys):
            raise ValueError("TagKeys needs five 16-byte keys")
        if not 0 <= self.version <= 0xFF:
            raise ValueError("version must be a byte")

    def __getitem__(self, slot: int) -> bytes:
        return self.keys[slot]

    def __repr__(self) -> str:   # never print key material
        kcvs = " ".join(key_check_value(k) for k in self.keys)
        return f"TagKeys({self.label}, version {self.version:02X}, KCV {kcvs})"


class KeyScheme(Protocol):
    label: str
    version: int
    meta_read_key: bytes        # slot 2, shared: needed to read a UID from a tap

    def keys_for(self, uid: bytes) -> TagKeys: ...


@dataclass(frozen=True)
class FactoryKeys:
    label: str = "factory"
    version: int = FACTORY_VERSION
    meta_read_key: bytes = field(default=bytes(16), repr=False)

    def keys_for(self, uid: bytes) -> TagKeys:
        return TagKeys((bytes(16),) * KEY_SLOTS, self.version, self.label)


class DiversifiedTagKeys:
    """Per-UID keys derived from `master_admin`, `master_file` and `meta_read`."""

    def __init__(self, master_admin: bytes, master_file: bytes, meta_read: bytes,
                 context: bytes = b"", version: int = SPHRAGIS_VERSION,
                 label: str = "diversified") -> None:
        if any(len(k) != 16 for k in (master_admin, master_file, meta_read)):
            raise ValueError("master keys must be AES-128 (16 bytes)")
        if len(context) > 23:
            raise ValueError("context too long (UID || slot || context must fit 31 bytes)")
        if version == FACTORY_VERSION or not 0 < version <= 0xFF:
            raise ValueError("version must be 01h..FFh (00h marks factory keys)")
        self._admin = master_admin
        self._file = DiversifiedKeys(master_file, meta_read, context=context)
        self._context = context
        self.meta_read_key = meta_read
        self.version = version
        self.label = label

    @classmethod
    def from_secrets(cls, secrets, context: bytes = b"",
                     version: int = SPHRAGIS_VERSION) -> "DiversifiedTagKeys":
        return cls(secrets.get_key("master_admin"), secrets.get_key("master_file"),
                   secrets.get_key("meta_read"), context=context, version=version)

    def keys_for(self, uid: bytes) -> TagKeys:
        if not 4 <= len(uid) <= 10:
            raise ValueError(f"implausible UID length {len(uid)}")

        def admin(slot: int) -> bytes:
            return diversify_key(self._admin, uid + bytes([slot]) + self._context)

        keys = (admin(0), self._file.file_read_key(uid), self.meta_read_key,
                admin(3), admin(4))
        return TagKeys(keys, self.version, self.label)

    def __repr__(self) -> str:
        return f"DiversifiedTagKeys(version {self.version:02X})"


# --- Flow -----------------------------------------------------------------------

@dataclass
class RekeyReport:
    target: str
    dry_run: bool = False
    uid: bytes | None = None
    versions: list[int] = field(default_factory=list)
    current: list[str] = field(default_factory=list)
    planned: list[int] = field(default_factory=list)
    changed: list[int] = field(default_factory=list)
    verified: bool = False
    log: list[str] = field(default_factory=list)

    @property
    def already_done(self) -> bool:
        return self.uid is not None and not self.planned


def _select(transport) -> None:
    parse_response(transport.transceive(select_ndef_app())).check("select NDEF application")


def _authenticate(transport, key_no: int, key: bytes) -> Session | None:
    """AuthenticateEV2First, or None if the PICC rejects the key (91AE)."""
    try:
        return authenticate_ev2_first(transport, key_no, key)
    except ApduError as exc:
        if exc.sw == 0x91AE:
            return None
        raise


def _uid_from_tap(transport, schemes: Sequence[KeyScheme]) -> bytes | None:
    """
    Read a SUN tap and find the scheme it verifies under. Decrypting PICCData
    alone authenticates nothing (a wrong key yields a plausible-looking block),
    so a UID is accepted only when the whole tap verifies with that scheme's
    keys: MetaRead in slot 2, FileRead in slot 1, as provisioning sets them.
    """
    try:
        url = read_uri(transport)
    except (ApduError, NdefError):
        return None
    values = parse_qs(urlparse(url).query).get("picc_data", [])
    if len(values) != 1:
        return None
    try:
        enc = bytes.fromhex(values[0])
    except ValueError:
        return None
    verifier_cls = EncFileVerifier if "enc" in parse_qs(urlparse(url).query) else Verifier
    # Slots 2 and 1 may sit on different schemes while a key change is
    # interrupted, so every (MetaRead scheme, FileRead scheme) pair is tried.
    for meta_scheme in schemes:
        try:
            uid = decrypt_picc_data(enc, meta_scheme.meta_read_key).uid
        except SdmError:
            continue
        for file_scheme in schemes:
            try:
                file_key = file_scheme.keys_for(uid)[1]
            except ValueError:
                break
            keys = StaticKeys(meta_scheme.meta_read_key, file_key)
            if verifier_cls(keys, CounterStore()).verify(url).ok:
                return uid
    return None


def _open_session(transport, uid: bytes | None, schemes: Sequence[KeyScheme],
                  say: Callable[[str], None]) -> tuple[Session, KeyScheme, bytes]:
    """
    Authenticate with slot 0 under one of the known schemes and read the UID.
    Schemes that need the UID are tried once it is known (given, or decrypted
    from a SUN tap with a shared meta key).
    """
    candidates: list[tuple[KeyScheme, bytes | None]] = []
    if uid is None:
        uid = _uid_from_tap(transport, schemes)
        if uid is not None:
            say(f"UID (from tap): {uid.hex().upper()}")
    probe = uid or bytes(7)
    for scheme in schemes:
        if isinstance(scheme, FactoryKeys) or uid is not None:
            candidates.append((scheme, uid))
    for scheme, known_uid in candidates:
        _select(transport)
        session = _authenticate(transport, 0, scheme.keys_for(probe)[0])
        if session is None:
            continue
        card_uid = get_card_uid(session)
        if known_uid is not None and card_uid != known_uid:
            raise KeyProvisionError(
                f"tag UID {card_uid.hex().upper()} differs from the expected "
                f"{known_uid.hex().upper()}: refusing to touch this tag")
        return session, scheme, card_uid
    raise KeyProvisionError(
        "slot 0 matches none of the known key schemes"
        + ("" if uid else " (and no UID could be read from a SUN tap; pass it)"))


def rekey_tag(transport, target: KeyScheme, known: Sequence[KeyScheme] = (), *,
              uid: bytes | None = None, dry_run: bool = False,
              log: Callable[[str], None] | None = None) -> RekeyReport:
    """
    Bring the five application keys of the tag behind `transport` to `target`.
    `known` lists the schemes the tag may currently hold besides the factory
    one and the target itself; each needs a distinct key version.
    """
    schemes: list[KeyScheme] = [FactoryKeys()]
    for s in (target, *known):
        if all(s is not t for t in schemes) and not isinstance(s, FactoryKeys):
            schemes.append(s)
    by_version = {}
    for s in schemes:
        if s.version in by_version:
            raise ValueError(f"two key schemes share version {s.version:02X}")
        by_version[s.version] = s

    report = RekeyReport(target=target.label, dry_run=dry_run)

    def say(msg: str) -> None:
        report.log.append(msg)
        if log:
            log(msg)

    # 1. Authenticate with slot 0, read the UID and every slot's version.
    session, slot0, report.uid = _open_session(transport, uid, schemes, say)
    say(f"UID          : {report.uid.hex().upper()} (GetCardUID)")
    report.versions = [get_key_version(session, n) for n in range(KEY_SLOTS)]
    current = []
    for n, v in enumerate(report.versions):
        scheme = by_version.get(v)
        if scheme is None:
            raise KeyProvisionError(
                f"slot {n} has key version {v:02X}, which matches no known "
                f"scheme: refusing to guess its key")
        current.append(scheme)
    if current[0] is not slot0:
        raise KeyProvisionError("slot 0 authenticated under a scheme other than "
                                "its version says")
    report.current = [s.label for s in current]
    new = target.keys_for(report.uid)
    say("current      : " + ", ".join(f"{n}={s.label}" for n, s in enumerate(current)))
    say(f"target       : {target.label}, version {target.version:02X}, KCV "
        + " ".join(key_check_value(k) for k in new.keys))

    # 2. Plan: slots 1-4 first, slot 0 (the session key) last.
    report.planned = [n for n in (1, 2, 3, 4, 0) if current[n] is not target]
    if not report.planned:
        say("already on the target keys: nothing to change")
    elif dry_run:
        say("would change : slots " + ", ".join(map(str, report.planned)))
        return report
    else:
        for n in report.planned:
            old = current[n].keys_for(report.uid)[n]
            alive = change_key(session, n, new[n], target.version,
                               auth_key_no=0, old_key=old)
            report.changed.append(n)
            say(f"changed      : slot {n} ({current[n].label} -> {target.label})")
            if not alive:
                break

    # 3. Verify: every new key authenticates, every slot carries the version.
    _select(transport)
    check = _authenticate(transport, 0, new[0])
    if check is None or get_card_uid(check) != report.uid:
        say("check        : slot 0 does not authenticate with the target key")
        return report
    versions = [get_key_version(check, n) for n in range(KEY_SLOTS)]
    ok = all(v == target.version for v in versions)
    for n in range(1, KEY_SLOTS):
        _select(transport)
        ok = ok and _authenticate(transport, n, new[n]) is not None
    report.verified = ok
    say("check        : " + ("all five keys authenticate, versions "
                             f"{target.version:02X}" if ok else "MISMATCH"))
    return report


def current_tag_keys(transport, known: Sequence[KeyScheme] = (), *,
                     uid: bytes | None = None,
                     log: Callable[[str], None] | None = None) -> TagKeys:
    """
    Identify the keys the tag holds now (factory or one of `known`) without
    changing anything. Refuses a tag whose slots are on different schemes:
    finish or undo the interrupted `rekey_tag` run first.
    """
    schemes: list[KeyScheme] = [FactoryKeys(), *[s for s in known
                                                  if not isinstance(s, FactoryKeys)]]
    say = log or (lambda msg: None)
    session, slot0, card_uid = _open_session(transport, uid, schemes, say)
    versions = {get_key_version(session, n) for n in range(KEY_SLOTS)}
    if versions != {slot0.version}:
        raise KeyProvisionError(
            "the tag's key slots are on different schemes (versions "
            + ", ".join(f"{v:02X}" for v in sorted(versions))
            + "): complete or undo the key change first")
    say(f"tag keys     : {slot0.label} (UID {card_uid.hex().upper()})")
    return slot0.keys_for(card_uid)
