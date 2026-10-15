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

Identity checks before any key leaves the station (`rekey_tag`). The first
keying of a tag necessarily happens under the public factory key, so a device
that answers like a factory tag with a chosen UID would receive that UID's
keys. The flow therefore:

  - verifies the NXP originality signature (Read_Sig, ECDSA over the UID on
    secp224r1) and, where the transport exposes it, that the anticollision UID
    equals the GetCardUID one. A static signature can be replayed by an
    emulator copying a genuine tag, so this raises the cost but is not enough
    on its own;
  - keeps an inventory of UIDs it has keyed: a known UID that answers with
    factory keys and proves no key of its own (a UID-specific slot holding a
    non-factory key it can authenticate with) is refused, because a genuine
    keyed tag cannot be in that state;
  - records the UID in the inventory before the first key is sent, so an
    interrupted run is remembered too;
  - asks the caller to confirm the UID and the plan before writing.

What none of this removes: a passive RF capture of a factory keying session
yields the keys sent in it (the session keys follow from the zero key and the
exchanged randoms). Key tags in a shielded place, from a controlled supply.

Keys never appear in logs or reprs: only key check values (KCV, the first
three bytes of AES-ECB(key, 0^16)).
"""

from __future__ import annotations

import sqlite3
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable, Protocol, Sequence
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC

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
INS_READ_SIG = 0x3C
INS_ADDITIONAL_FRAME = 0xAF

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


# --- Originality signature -------------------------------------------------------

# NXP originality public key for NTAG 424 DNA (secp224r1, uncompressed point).
# Recovered from, and checked against, the signatures of three tags
# (tests/test_keyprov.py, PHYSICAL_SIGNATURES).
NXP_NTAG424_ORIGINALITY_KEY = bytes.fromhex(
    "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D6842"
    "2B81EC20B65A66B5102A61596AF3379200599316A00A1410")

_P224_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
_P224_G = (0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
           0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34)
SIGNATURE_LEN = 56
SW_READ_SIG_OK = 0x9190


def read_signature(transport) -> bytes:
    """Read_Sig (3Ch) without authentication: the 56-byte signature r || s."""
    apdu = bytes([0x90, INS_READ_SIG, 0x00, 0x00, 0x01, 0x00, 0x00])
    resp = parse_response(transport.transceive(apdu))
    data = resp.data
    for _ in range(4):
        if resp.sw != 0x91AF:
            break
        resp = parse_response(transport.transceive(
            bytes([0x90, INS_ADDITIONAL_FRAME, 0x00, 0x00, 0x00])))
        data += resp.data
    # Silicon (NTAG 424 DNA, UID 04084582161690) ends Read_Sig with 9190
    # rather than 9100; the signature check below is what authenticates it.
    if resp.sw not in (SW_OK, SW_READ_SIG_OK):
        raise ApduError(resp.sw, "Read_Sig failed")
    if len(data) != SIGNATURE_LEN:
        raise KeyProvisionError(f"Read_Sig returned {len(data)} bytes, expected 56")
    return data


def verify_originality(uid: bytes, signature: bytes,
                       public_key: bytes = NXP_NTAG424_ORIGINALITY_KEY) -> bool:
    """
    ECDSA verification on secp224r1 of `signature` (r || s) over the raw UID:
    the UID itself is the message representative, without hashing.
    """
    if len(signature) != SIGNATURE_LEN or len(public_key) != 57 or public_key[0] != 0x04:
        return False
    r = int.from_bytes(signature[:28], "big")
    s = int.from_bytes(signature[28:], "big")
    n = _P224_ORDER
    if not (0 < r < n and 0 < s < n):
        return False
    try:
        q = ECC.EccPoint(int.from_bytes(public_key[1:29], "big"),
                         int.from_bytes(public_key[29:], "big"), curve="P-224")
    except ValueError:              # not a point on the curve
        return False
    g = ECC.EccPoint(*_P224_G, curve="P-224")
    e = int.from_bytes(uid, "big")
    w = pow(s, -1, n)
    point = g * (e * w % n) + q * (r * w % n)
    if point.is_point_at_infinity():
        return False
    return int(point.x) % n == r


# --- Inventory of keyed UIDs ------------------------------------------------------

INVENTORY_KEYING = "keying"     # a key may have been sent; the run did not finish
INVENTORY_KEYED = "keyed"       # verified on non-factory keys
INVENTORY_FACTORY = "factory"   # verified back on the factory keys


class KeyInventory(Protocol):
    def state(self, uid: bytes) -> str | None: ...
    def record(self, uid: bytes, state: str, version: int) -> None: ...


class MemoryKeyInventory:
    """In-process inventory (tests, one-off runs)."""

    def __init__(self) -> None:
        self._rows: dict[bytes, tuple[str, int]] = {}

    def state(self, uid: bytes) -> str | None:
        row = self._rows.get(bytes(uid))
        return row[0] if row else None

    def record(self, uid: bytes, state: str, version: int) -> None:
        self._rows[bytes(uid)] = (state, version)


class SqliteKeyInventory:
    """
    Durable inventory of the UIDs a provisioning station has keyed. Share it
    between stations (or keep one station) so a UID cannot be keyed twice.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS keyed_uids ("
                " uid TEXT PRIMARY KEY, state TEXT NOT NULL,"
                " version INTEGER NOT NULL, updated_at REAL NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30)
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def state(self, uid: bytes) -> str | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT state FROM keyed_uids WHERE uid = ?",
                               (uid.hex().upper(),)).fetchone()
        return row[0] if row else None

    def record(self, uid: bytes, state: str, version: int) -> None:
        if state not in (INVENTORY_KEYING, INVENTORY_KEYED, INVENTORY_FACTORY):
            raise ValueError(f"unknown inventory state {state!r}")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO keyed_uids (uid, state, version, updated_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT (uid) DO UPDATE SET "
                "state = excluded.state, version = excluded.version, "
                "updated_at = excluded.updated_at",
                (uid.hex().upper(), state, version, time.time()))


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
    signature_ok: bool | None = None
    proven: list[int] = field(default_factory=list)
    inventory: str | None = None
    aborted: bool = False
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


def _is_factory(scheme: KeyScheme) -> bool:
    return scheme.version == FACTORY_VERSION


def rekey_tag(transport, target: KeyScheme, known: Sequence[KeyScheme] = (), *,
              uid: bytes | None = None, dry_run: bool = False,
              log: Callable[[str], None] | None = None,
              inventory: KeyInventory | None = None,
              originality_key: bytes | None = NXP_NTAG424_ORIGINALITY_KEY,
              confirm: Callable[[RekeyReport], bool] | None = None,
              allow_known_uid: bool = False) -> RekeyReport:
    """
    Bring the five application keys of the tag behind `transport` to `target`.
    `known` lists the schemes the tag may currently hold besides the factory
    one and the target itself; each needs a distinct key version.

    `inventory` records the UIDs keyed so far and is required to key a tag to
    non-factory keys. `originality_key` is the public key the Read_Sig
    signature must verify under (None skips the check). `confirm` sees the
    report (UID, current schemes, plan) before anything is written and returns
    whether to go ahead. `allow_known_uid` lets a UID the inventory already
    holds be keyed again from factory keys: only for a tag you reset outside
    this tool and have in hand.
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
    if inventory is None and not dry_run and not _is_factory(target):
        raise ValueError("keying a tag needs an inventory of keyed UIDs")

    report = RekeyReport(target=target.label, dry_run=dry_run)

    def say(msg: str) -> None:
        report.log.append(msg)
        if log:
            log(msg)

    # 1. Originality signature (plain, before any authentication).
    signature = None
    if originality_key is not None:
        _select(transport)
        signature = read_signature(transport)

    # 2. Authenticate with slot 0, read the UID and every slot's version.
    session, slot0, report.uid = _open_session(transport, uid, schemes, say)
    say(f"UID          : {report.uid.hex().upper()} (GetCardUID)")
    anticollision = getattr(transport, "anticollision_uid", None)
    if anticollision is not None and bytes(anticollision) != report.uid:
        raise KeyProvisionError(
            f"anticollision UID {bytes(anticollision).hex().upper()} differs from "
            f"GetCardUID {report.uid.hex().upper()}: refusing to touch this tag")
    if signature is not None:
        report.signature_ok = verify_originality(report.uid, signature, originality_key)
        if not report.signature_ok:
            raise KeyProvisionError("the originality signature does not verify for "
                                    "this UID: not a genuine NXP tag, refusing")
        say("originality  : NXP signature verifies for this UID")
    else:
        say("originality  : NOT CHECKED")

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

    # 3. Proof of possession: a UID-specific slot (not the shared MetaRead
    #    slot 2) on non-factory keys that authenticates with them. Only a tag
    #    keyed by us can do that; anything can claim factory keys.
    if not _is_factory(slot0):
        report.proven.append(0)
    else:
        for n in (1, 3, 4):
            if _is_factory(current[n]):
                continue
            _select(transport)
            if _authenticate(transport, n, current[n].keys_for(report.uid)[n]) is None:
                raise KeyProvisionError(
                    f"slot {n} claims {current[n].label} keys but does not "
                    f"authenticate with them: refusing")
            report.proven.append(n)
        if report.proven:
            _select(transport)
            session = _authenticate(transport, 0, slot0.keys_for(report.uid)[0])
            if session is None or get_card_uid(session) != report.uid:
                raise KeyProvisionError("slot 0 no longer authenticates: refusing")
    if report.proven:
        say("possession   : tag authenticates with its own keys in slots "
            + ", ".join(map(str, report.proven)))

    # 4. Plan: slots 1-4 first, slot 0 (the session key) last.
    report.planned = [n for n in (1, 2, 3, 4, 0) if current[n] is not target]
    sends_secrets = bool(report.planned) and not _is_factory(target)
    if inventory is not None:
        report.inventory = inventory.state(report.uid)
        say(f"inventory    : {report.inventory or 'unknown UID'}")
    if (sends_secrets and not report.proven
            and report.inventory in (INVENTORY_KEYING, INVENTORY_KEYED)):
        if not allow_known_uid:
            raise KeyProvisionError(
                f"UID {report.uid.hex().upper()} is already in the inventory "
                f"({report.inventory}) but this tag shows factory keys and proves "
                "no key of its own: a clone or emulator, or a tag reset outside "
                "this tool. Refusing to send keys")
        say("WARNING      : known UID keyed again from factory keys (allowed)")

    if not report.planned:
        say("already on the target keys: nothing to change")
    elif dry_run:
        say("would change : slots " + ", ".join(map(str, report.planned)))
        return report
    else:
        if confirm is not None and not confirm(report):
            report.aborted = True
            say("aborted      : not confirmed, nothing written")
            return report
        if sends_secrets and inventory is not None:
            inventory.record(report.uid, INVENTORY_KEYING, target.version)
        for n in report.planned:
            old = current[n].keys_for(report.uid)[n]
            alive = change_key(session, n, new[n], target.version,
                               auth_key_no=0, old_key=old)
            report.changed.append(n)
            say(f"changed      : slot {n} ({current[n].label} -> {target.label})")
            if not alive:
                break

    # 5. Verify: every new key authenticates, every slot carries the version.
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
    if ok and inventory is not None:
        inventory.record(report.uid, INVENTORY_FACTORY if _is_factory(target)
                         else INVENTORY_KEYED, target.version)
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
