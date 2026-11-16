"""
Command-line verifier.

Keys for verify / emulate, first match wins:
    --secrets-dir DIR      master_file and meta_read (hex files, 0600), diversified
                           per UID with --context, as the API does;
    --meta-key/--file-key  hex on the command line: visible to other users
                           (ps, shell history), so only for test keys;
    SPHRAGIS_CLI_META_KEY / SPHRAGIS_CLI_FILE_KEY  hex in the environment;
    otherwise both are asked for without echo.

Examples:
    # Verify a tapped URL with the deployment's keys
    python -m sphragis.cli verify --secrets-dir ~/.sphragis/keys --context DEMO \\
        "https://example.com/t?picc_data=...&cmac=..."

    # Verify a tap that also mirrors encrypted file data (SDMENCFileData)
    python -m sphragis.cli verify --enc --meta-key <hex> --file-key <hex> \\
        "https://example.com/t?picc_data=...&enc=...&cmac=..."

    # Decode what a tag emits (diagnostic; keys default to all-zero)
    python -m sphragis.cli inspect "https://example.com/t?picc_data=...&cmac=..."

    # Keep the anti-replay floor in SQLite, shareable with the API's database
    python -m sphragis.cli verify --secrets-dir ~/.sphragis/keys --sqlite sphragis.db "<url>"

Exit status of verify: 0 AUTHENTIC, 1 ERROR (malformed input), 3 REPLAY,
4 FORGED; 2 is a usage error for every command. Taps with an `enc`
parameter are verified as SDMENCFileData taps automatically.

    # Import a WebAuthn credential the relying party registered, list, revoke
    python -m sphragis.cli credentials import --sqlite sphragis.db \
        --credential-id <base64url> --cose-key <base64url> --rp-id verify.example.com
    python -m sphragis.cli credentials list --sqlite sphragis.db
    python -m sphragis.cli credentials revoke --sqlite sphragis.db --credential-id <base64url>

    # Generate a demo tap from an emulated tag (no hardware needed)
    python -m sphragis.cli emulate --meta-key <hex> --file-key <hex> --uid 04DE5F1EACC040
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from urllib.parse import parse_qs

from . import __version__
from .counterstore import CounterStore, CounterStoreError
from .diagnostics import ZERO_KEY, inspect_tap
from .emulator import EmulatedTag
from .encverifier import EncFileVerifier
from .sdm import SdmError
from .secrets import FileSecretsBackend, SecretsError, build_diversified_keys
from .verifier import _ENC_MARKERS, StaticKeys, Verdict, Verifier, _query_of

EXIT_CODES = {
    Verdict.AUTHENTIC: 0,
    Verdict.ERROR: 1,          # malformed input: not a tap at all
    Verdict.REPLAY: 3,         # valid MAC, stale counter
    Verdict.FORGED: 4,         # MAC does not verify
}
"""verify's exit status; 2 is argparse's usage error, as for every command."""

_VERDICT_LABEL = {
    Verdict.AUTHENTIC: "AUTHENTIC  - genuine tag, fresh tap",
    Verdict.REPLAY: "REPLAY     - valid MAC but stale counter (replay/clone)",
    Verdict.FORGED: "FORGED     - MAC mismatch, not a genuine tag",
    Verdict.ERROR: "ERROR      - malformed input",
}


def _hexkey(value: str) -> bytes:
    key = bytes.fromhex(value)
    if len(key) != 16:
        raise argparse.ArgumentTypeError("key must be 16 bytes (32 hex chars)")
    return key


MAX_COUNTER = 0xFFFFFF
"""SDMReadCtr is 24 bits; a real tag stops answering with SUN at the limit."""


def _uid(value: str) -> bytes:
    try:
        uid = bytes.fromhex(value)
    except ValueError:
        raise argparse.ArgumentTypeError("UID must be hex") from None
    if len(uid) != 7:
        raise argparse.ArgumentTypeError("UID must be 7 bytes (14 hex chars)")
    return uid


def _counter(value: str) -> int:
    try:
        counter = int(value, 0)
    except ValueError:
        raise argparse.ArgumentTypeError("counter must be an integer") from None
    if not 0 <= counter < MAX_COUNTER:
        raise argparse.ArgumentTypeError(
            f"counter must be between 0 and {MAX_COUNTER - 1} (each tap adds one)")
    return counter


def _taps(value: str) -> int:
    try:
        taps = int(value, 0)
    except ValueError:
        raise argparse.ArgumentTypeError("taps must be an integer") from None
    if taps < 1:
        raise argparse.ArgumentTypeError("taps must be at least 1")
    return taps


def _resolve_keys(args: argparse.Namespace):
    """The key provider for verify/emulate (see the module docstring)."""
    if args.secrets_dir:
        try:
            return build_diversified_keys(FileSecretsBackend(args.secrets_dir),
                                          context=args.context.encode())
        except (SecretsError, ValueError) as exc:
            raise SystemExit(f"error: {exc}") from None
    if args.meta_key is not None or args.file_key is not None:
        if args.meta_key is None or args.file_key is None:
            raise SystemExit("error: --meta-key and --file-key go together")
        print("warning: keys on the command line are visible to other users "
              "(ps, shell history); prefer --secrets-dir", file=sys.stderr)
        return StaticKeys(args.meta_key, args.file_key)
    env_meta = os.environ.get("SPHRAGIS_CLI_META_KEY")
    env_file = os.environ.get("SPHRAGIS_CLI_FILE_KEY")
    try:
        if env_meta and env_file:
            return StaticKeys(_hexkey(env_meta), _hexkey(env_file))
        if not sys.stdin.isatty():
            raise SystemExit("error: no keys given (--secrets-dir, environment or a "
                             "terminal to type them)")
        return StaticKeys(_hexkey(getpass.getpass("K_SDMMetaReadKey (hex): ")),
                          _hexkey(getpass.getpass("K_SDMFileReadKey (hex): ")))
    except (argparse.ArgumentTypeError, ValueError) as exc:
        raise SystemExit(f"error: invalid key: {exc}") from None


def _cmd_verify(args: argparse.Namespace) -> int:
    keys = _resolve_keys(args)
    verifier_cls = EncFileVerifier if args.enc or _mirrors_file_data(args.url) else Verifier
    try:
        if args.sqlite:
            from .sqlstore import SqliteCounterStore
            store = SqliteCounterStore(args.sqlite)
        else:
            store = CounterStore(args.store)
    except (CounterStoreError, ValueError, OSError) as exc:
        raise SystemExit(f"error: {exc}") from None
    try:
        result = verifier_cls(keys, store).verify(args.url)
    finally:
        getattr(store, "close", lambda: None)()
    print(_VERDICT_LABEL[result.verdict])
    if result.uid:
        print(f"UID        : {result.uid}")
    if result.read_counter is not None:
        print(f"ReadCounter: {result.read_counter}")
    if getattr(result, "file_data", None) is not None:
        print(f"FileData   : {result.file_data.hex().upper()}")
    print(f"Detail     : {result.detail}")
    return EXIT_CODES[result.verdict]


def _mirrors_file_data(url: str) -> bool:
    """Whether the tap carries SDMENCFileData (an `enc` parameter)."""
    try:
        query = _query_of(url)
    except SdmError:
        return False
    return any(k.lower() in _ENC_MARKERS for k in parse_qs(query, keep_blank_values=True))


def _cmd_inspect(args: argparse.Namespace) -> int:
    try:
        report = inspect_tap(args.url, args.meta_key, args.file_key)
    except SdmError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render())
    return 0


def _cmd_emulate(args: argparse.Namespace) -> int:
    if args.counter + args.taps > MAX_COUNTER:
        raise SystemExit(f"error: --counter {args.counter} plus {args.taps} taps passes "
                         f"the 24-bit limit ({MAX_COUNTER})")
    keys = _resolve_keys(args)
    uid = args.uid
    tag = EmulatedTag(
        uid=uid,
        meta_read_key=keys.meta_read_key(),
        file_read_key=keys.file_read_key(uid),
        read_counter=args.counter,
    )
    for _ in range(args.taps):
        print(tag.tap())
    return 0


def _cmd_verify_events(args: argparse.Namespace) -> int:
    from .events import EventError, read_event_file, verify_log
    try:
        public_key = bytes.fromhex(args.public_key)
    except ValueError:
        raise SystemExit("error: --public-key must be hex") from None
    try:
        events, (seq, head) = verify_log(read_event_file(args.file), public_key,
                                         log_id=args.log_id)
    except (EventError, ValueError) as exc:
        print(f"BROKEN     : {exc}")
        return 1
    except OSError as exc:
        raise SystemExit(f"error: cannot read {args.file}: {exc.strerror}") from None
    log = events[0].log_id if events else args.log_id
    print(f"OK         : {len(events)} events, log {log!r}")
    print(f"Head       : seq {seq}, digest {head.hex()}  (pin this as a checkpoint)")
    return 0


def _b64url(value: str) -> bytes:
    from .webauthn import b64url_decode
    try:
        data = b64url_decode(value.strip())
    except Exception:  # noqa: BLE001 - SdmError or ValueError: a usage error
        raise argparse.ArgumentTypeError("expected unpadded base64url") from None
    if not data:
        raise argparse.ArgumentTypeError("expected unpadded base64url")
    return data


def _credential_store(args: argparse.Namespace):
    if args.db_url:
        from .pgstore import PostgresCredentialStore
        return PostgresCredentialStore(args.db_url)
    from .sqlstore import SqliteCredentialStore
    if not os.path.exists(args.sqlite):
        raise SystemExit(f"error: {args.sqlite} does not exist (the API's database)")
    return SqliteCredentialStore(args.sqlite)


def _cmd_credentials(args: argparse.Namespace) -> int:
    import datetime

    from .webauthn import b64url_encode
    store = _credential_store(args)
    try:
        if args.action == "import":
            try:
                store.add(args.credential_id, args.cose_key, args.rp_id)
            except ValueError as exc:
                raise SystemExit(f"error: {exc}") from None
            print(f"IMPORTED  : {b64url_encode(args.credential_id)}"
                  + (f"  (RP ID {args.rp_id})" if args.rp_id else ""))
            return 0
        if args.action == "revoke":
            done = store.revoke(args.credential_id)
            print(("REVOKED   : " if done else "NOT ACTIVE: ")
                  + b64url_encode(args.credential_id))
            return 0 if done else 1
        records = store.entries(args.limit)
    finally:
        store.close()
    if args.json:
        print(json.dumps([{"credential_id": b64url_encode(r.credential_id),
                           "rp_id": r.rp_id, "created": r.created,
                           "revoked": r.revoked} for r in records]))
        return 0
    for r in records:
        when = datetime.datetime.fromtimestamp(r.created, datetime.timezone.utc)
        state = "revoked" if r.revoked is not None else "active"
        print(f"{b64url_encode(r.credential_id)}  {state:<7}  {when:%Y-%m-%d %H:%M}Z  "
              f"{r.rp_id or '-'}")
    return 0


def _add_db_args(parser: argparse.ArgumentParser) -> None:
    db = parser.add_mutually_exclusive_group(required=True)
    db.add_argument("--sqlite", metavar="DB", help="the API's SQLite database")
    db.add_argument("--db-url", metavar="URL", help="the API's postgresql:// database")


def _add_key_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--secrets-dir", help="directory with master_file and meta_read "
                                              "(hex, 0600): per-UID diversified keys")
    parser.add_argument("--context", default="", help="diversification context")
    parser.add_argument("--meta-key", type=_hexkey, help="K_SDMMetaReadKey (hex; test "
                                                         "keys only, visible in ps)")
    parser.add_argument("--file-key", type=_hexkey, help="K_SDMFileReadKey (hex; test "
                                                         "keys only, visible in ps)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sphragis",
        description="NTAG 424 DNA SUN/SDM verification toolkit",
        epilog="verify exits 0 AUTHENTIC, 1 ERROR (malformed), 3 REPLAY, 4 FORGED; "
               "2 is a usage error for every command",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="verify a tapped SUN URL")
    v.add_argument("url", help="the full URL (or query string) emitted by the tag")
    _add_key_args(v)
    stores = v.add_mutually_exclusive_group()
    stores.add_argument("--store", default=None,
                        help="JSON counter store (default: in memory, nothing kept)")
    stores.add_argument("--sqlite", default=None, metavar="DB",
                        help="SQLite counter store, shareable with the API's database")
    v.add_argument("--enc", action="store_true",
                   help="treat the URL as mirroring SDMENCFileData even without an "
                        "'enc' parameter (detected automatically otherwise)")
    v.set_defaults(func=_cmd_verify)

    i = sub.add_parser(
        "inspect",
        help="decode a tap's PICCData/offsets without judging it (diagnostic)",
    )
    i.add_argument("url", help="the full URL (or query string) emitted by the tag")
    i.add_argument("--meta-key", type=_hexkey, default=ZERO_KEY,
                   help="K_SDMMetaReadKey (hex, default all-zero factory key)")
    i.add_argument("--file-key", type=_hexkey, default=ZERO_KEY,
                   help="K_SDMFileReadKey for the informational CMAC check "
                        "(hex, default all-zero)")
    i.add_argument("--json", action="store_true", help="machine-readable output")
    i.set_defaults(func=_cmd_inspect)

    ve = sub.add_parser("verify-events",
                        help="check a chained signed-event log: signatures, sequence, links")
    ve.add_argument("file", help="event log written by FileEventSink")
    ve.add_argument("--public-key", required=True,
                    help="raw Ed25519 public key (hex), as served at /v1/event-key")
    ve.add_argument("--log-id", default=None, help="expected log id (default: the first)")
    ve.set_defaults(func=_cmd_verify_events)

    c = sub.add_parser("credentials", help="WebAuthn credentials the API accepts")
    actions = c.add_subparsers(dest="action", required=True)
    ci = actions.add_parser("import", help="import a credential the relying party "
                                           "registered (attestation is its job)")
    ci.add_argument("--credential-id", type=_b64url, required=True, help="base64url")
    ci.add_argument("--cose-key", type=_b64url, required=True,
                    help="COSE_Key from the registration, base64url (ES256 or EdDSA)")
    ci.add_argument("--rp-id", default=None,
                    help="only accept it for this RP ID (recommended)")
    cr = actions.add_parser("revoke", help="stop accepting a credential")
    cr.add_argument("--credential-id", type=_b64url, required=True, help="base64url")
    cl = actions.add_parser("list", help="list imported credentials, newest first")
    cl.add_argument("--limit", type=_taps, default=1000)
    cl.add_argument("--json", action="store_true", help="machine-readable output")
    for action in (ci, cr, cl):
        _add_db_args(action)
    c.set_defaults(func=_cmd_credentials)

    e = sub.add_parser("emulate", help="emit SUN URL(s) from a virtual tag")
    _add_key_args(e)
    e.add_argument("--uid", required=True, type=_uid, help="7-byte UID (hex)")
    e.add_argument("--counter", type=_counter, default=0, help="starting read counter")
    e.add_argument("--taps", type=_taps, default=1, help="number of taps to emit")
    e.set_defaults(func=_cmd_emulate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
