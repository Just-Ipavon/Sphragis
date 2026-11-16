"""
API configuration, loaded from `SPHRAGIS_*` environment variables.

Key material (SDM keys, pseudonymization key, webhook secret) is read through a
`SecretsBackend`, never from these settings directly.

| Variable                      | Default         | Meaning                                    |
|-------------------------------|-----------------|--------------------------------------------|
| SPHRAGIS_DB_PATH              | sphragis.db     | SQLite file: counter floor, history, alerts|
| SPHRAGIS_DB_URL               | (none)          | postgresql:// URL; replaces SQLite (multi-host)|
| SPHRAGIS_KEY_CONTEXT          | (empty)         | AN10922 diversification context            |
| SPHRAGIS_READER_TOKENS        | (none)          | `reader=sha256hex,...` authenticated readers|
| SPHRAGIS_TRUSTED_PROXIES      | (none)          | proxy IPs or CIDRs (or `unix`) allowed to set X-Forwarded-For |
| SPHRAGIS_IP_RATE / _IP_BURST  | 5 / 20          | per-client-IP token bucket                 |
| SPHRAGIS_UID_RATE / _UID_BURST| 0.2 / 10        | per-tag token bucket (authentic taps only) |
| SPHRAGIS_MIN_TRAVEL_SECONDS   | 60              | impossible-velocity threshold              |
| SPHRAGIS_ALERT_ON             | CLONE_LIKELY,REVOKED | classifications that raise an alert   |
| SPHRAGIS_ALERT_UID_BURST      | 5               | alerts per tag before throttling           |
| SPHRAGIS_ALERT_UID_WINDOW     | 3600            | seconds to refill a tag's alert budget     |
| SPHRAGIS_ALERT_DEDUP_SECONDS  | 300             | identical alerts for a tag within this are dropped |
| SPHRAGIS_COUNTER_WARN_AT      | 16711680        | counter that raises `counter_near_limit` (`off`) |
| SPHRAGIS_COUNTER_REFUSE_AT    | off             | counter from which taps are COUNTER_LIMIT  |
| SPHRAGIS_MAX_BODY_BYTES       | 8192            | largest accepted request body              |
| SPHRAGIS_WEBHOOK_URL          | (none)          | HMAC-signed alert webhook (https)          |
| SPHRAGIS_LOG_UID              | hmac            | `hmac` (pseudonymized) or `plain`          |
| SPHRAGIS_LOG_LEVEL            | INFO            | log level                                  |
| SPHRAGIS_KEY_PROVIDER         | secrets         | `secrets` or `pkcs11` (masters in an HSM)  |
| SPHRAGIS_PKCS11_MODULE        | (none)          | PKCS#11 library path (with pkcs11)         |
| SPHRAGIS_PKCS11_TOKEN         | (none)          | token label (with pkcs11)                  |
| SPHRAGIS_PKCS11_KEY_PREFIX    | sphragis.       | prefix of the key labels on the token      |
| SPHRAGIS_PKCS11_CACHE_SECONDS | 60              | per-UID key cache lifetime (0: off)        |
| SPHRAGIS_WEBAUTHN_RP_ID       | (none)          | relying party ID (with fido2-webauthn)     |
| SPHRAGIS_WEBAUTHN_ORIGINS     | (none)          | allowed origins, comma-separated (https)   |
| SPHRAGIS_WEBAUTHN_USER_VERIFICATION | preferred | required, preferred or discouraged       |
| SPHRAGIS_WEBAUTHN_CHALLENGE_TTL | 120           | seconds a challenge stays valid            |
| SPHRAGIS_WEBAUTHN_MAX_CHALLENGES | 100000       | outstanding challenges before 503          |

Every value is validated at startup: a typo or an out-of-range number stops
the service instead of silently disabling a limit or an alert.

Secrets (through `EnvSecretsBackend` by default: `SPHRAGIS_<NAME>` hex):
`master_file`, `meta_read` (required, unless SPHRAGIS_KEY_PROVIDER=pkcs11 keeps
them in the token); `log_pseudonym` (required when SPHRAGIS_LOG_UID=hmac);
`webhook` (required when SPHRAGIS_WEBHOOK_URL is set). The token PIN is read
from SPHRAGIS_PKCS11_PIN, or from the file named by SPHRAGIS_PKCS11_PIN_FILE,
and is never kept in the settings.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
CLASSIFICATIONS = frozenset({"GENUINE", "SUSPICIOUS", "REPLAY", "CLONE_LIKELY",
                             "FORGED", "ERROR", "THROTTLED", "REVOKED",
                             "COUNTER_LIMIT"})
MAX_READ_COUNTER = 0xFFFFFF
# Verification backends selectable with SPHRAGIS_BACKENDS, most specific first.
BACKENDS = ("fido2-webauthn", "ntag424-sun-enc", "ntag424-sun")
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


UNIX_SOCKET = "unix"
"""Trusted-proxy entry for a server listening on a Unix socket (uvicorn
`--uds`): the peer has no address, so the proxy in front must be trusted by
name for `X-Forwarded-For` to be read."""


def parse_trusted_proxies(entries: Iterable[str]) -> tuple:
    """Proxy addresses or CIDR networks, or `unix`; anything else is a
    configuration error."""
    out = []
    for entry in entries:
        if entry.strip().lower() == UNIX_SOCKET:
            out.append(UNIX_SOCKET)
            continue
        try:
            out.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid trusted proxy {entry!r}") from exc
    return tuple(out)


def _positive(name: str, raw: str, kind=float):
    try:
        value = kind(raw)
    except ValueError:
        raise ValueError(f"SPHRAGIS_{name} must be a number, got {raw!r}") from None
    if not (math.isfinite(value) and value > 0):
        raise ValueError(f"SPHRAGIS_{name} must be finite and > 0, got {raw!r}")
    return value


def parse_reader_tokens(raw: str) -> dict[str, str]:
    """
    Parse `reader-id=sha256hex,...` into {sha256hex: reader-id}.

    Only the SHA-256 of each token is configured, so a leaked config does not
    leak usable credentials. Generate one with:
    `python -c "import secrets,hashlib;t=secrets.token_urlsafe(32);print(t, hashlib.sha256(t.encode()).hexdigest())"`
    """
    out: dict[str, str] = {}
    for item in filter(None, (p.strip() for p in raw.split(","))):
        reader, sep, digest = item.partition("=")
        reader, digest = reader.strip(), digest.strip().lower()
        if not sep or not reader or not _HEX64.match(digest):
            raise ValueError(f"invalid reader token entry: {reader or item!r}")
        if digest in out:
            raise ValueError(f"duplicate reader token for {reader!r}")
        out[digest] = reader
    return out


@dataclass(frozen=True)
class ApiSettings:
    db_path: str = "sphragis.db"
    db_url: str | None = field(default=None, repr=False)   # may embed a password
    key_context: bytes = b""
    reader_tokens: Mapping[str, str] = field(default_factory=dict)
    trusted_proxies: frozenset[str] = frozenset()
    ip_rate: float = 5.0
    ip_burst: int = 20
    uid_rate: float = 0.2
    uid_burst: int = 10
    min_travel_seconds: float = 60.0
    alert_on: frozenset[str] = frozenset({"CLONE_LIKELY", "REVOKED"})
    max_body_bytes: int = 8192
    webhook_url: str | None = None
    log_uid: str = "hmac"
    log_level: str = "INFO"
    backends: tuple[str, ...] = ("ntag424-sun",)
    key_versions: tuple[int, ...] = (1,)
    events_file: str | None = None
    events_on: frozenset[str] | None = None        # None: every verification
    event_key_version: int = 1
    rate_limit_store: str = "memory"                # or "db": shared by every replica
    ipv6_prefix: int = 64
    ledger_window: int | None = None                # None: keep every counter
    event_log_id: str | None = None                 # set: chained events (schema 2)
    key_provider: str = "secrets"                   # or "pkcs11"
    pkcs11_module: str | None = None
    pkcs11_token: str | None = None
    pkcs11_key_prefix: str = "sphragis."
    pkcs11_cache_seconds: float = 60.0
    webauthn_rp_id: str | None = None
    webauthn_origins: tuple[str, ...] = ()
    webauthn_user_verification: str = "preferred"
    webauthn_challenge_ttl: float = 120.0
    webauthn_max_challenges: int = 100_000
    alert_uid_burst: int = 5
    alert_uid_window: float = 3600.0
    alert_dedup_seconds: float = 300.0
    counter_warn_at: int | None = MAX_READ_COUNTER - 0xFFFF
    counter_refuse_at: int | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ApiSettings":
        e = os.environ if env is None else env

        def get(name: str, default: str) -> str:
            return e.get("SPHRAGIS_" + name, default).strip()

        def csv(name: str, default: str = "") -> list[str]:
            return [p.strip() for p in get(name, default).split(",") if p.strip()]

        db_url = get("DB_URL", "") or None
        if db_url and not db_url.startswith(("postgresql://", "postgres://")):
            raise ValueError("SPHRAGIS_DB_URL must be a postgresql:// URL")
        log_uid = get("LOG_UID", "hmac").lower()
        if log_uid not in ("hmac", "plain"):
            raise ValueError("SPHRAGIS_LOG_UID must be 'hmac' or 'plain'")
        alert_on = frozenset(c.upper() for c in csv("ALERT_ON", "CLONE_LIKELY,REVOKED"))
        unknown = alert_on - CLASSIFICATIONS
        if not alert_on or unknown:
            raise ValueError("SPHRAGIS_ALERT_ON must list classifications among "
                             + ", ".join(sorted(CLASSIFICATIONS))
                             + (f" (unknown: {', '.join(sorted(unknown))})" if unknown else ""))
        key_context = get("KEY_CONTEXT", "").encode()
        if len(key_context) > 23:
            # UID (7) + slot (1) + context must fit AN10922's 31 bytes.
            raise ValueError("SPHRAGIS_KEY_CONTEXT must be at most 23 bytes")
        log_level = get("LOG_LEVEL", "INFO").upper()
        if log_level not in _LOG_LEVELS:
            raise ValueError(f"SPHRAGIS_LOG_LEVEL must be one of {', '.join(sorted(_LOG_LEVELS))}")
        backends = tuple(dict.fromkeys(b.lower() for b in csv("BACKENDS", "ntag424-sun")))
        unknown_backends = [b for b in backends if b not in BACKENDS]
        if not backends or unknown_backends:
            raise ValueError("SPHRAGIS_BACKENDS must list backends among "
                             + ", ".join(BACKENDS)
                             + (f" (unknown: {', '.join(unknown_backends)})"
                                if unknown_backends else ""))
        # Most specific first, whatever order they were listed in.
        backends = tuple(b for b in BACKENDS if b in backends)
        try:
            key_versions = tuple(int(v) for v in csv("KEY_VERSIONS", "1"))
        except ValueError:
            key_versions = ()
        if (not key_versions or min(key_versions) < 1
                or len(set(key_versions)) != len(key_versions)):
            raise ValueError("SPHRAGIS_KEY_VERSIONS must list distinct key versions "
                             ">= 1, current first (e.g. 2,1)")
        events_on_raw = csv("EVENTS_ON")
        events_on = frozenset(c.upper() for c in events_on_raw) or None
        if events_on is not None and events_on - CLASSIFICATIONS:
            raise ValueError("SPHRAGIS_EVENTS_ON must list classifications among "
                             + ", ".join(sorted(CLASSIFICATIONS)))
        try:
            event_key_version = int(get("EVENT_KEY_VERSION", "1"))
        except ValueError:
            event_key_version = 0
        if event_key_version < 1:
            raise ValueError("SPHRAGIS_EVENT_KEY_VERSION must be a key version >= 1")
        rate_limit_store = get("RATE_LIMIT_STORE", "memory").lower()
        if rate_limit_store not in ("memory", "db"):
            raise ValueError("SPHRAGIS_RATE_LIMIT_STORE must be 'memory' or 'db'")
        try:
            ipv6_prefix = int(get("IPV6_PREFIX", "64"))
        except ValueError:
            ipv6_prefix = 0
        if not 16 <= ipv6_prefix <= 128:
            raise ValueError("SPHRAGIS_IPV6_PREFIX must be between 16 and 128")
        raw_window = get("LEDGER_WINDOW", "")
        ledger_window = None
        if raw_window:
            try:
                ledger_window = int(raw_window)
            except ValueError:
                ledger_window = 0
            if ledger_window < 1:
                raise ValueError("SPHRAGIS_LEDGER_WINDOW must be a positive number of "
                                 "counter values")
        key_provider = get("KEY_PROVIDER", "secrets").lower()
        if key_provider not in ("secrets", "pkcs11"):
            raise ValueError("SPHRAGIS_KEY_PROVIDER must be 'secrets' or 'pkcs11'")
        pkcs11_module = get("PKCS11_MODULE", "") or None
        pkcs11_token = get("PKCS11_TOKEN", "") or None
        if key_provider == "pkcs11" and not (pkcs11_module and pkcs11_token):
            raise ValueError("SPHRAGIS_KEY_PROVIDER=pkcs11 needs SPHRAGIS_PKCS11_MODULE "
                             "and SPHRAGIS_PKCS11_TOKEN")
        try:
            pkcs11_cache = float(get("PKCS11_CACHE_SECONDS", "60"))
        except ValueError:
            pkcs11_cache = -1.0
        if not 0 <= pkcs11_cache < math.inf:
            raise ValueError("SPHRAGIS_PKCS11_CACHE_SECONDS must be a number of "
                             "seconds >= 0")
        webauthn_rp_id = get("WEBAUTHN_RP_ID", "").lower() or None
        webauthn_origins = tuple(csv("WEBAUTHN_ORIGINS"))
        webauthn_uv = get("WEBAUTHN_USER_VERIFICATION", "preferred").lower()
        if webauthn_uv not in ("required", "preferred", "discouraged"):
            raise ValueError("SPHRAGIS_WEBAUTHN_USER_VERIFICATION must be required, "
                             "preferred or discouraged")
        if "fido2-webauthn" in backends:
            if not webauthn_rp_id or not webauthn_origins:
                raise ValueError("fido2-webauthn needs SPHRAGIS_WEBAUTHN_RP_ID and "
                                 "SPHRAGIS_WEBAUTHN_ORIGINS")
            from ..webauthn import check_rp_id
            try:
                check_rp_id(webauthn_rp_id, webauthn_origins)
            except ValueError as exc:
                raise ValueError(f"SPHRAGIS_WEBAUTHN_ORIGINS: {exc}") from None
        def counter(name: str, default: str) -> int | None:
            raw = get(name, default).lower()
            if raw == "off":
                return None
            try:
                value = int(raw, 0)
            except ValueError:
                value = 0
            if not 1 <= value <= MAX_READ_COUNTER:
                raise ValueError(f"SPHRAGIS_{name} must be a counter between 1 and "
                                 f"{MAX_READ_COUNTER}, or 'off'")
            return value

        counter_warn_at = counter("COUNTER_WARN_AT", str(MAX_READ_COUNTER - 0xFFFF))
        counter_refuse_at = counter("COUNTER_REFUSE_AT", "off")
        if (counter_warn_at is not None and counter_refuse_at is not None
                and counter_warn_at >= counter_refuse_at):
            raise ValueError("SPHRAGIS_COUNTER_WARN_AT must be below "
                             "SPHRAGIS_COUNTER_REFUSE_AT")
        dedup_raw = get("ALERT_DEDUP_SECONDS", "300")
        try:
            alert_dedup_seconds = float(dedup_raw)
        except ValueError:
            alert_dedup_seconds = -1.0
        if not 0 <= alert_dedup_seconds < math.inf:
            raise ValueError("SPHRAGIS_ALERT_DEDUP_SECONDS must be a number of "
                             "seconds >= 0")
        proxies = csv("TRUSTED_PROXIES")
        try:
            parse_trusted_proxies(proxies)
        except ValueError as exc:
            raise ValueError(f"SPHRAGIS_TRUSTED_PROXIES: {exc}") from None
        return cls(
            db_path=get("DB_PATH", "sphragis.db"),
            db_url=db_url,
            key_context=key_context,
            reader_tokens=parse_reader_tokens(get("READER_TOKENS", "")),
            trusted_proxies=frozenset(proxies),
            ip_rate=_positive("IP_RATE", get("IP_RATE", "5")),
            ip_burst=_positive("IP_BURST", get("IP_BURST", "20"), int),
            uid_rate=_positive("UID_RATE", get("UID_RATE", "0.2")),
            uid_burst=_positive("UID_BURST", get("UID_BURST", "10"), int),
            min_travel_seconds=_positive("MIN_TRAVEL_SECONDS",
                                         get("MIN_TRAVEL_SECONDS", "60")),
            alert_on=alert_on,
            max_body_bytes=_positive("MAX_BODY_BYTES", get("MAX_BODY_BYTES", "8192"), int),
            webhook_url=get("WEBHOOK_URL", "") or None,
            log_uid=log_uid,
            log_level=log_level,
            backends=backends,
            key_versions=key_versions,
            events_file=get("EVENTS_FILE", "") or None,
            events_on=events_on,
            event_key_version=event_key_version,
            rate_limit_store=rate_limit_store,
            ipv6_prefix=ipv6_prefix,
            ledger_window=ledger_window,
            event_log_id=get("EVENT_LOG_ID", "") or None,
            key_provider=key_provider,
            pkcs11_module=pkcs11_module,
            pkcs11_token=pkcs11_token,
            pkcs11_key_prefix=get("PKCS11_KEY_PREFIX", "sphragis."),
            pkcs11_cache_seconds=pkcs11_cache,
            webauthn_rp_id=webauthn_rp_id,
            webauthn_origins=webauthn_origins,
            webauthn_user_verification=webauthn_uv,
            webauthn_challenge_ttl=_positive("WEBAUTHN_CHALLENGE_TTL",
                                             get("WEBAUTHN_CHALLENGE_TTL", "120")),
            webauthn_max_challenges=_positive("WEBAUTHN_MAX_CHALLENGES",
                                              get("WEBAUTHN_MAX_CHALLENGES", "100000"), int),
            alert_uid_burst=_positive("ALERT_UID_BURST", get("ALERT_UID_BURST", "5"), int),
            alert_uid_window=_positive("ALERT_UID_WINDOW", get("ALERT_UID_WINDOW", "3600")),
            alert_dedup_seconds=alert_dedup_seconds,
            counter_warn_at=counter_warn_at,
            counter_refuse_at=counter_refuse_at,
        )
