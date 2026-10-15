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
| SPHRAGIS_TRUSTED_PROXIES      | (none)          | proxy IPs or CIDRs allowed to set X-Forwarded-For |
| SPHRAGIS_IP_RATE / _IP_BURST  | 5 / 20          | per-client-IP token bucket                 |
| SPHRAGIS_UID_RATE / _UID_BURST| 0.2 / 10        | per-tag token bucket (authentic taps only) |
| SPHRAGIS_MIN_TRAVEL_SECONDS   | 60              | impossible-velocity threshold              |
| SPHRAGIS_ALERT_ON             | CLONE_LIKELY    | classifications that raise an alert        |
| SPHRAGIS_MAX_BODY_BYTES       | 8192            | largest accepted request body              |
| SPHRAGIS_WEBHOOK_URL          | (none)          | HMAC-signed alert webhook (https)          |
| SPHRAGIS_LOG_UID              | hmac            | `hmac` (pseudonymized) or `plain`          |
| SPHRAGIS_LOG_LEVEL            | INFO            | log level                                  |

Every value is validated at startup: a typo or an out-of-range number stops
the service instead of silently disabling a limit or an alert.

Secrets (through `EnvSecretsBackend` by default: `SPHRAGIS_<NAME>` hex):
`master_file`, `meta_read` (required); `log_pseudonym` (required when
SPHRAGIS_LOG_UID=hmac); `webhook` (required when SPHRAGIS_WEBHOOK_URL is set).
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
                             "FORGED", "ERROR", "THROTTLED"})
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def parse_trusted_proxies(entries: Iterable[str]) -> tuple:
    """Proxy addresses or CIDR networks; anything else is a configuration error."""
    out = []
    for entry in entries:
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
    alert_on: frozenset[str] = frozenset({"CLONE_LIKELY"})
    max_body_bytes: int = 8192
    webhook_url: str | None = None
    log_uid: str = "hmac"
    log_level: str = "INFO"

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
        alert_on = frozenset(c.upper() for c in csv("ALERT_ON", "CLONE_LIKELY"))
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
        )
