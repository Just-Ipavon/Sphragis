"""
API configuration, loaded from `SPHRAGIS_*` environment variables.

Key material (SDM keys, pseudonymization key, webhook secret) is read through a
`SecretsBackend`, never from these settings directly.

| Variable                      | Default         | Meaning                                    |
|-------------------------------|-----------------|--------------------------------------------|
| SPHRAGIS_DB_PATH              | sphragis.db     | SQLite file: counter floor, history, alerts|
| SPHRAGIS_KEY_CONTEXT          | (empty)         | AN10922 diversification context            |
| SPHRAGIS_READER_TOKENS        | (none)          | `reader=sha256hex,...` authenticated readers|
| SPHRAGIS_TRUSTED_PROXIES      | (none)          | proxy IPs allowed to set X-Forwarded-For   |
| SPHRAGIS_IP_RATE / _IP_BURST  | 5 / 20          | per-client-IP token bucket                 |
| SPHRAGIS_UID_RATE / _UID_BURST| 0.2 / 10        | per-tag token bucket (authentic taps only) |
| SPHRAGIS_MIN_TRAVEL_SECONDS   | 60              | impossible-velocity threshold              |
| SPHRAGIS_ALERT_ON             | CLONE_LIKELY    | classifications that raise an alert        |
| SPHRAGIS_WEBHOOK_URL          | (none)          | HMAC-signed alert webhook (https)          |
| SPHRAGIS_LOG_UID              | hmac            | `hmac` (pseudonymized) or `plain`          |
| SPHRAGIS_LOG_LEVEL            | INFO            | log level                                  |

Secrets (through `EnvSecretsBackend` by default: `SPHRAGIS_<NAME>` hex):
`master_file`, `meta_read` (required); `log_pseudonym` (required when
SPHRAGIS_LOG_UID=hmac); `webhook` (required when SPHRAGIS_WEBHOOK_URL is set).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Mapping

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


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
    key_context: bytes = b""
    reader_tokens: Mapping[str, str] = field(default_factory=dict)
    trusted_proxies: frozenset[str] = frozenset()
    ip_rate: float = 5.0
    ip_burst: int = 20
    uid_rate: float = 0.2
    uid_burst: int = 10
    min_travel_seconds: float = 60.0
    alert_on: frozenset[str] = frozenset({"CLONE_LIKELY"})
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

        log_uid = get("LOG_UID", "hmac").lower()
        if log_uid not in ("hmac", "plain"):
            raise ValueError("SPHRAGIS_LOG_UID must be 'hmac' or 'plain'")
        return cls(
            db_path=get("DB_PATH", "sphragis.db"),
            key_context=get("KEY_CONTEXT", "").encode(),
            reader_tokens=parse_reader_tokens(get("READER_TOKENS", "")),
            trusted_proxies=frozenset(csv("TRUSTED_PROXIES")),
            ip_rate=float(get("IP_RATE", "5")),
            ip_burst=int(get("IP_BURST", "20")),
            uid_rate=float(get("UID_RATE", "0.2")),
            uid_burst=int(get("UID_BURST", "10")),
            min_travel_seconds=float(get("MIN_TRAVEL_SECONDS", "60")),
            alert_on=frozenset(c.upper() for c in csv("ALERT_ON", "CLONE_LIKELY")),
            webhook_url=get("WEBHOOK_URL", "") or None,
            log_uid=log_uid,
            log_level=get("LOG_LEVEL", "INFO").upper(),
        )
