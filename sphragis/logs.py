"""
Structured logging: one JSON object per line, stdlib only.

Every verification emits a single machine-readable event that a log pipeline
(Loki, ELK, Datadog, CloudWatch, ...) can index and alert on. Structured fields
are passed through `extra={"fields": {...}}` and merged into the JSON object.

Privacy: a tag UID identifies a physical object — and often, indirectly, its
owner. `UidPseudonymizer` replaces it with a keyed HMAC reference by default, so
logs and alerts can be correlated per tag without storing the raw identifier.
An operator who holds the pseudonymization key can recompute the reference of a
known UID to search for it. Raw `picc_data` / `cmac` values are never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

_RESERVED = {"ts", "level", "logger", "event"}


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc)
                          .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            for key, value in fields.items():
                payload[key if key not in _RESERVED else f"field_{key}"] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), default=str)


def configure_logging(level: int | str = logging.INFO,
                      logger_name: str = "sphragis") -> logging.Logger:
    """Attach a JSON stdout handler to the `sphragis` logger (idempotent)."""
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    if not any(getattr(h, "_sphragis_json", False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler._sphragis_json = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.propagate = False
    return logger


class UidPseudonymizer:
    """
    Maps a UID to the reference used in logs and alerts.

    With a key: `"h:" + HMAC-SHA256(key, UID)[:16 bytes]` (stable, not
    reversible without the key). Without a key: the UID itself, upper-case —
    an explicit opt-in for deployments where the UID is not sensitive.
    """

    def __init__(self, key: bytes | None) -> None:
        if key is not None and len(key) < 16:
            raise ValueError("pseudonymization key must be at least 16 bytes")
        self._key = key

    @property
    def is_plain(self) -> bool:
        return self._key is None

    def ref(self, uid_hex: str | None) -> str | None:
        if uid_hex is None:
            return None
        uid_hex = uid_hex.upper()
        if self._key is None:
            return uid_hex
        digest = hmac.new(self._key, uid_hex.encode(), hashlib.sha256).hexdigest()
        return "h:" + digest[:32]
