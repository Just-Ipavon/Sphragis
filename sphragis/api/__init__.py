"""
REST verification API (optional extra: `pip install "sphragis[api]"`).

    uvicorn --factory sphragis.api:create_app_from_env

See docs/api.md.
"""

from __future__ import annotations

import logging
from typing import Mapping

from ..alerts import AlertSink, LogAlertSink, SqliteAlertSink, WebhookAlertSink
from ..analyzer import TagAnalyzer
from ..detection import CloneDetector
from ..logs import UidPseudonymizer, configure_logging
from ..observations import SqliteObservationStore
from ..ratelimit import TokenBucketLimiter
from ..secrets import EnvSecretsBackend, SecretsBackend, build_diversified_keys
from ..service import VerificationService
from ..sqlstore import SqliteCounterStore
from .app import create_app
from .settings import ApiSettings, parse_reader_tokens

__all__ = ["create_app", "create_app_from_env", "ApiSettings", "parse_reader_tokens"]


def create_app_from_env(env: Mapping[str, str] | None = None,
                        secrets: SecretsBackend | None = None):
    """Assemble the production stack from `SPHRAGIS_*` settings and secrets."""
    settings = ApiSettings.from_env(env)
    secrets = secrets or EnvSecretsBackend()
    configure_logging(getattr(logging, settings.log_level, logging.INFO))

    keys = build_diversified_keys(secrets, context=settings.key_context)
    detector = CloneDetector(
        min_travel_seconds=settings.min_travel_seconds,
        store=SqliteObservationStore(settings.db_path),
    )
    analyzer = TagAnalyzer(keys, detector=detector,
                           store=SqliteCounterStore(settings.db_path))

    sinks: list[AlertSink] = [LogAlertSink(), SqliteAlertSink(settings.db_path)]
    if settings.webhook_url:
        sinks.append(WebhookAlertSink(settings.webhook_url, secrets.get_key("webhook")))

    pseudo = UidPseudonymizer(
        None if settings.log_uid == "plain" else secrets.get_key("log_pseudonym")
    )
    service = VerificationService(
        analyzer,
        alert_sinks=sinks,
        pseudonymizer=pseudo,
        alert_on=settings.alert_on,
        uid_limiter=TokenBucketLimiter(settings.uid_rate, settings.uid_burst),
    )
    return create_app(
        service,
        ip_limiter=TokenBucketLimiter(settings.ip_rate, settings.ip_burst),
        reader_tokens=settings.reader_tokens,
        trusted_proxies=settings.trusted_proxies,
        throttle_retry_after=1.0 / settings.uid_rate,
    )
