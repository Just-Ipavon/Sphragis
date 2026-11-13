"""
REST verification API (optional extra: `pip install "sphragis[api]"`).

    uvicorn --factory sphragis.api:create_app_from_env

See docs/api.md.
"""

from __future__ import annotations

import logging
from typing import Mapping

from ..alerts import (
    AlertSink,
    BackgroundAlertSink,
    LogAlertSink,
    SqliteAlertSink,
    WebhookAlertSink,
)
from ..analyzer import TagAnalyzer
from ..backends import VerificationBackend
from ..detection import CloneDetector
from ..encverifier import Ntag424EncBackend
from ..events import EventChain, EventSigner, FileEventSink, read_event_file
from ..keyring import build_keyring
from ..logs import UidPseudonymizer, configure_logging
from ..observations import SqliteObservationStore
from ..ratelimit import TokenBucketLimiter
from ..secrets import EnvSecretsBackend, SecretsBackend
from ..service import VerificationService
from ..sqlstore import SqliteCounterStore
from ..verifier import Ntag424SunBackend
from .app import create_app
from .settings import ApiSettings, parse_reader_tokens

__all__ = ["create_app", "create_app_from_env", "ApiSettings", "parse_reader_tokens"]


def create_app_from_env(env: Mapping[str, str] | None = None,
                        secrets: SecretsBackend | None = None):
    """Assemble the production stack from `SPHRAGIS_*` settings and secrets."""
    settings = ApiSettings.from_env(env)
    secrets = secrets or EnvSecretsBackend()
    configure_logging(getattr(logging, settings.log_level, logging.INFO))

    keys = build_keyring(secrets, settings.key_versions, context=settings.key_context)
    if settings.db_url:
        # One shared database for every replica, on any number of hosts.
        from ..pgstore import PostgresAlertSink, PostgresCounterStore, PostgresObservationStore
        history, floor = (PostgresObservationStore(settings.db_url),
                          PostgresCounterStore(settings.db_url, settings.ledger_window))
        audit: AlertSink = PostgresAlertSink(settings.db_url)
    else:
        history, floor = (SqliteObservationStore(settings.db_path),
                          SqliteCounterStore(settings.db_path, settings.ledger_window))
        audit = SqliteAlertSink(settings.db_path)
    detector = CloneDetector(min_travel_seconds=settings.min_travel_seconds, store=history)
    factories = {"ntag424-sun-enc": Ntag424EncBackend, "ntag424-sun": Ntag424SunBackend}
    backends: list[VerificationBackend] = [factories[n](keys) for n in settings.backends]
    analyzer = TagAnalyzer(backends=backends, detector=detector, store=floor)

    sinks: list[AlertSink] = [LogAlertSink(), audit]
    background = None
    if settings.webhook_url:
        # Off the request path: a slow incident endpoint never delays a tap.
        background = BackgroundAlertSink(
            WebhookAlertSink(settings.webhook_url, secrets.get_key("webhook")))
        sinks.append(background)

    pseudo = UidPseudonymizer(
        None if settings.log_uid == "plain" else secrets.get_key("log_pseudonym")
    )
    signer = sinks_for_events = None
    chain = None
    if settings.events_file:
        signer = EventSigner(secrets, version=settings.event_key_version)
        sinks_for_events = [FileEventSink(settings.events_file)]
        if settings.event_log_id:
            # Continue the chain the file already holds (one log per replica).
            chain = EventChain.resume(settings.event_log_id,
                                      read_event_file(settings.events_file))
    service = VerificationService(
        analyzer,
        alert_sinks=sinks,
        pseudonymizer=pseudo,
        alert_on=settings.alert_on,
        uid_limiter=_limiter(settings, settings.uid_rate, settings.uid_burst),
        event_signer=signer,
        event_sinks=sinks_for_events or (),
        events_on=settings.events_on,
        event_chain=chain,
    )
    return create_app(
        service,
        ip_limiter=_limiter(settings, settings.ip_rate, settings.ip_burst),
        ipv6_prefix=settings.ipv6_prefix,
        reader_tokens=settings.reader_tokens,
        trusted_proxies=settings.trusted_proxies,
        throttle_retry_after=1.0 / settings.uid_rate,
        max_body_bytes=settings.max_body_bytes,
        event_signer=signer,
        ready_checks=_ready_checks(floor, history, background),
        # Deliver queued webhook alerts first, then close the stores they
        # and the requests in flight were using.
        on_shutdown=[*([lambda: background.close(SHUTDOWN_DRAIN_SECONDS)]
                       if background is not None else []),
                     floor.close, history.close, audit.close],
    )


def _limiter(settings: ApiSettings, rate: float, burst: int):
    """In-process buckets, or buckets in the database every replica shares."""
    if settings.rate_limit_store != "db":
        return TokenBucketLimiter(rate, burst)
    if settings.db_url:
        from ..pgstore import PostgresRateLimiter
        return PostgresRateLimiter(settings.db_url, rate, burst)
    from ..sqlstore import SqliteRateLimiter
    return SqliteRateLimiter(settings.db_path, rate, burst)


SHUTDOWN_DRAIN_SECONDS = 10.0
"""How long shutdown waits for queued webhook alerts (the audit store keeps
every alert regardless)."""


def _ready_checks(floor, history, background) -> dict:
    checks = {
        # A read on each store: the database is reachable and the schema there.
        "counters": lambda: floor.last_counter("00") or True,
        "history": lambda: history.history("00") is not None,
    }
    if background is not None:
        checks["alert_queue"] = lambda: background.pending < background.capacity * 0.9
    return checks
