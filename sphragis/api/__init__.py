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
    AlertThrottle,
    BackgroundAlertSink,
    LogAlertSink,
    SqliteAlertSink,
    WebhookAlertSink,
)
from ..analyzer import CounterPolicy, TagAnalyzer
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
from ..sqlstore import SqliteCounterStore, SqliteRevocationList
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
        from ..pgstore import (
            PostgresAlertSink,
            PostgresCounterStore,
            PostgresObservationStore,
            PostgresRevocationList,
        )
        history, floor = (PostgresObservationStore(settings.db_url),
                          PostgresCounterStore(settings.db_url, settings.ledger_window))
        audit: AlertSink = PostgresAlertSink(settings.db_url)
        revocations = PostgresRevocationList(settings.db_url)
    else:
        history, floor = (SqliteObservationStore(settings.db_path),
                          SqliteCounterStore(settings.db_path, settings.ledger_window))
        audit = SqliteAlertSink(settings.db_path)
        revocations = SqliteRevocationList(settings.db_path)
    detector = CloneDetector(min_travel_seconds=settings.min_travel_seconds, store=history)
    factories = {"ntag424-sun-enc": Ntag424EncBackend, "ntag424-sun": Ntag424SunBackend}
    backends: list[VerificationBackend] = [factories[n](keys) for n in settings.backends
                                           if n in factories]
    issuer = None
    webauthn_stores: list = []
    if "fido2-webauthn" in settings.backends:
        webauthn_backend, issuer, webauthn_stores = _webauthn(settings)
        backends.insert(0, webauthn_backend)
    analyzer = TagAnalyzer(backends=backends, detector=detector, store=floor,
                           revocations=revocations,
                           counter_policy=CounterPolicy(settings.counter_warn_at,
                                                        settings.counter_refuse_at))

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
        alert_throttle=AlertThrottle(settings.alert_uid_burst, settings.alert_uid_window,
                                     settings.alert_dedup_seconds),
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
        challenge_issuer=issuer,
        ready_checks=_ready_checks(floor, history, revocations, background),
        # Deliver queued webhook alerts first, then close the stores they
        # and the requests in flight were using.
        on_shutdown=[*([lambda: background.close(SHUTDOWN_DRAIN_SECONDS)]
                       if background is not None else []),
                     floor.close, history.close, audit.close, revocations.close,
                     *(store.close for store in webauthn_stores)],
    )


def _webauthn(settings: ApiSettings):
    """The WebAuthn backend, its challenge issuer and the stores to close: the
    credential registry and the challenges live in the shared database, so a
    challenge one replica issues is consumed by whichever replica verifies."""
    from ..webauthn import ChallengeIssuer, WebAuthnBackend
    ttl, cap = settings.webauthn_challenge_ttl, settings.webauthn_max_challenges
    if settings.db_url:
        from ..pgstore import PostgresChallengeStore, PostgresCredentialStore
        creds = PostgresCredentialStore(settings.db_url)
        challenges = PostgresChallengeStore(settings.db_url, ttl, max_outstanding=cap)
    else:
        from ..sqlstore import SqliteChallengeStore, SqliteCredentialStore
        creds = SqliteCredentialStore(settings.db_path)
        challenges = SqliteChallengeStore(settings.db_path, ttl, max_outstanding=cap)
    uv = settings.webauthn_user_verification
    backend = WebAuthnBackend(settings.webauthn_rp_id, settings.webauthn_origins,
                              creds, challenges, require_user_verification=uv == "required")
    issuer = ChallengeIssuer(challenges, settings.webauthn_rp_id, ttl, uv)
    return backend, issuer, [creds, challenges]


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


def _ready_checks(floor, history, revocations, background) -> dict:
    checks = {
        # A read on each store: the database is reachable and the schema there.
        "counters": lambda: floor.last_counter("00") or True,
        "history": lambda: history.history("00") is not None,
        "revocations": lambda: revocations.get("00") or True,
    }
    if background is not None:
        checks["alert_queue"] = lambda: background.pending < background.capacity * 0.9
    return checks
