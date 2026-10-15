"""
VerificationService — the framework-agnostic core behind the REST API.

It wraps a `TagAnalyzer` with what a deployed verifier needs around the crypto:

- **server-side time**: the timestamp fed to the clone detector always comes
  from the service clock, never from the client (a client-supplied time would
  let an attacker defeat or fake the impossible-velocity check);
- **per-UID admission** (optional rate limit) applied after the SDMMAC is
  verified, through the analyzer's `admit` hook;
- **one structured log event per verification**, with a pseudonymized UID;
- **alert dispatch** for the classifications that warrant it (`CLONE_LIKELY`
  by default).

`reader_id` is taken as given: deciding *who* the reader is (e.g. from an
authenticated API key) is the caller's job — see `sphragis.api`.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable

from .alerts import Alert, AlertSink, dispatch
from .analyzer import AnalysisResult, TagAnalyzer
from .logs import UidPseudonymizer
from .ratelimit import RateLimiter

_log = logging.getLogger("sphragis.verify")

DEFAULT_ALERT_ON = frozenset({"CLONE_LIKELY"})
# A genuine SUN URL is a couple of hundred characters; anything far larger is
# rejected before parsing.
MAX_INPUT_LENGTH = 4096


@dataclass(frozen=True)
class VerificationOutcome:
    event_id: str
    timestamp: float
    result: AnalysisResult
    uid_ref: str | None
    reader_id: str | None
    alerted: bool


class VerificationService:
    def __init__(
        self,
        analyzer: TagAnalyzer,
        alert_sinks: Iterable[AlertSink] = (),
        pseudonymizer: UidPseudonymizer | None = None,
        alert_on: Iterable[str] = DEFAULT_ALERT_ON,
        uid_limiter: RateLimiter | None = None,
        clock: Callable[[], float] = time.time,
        logger: logging.Logger | None = None,
    ) -> None:
        self._analyzer = analyzer
        self._sinks = tuple(alert_sinks)
        # Pseudonymize by default: a random per-process key keeps raw UIDs out
        # of the logs even when no key was configured (references are then only
        # stable for the lifetime of the process).
        self._pseudo = pseudonymizer or UidPseudonymizer(uuid.uuid4().bytes)
        self._alert_on = frozenset(alert_on)
        self._uid_limiter = uid_limiter
        self._clock = clock
        self._log = logger or _log

    def _admit(self, uid_hex: str) -> bool:
        assert self._uid_limiter is not None
        return self._uid_limiter.check("uid:" + uid_hex).allowed

    def verify(self, url_or_query: str, reader_id: str | None = None) -> VerificationOutcome:
        event_id = uuid.uuid4().hex
        now = self._clock()
        if len(url_or_query) > MAX_INPUT_LENGTH:
            result = AnalysisResult("ERROR", False, None, None, 0, (),
                                    "input too long")
        else:
            try:
                result = self._analyzer.analyze(
                    url_or_query,
                    timestamp=now,
                    reader_id=reader_id,
                    admit=self._admit if self._uid_limiter is not None else None,
                )
            except Exception as exc:
                # Storage or key backend failure: fail closed (the caller gets
                # an error), but never without a trace. The input is not logged.
                self._log.error("verification_failed", extra={"fields": {
                    "event_id": event_id, "reader_id": reader_id,
                    "error": type(exc).__name__}})
                raise
        uid_ref = self._pseudo.ref(result.uid)
        signal_names = tuple(s.name for s in result.signals)

        alerted = False
        if result.classification in self._alert_on:
            alert = Alert(
                event_id=event_id, timestamp=now,
                classification=result.classification,
                risk_score=result.risk_score, uid_ref=uid_ref,
                read_counter=result.read_counter, reader_id=reader_id,
                signals=signal_names, detail=result.detail,
            )
            alerted = dispatch(alert, self._sinks) > 0

        level = logging.WARNING if result.classification != "GENUINE" else logging.INFO
        self._log.log(level, "verification", extra={"fields": {
            "event_id": event_id,
            "classification": result.classification,
            "risk_score": result.risk_score,
            "signals": list(signal_names),
            "uid_ref": uid_ref,
            "read_counter": result.read_counter,
            "reader_id": reader_id,
            "alerted": alerted,
        }})
        return VerificationOutcome(event_id, now, result, uid_ref, reader_id, alerted)
