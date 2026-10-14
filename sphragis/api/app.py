"""
FastAPI application: the HTTP face of `VerificationService`.

Endpoints
---------
GET  /t?picc_data=..&cmac=..   the URL a tag points to: a phone opens it on tap
POST /v1/verify {"url": ...}   an app or backend forwards a tapped URL
GET  /healthz                  liveness probe (not rate limited)

Two response tiers
------------------
*Public* (no credentials): verdict, score, a human message and the event id.
Malformed and forged inputs both map to the same `INVALID` answer, and no UID,
counter or signal detail is returned — the endpoint must not become an oracle
that helps an attacker iterate on a clone.

*Detailed* (`Authorization: Bearer <reader token>`): the full assessment. The
`reader_id` fed to the clone detector is derived **only** from the token; it is
never accepted from the request, so an unauthenticated client can neither fake
nor dodge the impossible-velocity check.

Run it:  uvicorn --factory sphragis.api:create_app_from_env
"""

from __future__ import annotations

import hashlib
import math
from typing import Mapping

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..ratelimit import RateLimiter
from ..service import VerificationOutcome, VerificationService

PUBLIC_MESSAGES = {
    "GENUINE": "Authentic tag.",
    "SUSPICIOUS": "Authentic tag; unusual activity was observed.",
    "REPLAY": "This verification link was already used. Tap the tag again.",
    "CLONE_LIKELY": "Warning: this tag shows signs of duplication.",
    "INVALID": "This link could not be verified.",
}

_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=4096)


class RateLimited(Exception):
    def __init__(self, retry_after: float) -> None:
        self.retry_after = max(1, math.ceil(retry_after))


def client_ip(request: Request, trusted_proxies: frozenset[str]) -> str:
    """
    The client address used for rate limiting. `X-Forwarded-For` is honoured
    only when the direct peer is a configured trusted proxy; the client is then
    the right-most hop that is not itself a trusted proxy (left-most entries are
    client-controlled and trivially spoofed).
    """
    peer = request.client.host if request.client else "unknown"
    if peer not in trusted_proxies:
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",")]
    for hop in reversed([h for h in hops if h]):
        if hop not in trusted_proxies:
            return hop
    return peer


def _public_body(outcome: VerificationOutcome) -> dict:
    cls = outcome.result.classification
    if cls in ("ERROR", "FORGED"):
        verdict, score = "INVALID", 100
    else:
        verdict, score = cls, outcome.result.risk_score
    return {
        "event_id": outcome.event_id,
        "verdict": verdict,
        "risk_score": score,
        "message": PUBLIC_MESSAGES[verdict],
    }


def _detailed_body(outcome: VerificationOutcome) -> dict:
    r = outcome.result
    body = _public_body(outcome)
    body.update({
        "classification": r.classification,
        "authentic_mac": r.authentic_mac,
        "uid": r.uid,
        "read_counter": r.read_counter,
        "reader_id": outcome.reader_id,
        "signals": [{"name": s.name, "weight": s.weight, "detail": s.detail}
                    for s in r.signals],
        "detail": r.detail,
        "alerted": outcome.alerted,
    })
    return body


def create_app(
    service: VerificationService,
    *,
    ip_limiter: RateLimiter | None = None,
    reader_tokens: Mapping[str, str] | None = None,
    trusted_proxies: frozenset[str] = frozenset(),
    throttle_retry_after: float = 5.0,
    enable_docs: bool = False,
) -> FastAPI:
    """
    Build the API around an already-configured service.

    `reader_tokens` maps SHA-256(token) hex -> reader id (see
    `settings.parse_reader_tokens`). Interactive docs are off by default to keep
    the public surface minimal.
    """
    tokens = {k.lower(): v for k, v in (reader_tokens or {}).items()}
    app = FastAPI(
        title="Sphragis verification API",
        docs_url="/docs" if enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if enable_docs else None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(RateLimited)
    async def on_rate_limited(_: Request, exc: RateLimited):
        return JSONResponse(
            {"error": "rate_limited"}, status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
        )

    def limit_by_ip(request: Request) -> None:
        if ip_limiter is None:
            return
        decision = ip_limiter.check("ip:" + client_ip(request, trusted_proxies))
        if not decision.allowed:
            raise RateLimited(decision.retry_after)

    def reader_identity(request: Request) -> str | None:
        header = request.headers.get("authorization")
        if header is None:
            return None
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(401, "invalid credentials",
                                headers={"WWW-Authenticate": "Bearer"})
        # Look up by digest: timing can at most reveal bits of a SHA-256 hash,
        # never of the token itself.
        digest = hashlib.sha256(token.strip().encode()).hexdigest()
        reader = tokens.get(digest)
        if reader is None:
            raise HTTPException(401, "invalid credentials",
                                headers={"WWW-Authenticate": "Bearer"})
        return reader

    def respond(outcome: VerificationOutcome, reader: str | None) -> dict:
        if outcome.result.classification == "THROTTLED":
            raise RateLimited(throttle_retry_after)
        return _detailed_body(outcome) if reader else _public_body(outcome)

    # Plain `def` endpoints: crypto and SQLite run in FastAPI's thread pool.

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/t", dependencies=[Depends(limit_by_ip)])
    def tap(request: Request, reader: str | None = Depends(reader_identity)) -> dict:
        # The raw query string goes to the parser untouched, so duplicated
        # parameters and encrypted-file-data markers are still detected.
        outcome = service.verify(request.url.query, reader_id=reader)
        return respond(outcome, reader)

    @app.post("/v1/verify", dependencies=[Depends(limit_by_ip)])
    def verify(body: VerifyRequest,
               reader: str | None = Depends(reader_identity)) -> dict:
        outcome = service.verify(body.url, reader_id=reader)
        return respond(outcome, reader)

    return app
