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

Request guard
-------------
Before routing or parsing, a plain ASGI layer applies the per-IP rate limit to
the verification endpoints and caps the request body (`max_body_bytes`), so an
oversized or malformed body is refused without being read in full or parsed,
and invalid JSON still counts against the limit.

Logs
----
uvicorn's access log would record every tapped URL, `picc_data` and `cmac`
included, and an unused tap stays redeemable from it. `QueryRedactingFilter`
(installed on `uvicorn.access` by `create_app`) drops the query string from
those lines; running uvicorn with `--no-access-log` is stricter still.

Run it:  uvicorn --factory sphragis.api:create_app_from_env
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import re
from typing import Iterable, Mapping

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..ratelimit import RateLimiter
from ..service import VerificationOutcome, VerificationService
from .settings import parse_trusted_proxies

PUBLIC_MESSAGES = {
    "GENUINE": "Authentic tag.",
    "SUSPICIOUS": "Authentic tag; unusual activity was observed.",
    "REPLAY": "This verification link was already used. Tap the tag again.",
    "CLONE_LIKELY": "Warning: this tag shows signs of duplication.",
    "INVALID": "This link could not be verified.",
}

# The public score is fixed per verdict: the analyzer's score would tell an
# anonymous caller which signals fired. Readers still get the real score.
PUBLIC_SCORES = {"GENUINE": 0, "SUSPICIOUS": 50, "REPLAY": 100,
                 "CLONE_LIKELY": 100, "INVALID": 100}

# Link previewers fetch a shared URL before the person does; verifying for
# them would spend the tap and show the owner REPLAY. They get a neutral
# answer and the tap stays fresh. Spoofing the header gains nothing.
_PREVIEWERS = re.compile(
    r"facebookexternalhit|facebot|twitterbot|slackbot|slack-imgproxy|whatsapp|"
    r"telegrambot|discordbot|linkedinbot|skypeuripreview|pinterest|redditbot|"
    r"embedly|iframely|vkshare|bitlybot|google-pagerenderer|mastodon|"
    r"applebot|bingpreview", re.I)
PREVIEW_BODY = {"message": "Open this link on the device that tapped the tag "
                           "to verify it."}


def is_link_previewer(user_agent: str | None) -> bool:
    return bool(user_agent) and _PREVIEWERS.search(user_agent) is not None


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


DEFAULT_MAX_BODY_BYTES = 8 * 1024
LIMITED_PATHS = frozenset({"/t", "/v1/verify"})

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def _address(text: str) -> Address | None:
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def bucket_key(addr: Address) -> str:
    """Rate-limit key: the IPv4 address, or the /64 of an IPv6 address (one
    host usually controls a whole /64)."""
    if isinstance(addr, ipaddress.IPv6Address):
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def client_address(peer: str | None, forwarded: list[str],
                   trusted: Iterable[Network]) -> str:
    """
    The client address used for rate limiting. `X-Forwarded-For` (every
    header line, in order) is honoured only when the direct peer is a trusted
    proxy; the client is then the right-most hop that is not itself a trusted
    proxy (left-most entries are client-controlled and trivially spoofed).
    """
    trusted = tuple(trusted)

    def is_trusted(addr: Address) -> bool:
        return any(addr in net for net in trusted)

    peer_addr = _address(peer or "")
    if peer_addr is None:
        return peer or "unknown"
    if not is_trusted(peer_addr):
        return bucket_key(peer_addr)
    hops = [h for line in forwarded for h in line.split(",") if h.strip()]
    for hop in reversed(hops):
        addr = _address(hop)
        if addr is None:          # garbage where our proxy should have written
            break                 # an address: fall back to the proxy itself
        if not is_trusted(addr):
            return bucket_key(addr)
    return bucket_key(peer_addr)


def client_ip(request: Request, trusted_proxies: Iterable[Network | str]) -> str:
    """`client_address` for a Starlette request."""
    trusted = tuple(t if not isinstance(t, str) else ipaddress.ip_network(t, strict=False)
                    for t in trusted_proxies)
    return client_address(request.client.host if request.client else None,
                          request.headers.getlist("x-forwarded-for"), trusted)


class QueryRedactingFilter(logging.Filter):
    """Drop the query string from uvicorn access-log lines (tapped URLs)."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            record.args = args[:2] + (args[2].split("?", 1)[0],) + args[3:]
        return True


def install_access_log_redaction(logger_name: str = "uvicorn.access") -> None:
    logger = logging.getLogger(logger_name)
    if not any(isinstance(f, QueryRedactingFilter) for f in logger.filters):
        logger.addFilter(QueryRedactingFilter())


class RequestGuard:
    """
    ASGI layer in front of the app: per-IP rate limit on the verification
    paths and a cap on request bodies, both before any parsing.
    """

    def __init__(self, app, *, ip_limiter: RateLimiter | None,
                 trusted_proxies: tuple[Network, ...], max_body_bytes: int) -> None:
        self.app = app
        self._limiter = ip_limiter
        self._trusted = trusted_proxies
        self._max = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self._limiter is not None and scope["path"] in LIMITED_PATHS:
            headers = [(k.decode("latin-1").lower(), v.decode("latin-1"))
                       for k, v in scope.get("headers", [])]
            peer = scope.get("client")
            ip = client_address(peer[0] if peer else None,
                                [v for k, v in headers if k == "x-forwarded-for"],
                                self._trusted)
            decision = self._limiter.check("ip:" + ip)
            if not decision.allowed:
                retry = str(max(1, math.ceil(decision.retry_after)))
                return await _respond(send, 429, {"error": "rate_limited"},
                                      [("retry-after", retry)])
        if scope["method"] in ("GET", "HEAD", "OPTIONS", "DELETE"):
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k.lower() == b"content-length":
                try:
                    declared = int(v)
                except ValueError:
                    return await _respond(send, 400, {"error": "bad_request"})
                if declared > self._max:
                    return await _respond(send, 413, {"error": "body_too_large"})
        body, more = b"", True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            more = message.get("more_body", False)
            if len(body) > self._max:
                return await _respond(send, 413, {"error": "body_too_large"})
        delivered = False

        async def replay():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        return await self.app(scope, replay, send)


async def _respond(send, status: int, payload: dict,
                   extra: list[tuple[str, str]] = ()) -> None:
    body = json.dumps(payload).encode()
    headers = [(b"content-type", b"application/json"),
               (b"content-length", str(len(body)).encode())]
    headers += [(k.lower().encode(), v.encode()) for k, v in _SECURITY_HEADERS.items()]
    headers += [(k.encode(), v.encode()) for k, v in extra]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _public_body(outcome: VerificationOutcome) -> dict:
    cls = outcome.result.classification
    verdict = "INVALID" if cls in ("ERROR", "FORGED") else cls
    return {
        "event_id": outcome.event_id,
        "verdict": verdict,
        "risk_score": PUBLIC_SCORES[verdict],
        "message": PUBLIC_MESSAGES[verdict],
    }


def _detailed_body(outcome: VerificationOutcome) -> dict:
    r = outcome.result
    body = _public_body(outcome)
    if r.classification in ("ERROR", "FORGED"):
        # Same answer for both, even to readers: telling them apart would be a
        # one-bit oracle on the decrypted PICCData. The log keeps the reason.
        body.update({"classification": "INVALID", "authentic_mac": False,
                     "uid": None, "read_counter": None,
                     "reader_id": outcome.reader_id, "signals": [],
                     "detail": "the tap could not be verified", "alerted": False})
        return body
    body.update({
        "risk_score": r.risk_score,
        "classification": r.classification,
        "authentic_mac": r.authentic_mac,
        "uid": r.uid,
        "read_counter": r.read_counter,
        "backend": r.backend,
        "algorithm": r.algorithm,
        "key_version": r.key_version,
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
    trusted_proxies: Iterable[str] = (),
    throttle_retry_after: float = 5.0,
    enable_docs: bool = False,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> FastAPI:
    """
    Build the API around an already-configured service.

    `reader_tokens` maps SHA-256(token) hex -> reader id (see
    `settings.parse_reader_tokens`). Interactive docs are off by default to keep
    the public surface minimal.
    """
    tokens = {k.lower(): v for k, v in (reader_tokens or {}).items()}
    trusted = parse_trusted_proxies(trusted_proxies)
    install_access_log_redaction()
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

    app.add_middleware(RequestGuard, ip_limiter=ip_limiter, trusted_proxies=trusted,
                       max_body_bytes=max_body_bytes)

    @app.exception_handler(RateLimited)
    async def on_rate_limited(_: Request, exc: RateLimited):
        return JSONResponse(
            {"error": "rate_limited"}, status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
        )

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

    @app.get("/t")
    def tap(request: Request, reader: str | None = Depends(reader_identity)) -> dict:
        if reader is None and is_link_previewer(request.headers.get("user-agent")):
            return dict(PREVIEW_BODY)
        # The raw query string goes to the parser untouched, so duplicated
        # parameters and encrypted-file-data markers are still detected.
        outcome = service.verify(request.url.query, reader_id=reader)
        return respond(outcome, reader)

    @app.post("/v1/verify")
    def verify(body: VerifyRequest,
               reader: str | None = Depends(reader_identity)) -> dict:
        outcome = service.verify(body.url, reader_id=reader)
        return respond(outcome, reader)

    return app
