"""
Rate limiting for the verification endpoint.

Token bucket per key (client IP, tag UID, ...): `burst` requests may arrive at
once, then the bucket refills at `rate` tokens per second.

`TokenBucketLimiter` is in-process: with several replicas each one enforces its
own budget, so the effective limit is multiplied by the replica count. For a
global limit, implement the `RateLimiter` protocol on a shared store (e.g.
Redis) — the API depends only on the protocol.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after: float  # seconds until one token is available (0 if allowed)


@runtime_checkable
class RateLimiter(Protocol):
    def check(self, key: str) -> RateDecision: ...


class TokenBucketLimiter:
    """
    Thread-safe token bucket with a bounded key table.

    `max_keys` caps memory: the least-recently-used buckets are evicted first.
    An evicted key simply starts again with a full bucket, which errs on the
    side of availability, never of accepting a forged tap (rate limiting is a
    resource guard, not an authenticity check).
    """

    def __init__(self, rate: float, burst: int, max_keys: int = 100_000,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self.rate = rate
        self.burst = burst
        self._max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def check(self, key: str) -> RateDecision:
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.pop(key, (float(self.burst), now))
            tokens = min(float(self.burst), tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                tokens -= 1.0
                decision = RateDecision(True, 0.0)
            else:
                decision = RateDecision(False, (1.0 - tokens) / self.rate)
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self._max_keys:
                self._buckets.popitem(last=False)
        return decision

    def __len__(self) -> int:
        return len(self._buckets)
