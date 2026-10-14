"""
Clone-detection intelligence.

A valid SDMMAC only proves that *whoever produced this tap holds the tag's
secret key*. It does NOT prove there is only one physical tag. The read counter
is what exposes duplication — and reasoning about it well is where real
anti-counterfeiting value lives.

This module consumes a stream of *cryptographically authentic* observations
(UID, read counter, time, reader) and produces a scored verdict rather than a
bare yes/no. Each heuristic emits a weighted `Signal`; the weights aggregate
into a 0-100 risk score and a classification.

Heuristics
----------
- exact_replay       : a counter value already seen verbatim -> a captured URL
                       is being resent (attacker needs no key).
- counter_regression : a counter below the maximum ever seen -> a second device
                       emitting its own, lower counter stream (key-cloned tag).
- impossible_velocity: two reads from different readers closer in time than any
                       physical object could travel -> two tags in two places.
- large_counter_gap  : an unusually large jump (weak, informational).

The genuine tag can only ever move the counter strictly upward from one place,
so a regression or an impossible velocity on authentic taps is the fingerprint
of a clone.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    GENUINE = "GENUINE"           # no anomaly
    SUSPICIOUS = "SUSPICIOUS"     # weak signal(s), worth watching
    REPLAY = "REPLAY"             # a captured tap is being resent
    CLONE_LIKELY = "CLONE_LIKELY" # strong evidence of a duplicated tag


@dataclass(frozen=True)
class Signal:
    name: str
    weight: int
    detail: str


@dataclass
class Observation:
    counter: int
    timestamp: float
    reader_id: str | None = None


@dataclass(frozen=True)
class DetectionResult:
    risk_level: RiskLevel
    risk_score: int            # 0-100
    signals: tuple[Signal, ...]
    detail: str


# Score thresholds mapping aggregate weight -> classification.
_STRONG = 60
_WEAK = 25


class CloneDetector:
    """
    Stateful detector keeping a bounded per-UID observation history.

    Parameters
    ----------
    min_travel_seconds : minimum plausible time between taps at *different*
                         readers. Two authentic taps from different readers
                         closer than this imply two physical tags.
    gap_threshold      : counter jump above which we raise a weak gap signal.
    history_limit      : max observations retained per UID.
    """

    def __init__(
        self,
        min_travel_seconds: float = 60.0,
        gap_threshold: int = 1000,
        history_limit: int = 50,
    ) -> None:
        self.min_travel_seconds = min_travel_seconds
        self.gap_threshold = gap_threshold
        self.history_limit = history_limit
        self._history: dict[str, list[Observation]] = {}

    def history(self, uid_hex: str) -> list[Observation]:
        return list(self._history.get(uid_hex.upper(), []))

    def analyze(
        self,
        uid_hex: str,
        counter: int,
        timestamp: float | None = None,
        reader_id: str | None = None,
    ) -> DetectionResult:
        uid_hex = uid_hex.upper()
        now = time.time() if timestamp is None else timestamp
        hist = self._history.get(uid_hex, [])
        signals: list[Signal] = []

        seen_counters = {o.counter for o in hist}
        max_seen = max(seen_counters) if seen_counters else None

        # --- exact replay: this counter value was already observed verbatim ---
        if counter in seen_counters:
            signals.append(Signal(
                "exact_replay", 65,
                f"read counter {counter} was already seen for this UID: "
                f"a previously captured tap is being replayed",
            ))
        # --- counter regression: below the max, but a new (lower) value --------
        elif max_seen is not None and counter < max_seen:
            signals.append(Signal(
                "counter_regression", 70,
                f"read counter {counter} is below the maximum seen ({max_seen}): "
                f"a second device is emitting its own counter stream (clone)",
            ))

        # --- impossible velocity: different readers, too little time between ---
        if reader_id is not None and hist:
            last = hist[-1]
            if (last.reader_id is not None
                    and last.reader_id != reader_id
                    and (now - last.timestamp) < self.min_travel_seconds):
                dt = now - last.timestamp
                signals.append(Signal(
                    "impossible_velocity", 60,
                    f"seen at reader '{last.reader_id}' then '{reader_id}' "
                    f"{dt:.1f}s apart (< {self.min_travel_seconds:.0f}s): "
                    f"one tag cannot be in two places",
                ))

        # --- large counter gap (weak / informational) -------------------------
        if max_seen is not None and counter > max_seen + self.gap_threshold:
            signals.append(Signal(
                "large_counter_gap", 15,
                f"counter jumped from {max_seen} to {counter} "
                f"(+{counter - max_seen}); unusual but not conclusive",
            ))

        result = self._aggregate(signals)
        self._record(uid_hex, Observation(counter, now, reader_id))
        return result

    def _aggregate(self, signals: list[Signal]) -> DetectionResult:
        score = min(100, sum(s.weight for s in signals))
        names = {s.name for s in signals}

        if score >= _STRONG:
            if "counter_regression" in names or "impossible_velocity" in names:
                level = RiskLevel.CLONE_LIKELY
            elif "exact_replay" in names:
                level = RiskLevel.REPLAY
            else:
                level = RiskLevel.CLONE_LIKELY
        elif score >= _WEAK:
            level = RiskLevel.SUSPICIOUS
        elif score > 0:
            level = RiskLevel.SUSPICIOUS
        else:
            level = RiskLevel.GENUINE

        if signals:
            detail = "; ".join(s.detail for s in signals)
        else:
            detail = "counter advancing normally; no duplication signals"
        return DetectionResult(level, score, tuple(signals), detail)

    def _record(self, uid_hex: str, obs: Observation) -> None:
        hist = self._history.setdefault(uid_hex, [])
        hist.append(obs)
        if len(hist) > self.history_limit:
            del hist[0 : len(hist) - self.history_limit]
