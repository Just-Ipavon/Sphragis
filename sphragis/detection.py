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
                       Every authenticated reader observation inside the window
                       counts, so an anonymous tap in between hides nothing.
- large_counter_gap  : an unusually large jump (weak, informational).
- counter_rate       : the counter advanced faster than a tag can be read
                       since the floor was set (e.g. +500 in 10 s): an emulator
                       or a clone with a manipulated counter, or a delayed URL.
- prior_divergence   : the UID's history already holds a counter regression,
                       so its counter stream has forked; later taps inherit
                       the doubt while the fork is still in the window.
- counter_reordered  : a counter just below the floor, at the same reader that
                       set the floor a moment ago: two quick taps whose
                       requests arrived out of order, not a second device.

The genuine tag can only ever move the counter strictly upward from one place,
so a regression or an impossible velocity on authentic taps is the fingerprint
of a clone.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum

from .observations import MemoryObservationStore, Observation, ObservationStore


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
    history_limit      : max observations retained per UID. A recorded
                         regression marks the UID as diverged until the
                         counter it regressed from falls out of this window.
    max_tap_rate       : most reads per second a genuine tag can produce; a
                         counter advancing faster since the floor was set
                         raises `counter_rate`.
    rate_slack_seconds : added to the elapsed time before applying
                         `max_tap_rate`, to absorb network jitter.
    reorder_counters   : how far below the floor a counter may be to count as
                         reordered rather than regressed (0 disables).
    reorder_seconds    : how recently the floor must have been set, by the
                         same reader, for a reorder.
    store              : where the per-UID history lives. Defaults to an
                         in-process store; pass a shared one (e.g.
                         `SqliteObservationStore`) when several processes score
                         the same tags.
    """

    def __init__(
        self,
        min_travel_seconds: float = 60.0,
        gap_threshold: int = 1000,
        history_limit: int = 50,
        store: ObservationStore | None = None,
        max_tap_rate: float = 25.0,
        rate_slack_seconds: float = 2.0,
        reorder_counters: int = 2,
        reorder_seconds: float = 2.0,
    ) -> None:
        self.min_travel_seconds = min_travel_seconds
        self.gap_threshold = gap_threshold
        self.history_limit = history_limit
        self.max_tap_rate = max_tap_rate
        self.rate_slack_seconds = rate_slack_seconds
        self.reorder_counters = reorder_counters
        self.reorder_seconds = reorder_seconds
        self._store: ObservationStore = store or MemoryObservationStore()

    def history(self, uid_hex: str) -> list[Observation]:
        return self._store.history(uid_hex.upper())

    def analyze(
        self,
        uid_hex: str,
        counter: int,
        timestamp: float | None = None,
        reader_id: str | None = None,
    ) -> DetectionResult:
        uid_hex = uid_hex.upper()
        now = time.time() if timestamp is None else timestamp
        # Read the prior history and record this tap in one atomic step, so
        # concurrent taps for the same UID are scored against each other.
        hist = self._store.observe(
            uid_hex, Observation(counter, now, reader_id), self.history_limit
        )
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

        signals += self._history_signals(hist, counter, now, reader_id, max_seen)
        return self._aggregate(signals)

    def assess_fresh(
        self,
        uid_hex: str,
        counter: int,
        timestamp: float | None = None,
        reader_id: str | None = None,
        floor_before: int | None = None,
    ) -> DetectionResult:
        """
        Score a tap the caller has already established as fresh (a new counter
        above the persistent floor `floor_before`), and record it in the
        history. Replays and regressions are decided by the caller's tap
        ledger (see `assess_stale`), so only the history signals are scored
        here.
        """
        uid_hex = uid_hex.upper()
        now = time.time() if timestamp is None else timestamp
        hist = self._store.observe(
            uid_hex, Observation(counter, now, reader_id), self.history_limit
        )
        return self._aggregate(
            self._history_signals(hist, counter, now, reader_id, floor_before))

    def assess_stale(
        self,
        uid_hex: str,
        counter: int,
        floor: int,
        timestamp: float | None = None,
        reader_id: str | None = None,
    ) -> DetectionResult:
        """
        Score a tap the caller's tap ledger found below the floor and never
        submitted before. Normally a regression: it is recorded in the history,
        so later fresh taps carry `prior_divergence`. A counter just below the
        floor, at the same reader that set the floor moments ago, is two quick
        taps delivered out of order: weak, and kept out of the history.
        """
        uid_hex = uid_hex.upper()
        now = time.time() if timestamp is None else timestamp
        top = _floor_observation(self._store.history(uid_hex), floor)
        if (reader_id is not None and top is not None
                and top.reader_id == reader_id
                and floor - counter <= self.reorder_counters
                and 0 <= now - top.timestamp <= self.reorder_seconds):
            return self._aggregate([Signal(
                "counter_reordered", 30,
                f"read counter {counter} arrived after {floor} from the same reader "
                f"'{reader_id}' {now - top.timestamp:.1f}s later: two quick taps "
                f"delivered out of order",
            )])
        self._store.observe(
            uid_hex, Observation(counter, now, reader_id), self.history_limit
        )
        return self._aggregate([Signal(
            "counter_regression", 70,
            f"read counter {counter} is below the floor ({floor}) and was "
            f"never submitted before: a second device emitting its own "
            f"counter stream (clone), or a genuine tap that was read and "
            f"withheld (pre-play)",
        )])

    def _history_signals(self, hist: list[Observation], counter: int, now: float,
                         reader_id: str | None, reference: int | None) -> list[Signal]:
        signals: list[Signal] = []
        # --- impossible velocity: another reader, too little time ago ----------
        if reader_id is not None:
            for prior in reversed(hist):
                dt = now - prior.timestamp
                if dt >= self.min_travel_seconds:
                    break
                if prior.reader_id is not None and prior.reader_id != reader_id:
                    signals.append(Signal(
                        "impossible_velocity", 60,
                        f"seen at reader '{prior.reader_id}' then '{reader_id}' "
                        f"{dt:.1f}s apart (< {self.min_travel_seconds:.0f}s): "
                        f"one tag cannot be in two places",
                    ))
                    break

        # --- large counter gap (weak / informational) -------------------------
        if reference is not None and counter > reference + self.gap_threshold:
            signals.append(Signal(
                "large_counter_gap", 15,
                f"counter jumped from {reference} to {counter} "
                f"(+{counter - reference}); unusual but not conclusive",
            ))

        # --- counter rate: more reads since the floor than a tag can produce ---
        top = _floor_observation(hist, reference)
        if top is not None and counter > reference + 1:
            skipped = counter - reference - 1
            dt = now - top.timestamp
            if skipped > self.max_tap_rate * (max(dt, 0.0) + self.rate_slack_seconds):
                signals.append(Signal(
                    "counter_rate", 40,
                    f"counter advanced from {reference} to {counter} in {dt:.1f}s: "
                    f"{skipped} unseen reads exceed {self.max_tap_rate:g} reads/s",
                ))

        # --- prior divergence: the counter stream already forked --------------
        fork = _first_regression(hist)
        if fork is not None:
            signals.append(Signal(
                "prior_divergence", 35,
                f"this UID already emitted a regressed counter ({fork.counter}): "
                f"its counter stream has forked, so this tap may come from either "
                f"device",
            ))
        return signals

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


def _floor_observation(hist: list[Observation], floor: int | None) -> Observation | None:
    """The latest observation that set `floor`, if still in the window."""
    if floor is None:
        return None
    for obs in reversed(hist):
        if obs.counter == floor:
            return obs
    return None


def _first_regression(hist: list[Observation]) -> Observation | None:
    """The first observation below an earlier maximum and not a repeat of an
    earlier value (a repeat is a replay, not a fork)."""
    seen: set[int] = set()
    top: int | None = None
    for obs in hist:
        if top is not None and obs.counter < top and obs.counter not in seen:
            return obs
        seen.add(obs.counter)
        top = obs.counter if top is None else max(top, obs.counter)
    return None
