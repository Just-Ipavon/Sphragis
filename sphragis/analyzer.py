"""
TagAnalyzer — the full pipeline, crypto + intelligence.

`Verifier` answers "is this tap cryptographically valid and fresh?" with a
single verdict. `TagAnalyzer` goes further: once a tap is proven authentic, it
runs the `CloneDetector` over the observation stream and returns a *scored*
assessment — the distinctive output of this project.

Classification:
    ERROR        malformed input
    FORGED       SDMMAC mismatch -> not from a genuine key holder
    GENUINE      authentic and no duplication signals
    SUSPICIOUS   authentic but weak anomaly signals
    REPLAY       authentic MAC, but a captured tap resent
    CLONE_LIKELY authentic MAC, but strong evidence of a duplicated tag
    THROTTLED    authentic MAC, but refused by the caller's `admit` policy
                 before any state was touched (e.g. a per-UID rate limit)
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Sequence

from .backends import (
    AuthenticTap,
    ForgedTap,
    Provenance,
    VerificationBackend,
    select_backend,
)
from .counterstore import CounterStore, TapLedger
from .detection import CloneDetector, DetectionResult, RiskLevel, Signal
from .sdm import SdmError
from .verifier import KeyProvider, Ntag424SunBackend


@dataclass(frozen=True)
class AnalysisResult:
    classification: str
    authentic_mac: bool
    uid: str | None
    read_counter: int | None
    risk_score: int
    signals: tuple[Signal, ...]
    detail: str
    backend: str | None = None      # backend that verified the tap
    algorithm: str | None = None    # its authenticator algorithm
    payload: bytes | None = None    # authenticated payload, fresh taps only
    key_version: int | None = None  # version of the key that verified it

    @property
    def is_genuine(self) -> bool:
        return self.classification == RiskLevel.GENUINE.value


class TagAnalyzer:
    """
    `keys` sets up the plain NTAG 424 DNA SUN backend. To verify other tap
    shapes or chips, pass `backends` instead: each tap goes to the first
    backend that accepts it (most specific first), and everything after the
    cryptographic check is the same for all of them. Identities from backends
    sharing the stores must not collide (see `sphragis.backends`).
    """

    def __init__(
        self,
        keys: KeyProvider | None = None,
        detector: CloneDetector | None = None,
        store: TapLedger | None = None,
        *,
        backends: Sequence[VerificationBackend] | None = None,
    ) -> None:
        if (keys is None) == (backends is None):
            raise TypeError("TagAnalyzer needs either keys or backends")
        self._backends: tuple[VerificationBackend, ...] = (
            (Ntag424SunBackend(keys),) if backends is None else tuple(backends))
        if not self._backends:
            raise TypeError("TagAnalyzer needs at least one backend")
        self._detector = detector or CloneDetector()
        # Persistent tap ledger: the monotonic floor plus every counter value
        # submitted per UID, updated atomically. It decides replay and
        # regression exactly and survives restarts; the detector's bounded
        # history only scores fresh taps. Pass a durable backend in production
        # (SqliteCounterStore, PostgresCounterStore).
        self._store = store if store is not None else CounterStore()
        if not isinstance(self._store, TapLedger):
            raise TypeError("TagAnalyzer needs a tap ledger store "
                            "(last_counter, record_tap)")

    @property
    def detector(self) -> CloneDetector:
        return self._detector

    def analyze(
        self,
        url_or_query: str,
        timestamp: float | None = None,
        reader_id: str | None = None,
        admit: Callable[[str], bool] | None = None,
    ) -> AnalysisResult:
        """
        Stale counters are decided by the tap ledger: one already submitted
        is REPLAY and touches no other state; one below the floor and never
        submitted is CLONE_LIKELY, once (submitting it again is REPLAY), and
        enters the detector's history so later taps carry `prior_divergence`.
        Two quick taps from one reader arriving out of order are SUSPICIOUS
        (`counter_reordered`) instead.

        `admit`, if given, is called with the UID once the SDMMAC has been
        verified and only for a counter above the floor, before any state is
        touched. Returning False yields THROTTLED and leaves all state
        unchanged, so a throttled genuine tap does not burn its counter value.
        Gating only authentic, fresh taps means neither forged junk nor
        replays of a captured URL can drain a specific tag's budget.
        """
        # 1-3: pick the backend and verify the tap. Everything here runs on
        #    unauthenticated input, so any failure is an ERROR, never an
        #    exception reaching the caller.
        backend = select_backend(self._backends, url_or_query)
        if backend is None:
            return AnalysisResult("ERROR", False, None, None, 0, (),
                                  "no verification backend accepts this tap")
        try:
            tap = backend.authenticate(url_or_query)
        except ForgedTap as exc:
            # The identity and counter are unauthenticated: they are neither
            # returned (decryption oracle) nor fed to the detector.
            return AnalysisResult("FORGED", False, None, None, 100, (), str(exc),
                                  backend.name)
        except (SdmError, ValueError) as exc:
            return AnalysisResult("ERROR", False, None, None, 0, (), str(exc),
                                  backend.name)

        uid_hex = tap.identity

        # 4: classify against the tap ledger (floor + every counter submitted).
        counter = tap.counter
        floor = self._store.last_counter(uid_hex)
        if counter is None:
            if floor is None:
                return self._no_counter(tap, admit)
            # It counted before: a drop to "no counter" (0) is a regression.
            tap = replace(tap, counter=0)
            counter = 0
        stale = floor is not None and counter <= floor

        # Only a fresh counter, which needs the physical tag, is charged to the
        # per-UID budget: replays of a captured URL cannot throttle the tag.
        if not stale and admit is not None and not admit(uid_hex):
            return AnalysisResult(
                "THROTTLED", True, uid_hex, counter, 0, (),
                "verification refused by admission policy (rate limit)",
                tap.backend, tap.algorithm, key_version=tap.key_version,
            )

        record = self._store.record_tap(uid_hex, counter)
        if not record.new:                       # already submitted (or a racing copy)
            return self._replay(tap, record.floor_before)
        if not record.fresh:
            if record.predates_ledger:          # store upgraded from a bare floor
                return self._replay(tap, record.floor_before,
                                    "below the floor the UID had when its tap "
                                    "ledger began: treated as a replay")
            det = self._detector.assess_stale(
                uid_hex, counter, record.floor_before,
                timestamp=timestamp, reader_id=reader_id,
                provenance=Provenance.of(tap),
            )
            return self._result(tap, det)

        # 5: a fresh counter: score velocity and gap, and keep it in the history.
        det: DetectionResult = self._detector.assess_fresh(
            uid_hex, counter, timestamp=timestamp, reader_id=reader_id,
            floor_before=record.floor_before, provenance=Provenance.of(tap),
        )
        return self._result(tap, det, tap.payload)

    @staticmethod
    def _result(tap: AuthenticTap, det: DetectionResult,
                payload: bytes | None = None) -> AnalysisResult:
        return AnalysisResult(
            classification=det.risk_level.value,
            authentic_mac=True,
            uid=tap.identity,
            read_counter=tap.counter,
            risk_score=det.risk_score,
            signals=det.signals,
            detail=det.detail,
            backend=tap.backend,
            algorithm=tap.algorithm,
            payload=payload,
            key_version=tap.key_version,
        )

    @staticmethod
    def _no_counter(tap: AuthenticTap,
                    admit: Callable[[str], bool] | None) -> AnalysisResult:
        """An authentic tap from a chip that keeps no counter (e.g. a synced
        passkey): nothing to score, so no clone detection either."""
        if admit is not None and not admit(tap.identity):
            return AnalysisResult(
                "THROTTLED", True, tap.identity, None, 0, (),
                "verification refused by admission policy (rate limit)",
                tap.backend, tap.algorithm, key_version=tap.key_version)
        signal = Signal("no_counter", 0,
                        "the authenticator keeps no signature counter: authentic, "
                        "but counter-based clone detection is not available")
        return AnalysisResult(RiskLevel.GENUINE.value, True, tap.identity, None, 0,
                              (signal,), signal.detail, tap.backend, tap.algorithm,
                              tap.payload, tap.key_version)

    @staticmethod
    def _replay(tap: AuthenticTap, floor: int | None,
                why: str | None = None) -> AnalysisResult:
        counter = tap.counter
        if why is None:
            signal = Signal("exact_replay", 65,
                            f"read counter {counter} was already submitted for this "
                            f"UID (floor {floor}): a captured tap is being replayed")
        else:
            signal = Signal("stale_counter", 65, f"read counter {counter} is {why} "
                                                 f"(floor {floor})")
        return AnalysisResult(RiskLevel.REPLAY.value, True, tap.identity, counter,
                              signal.weight, (signal,), signal.detail,
                              tap.backend, tap.algorithm, key_version=tap.key_version)
