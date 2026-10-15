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

from dataclasses import dataclass
from typing import Callable

from .counterstore import CounterStore, TapLedger
from .detection import CloneDetector, DetectionResult, RiskLevel, Signal
from .sdm import SdmError, compute_sdmmac, decrypt_picc_data
from .verifier import KeyProvider, _consttime_eq, _extract_params, _require_standard_picc


@dataclass(frozen=True)
class AnalysisResult:
    classification: str
    authentic_mac: bool
    uid: str | None
    read_counter: int | None
    risk_score: int
    signals: tuple[Signal, ...]
    detail: str

    @property
    def is_genuine(self) -> bool:
        return self.classification == RiskLevel.GENUINE.value


class TagAnalyzer:
    def __init__(
        self,
        keys: KeyProvider,
        detector: CloneDetector | None = None,
        store: TapLedger | None = None,
    ) -> None:
        self._keys = keys
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
        Stale counters are decided by the tap ledger alone and touch no other
        state: one already submitted is REPLAY; one below the floor and never
        submitted is CLONE_LIKELY, once (submitting it again is REPLAY).

        `admit`, if given, is called with the UID once the SDMMAC has been
        verified and only for a counter above the floor, before any state is
        touched. Returning False yields THROTTLED and leaves all state
        unchanged, so a throttled genuine tap does not burn its counter value.
        Gating only authentic, fresh taps means neither forged junk nor
        replays of a captured URL can drain a specific tag's budget.
        """
        # 1-3: parse, decrypt, derive the tag key and check the MAC. Everything
        #    here runs on unauthenticated input, so any failure is an ERROR,
        #    never an exception reaching the caller.
        try:
            enc_picc, cmac = _extract_params(url_or_query)
            picc = decrypt_picc_data(enc_picc, self._keys.meta_read_key())
            _require_standard_picc(picc)
            expected = compute_sdmmac(
                self._keys.file_read_key(picc.uid), picc.uid, picc.read_counter
            )
        except (SdmError, ValueError) as exc:
            return AnalysisResult("ERROR", False, None, None, 0, (), str(exc))

        uid_hex = picc.uid_hex

        # A bad MAC means UID and counter are unauthenticated: they are neither
        # returned (decryption oracle) nor fed to the detector.
        if not _consttime_eq(expected, cmac):
            return AnalysisResult(
                "FORGED", False, None, None, 100, (),
                "SDMMAC mismatch: payload is not from a genuine tag",
            )

        # 4: classify against the tap ledger (floor + every counter submitted).
        counter = picc.read_counter
        floor = self._store.last_counter(uid_hex)
        stale = floor is not None and counter <= floor

        # Only a fresh counter, which needs the physical tag, is charged to the
        # per-UID budget: replays of a captured URL cannot throttle the tag.
        if not stale and admit is not None and not admit(uid_hex):
            return AnalysisResult(
                "THROTTLED", True, uid_hex, counter, 0, (),
                "verification refused by admission policy (rate limit)",
            )

        record = self._store.record_tap(uid_hex, counter)
        if not record.new:                       # already submitted (or a racing copy)
            return self._replay(uid_hex, counter, record.floor_before)
        if not record.fresh:
            if record.predates_ledger:          # store upgraded from a bare floor
                return self._replay(uid_hex, counter, record.floor_before,
                                    "below the floor the UID had when its tap "
                                    "ledger began: treated as a replay")
            return self._regression(uid_hex, counter, record.floor_before)

        # 5: a fresh counter: score velocity and gap, and keep it in the history.
        det: DetectionResult = self._detector.assess_fresh(
            uid_hex, counter, timestamp=timestamp, reader_id=reader_id,
            floor_before=record.floor_before,
        )
        return AnalysisResult(
            classification=det.risk_level.value,
            authentic_mac=True,
            uid=uid_hex,
            read_counter=counter,
            risk_score=det.risk_score,
            signals=det.signals,
            detail=det.detail,
        )

    @staticmethod
    def _replay(uid_hex: str, counter: int, floor: int | None,
                why: str | None = None) -> AnalysisResult:
        if why is None:
            signal = Signal("exact_replay", 65,
                            f"read counter {counter} was already submitted for this "
                            f"UID (floor {floor}): a captured tap is being replayed")
        else:
            signal = Signal("stale_counter", 65, f"read counter {counter} is {why} "
                                                 f"(floor {floor})")
        return AnalysisResult(RiskLevel.REPLAY.value, True, uid_hex, counter,
                              signal.weight, (signal,), signal.detail)

    @staticmethod
    def _regression(uid_hex: str, counter: int, floor: int | None) -> AnalysisResult:
        signal = Signal("counter_regression", 70,
                        f"read counter {counter} is below the floor ({floor}) and was "
                        f"never submitted before: a second device emitting its own "
                        f"counter stream (clone), or a genuine tap that was read and "
                        f"withheld (pre-play)")
        return AnalysisResult(RiskLevel.CLONE_LIKELY.value, True, uid_hex, counter,
                              signal.weight, (signal,), signal.detail)
