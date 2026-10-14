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
"""

from __future__ import annotations

from dataclasses import dataclass

from .counterstore import CounterBackend, CounterStore
from .detection import CloneDetector, DetectionResult, RiskLevel, Signal
from .sdm import SdmError, compute_sdmmac, decrypt_picc_data
from .verifier import KeyProvider, _consttime_eq, _extract_params


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
        store: CounterBackend | None = None,
    ) -> None:
        self._keys = keys
        self._detector = detector or CloneDetector()
        # Persistent monotonic floor. The in-memory detector gives rich scoring
        # but its history is lost on restart; this store keeps a hard anti-replay
        # floor that survives restarts/crashes. Pass a path-backed CounterStore
        # in production.
        self._store = store or CounterStore()

    @property
    def detector(self) -> CloneDetector:
        return self._detector

    def analyze(
        self,
        url_or_query: str,
        timestamp: float | None = None,
        reader_id: str | None = None,
    ) -> AnalysisResult:
        # 1 + 2: parse and decrypt
        try:
            enc_picc, cmac = _extract_params(url_or_query)
            picc = decrypt_picc_data(enc_picc, self._keys.meta_read_key())
        except SdmError as exc:
            return AnalysisResult("ERROR", False, None, None, 0, (), str(exc))

        uid_hex = picc.uid_hex

        # 3: authenticity. A bad MAC means the counter is untrusted, so we stop
        #    here and never feed forged data to the detector.
        expected = compute_sdmmac(
            self._keys.file_read_key(picc.uid), picc.uid, picc.read_counter
        )
        if not _consttime_eq(expected, cmac):
            return AnalysisResult(
                "FORGED", False, uid_hex, picc.read_counter, 100, (),
                "SDMMAC mismatch: payload is not from a genuine tag",
            )

        # 4: persistent anti-replay floor (survives restarts) + scored analysis.
        fresh = self._store.check_and_advance(uid_hex, picc.read_counter)
        det: DetectionResult = self._detector.analyze(
            uid_hex, picc.read_counter, timestamp=timestamp, reader_id=reader_id
        )

        # If the rich (in-memory) detector sees nothing but the persistent store
        # knows this counter was already used (e.g. a replay after a restart
        # cleared the detector's history), fall back to REPLAY.
        if det.risk_level is RiskLevel.GENUINE and not fresh:
            return AnalysisResult(
                classification=RiskLevel.REPLAY.value,
                authentic_mac=True,
                uid=uid_hex,
                read_counter=picc.read_counter,
                risk_score=65,
                signals=(),
                detail="counter already seen in the persistent store "
                       "(replay across a detector-history reset)",
            )

        return AnalysisResult(
            classification=det.risk_level.value,
            authentic_mac=True,
            uid=uid_hex,
            read_counter=picc.read_counter,
            risk_score=det.risk_score,
            signals=det.signals,
            detail=det.detail,
        )
