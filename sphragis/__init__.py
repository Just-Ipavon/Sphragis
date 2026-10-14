"""
sphragis — NTAG 424 DNA clone-detection engine (SUN/SDM).

Cryptographic layer:
    from sphragis import Verifier, StaticKeys, Verdict, CounterStore

Intelligence layer (scored clone detection):
    from sphragis import TagAnalyzer, CloneDetector, RiskLevel

Key management:
    from sphragis import DiversifiedKeys, diversify_key

Service layer (logging, alerting, rate limiting):
    from sphragis import VerificationService, SqliteAlertSink, TokenBucketLimiter

REST API (optional extra `sphragis[api]`):
    uvicorn --factory sphragis.api:create_app_from_env

Testing / demos:
    from sphragis.emulator import EmulatedTag, random_tag, tag_from_provider
    from sphragis.adversary import KeylessAttacker, KeyCloner
"""

from .alerts import Alert, AlertSink, LogAlertSink, SqliteAlertSink, WebhookAlertSink
from .analyzer import AnalysisResult, TagAnalyzer
from .counterstore import CounterBackend, CounterStore
from .detection import CloneDetector, DetectionResult, RiskLevel, Signal
from .diversify import DiversifiedKeys, diversify_key
from .logs import JsonFormatter, UidPseudonymizer, configure_logging
from .observations import (
    MemoryObservationStore,
    Observation,
    ObservationStore,
    SqliteObservationStore,
)
from .ratelimit import RateDecision, RateLimiter, TokenBucketLimiter
from .sdm import PiccData, SdmError, compute_sdmmac, decrypt_picc_data
from .secrets import (
    EnvSecretsBackend,
    FileSecretsBackend,
    KmsSecretsBackend,
    SecretsBackend,
    SecretsError,
    build_diversified_keys,
)
from .service import VerificationOutcome, VerificationService
from .sqlstore import SqliteCounterStore
from .verifier import StaticKeys, Verdict, VerificationResult, Verifier

__all__ = [
    # crypto
    "Verifier",
    "StaticKeys",
    "Verdict",
    "VerificationResult",
    "CounterStore",
    "PiccData",
    "SdmError",
    "compute_sdmmac",
    "decrypt_picc_data",
    # intelligence
    "TagAnalyzer",
    "AnalysisResult",
    "CloneDetector",
    "DetectionResult",
    "RiskLevel",
    "Signal",
    # key management
    "DiversifiedKeys",
    "diversify_key",
    # production layer
    "CounterBackend",
    "SqliteCounterStore",
    "SecretsBackend",
    "EnvSecretsBackend",
    "FileSecretsBackend",
    "KmsSecretsBackend",
    "SecretsError",
    "build_diversified_keys",
    "ObservationStore",
    "Observation",
    "MemoryObservationStore",
    "SqliteObservationStore",
    # service layer
    "VerificationService",
    "VerificationOutcome",
    "Alert",
    "AlertSink",
    "LogAlertSink",
    "SqliteAlertSink",
    "WebhookAlertSink",
    "RateLimiter",
    "RateDecision",
    "TokenBucketLimiter",
    "JsonFormatter",
    "UidPseudonymizer",
    "configure_logging",
]

__version__ = "0.4.0"
