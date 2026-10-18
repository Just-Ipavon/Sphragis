"""
sphragis — NTAG 424 DNA clone-detection engine (SUN/SDM).

Cryptographic layer:
    from sphragis import Verifier, StaticKeys, Verdict, CounterStore

Encrypted file-data mirror (SDMENCFileData):
    from sphragis import EncFileVerifier, decrypt_file_data

Verification backends (chip-specific half of the pipeline):
    from sphragis import VerificationBackend, Ntag424SunBackend, Ntag424EncBackend

Intelligence layer (scored clone detection):
    from sphragis import TagAnalyzer, CloneDetector, RiskLevel

Key management:
    from sphragis import DiversifiedKeys, diversify_key

Service layer (logging, alerting, rate limiting):
    from sphragis import VerificationService, SqliteAlertSink, TokenBucketLimiter

Signed verification events (COSE_Sign1):
    from sphragis import EventSigner, FileEventSink, verify_event

REST API (optional extra `sphragis[api]`):
    uvicorn --factory sphragis.api:create_app_from_env

Testing / demos:
    from sphragis.emulator import EmulatedTag, random_tag, tag_from_provider
    from sphragis.adversary import KeylessAttacker, KeyCloner
"""

from . import _cryptocheck  # noqa: F401  (must run before any Crypto import)
from .alerts import Alert, AlertSink, LogAlertSink, SqliteAlertSink, WebhookAlertSink
from .analyzer import AnalysisResult, TagAnalyzer
from .backends import (
    AuthenticTap,
    ForgedTap,
    Provenance,
    VerificationBackend,
    select_backend,
)
from .counterstore import CounterBackend, CounterStore
from .detection import CloneDetector, DetectionResult, RiskLevel, Signal
from .diversify import DiversifiedKeys, diversify_key
from .keyring import KeyRing, build_keyring, versioned_name
from .encverifier import EncFileVerifier, EncVerificationResult, Ntag424EncBackend
from .events import (
    EventError,
    EventSigner,
    EventSink,
    FileEventSink,
    SignedEvent,
    read_event_file,
    verify_event,
)
from .logs import JsonFormatter, UidPseudonymizer, configure_logging
from .observations import (
    MemoryObservationStore,
    Observation,
    ObservationStore,
    SqliteObservationStore,
)
from .pgstore import PostgresAlertSink, PostgresCounterStore, PostgresObservationStore
from .ratelimit import RateDecision, RateLimiter, TokenBucketLimiter
from .sdm import PiccData, SdmError, compute_sdmmac, decrypt_picc_data
from .sdmenc import decrypt_file_data, encrypt_file_data
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
from .verifier import Ntag424SunBackend, StaticKeys, Verdict, VerificationResult, Verifier

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
    "EncFileVerifier",
    "EncVerificationResult",
    "decrypt_file_data",
    "encrypt_file_data",
    # verification backends
    "VerificationBackend",
    "AuthenticTap",
    "ForgedTap",
    "Provenance",
    "select_backend",
    "Ntag424SunBackend",
    "Ntag424EncBackend",
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
    "KeyRing",
    "build_keyring",
    "versioned_name",
    # production layer
    "CounterBackend",
    "SqliteCounterStore",
    "PostgresCounterStore",
    "PostgresObservationStore",
    "PostgresAlertSink",
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
    # signed events
    "SignedEvent",
    "EventSigner",
    "EventSink",
    "FileEventSink",
    "EventError",
    "verify_event",
    "read_event_file",
]

__version__ = "1.0.0"
