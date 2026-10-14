"""
sphragis — NTAG 424 DNA clone-detection engine (SUN/SDM).

Cryptographic layer:
    from sphragis import Verifier, StaticKeys, Verdict, CounterStore

Intelligence layer (scored clone detection):
    from sphragis import TagAnalyzer, CloneDetector, RiskLevel

Key management:
    from sphragis import DiversifiedKeys, diversify_key

Testing / demos:
    from sphragis.emulator import EmulatedTag, random_tag, tag_from_provider
    from sphragis.adversary import KeylessAttacker, KeyCloner
"""

from .analyzer import AnalysisResult, TagAnalyzer
from .counterstore import CounterBackend, CounterStore
from .detection import CloneDetector, DetectionResult, RiskLevel, Signal
from .diversify import DiversifiedKeys, diversify_key
from .sdm import PiccData, SdmError, compute_sdmmac, decrypt_picc_data
from .secrets import (
    EnvSecretsBackend,
    FileSecretsBackend,
    KmsSecretsBackend,
    SecretsBackend,
    SecretsError,
    build_diversified_keys,
)
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
]

__version__ = "0.3.0"
