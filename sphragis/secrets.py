"""
Key material backends — keep master keys out of the code and the repo.

Hardcoding AES keys is the classic fatal mistake. This module abstracts *where*
key material comes from behind a tiny `SecretsBackend` interface, so the same
verifier runs against an env var in dev and a managed KMS/Vault in production
without code changes.

Honest limitation: a software backend fetches the key into process memory, where
it cannot be reliably zeroized (Python `bytes` are immutable). A true HSM keeps
the key resident and performs the crypto inside the module; `KmsSecretsBackend`
is the extension point where that integration goes. For NTAG 424 DNA the master
key should live in an HSM/KMS and only diversified session material should ever
transit, which this structure is built to support.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Protocol

from .diversify import DiversifiedKeys


class SecretsError(Exception):
    pass


class SecretsBackend(Protocol):
    """Returns a 16-byte AES-128 key for a logical key name."""

    def get_key(self, name: str) -> bytes: ...


def _validate(name: str, key: bytes) -> bytes:
    if len(key) != 16:
        raise SecretsError(
            f"key '{name}' must be AES-128 (16 bytes), got {len(key)}"
        )
    return key


class EnvSecretsBackend:
    """
    Reads hex-encoded keys from environment variables.

    Example: name 'master_file' -> env var 'SPHRAGIS_MASTER_FILE'.
    Good for dev/CI; never commit the values.
    """

    def __init__(self, prefix: str = "SPHRAGIS_") -> None:
        self._prefix = prefix

    def get_key(self, name: str) -> bytes:
        var = self._prefix + name.upper()
        raw = os.environ.get(var)
        if raw is None:
            raise SecretsError(f"environment variable {var} is not set")
        try:
            key = bytes.fromhex(raw.strip())
        except ValueError as exc:
            raise SecretsError(f"{var} is not valid hex: {exc}") from exc
        return _validate(name, key)


class FileSecretsBackend:
    """
    Reads hex-encoded keys from `<directory>/<name>` files.

    Refuses files that are group/world readable (POSIX), to catch the common
    misconfiguration of leaving key material readable by other users.
    """

    def __init__(self, directory: str | os.PathLike, enforce_perms: bool = True) -> None:
        self._dir = Path(directory)
        self._enforce = enforce_perms

    def get_key(self, name: str) -> bytes:
        path = self._dir / name
        if not path.exists():
            raise SecretsError(f"key file not found: {path}")
        if self._enforce and os.name == "posix":
            mode = path.stat().st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise SecretsError(
                    f"insecure permissions on {path}: must not be group/world "
                    f"accessible (chmod 600)"
                )
        try:
            key = bytes.fromhex(path.read_text().strip())
        except ValueError as exc:
            raise SecretsError(f"{path} is not valid hex: {exc}") from exc
        return _validate(name, key)


class KmsSecretsBackend:
    """
    Extension point for a managed KMS / Vault / HSM.

    Subclass and implement `get_key` to call your provider (AWS KMS, GCP KMS,
    HashiCorp Vault, PKCS#11 HSM, ...). Example sketch:

        class AwsKmsBackend(KmsSecretsBackend):
            def __init__(self, client, key_ids): ...
            def get_key(self, name):
                resp = self._client.decrypt(CiphertextBlob=self._blobs[name])
                return resp["Plaintext"]   # 16 bytes

    Keeping this behind the SecretsBackend interface means the verifier never
    changes when you move from env vars to a real KMS.
    """

    def get_key(self, name: str) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError(
            "KmsSecretsBackend is an extension point; subclass and implement "
            "get_key() for your KMS/HSM provider"
        )


def build_diversified_keys(
    backend: SecretsBackend,
    master_file_name: str = "master_file",
    meta_name: str = "meta_read",
    context: bytes = b"",
) -> DiversifiedKeys:
    """
    Load the master file key and meta-read key from a secrets backend and wrap
    them in a per-UID DiversifiedKeys provider — no raw keys in code.
    """
    master_file = backend.get_key(master_file_name)
    meta_read = backend.get_key(meta_name)
    return DiversifiedKeys(master_file, meta_read, context=context)
