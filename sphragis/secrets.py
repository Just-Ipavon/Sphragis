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
import warnings
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
    if key == bytes(16):
        raise SecretsError(f"key '{name}' is all zero: the public factory key "
                           "is not a secret")
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

    On POSIX, with `enforce_perms` (the default) it refuses:
    - a key file that is a symlink, not a regular file, not owned by the
      current user, or group/world accessible (chmod 600);
    - a directory that is group/world writable (someone else could swap a
      key file in) or owned by another user.
    The checks run on the opened file descriptor (`O_NOFOLLOW` + `fstat`), so
    the file that is checked is the file that is read. On other systems the
    permissions cannot be checked this way: a warning is emitted, or pass
    `enforce_perms=False` knowingly.
    """

    def __init__(self, directory: str | os.PathLike, enforce_perms: bool = True) -> None:
        self._dir = Path(directory)
        self._enforce = enforce_perms
        if enforce_perms and os.name != "posix":
            warnings.warn("FileSecretsBackend cannot check key file permissions on "
                          f"{os.name}: protect {self._dir} with the OS ACLs",
                          RuntimeWarning, stacklevel=2)

    def _check_dir(self) -> None:
        try:
            st = os.stat(self._dir)
        except FileNotFoundError:
            raise SecretsError(f"secrets directory not found: {self._dir}") from None
        if not stat.S_ISDIR(st.st_mode):
            raise SecretsError(f"{self._dir} is not a directory")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise SecretsError(f"insecure permissions on {self._dir}: must not be "
                               "group/world writable (chmod 700)")
        if st.st_uid not in (os.geteuid(), 0):
            raise SecretsError(f"{self._dir} is owned by another user")

    def get_key(self, name: str) -> bytes:
        if not name or "/" in name or name in (".", ".."):
            raise SecretsError(f"invalid key name {name!r}")
        path = self._dir / name
        posix = os.name == "posix"
        if self._enforce and posix:
            self._check_dir()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            raise SecretsError(f"key file not found: {path}") from None
        except OSError as exc:            # ELOOP: a symlink under O_NOFOLLOW
            raise SecretsError(f"cannot open {path} safely: {exc.strerror}") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise SecretsError(f"{path} is not a regular file")
            if self._enforce and posix:
                if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                    raise SecretsError(
                        f"insecure permissions on {path}: must not be group/world "
                        f"accessible (chmod 600)"
                    )
                if st.st_uid != os.geteuid():
                    raise SecretsError(f"{path} is owned by another user")
            raw = os.read(fd, 4096)
        finally:
            os.close(fd)
        try:
            key = bytes.fromhex(raw.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as exc:
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
