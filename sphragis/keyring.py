"""
Key rings — several key versions active at once, for rotation without loss.

Rotating keys on deployed tags is gradual: tags are rekeyed one by one, so for
a while some answer under the old keys and some under the new. A `KeyRing`
holds every active version, newest first; the NTAG 424 DNA backends try each
in turn and report which one verified (`AuthenticTap.key_version`). The
identity of a tag (its UID) does not depend on the key version, so its anti-
replay floor and detector history carry over the rotation unchanged.

Versions are addressed by (name, version) in a `SecretsBackend`: version 1 is
the unsuffixed name every deployment already has (`master_file`), version N > 1
is `<name>_v<N>` (`master_file_v2`, env `SPHRAGIS_MASTER_FILE_V2`). Retire a
version by dropping it from the ring once no tag answers under it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Iterator, Sequence

from .diversify import DiversifiedKeys

if TYPE_CHECKING:
    from .verifier import KeyProvider


def versioned_name(name: str, version: int) -> str:
    """The secrets-backend name of key `name` at `version`."""
    if version < 1:
        raise ValueError("key versions start at 1")
    return name if version == 1 else f"{name}_v{version}"


class KeyRing:
    """Ordered (version, KeyProvider) pairs, current version first."""

    def __init__(self, entries: Iterable[tuple[int, KeyProvider]]) -> None:
        self._entries = tuple(entries)
        if not self._entries:
            raise ValueError("a key ring needs at least one version")
        versions = [v for v, _ in self._entries]
        if len(set(versions)) != len(versions) or min(versions) < 1:
            raise ValueError("key versions must be distinct and >= 1")

    @classmethod
    def of(cls, keys: "KeyProvider | KeyRing") -> "KeyRing":
        """A ring as is, or a single provider as version 1."""
        return keys if isinstance(keys, KeyRing) else cls([(1, keys)])

    @property
    def current_version(self) -> int:
        return self._entries[0][0]

    @property
    def versions(self) -> tuple[int, ...]:
        return tuple(v for v, _ in self._entries)

    def __iter__(self) -> Iterator[tuple[int, KeyProvider]]:
        return iter(self._entries)


def build_keyring(
    backend,
    versions: Sequence[int] = (1,),
    master_file_name: str = "master_file",
    meta_name: str = "meta_read",
    context: bytes = b"",
) -> KeyRing:
    """
    Load every listed version of the master file key and meta-read key from a
    `SecretsBackend`, current version first, as per-UID `DiversifiedKeys`.
    """
    return KeyRing(
        (v, DiversifiedKeys(backend.get_key(versioned_name(master_file_name, v)),
                            backend.get_key(versioned_name(meta_name, v)),
                            context=context))
        for v in versions
    )
