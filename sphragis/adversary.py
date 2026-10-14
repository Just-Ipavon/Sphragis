"""
Adversary toolkit.

"I can build it" is worth more when paired with "and I can break it." This
module models concrete attackers so the test harness can mount real attacks
against the verifier instead of merely asserting that happy-path checks pass.

Two threat classes:

* Key-less attacker — the realistic field adversary. They can read, store and
  resend the URLs a tag emits, and tamper with the bytes, but they do NOT hold
  the secret keys. Everything here must be caught by the MAC or the counter.

* Key-extracting cloner — the worst case. They have physically extracted the
  tag's keys and manufactured a perfect clone. The MAC can no longer tell the
  clone apart; only the *behaviour* of the read counter over time can.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse, urlencode

from .emulator import EmulatedTag


class KeylessAttacker:
    """An attacker who has only observed URLs, without the secret keys."""

    @staticmethod
    def replay(captured_url: str) -> str:
        """Resend a captured tap exactly as-is."""
        return captured_url

    @staticmethod
    def forge_mac(url: str) -> str:
        """Flip one hex digit of the CMAC, hoping to pass authentication."""
        base, _, query = url.partition("?")
        params = parse_qs(query)
        cmac = params["cmac"][0]
        flipped = cmac[:-1] + ("0" if cmac[-1] != "0" else "1")
        params["cmac"] = [flipped]
        return f"{base}?{urlencode({k: v[0] for k, v in params.items()})}"

    @staticmethod
    def truncate_mac(url: str) -> str:
        """Submit a structurally invalid (too-short) CMAC."""
        base, _, query = url.partition("?")
        params = parse_qs(query)
        params["cmac"] = [params["cmac"][0][:8]]
        return f"{base}?{urlencode({k: v[0] for k, v in params.items()})}"

    @staticmethod
    def rollback(older_url: str) -> str:
        """
        Resend an *older* captured tap (lower counter) — e.g. hoping a naive
        backend only checks the MAC and not counter monotonicity.
        """
        return older_url


class KeyCloner:
    """
    Worst case: the attacker extracted the keys and built a perfect clone.

    The clone is cryptographically indistinguishable from the original tap by
    tap. It is a second `EmulatedTag` with the same UID and keys but its own,
    independent counter — which is exactly what the CloneDetector exploits.
    """

    @staticmethod
    def clone(original: EmulatedTag, start_counter: int = 0) -> EmulatedTag:
        return EmulatedTag(
            uid=original.uid,
            meta_read_key=original.meta_read_key,
            file_read_key=original.file_read_key,
            base_url=original.base_url,
            read_counter=start_counter,
        )
