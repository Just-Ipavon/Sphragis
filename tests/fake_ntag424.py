"""Tests' name for the packaged simulator (sphragis.simulator)."""

from sphragis.simulator import TEST_ORIGINALITY_KEY, SimulatedNtag424, sign_uid

FakeNtag424 = SimulatedNtag424

__all__ = ["FakeNtag424", "TEST_ORIGINALITY_KEY", "sign_uid"]
