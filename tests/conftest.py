"""
Test-wide settings: every SQLite connection a store opens is closed when the
test ends, so `ResourceWarning` (an error here, see pyproject.toml) flags only
real leaks, not stores a test simply let go of.
"""

import pytest

from sphragis.sqlstore import ThreadConnections


@pytest.fixture(autouse=True)
def _close_store_connections(monkeypatch):
    opened = []
    original = ThreadConnections.__init__

    def tracking_init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(ThreadConnections, "__init__", tracking_init)
    yield
    for conns in opened:
        conns.close()
