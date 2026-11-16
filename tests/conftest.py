"""
Test-wide settings: every SQLite connection a store opens is closed when the
test ends, so `ResourceWarning` (an error here, see pyproject.toml) flags only
real leaks, not stores a test simply let go of.
"""

import os

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


# --- SoftHSM2 token for the PKCS#11 tests (tests/test_hsm.py, test_api_hsm.py) ----

PKCS11_MODULE = os.environ.get("SPHRAGIS_TEST_PKCS11_MODULE",
                               "/usr/lib/softhsm/libsofthsm2.so")
PKCS11_TOKEN, PKCS11_PIN = "sphragis-test", "5678"


def softhsm_available() -> bool:
    import shutil
    return os.path.exists(PKCS11_MODULE) and shutil.which("softhsm2-util") is not None


@pytest.fixture(scope="session")
def token(tmp_path_factory):
    """A logged-in read-write session on a fresh SoftHSM2 token. SoftHSM reads
    its configuration once per process, so one token serves the whole run;
    tests keep apart by key-label prefix."""
    import subprocess
    pytest.importorskip("pkcs11")
    if not softhsm_available():
        pytest.skip("SoftHSM2 not installed (set SPHRAGIS_TEST_PKCS11_MODULE)")
    from sphragis.hsm import Pkcs11Token
    root = tmp_path_factory.mktemp("softhsm")
    (root / "tokens").mkdir()
    conf = root / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {root / 'tokens'}\n"
                    "objectstore.backend = file\nlog.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = str(conf)
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", PKCS11_TOKEN,
                    "--so-pin", "1234", "--pin", PKCS11_PIN], check=True,
                   capture_output=True)
    tok = Pkcs11Token(PKCS11_MODULE, PKCS11_TOKEN, PKCS11_PIN, rw=True)
    yield tok
    tok.close()
