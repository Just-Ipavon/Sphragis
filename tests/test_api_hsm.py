"""The REST API with SPHRAGIS_KEY_PROVIDER=pkcs11: no master key in the process."""

import os
import stat
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(__file__))

pytest.importorskip("fastapi")
pytest.importorskip("pkcs11")

from conftest import PKCS11_MODULE, PKCS11_PIN, PKCS11_TOKEN  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sphragis.api import create_app_from_env  # noqa: E402
from sphragis.api.settings import ApiSettings  # noqa: E402
from sphragis.cli import main as cli  # noqa: E402
from sphragis.diversify import DiversifiedKeys  # noqa: E402
from sphragis.emulator import tag_from_provider  # noqa: E402


class NoMasterKeys:
    """Only what the API needs besides the SDM keys; asking for a master fails."""

    def get_key(self, name):
        if name == "log_pseudonym":
            return bytes(range(16))
        raise AssertionError(f"the API asked the secrets backend for {name!r}")


@pytest.fixture
def keys_dir(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir(mode=0o700)
    keys = {}
    for name in ("master_file", "meta_read", "master_file_v2", "meta_read_v2"):
        keys[name] = os.urandom(16)
        path = directory / name
        path.write_text(keys[name].hex())
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return directory, keys


def test_api_verifies_with_the_masters_in_the_token(token, keys_dir, tmp_path,
                                                    monkeypatch, capsys):
    directory, keys = keys_dir
    prefix = f"api{uuid.uuid4().hex[:6]}."
    monkeypatch.setenv("SPHRAGIS_PKCS11_PIN", PKCS11_PIN)
    assert cli(["hsm-import", "--module", PKCS11_MODULE, "--token", PKCS11_TOKEN,
                "--secrets-dir", str(directory), "--versions", "1,2",
                "--prefix", prefix]) == 0
    assert capsys.readouterr().out.count("not extractable") == 4
    with pytest.raises(SystemExit):              # labels already there
        cli(["hsm-import", "--module", PKCS11_MODULE, "--token", PKCS11_TOKEN,
             "--secrets-dir", str(directory), "--prefix", prefix])

    pin_file = tmp_path / "pin"
    pin_file.write_text(PKCS11_PIN + "\n")
    env = {"SPHRAGIS_DB_PATH": str(tmp_path / "s.db"), "SPHRAGIS_KEY_CONTEXT": "DEMO",
           "SPHRAGIS_KEY_PROVIDER": "pkcs11", "SPHRAGIS_PKCS11_MODULE": PKCS11_MODULE,
           "SPHRAGIS_PKCS11_TOKEN": PKCS11_TOKEN, "SPHRAGIS_PKCS11_KEY_PREFIX": prefix,
           "SPHRAGIS_PKCS11_PIN_FILE": str(pin_file), "SPHRAGIS_KEY_VERSIONS": "2,1"}
    with TestClient(create_app_from_env(env, secrets=NoMasterKeys())) as client:
        for suffix in ("", "_v2"):
            software = DiversifiedKeys(keys["master_file" + suffix],
                                       keys["meta_read" + suffix], context=b"DEMO")
            tag = tag_from_provider(software, os.urandom(7))
            url = tag.tap()
            assert client.post("/v1/verify", json={"url": url}).json()["verdict"] == \
                "GENUINE"
            assert client.post("/v1/verify", json={"url": url}).json()["verdict"] == \
                "REPLAY"


@pytest.mark.parametrize("env", [
    {"SPHRAGIS_KEY_PROVIDER": "kms"},
    {"SPHRAGIS_KEY_PROVIDER": "pkcs11"},
    {"SPHRAGIS_KEY_PROVIDER": "pkcs11", "SPHRAGIS_PKCS11_MODULE": "/x.so"},
    {"SPHRAGIS_PKCS11_CACHE_SECONDS": "-1"},
])
def test_key_provider_settings_are_validated(env):
    with pytest.raises(ValueError):
        ApiSettings.from_env(env)


def test_pkcs11_needs_a_pin(tmp_path, monkeypatch):
    monkeypatch.delenv("SPHRAGIS_PKCS11_PIN", raising=False)
    env = {"SPHRAGIS_DB_PATH": str(tmp_path / "s.db"), "SPHRAGIS_KEY_PROVIDER": "pkcs11",
           "SPHRAGIS_PKCS11_MODULE": PKCS11_MODULE, "SPHRAGIS_PKCS11_TOKEN": "t"}
    with pytest.raises(ValueError, match="PIN"):
        create_app_from_env(env, secrets=NoMasterKeys())
