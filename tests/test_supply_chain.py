"""
Supply-chain guards (#28): the engine refuses the abandoned PyCrypto, the CI
installs only hash-locked dependencies and pins its actions by commit.
"""

import importlib.util
import os
import re
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)


def _reload_check(monkeypatch, crypto):
    """Run sphragis/_cryptocheck.py against a stand-in `Crypto` module."""
    monkeypatch.setitem(sys.modules, "Crypto", crypto)
    spec = importlib.util.spec_from_file_location(
        "_cryptocheck_under_test", os.path.join(ROOT, "sphragis", "_cryptocheck.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("attrs", [
    {"__version__": "2.6.1"},                           # PyCrypto: no version_info
    {"__version__": "2.6.1", "version_info": (2, 6, 1)},
])
def test_pycrypto_is_refused(monkeypatch, attrs):
    with pytest.raises(ImportError, match="not pycryptodome"):
        _reload_check(monkeypatch, types.SimpleNamespace(**attrs))


def test_pycryptodome_is_accepted(monkeypatch):
    fake = types.SimpleNamespace(__version__="3.20.0", version_info=(3, 20, "0"))
    assert _reload_check(monkeypatch, fake)
    monkeypatch.undo()
    import Crypto
    assert Crypto.version_info[0] >= 3                  # the real environment


def _read(*parts):
    with open(os.path.join(ROOT, *parts)) as f:
        return f.read()


def test_ci_installs_only_locked_hashed_dependencies():
    ci = _read(".github", "workflows", "ci.yml")
    assert ci.count("--require-hashes -r requirements/ci.lock") == 2
    assert "pip install -e" not in ci                   # nothing resolved on the fly
    lock = _read("requirements", "ci.lock")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==", lock, re.M)
    assert {"pycryptodome", "fastapi", "psycopg", "pytest"} <= {p.lower() for p in pins}
    assert lock.count("--hash=sha256:") >= len(pins)


@pytest.mark.parametrize("workflow", ["ci.yml", "security.yml"])
def test_workflows_pin_actions_and_drop_token_rights(workflow):
    text = _read(".github", "workflows", workflow)
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses
    assert re.search(r"^permissions:\n  contents: read", text, re.M)


def test_runtime_state_and_secrets_are_ignored():
    ignore = _read(".gitignore")
    for pattern in ("*.db", "*.sqlite", "keys/", "*.lock", "!requirements/*.lock"):
        assert pattern in ignore.splitlines(), pattern
