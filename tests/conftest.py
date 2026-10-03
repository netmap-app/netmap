"""Shared fixtures.

NetMap reads its configuration once, at import: the auth mode and tokens in
web_security, the database path in db, the MCP path in main. Sources are
database rows, seeded once from the environment by sources.migrate_legacy(),
which `make_app` runs like start-up does. A test that needs a particular configuration
therefore needs those modules *re-imported* under that environment — which is
what `make_app` does. `importlib.reload` re-executes a module inside the same
module object, so every `from . import db` elsewhere keeps pointing at the
reloaded one.

Nothing here reaches the network or a real homelab: each app gets an empty
database in a temp directory, and no source exists unless a test adds one.
"""
import importlib
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Order matters: a module is reloaded after the modules whose state it reads.
_RELOAD = [
    "app.db", "app.icons", "app.crypto", "app.accounts", "app.status", "app.digest", "app.notify",
    "app.sources.fields", "app.sources.portscan", "app.sources.npm",
    "app.sources.pihole", "app.sources.unifi", "app.sources.opnsense",
    "app.sources.cloudflare", "app.sources",
    "app.web_security", "app.main",
]

BASE_ENV = {
    "NETMAP_ALLOWED_HOSTS": "testserver,netmap.example.org",
    "NETMAP_MCP_PATH": "/private_test",
    "NETMAP_MCP_TOKEN": "mcp-test-token",
}


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    """make_app(**env) -> (main module, TestClient). Every NETMAP_* variable
    from the outer environment is cleared first, so a developer's shell cannot
    change what a test sees."""
    from fastapi.testclient import TestClient

    def _make(**env):
        for k in list(os.environ):
            if k.startswith("NETMAP_"):
                monkeypatch.delenv(k)
        monkeypatch.setenv("NETMAP_DB", str(tmp_path / "netmap.db"))
        for k, v in {**BASE_ENV, **env}.items():
            monkeypatch.setenv(k, v)
        mods = {}
        for name in _RELOAD:
            mods[name] = (importlib.reload(sys.modules[name]) if name in sys.modules
                          else importlib.import_module(name))
        # No lifespan: the background loops and the icon fetch reach the
        # network. Do the parts of start-up the tests rely on by hand.
        mods["app.db"].init()
        mods["app.sources"].migrate_legacy()
        return mods["app.main"], TestClient(mods["app.main"].application)

    return _make
