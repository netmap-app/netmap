"""Browser tests: a real NetMap server per test, driven by headless Chromium.

Each test gets its own server process on a free port with an empty database
in a temp directory, authentication off and the background loops slowed to
a crawl — so nothing reaches a homelab. State is set up through the REST API,
or written straight into the database for what only a scan would produce
(sightings), and the page is asserted on by its DOM, not a screenshot.

Every test also fails on an uncaught page error. A render exception is how
the Overview once showed "Loading…" forever.

Needs Chromium for Playwright:
    .venv/bin/python -m playwright install chromium
Without it these tests are skipped locally; CI installs it, sets
NETMAP_UI_REQUIRED=1, and fails rather than skips if it is missing.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sync_api = pytest.importorskip("playwright.sync_api")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, tmp):
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.db = str(tmp / "netmap.db")
        env = {k: v for k, v in os.environ.items() if not k.startswith("NETMAP_")}
        env.update(NETMAP_DB=self.db, NETMAP_AUTH="off",
                   NETMAP_ALLOWED_HOSTS="127.0.0.1",
                   NETMAP_CHECK_INTERVAL="3600", NETMAP_DISCOVERY_INTERVAL="86400")
        self.log = open(tmp / "server.log", "w")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:application",
             "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                urllib.request.urlopen(self.url + "/healthz", timeout=1)
                return
            except Exception:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.1)
        raise RuntimeError("server did not start — see " + str(tmp / "server.log"))

    def api(self, method: str, path: str, body=None):
        req = urllib.request.Request(
            self.url + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read() or "null")

    def sightings(self, source: str, rows: list[dict]):
        """What a scan would have recorded — written straight into the database."""
        c = sqlite3.connect(self.db)
        c.executemany("INSERT INTO sightings (entry_id, fact, value, source, seen_at) "
                      "VALUES (?,?,?,?, datetime('now'))",
                      [(r["entry_id"], r["fact"], r["value"], source) for r in rows])
        c.commit()
        c.close()

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


@pytest.fixture
def server(tmp_path):
    s = Server(tmp_path)
    yield s
    s.stop()


@pytest.fixture(scope="session")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:
            why = (f"Chromium for Playwright is not installed ({exc.__class__.__name__}) — "
                   ".venv/bin/python -m playwright install chromium")
            if os.environ.get("NETMAP_UI_REQUIRED"):
                pytest.fail(why)             # CI: a skipped UI suite is not a pass
            pytest.skip(why)
        yield b
        b.close()


@pytest.fixture
def page(browser, server):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    errors: list[str] = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.set_default_timeout(8000)
    pg.goto(server.url + "/")
    pg.wait_for_selector("#overview .verdict")
    yield pg
    ctx.close()
    assert not errors, f"uncaught page errors: {errors}"
