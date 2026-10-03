"""The local password login and Settings > Profile. See app/accounts.py."""
import os
import subprocess
import sys

import pytest

START = "start-pass-123"


@pytest.fixture
def pw(make_app):
    main, c = make_app(NETMAP_ADMIN_PASSWORD=START)
    from app import accounts
    assert accounts.bootstrap() is None          # supplied, so nothing to print
    return c, accounts


def login(c, user="admin", password=START, **headers):
    return c.post("/api/auth/login", json={"username": user, "password": password},
                  headers=headers)


def test_generated_password_when_none_supplied(make_app):
    make_app()
    from app import accounts
    generated = accounts.bootstrap()
    assert generated and len(generated) >= 12
    assert accounts.verify("admin", generated)
    assert accounts.profile()["must_change"]
    assert accounts.bootstrap() is None          # only ever on the first start


def test_login_sets_a_strict_httponly_session(pw):
    c, _ = pw
    assert login(c, password="wrong").status_code == 401
    r = login(c, user="Admin")                   # username is case-insensitive
    assert r.status_code == 200 and r.json()["must_change"]
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "samesite=strict" in cookie.lower()
    assert c.get("/api/meta").status_code == 200
    p = c.get("/api/profile").json()
    assert p["via"] == "password" and p["signed_in_as"] == "admin"


def test_login_from_another_site_is_refused(pw):
    c, _ = pw
    assert login(c, origin="https://evil.example").status_code == 403


def test_password_change_rules_and_session_invalidation(pw):
    c, accounts = pw
    login(c)
    old = c.cookies.get(accounts.COOKIE)
    change = lambda cur, new: c.post("/api/profile/password", json={"current": cur, "new": new})
    assert change("bad", "another-good-pass").status_code == 403
    assert change(START, "short").status_code == 400
    assert change(START, "admin").status_code == 400
    r = change(START, "a-much-better-pass")
    assert r.status_code == 200 and not r.json()["must_change"]
    assert c.get("/api/meta").status_code == 200          # this browser stays in
    from fastapi.testclient import TestClient
    from app import main
    other = TestClient(main.application)
    other.cookies.set(accounts.COOKIE, old)
    assert other.get("/api/meta").status_code == 401      # every other session ends


def test_rename_keeps_the_session(pw):
    c, accounts = pw
    login(c)
    assert c.put("/api/profile", json={"username": "has space"}).status_code == 400
    assert c.put("/api/profile", json={"username": "alex"}).status_code == 200
    assert c.get("/api/meta").status_code == 200
    assert accounts.verify("alex", START) and not accounts.verify("admin", START)


def test_logout(pw):
    c, _ = pw
    login(c)
    c.post("/api/auth/logout")
    assert c.get("/api/meta").status_code == 401


def test_throttle_after_five_failures(pw):
    c, _ = pw
    codes = [login(c, password="wrong").status_code for _ in range(6)]
    assert codes == [401] * 5 + [429]
    assert login(c).status_code == 429          # even the right password, until it expires


def test_cli_reset(pw, tmp_path):
    _, accounts = pw
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {**os.environ, "NETMAP_DB": str(tmp_path / "netmap.db")}
    out = subprocess.run([sys.executable, "-m", "app.accounts", "reset"], cwd=root,
                         env=env, capture_output=True, text=True, check=True).stdout
    new = out.split("reset to:")[1].split()[0]
    assert accounts.verify("admin", new) and accounts.profile()["must_change"]


def test_the_database_alone_cannot_sign_a_session_when_a_secret_key_is_set(make_app):
    import base64
    import hashlib
    import hmac
    import json
    import time
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode()
    _, c = make_app(NETMAP_ADMIN_PASSWORD=START, NETMAP_SECRET_KEY=key)
    from app import accounts, db
    accounts.bootstrap()
    assert login(c).status_code == 200
    assert c.get("/api/meta").status_code == 200
    # What someone holding only a copy of netmap.db could build.
    a = json.loads(db.get_setting("account"))
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")      # noqa: E731
    body = b64(json.dumps({"u": a["username"], "exp": int(time.time()) + 3600,
                           "v": hashlib.sha256(a["hash"].encode()).hexdigest()[:16]},
                          separators=(",", ":")).encode())
    sig = b64(hmac.new(db.get_setting("session_key").encode(), body.encode(),
                       hashlib.sha256).digest())
    assert accounts.check_session(f"{body}.{sig}") is None
    assert accounts.check_session(accounts.issue()) == "admin"
