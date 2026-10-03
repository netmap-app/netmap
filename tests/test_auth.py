"""Who gets in: the three identities, the host check, the MCP path's own guard,
and the headers every response carries. See app/web_security.py."""
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

TOKEN = {"authorization": "Bearer full-token"}


# ---- nothing configured ---------------------------------------------------------
def test_no_identity_is_refused(make_app):
    _, c = make_app()
    assert c.get("/api/meta").status_code == 401
    assert c.get("/api/entries").status_code == 401


def test_open_paths_stay_open(make_app):
    _, c = make_app()
    assert c.get("/healthz").status_code == 200
    assert c.get("/static/js/boot.js").status_code == 200
    assert c.get("/login").status_code == 200


def test_signed_out_browser_goes_to_login(make_app):
    _, c = make_app()
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_client_chosen_identity_headers_are_ignored(make_app):
    _, c = make_app()
    r = c.get("/api/meta", headers={"cf-access-authenticated-user-email": "x@y.z",
                                    "x-netmap-actor": "someone"})
    assert r.status_code == 401


def test_auth_off_opens_everything(make_app):
    _, c = make_app(NETMAP_AUTH="off")
    assert c.get("/api/meta").status_code == 200


# ---- API token --------------------------------------------------------------------
def test_api_token(make_app):
    main, c = make_app(NETMAP_API_TOKEN="full-token")
    assert c.get("/api/meta", headers=TOKEN).status_code == 200
    assert c.get("/api/meta", headers={"authorization": "Bearer nope"}).status_code == 401
    c.post("/api/entries", headers=TOKEN, json={"name": "made-by-token"})
    from app import db
    assert db.audit(1)[0]["actor"] == "api-token"


# ---- read-only summary token ---------------------------------------------------------
def test_summary_token_opens_summary_only(make_app):
    _, c = make_app(NETMAP_SUMMARY_TOKEN="ro-token", NETMAP_API_TOKEN="full-token")
    ro = {"authorization": "Bearer ro-token"}
    r = c.get("/api/summary", headers=ro)
    assert r.status_code == 200 and "total" in r.json()
    for path in ("/api/entries", "/api/meta", "/api/about", "/api/export.json"):
        assert c.get(path, headers=ro).status_code == 401, path
    assert c.post("/api/entries", headers=ro, json={"name": "x"}).status_code == 401
    assert c.get("/api/summary", headers=TOKEN).status_code == 200


# ---- host check -----------------------------------------------------------------------
def test_foreign_host_is_refused(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    r = c.get("/api/meta", headers={**TOKEN, "host": "attacker.example"})
    assert r.status_code == 400
    # It says which name and what to set — a new install opened by its IP
    # address sees exactly this.
    assert "'attacker.example'" in r.text and "NETMAP_ALLOWED_HOSTS" in r.text
    r = c.get("/api/meta", headers={**TOKEN, "host": "192.0.2.7:8087"})
    assert r.status_code == 400 and "'192.0.2.7'" in r.text
    assert c.get("/api/meta", headers={**TOKEN, "host": "localhost:8087"}).status_code == 200
    assert c.get("/api/meta", headers={**TOKEN, "host": "[::1]:8087"}).status_code == 400
    assert c.get("/api/meta", headers={**TOKEN, "host": "netmap.example.org"}).status_code == 200


# ---- Cloudflare Access ------------------------------------------------------------------
@pytest.fixture
def cf(make_app):
    """An app that trusts a test signing key instead of Cloudflare's."""
    main, c = make_app(NETMAP_CF_ACCESS_TEAM="example-team", NETMAP_CF_ACCESS_AUD="aud123")
    from app import web_security
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class _Key:
        pass
    _Key.key = key.public_key()

    class _Jwks:
        def get_signing_key_from_jwt(self, _token):
            return _Key

    web_security._JWKS = _Jwks()

    def token(signer=key, **claims):
        base = {"iss": "https://example-team.cloudflareaccess.com", "aud": ["aud123"],
                "email": "me@example.com", "exp": int(time.time()) + 60}
        return jwt.encode({**base, **claims}, signer, algorithm="RS256")

    return c, token


def test_access_jwt_header(cf):
    c, token = cf
    r = c.post("/api/entries", headers={"cf-access-jwt-assertion": token()}, json={"name": "cf"})
    assert r.status_code == 201
    from app import db
    assert db.audit(1)[0]["actor"] == "me@example.com"


def test_access_jwt_cookie(cf):
    c, token = cf
    c.cookies.set("CF_Authorization", token())
    assert c.get("/api/meta").status_code == 200


@pytest.mark.parametrize("claims", [{"aud": ["other"]}, {"exp": int(time.time()) - 300},
                                    {"iss": "https://evil.cloudflareaccess.com"}])
def test_access_jwt_bad_claims(cf, claims):
    c, token = cf
    assert c.get("/api/meta", headers={"cf-access-jwt-assertion": token(**claims)}).status_code == 401


def test_access_jwt_forged_signature(cf):
    c, token = cf
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert c.get("/api/meta", headers={"cf-access-jwt-assertion": token(signer=other)}).status_code == 401


def test_cookie_write_from_foreign_origin_is_refused(cf):
    c, token = cf
    c.cookies.set("CF_Authorization", token())
    assert c.post("/api/entries", json={"name": "x"},
                  headers={"origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/entries", json={"name": "x"},
                  headers={"origin": "http://testserver"}).status_code == 201


# ---- MCP path ------------------------------------------------------------------------------
def test_mcp_path_keeps_its_own_token(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    h = {"host": "localhost", "accept": "application/json, text/event-stream"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    assert c.post("/private_test", headers=h, json=body).status_code == 401
    # The web API's token is not the MCP token.
    assert c.post("/private_test", headers={**h, **TOKEN}, json=body).status_code == 401


# ---- response headers ------------------------------------------------------------------------
def test_page_security_headers(make_app):
    _, c = make_app(NETMAP_AUTH="off")
    r = c.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_icons_are_sandboxed(make_app):
    _, c = make_app(NETMAP_AUTH="off")
    from app import icons
    import os
    os.makedirs(icons.CACHE, exist_ok=True)
    with open(icons._file("plex", ".svg"), "wb") as f:
        f.write(b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>")
    r = c.get("/api/icon/plex.svg")
    assert r.status_code == 200 and "sandbox" in r.headers["content-security-policy"]


def test_allowed_hosts_listed_once(make_app):
    main, _ = make_app(NETMAP_ALLOWED_HOSTS="localhost,netmap.example.org")
    assert main.ALLOWED_HOSTS.count("localhost") == 1


# ---- malformed headers and an MCP endpoint without its token ---------------------------------
def _raw(app, path: str, auth: bytes) -> int:
    """One request straight to the ASGI app — a test client refuses to send
    the malformed header this is about."""
    import asyncio
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "method": "POST", "path": path, "query_string": b"",
             "headers": [(b"host", b"localhost"), (b"authorization", auth)],
             "scheme": "http", "server": ("localhost", 80), "client": ("127.0.0.1", 1),
             "root_path": "", "http_version": "1.1"}
    asyncio.run(app(scope, receive, send))
    return sent[0]["status"]


def test_a_malformed_authorization_header_is_refused_not_a_crash(make_app):
    main, _ = make_app(NETMAP_API_TOKEN="full-token")
    assert _raw(main.application, "/private_test", "Bearer café".encode()) == 401
    assert _raw(main.application, "/api/entries", b"Bearer \xff\xfe") == 401


def test_an_mcp_endpoint_without_a_token_is_warned_about(make_app):
    main, c = make_app(NETMAP_API_TOKEN="full-token", NETMAP_MCP_TOKEN="")
    assert main.mcp_warnings() and "NETMAP_MCP_TOKEN" in main.mcp_warnings()[0]
    keys = [i["key"] for i in c.get("/api/overview", headers=TOKEN).json()["attention"]]
    assert "mcp-open" in keys
    main, c = make_app(NETMAP_API_TOKEN="full-token")
    assert main.mcp_warnings() == []
    keys = [i["key"] for i in c.get("/api/overview", headers=TOKEN).json()["attention"]]
    assert "mcp-open" not in keys


def test_health_does_not_name_the_mcp_path(make_app):
    _, c = make_app(NETMAP_MCP_PATH="/mcp")
    assert "mcp_path" not in c.get("/healthz").json()
