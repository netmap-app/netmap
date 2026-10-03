"""Who may use the web UI and REST API, and what the browser is told to allow.

The MCP endpoint is not handled here — `_MCPDispatcher` in main.py sends it
to the MCP app before any of this runs, and it keeps its own two credentials
(the secret path and the bearer token) and its own Host check.

Everything else used to trust the network: Cloudflare Access stood in front of
the public hostname, but the container's port was also open on the LAN, where the
same API answered anyone — including requests that could point a source at
another address and collect the credential stored for it. Being on the LAN is
not an identity, so every request now carries one of three:

  Cf-Access-Jwt-Assertion   the signed token Cloudflare Access adds to every
                            request it lets through (or its CF_Authorization
                            cookie). Verified here — signature, audience,
                            issuer, expiry — because a header anyone can type
                            is not proof that Access ever saw the request.
  Authorization: Bearer     NETMAP_API_TOKEN, for machines on the LAN that
                            cannot log in to Access: a dashboard widget,
                            scripts.
  netmap_session cookie     the local account's password login (/login) —
                            the spare key for when Access is misconfigured.
                            See app/accounts.py.

A browser with none of them is sent to /login; anything else gets a 401.
NETMAP_AUTH=off switches all of it off for a local development copy, and says
so loudly at start-up and in Settings > About.

Two of the three ride on cookies (Access converts its CF_Authorization cookie
into the header), and a cookie is sent on a request another site's page
starts. So a state-changing request identified that way must not carry a
foreign Origin — the bearer token is exempt, since no browser sends it on
its own.
"""
import os
import secrets
from urllib.parse import urlsplit

import anyio
import jwt

from . import accounts

# ---- configuration --------------------------------------------------------
_TEAM = os.environ.get("NETMAP_CF_ACCESS_TEAM", "").strip().rstrip("/")
# Accept "myteam", "myteam.cloudflareaccess.com" or the full https:// URL.
if _TEAM and not _TEAM.startswith("https://"):
    _TEAM = "https://" + (_TEAM if "." in _TEAM else _TEAM + ".cloudflareaccess.com")
CF_ISSUER = _TEAM
CF_AUD = os.environ.get("NETMAP_CF_ACCESS_AUD", "").strip()
API_TOKEN = os.environ.get("NETMAP_API_TOKEN", "").strip()
# Read-only, and only for the counters a dashboard shows: this token opens
# GET /api/summary and nothing else. It lives in a dashboard's config, which
# is exactly the kind of file that gets copied around — so it must not be
# able to change anything, or read the inventory itself.
SUMMARY_TOKEN = os.environ.get("NETMAP_SUMMARY_TOKEN", "").strip()
SUMMARY_PATHS = {"/api/summary"}
# The same idea for a Prometheus scraper: GET /metrics and nothing else, so a
# scrape config never holds a token that can change the inventory.
METRICS_TOKEN = os.environ.get("NETMAP_METRICS_TOKEN", "").strip()
METRICS_PATHS = {"/metrics"}
DISABLED = os.environ.get("NETMAP_AUTH", "").strip().lower() in ("off", "0", "false", "no")

CF_CONFIGURED = bool(CF_ISSUER and CF_AUD)

# Reachable without an identity: the container health check, and the static
# files (public code and images — the page that uses them is not public).
EXEMPT_EXACT = {"/healthz", "/login", "/api/auth/login", "/api/auth/logout"}
EXEMPT_PREFIX = ("/static/",)

_JWKS = (jwt.PyJWKClient(CF_ISSUER + "/cdn-cgi/access/certs",
                         cache_keys=True, lifespan=3600, timeout=5)
         if CF_CONFIGURED else None)


def describe() -> dict:
    """For Settings > About: which doors exist, never what opens them."""
    return {"cf_access": CF_CONFIGURED, "api_token": bool(API_TOKEN),
            "summary_token": bool(SUMMARY_TOKEN), "metrics_token": bool(METRICS_TOKEN),
            "password": True,
            "disabled": DISABLED}


def startup_lines() -> list[str]:
    if DISABLED:
        return ["[netmap] WARNING: NETMAP_AUTH=off — the web UI and REST API "
                "answer anyone who can reach this port"]
    ways = (["Cloudflare Access JWT"] if CF_CONFIGURED else []) + \
           (["API token"] if API_TOKEN else []) + ["password login (/login)"]
    out = [f"[netmap] web UI and REST API require: {' or '.join(ways)}"]
    if not CF_CONFIGURED:
        out.append("[netmap] Cloudflare Access login is off — set "
                   "NETMAP_CF_ACCESS_TEAM and NETMAP_CF_ACCESS_AUD")
    return out


# ---- identity ---------------------------------------------------------------
def _h(headers: dict[bytes, bytes], name: bytes) -> str:
    """A header as text. Latin-1 maps every byte, so a malformed header is
    just a wrong value — never an exception and a 500."""
    return headers.get(name, b"").decode("latin-1")


def bearer_ok(headers: dict[bytes, bytes], token: str) -> bool:
    """The Authorization header is exactly "Bearer <token>". Compared as
    bytes: compare_digest refuses a str with non-ASCII characters."""
    return bool(token) and secrets.compare_digest(
        headers.get(b"authorization", b""), f"Bearer {token}".encode())


def _cookie(raw: str, name: str) -> str:
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return ""


def _verify_cf(token: str) -> str | None:
    """The authenticated identity inside a Cloudflare Access token, or None.
    Runs on a thread: the first call (and a key rotation) fetches the team's
    signing keys over the network."""
    try:
        key = _JWKS.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=CF_AUD,
                            issuer=CF_ISSUER, leeway=30)
    except Exception as exc:
        print(f"[auth] Cloudflare Access token rejected: {type(exc).__name__}: {exc}",
              flush=True)
        return None
    # A person has an e-mail; an Access service token has a common_name.
    return claims.get("email") or claims.get("common_name") or "cloudflare-access"


async def identify(headers: dict[bytes, bytes]) -> tuple[str, str] | None:
    """(who, how) — how is "token", "access", "password" or "off"."""
    if DISABLED:
        return "web", "off"
    if bearer_ok(headers, API_TOKEN):
        return "api-token", "token"
    cookies = _h(headers, b"cookie")
    if CF_CONFIGURED:
        token = _h(headers, b"cf-access-jwt-assertion") or _cookie(cookies, "CF_Authorization")
        if token:
            who = await anyio.to_thread.run_sync(_verify_cf, token)
            if who:
                return who, "access"
    session = _cookie(cookies, accounts.COOKIE)
    if session:
        who = await anyio.to_thread.run_sync(accounts.check_session, session)
        if who:
            return who, "password"
    return None


def _foreign_origin(headers: dict[bytes, bytes]) -> bool:
    """A browser names the page that started a request in Origin. If that
    page is not on this host, the request is someone else's."""
    origin = _h(headers, b"origin")
    if not origin:
        return False
    host = _h(headers, b"host").lower()
    return origin == "null" or urlsplit(origin).netloc.lower() != host


_SAFE = {"GET", "HEAD", "OPTIONS"}


class RequireIdentity:
    """ASGI middleware: no identity, no API. The identity lands in
    `request.state.actor`, which is what the change history records — it
    replaces reading an e-mail out of a header the client chose."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path in EXEMPT_EXACT or path.startswith(EXEMPT_PREFIX):
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        for token, paths, who in ((SUMMARY_TOKEN, SUMMARY_PATHS, "summary"),
                                  (METRICS_TOKEN, METRICS_PATHS, "metrics")):
            if token and path in paths and scope.get("method") in ("GET", "HEAD"):
                if bearer_ok(headers, token):
                    scope.setdefault("state", {}).update(actor=f"{who}-token", auth=who)
                    return await self.app(scope, receive, send)
        found = await identify(headers)
        if found is None:
            # A person arriving at the page goes to the login form; anything
            # else — the API, a script — gets a status it can act on.
            if path == "/" and scope.get("method") in ("GET", "HEAD"):
                return await _redirect(send, "/login")
            return await _deny(send)
        who, how = found
        if how in ("access", "password") and scope.get("method") not in _SAFE \
                and _foreign_origin(headers):
            return await _deny(send, 403, b'{"error":"cross-site request refused"}')
        state = scope.setdefault("state", {})
        state["actor"], state["auth"] = who, how
        return await self.app(scope, receive, send)


async def _deny(send, status: int = 401, body: bytes =
                b'{"error":"authentication required: sign in at /login or through '
                b'Cloudflare Access, or send Authorization: Bearer <NETMAP_API_TOKEN>"}'):
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"),
        (b"www-authenticate", b'Bearer realm="netmap"'),
        (b"cache-control", b"no-store")]})
    await send({"type": "http.response.body", "body": body})


async def _redirect(send, to: str):
    await send({"type": "http.response.start", "status": 303, "headers": [
        (b"location", to.encode()), (b"cache-control", b"no-store")]})
    await send({"type": "http.response.body", "body": b""})


# ---- response headers ---------------------------------------------------------
# One origin serves everything the page needs; nothing is loaded from anywhere
# else, so nothing else is allowed. Inline style attributes remain (the
# templates position a few things with style="…"); inline script does not.
PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            "manifest-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'")

# For the service marks: SVGs fetched from a CDN and served from this origin.
# An <img> never runs script, but opening the URL directly makes it a document —
# sandboxed, it cannot.
ICON_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"

_BASE = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", PAGE_CSP.encode()),
]


class SecurityHeaders:
    """Adds the headers above to every response that does not set its own."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def wrapped(msg):
            if msg["type"] == "http.response.start":
                have = {k.lower() for k, _ in msg.get("headers", [])}
                msg["headers"] = list(msg.get("headers", [])) + [
                    (k, v) for k, v in _BASE if k not in have]
            await send(msg)

        return await self.app(scope, receive, wrapped)


class HostCheck:
    """Refuse a request whose Host is not an allowed name (DNS rebinding:
    a page elsewhere re-pointing its own name at this address). Starlette's
    TrustedHostMiddleware does the same with a bare "Invalid host header",
    which is the first thing a new install opened by its IP address sees —
    so this one says which name was refused and what to set."""

    def __init__(self, app, allowed_hosts: list[str]):
        self.app = app
        self.allowed = [h.lower() for h in allowed_hosts]
        self.any = "*" in self.allowed

    def _ok(self, name: str) -> bool:
        return any(name == h or (h.startswith("*.") and name.endswith(h[1:]))
                   for h in self.allowed)

    async def __call__(self, scope, receive, send):
        if self.any or scope.get("type") not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        host = _h(dict(scope.get("headers") or []), b"host").strip().lower()
        name = host[1:host.index("]")] if host.startswith("[") and "]" in host \
            else host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        if name and self._ok(name):
            return await self.app(scope, receive, send)
        shown = "".join(c for c in name if c.isprintable())[:100] or "(none)"
        body = (f"NetMap does not answer to the name '{shown}'.\n\n"
                "Add it to NETMAP_ALLOWED_HOSTS (comma separated, e.g. "
                f"NETMAP_ALLOWED_HOSTS={shown}) in docker-compose.yml and restart "
                "the container. Only listed names are accepted, which is what "
                "stops DNS rebinding.\n").encode()
        if scope["type"] == "websocket":
            return await send({"type": "websocket.close", "code": 1008})
        await send({"type": "http.response.start", "status": 400,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

