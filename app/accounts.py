"""The local account: one user, one password — the way in when Cloudflare
Access is not.

Access stays the front door. This is the spare key for the day it is
misconfigured — a wrong team name or AUD tag after a deploy, or Cloudflare
itself having a bad day — when every request would otherwise be refused and
the only fix would be a shell on the VM.

**There is no default password in the code.** The first start takes
NETMAP_ADMIN_PASSWORD if it is set, or else generates one and prints it once
to the container log. Either way the account is marked `must_change` until the
password is changed from Settings > Profile, and the UI says so on every page.
A password published in a README is the first one anybody tries.

Storage is the `kv` table, nothing new in the schema:
  account          JSON {username, hash, must_change, changed_at}
  session_key      random key that signs session cookies (combined with
                   NETMAP_SECRET_KEY when that is set)

Passwords are hashed with scrypt from the standard library. Sessions are
stateless signed cookies carrying the username, an expiry, and a fingerprint of
the password hash — so changing the password logs out every other session
without a sessions table to keep.

Forgot it? On the VM:  docker exec -it netmap python -m app.accounts reset
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time

from . import db

COOKIE = "netmap_session"
SESSION_DAYS = 14
MIN_LENGTH = 10
DEFAULT_USER = "admin"

_N, _R, _P = 2 ** 14, 8, 1


# ---- password hashing -------------------------------------------------------
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(h)}"


def _check(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, want = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=_unb64(salt), n=int(n), r=int(r),
                             p=int(p), dklen=len(_unb64(want)))
        return hmac.compare_digest(got, _unb64(want))
    except Exception:
        return False


# ---- the account ------------------------------------------------------------
def _load() -> dict | None:
    raw = db.get_setting("account")
    return json.loads(raw) if raw else None


def _save(acct: dict) -> None:
    db.set_setting("account", json.dumps(acct))


def bootstrap() -> str | None:
    """Create the account on first start. Returns a generated password to
    print, or None when one was supplied or the account already exists."""
    if _load():
        return None
    given = os.environ.get("NETMAP_ADMIN_PASSWORD", "")
    pw = given or secrets.token_urlsafe(12)
    _save({"username": DEFAULT_USER, "hash": hash_password(pw),
           "must_change": True, "changed_at": db.now()})
    db.log("system", "account-create", None, DEFAULT_USER,
           {"source": "NETMAP_ADMIN_PASSWORD" if given else "generated"})
    return None if given else pw


def profile() -> dict:
    a = _load() or {}
    return {"username": a.get("username", ""), "must_change": bool(a.get("must_change")),
            "password_changed_at": a.get("changed_at")}


def verify(username: str, password: str) -> bool:
    a = _load()
    if not a:
        return False
    # Hash even for a wrong username, so the answer takes the same time.
    ok = _check(password, a["hash"])
    return ok and hmac.compare_digest(username.strip().lower().encode(),
                                      a["username"].lower().encode())


def change_password(current: str, new: str, actor: str) -> None:
    a = _load()
    if not a or not _check(current, a["hash"]):
        raise PermissionError("current password is wrong")
    _validate(new, a["username"])
    if _check(new, a["hash"]):
        raise ValueError("the new password is the same as the current one")
    a.update(hash=hash_password(new), must_change=False, changed_at=db.now())
    _save(a)
    db.log(actor, "password-change", None, a["username"], None)


def rename(new: str, actor: str) -> dict:
    new = (new or "").strip()
    if not (1 <= len(new) <= 64) or any(c.isspace() for c in new):
        raise ValueError("username must be 1–64 characters, no spaces")
    a = _load()
    if not a:
        raise ValueError("there is no local account yet")
    old = a["username"]
    a["username"] = new
    _save(a)
    db.log(actor, "account-rename", None, new, {"from": old})
    return profile()


def _validate(pw: str, username: str) -> None:
    if len(pw) < MIN_LENGTH:
        raise ValueError(f"the password needs at least {MIN_LENGTH} characters")
    if pw.lower() in (username.lower(), "password", "netmap", "admin") or len(set(pw)) < 4:
        raise ValueError("that password is too easy to guess")


def reset(actor: str = "shell") -> str:
    """New random password, must_change set. For the CLI below."""
    a = _load() or {"username": DEFAULT_USER}
    pw = secrets.token_urlsafe(12)
    a.update(hash=hash_password(pw), must_change=True, changed_at=db.now())
    _save(a)
    db.log(actor, "password-reset", None, a["username"], None)
    return pw


# ---- sessions ---------------------------------------------------------------
def _key() -> bytes:
    """The key that signs session cookies. With NETMAP_SECRET_KEY set it is
    derived from that as well, so — like the source secrets — a copy of
    netmap.db alone is not enough to forge a session. Setting or changing the
    variable signs everyone out, once."""
    k = db.get_setting("session_key")
    if not k:
        k = secrets.token_urlsafe(32)
        db.set_setting("session_key", k)
    env = os.environ.get("NETMAP_SECRET_KEY", "").strip()
    if not env:
        return k.encode()
    return hmac.new(env.encode(), b"netmap-session:" + k.encode(), hashlib.sha256).digest()


def _fp(acct: dict) -> str:
    return hashlib.sha256(acct["hash"].encode()).hexdigest()[:16]


def issue() -> str:
    a = _load()
    body = _b64(json.dumps({"u": a["username"], "exp": int(time.time()) + SESSION_DAYS * 86400,
                            "v": _fp(a)}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_key(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def check_session(token: str) -> str | None:
    """The username a session cookie belongs to, if it is genuine, unexpired,
    and was issued under the current password and username."""
    try:
        body, sig = token.split(".")
        want = _b64(hmac.new(_key(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, want):
            return None
        d = json.loads(_unb64(body))
        a = _load()
        if not a or d["exp"] < time.time() or d["v"] != _fp(a) or d["u"] != a["username"]:
            return None
        return a["username"]
    except Exception:
        return None


# ---- throttling ---------------------------------------------------------------
# Per client and overall. Behind the tunnel every request arrives from the
# cloudflared container, so "per client" uses the address Cloudflare reports —
# which a LAN client could forge, hence the overall ceiling as well. Hitting it
# locks the password door only; Access and the API token still work.
WINDOW = 15 * 60
PER_CLIENT = 5
OVERALL = 20
_FAILS: dict[str, list[float]] = {}
_LOCK = threading.Lock()


def _recent(key: str, now: float) -> list[float]:
    ts = [t for t in _FAILS.get(key, []) if now - t < WINDOW]
    _FAILS[key] = ts
    return ts


def throttled(client: str) -> int:
    """Seconds until another attempt is allowed, or 0."""
    now = time.time()
    with _LOCK:
        for key, cap in ((client, PER_CLIENT), ("*", OVERALL)):
            ts = _recent(key, now)
            if len(ts) >= cap:
                return int(WINDOW - (now - ts[0])) + 1
    return 0


def failed(client: str) -> None:
    now = time.time()
    with _LOCK:
        for key in (client, "*"):
            _recent(key, now).append(now)


def succeeded(client: str) -> None:
    with _LOCK:
        _FAILS.pop(client, None)


# ---- CLI --------------------------------------------------------------------
if __name__ == "__main__":
    if sys.argv[1:] == ["reset"]:
        db.init()
        pw = reset()
        print(f"Password for '{profile()['username']}' reset to:\n\n    {pw}\n\n"
              "Sign in and change it under Settings > Profile. Every existing "
              "session has been logged out.")
    else:
        print("usage: python -m app.accounts reset")
        sys.exit(2)
