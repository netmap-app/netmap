"""Nginx Proxy Manager as a discovery source.

NPM was the last thing in the path a request takes that nothing read. The
Cloudflare source knows which hostnames arrive at the house; `runs_on` knows
where services live; between the two sits the proxy that decides which name
reaches which port, and NetMap could only *infer* it — `exposed_by` edges were
guessed from the `url` field, and the Cloudflare source had to ask Pi-hole what
NPM was probably doing.

This is also the one leg where comparing the forwarding target with the entry
is meaningful. At the edge it is not: most hostnames land on NPM rather than on
the service, so `plex.example.org → 10.0.0.10:443` is correct even though Plex
listens on 32400. NPM forwards to the service itself, so a mismatch here is a
real disagreement rather than an artefact of proxying.

  POST /api/tokens              log in (the one POST in this module)
  GET  /api/nginx/proxy-hosts   the hostnames and where each one goes
  GET  /api/nginx/certificates  what is about to expire

Unlike OPNsense, Pi-hole and Home Assistant, this source can be given a
credential that genuinely cannot write: NPM has per-resource permissions, and a
non-admin user set to **View Only** on proxy hosts is enforced by NPM itself.
"""
import datetime as dt
import json
import os
import time
import urllib.error
import urllib.request

from .. import db
from . import _http, _proxy, fields

FIELDS = [
    {"key": "url", "label": "NPM URL", "type": "text", "required": True, "wide": True,
     "placeholder": "http://10.0.0.10:81", "binds": True, "env": "NETMAP_NPM_URL"},
    {"key": "user", "label": "Email", "type": "text", "required": True, "wide": True,
     "binds": True, "env": "NETMAP_NPM_USER"},
    {"key": "password", "label": "Password", "type": "password", "secret": True,
     "required": True, "wide": True, "env": "NETMAP_NPM_PASSWORD"},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox",
     "default": True, "env": "NETMAP_NPM_VERIFY"},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 8,
     "env": "NETMAP_NPM_TIMEOUT"},
    # Let's Encrypt renews itself until the day it does not, and the failure
    # is silent until a browser refuses the page.
    {"key": "cert_days", "label": "Warn when a certificate expires within (days)",
     "type": "number", "integer": True, "default": 21, "env": "NETMAP_NPM_CERT_DAYS"},
]

ROLES = ("proxy",)  # see dynamic.ROLES


# NPM issues a bearer token with an expiry. Kept and reused, in the instance's
# own state (cfg["_state"]: token, token_at, and expires — whatever NPM said,
# verbatim, for diagnosis); a fresh login on every scan would be pointless
# traffic against a service whose whole job is answering other people's
# requests. Settings drops the state on any change.
# NPM issues tokens with a finite life and we cannot see the format of its
# expiry field without looking, so the token is simply refreshed on a timer
# well inside any plausible lifetime. A login is one cheap POST.
TOKEN_MAX_AGE = float(os.environ.get("NETMAP_NPM_TOKEN_MAX_AGE", "1800"))


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("user") and cfg.get("password"))


def _why(exc: urllib.error.HTTPError) -> str:
    """NPM's own explanation, which is in the body and not in the status.

    It answers 400 for a bad login as readily as for a malformed request, so
    the code alone cannot tell "wrong password" from "wrong request" — and a
    scan that reports only the number sends you looking in the wrong place.
    """
    try:
        body = json.loads(exc.read())
    except Exception:
        return ""
    err = body.get("error") if isinstance(body, dict) else None
    msg = (err or {}).get("message") if isinstance(err, dict) else None
    return str(msg or "").strip()


def _login(cfg: dict) -> str:
    """The one POST in this module."""
    # Exactly these two fields. NPM's token schema sets
    # additionalProperties:false, so sending a documented-looking extra like
    # `expiry` is refused with "data must NOT have additional properties" —
    # a 400 that looks exactly like a rejected login and is not one.
    body = json.dumps({"identity": cfg["user"], "secret": cfg["password"]}).encode()
    req = urllib.request.Request(
        cfg["url"] + "/api/tokens", data=body, method="POST",
        headers={"content-type": "application/json", "accept": "application/json"})
    try:
        with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as exc:
        why = _why(exc)
        raise RuntimeError(
            f"login refused, HTTP {exc.code}" + (f" — {why}" if why else "")
            + (" (the user is the account's e-mail address, not a name)"
               if exc.code in (400, 401) and not why else "")) from None
    token = data.get("token") or ""
    if not token:
        raise RuntimeError("NPM accepted the login but returned no token")
    state = cfg.setdefault("_state", {})
    state["token_at"] = time.time()
    state["expires"] = data.get("expires")
    return token


def _get(cfg: dict, path: str, _retry: bool = True):
    state = cfg.setdefault("_state", {})
    if not state.get("token") or time.time() - state.get("token_at", 0) > TOKEN_MAX_AGE:
        state["token"] = _login(cfg)
    req = urllib.request.Request(
        cfg["url"] + path, headers={"accept": "application/json",
                                    "authorization": f"Bearer {state['token']}"})
    try:
        with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        # 400 belongs in this list. NPM answers 400 for credential problems —
        # that is how "Invalid email or password" arrived — so an expired
        # token can come back as 400 rather than 401. Retrying only on
        # 401/403 left a stale token cached in this process, and because the
        # cache is ours rather than NPM's, the source stayed broken until
        # NetMap itself was restarted. That is a source that goes down for
        # days and comes back on deploy, looking like a network problem.
        if exc.code in (400, 401, 403) and _retry:
            state["token"] = None
            return _get(cfg, path, _retry=False)
        raise


def test(cfg: dict) -> dict:
    try:
        _get(cfg, "/api/nginx/proxy-hosts")
        return {"ok": True, "error": None}
    except urllib.error.HTTPError as exc:
        why = _why(exc)
        return {"ok": False, "error": f"NPM answered HTTP {exc.code}" + (f" — {why}" if why else "")}
    except Exception as exc:
        return {"ok": False, "error": f"NPM at {cfg['url']}: {exc}"}


def domains(cfg: dict) -> set[str]:
    """Every hostname NPM serves. Best effort, for other sources to lean on."""
    try:
        if not configured(cfg):
            return set()
        return {str(n).lower()
                for h in (_get(cfg, "/api/nginx/proxy-hosts") or [])
                for n in (h.get("domain_names") or [])}
    except Exception:
        return set()


def _expiry(value) -> dt.date | None:
    txt = str(value or "")[:10]
    try:
        return dt.date.fromisoformat(txt)
    except ValueError:
        return None


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "npm")          # finding-key prefix; see dynamic.py
    # What actually reached the container, not what the compose file says.
    # Docker Compose expands `$` in an environment value, so a password
    # containing one arrives mangled while looking perfectly correct on disk —
    # and NPM reports that as "Invalid email or password", which sends you
    # looking at the account instead. The e-mail is not a secret and is shown
    # in full; the password is reported only as a length and a shape.
    PASSWORD = cfg.get("password", "")
    state = cfg.setdefault("_state", {})
    out = {"source": cfg.get("_id", "npm"), "configured": configured(cfg), "scanned_at": db.now(),
           "host": {"url": cfg.get("url", ""), "user": cfg.get("user", ""),
                    "password_chars": len(PASSWORD),
                    "password_has_dollar": "$" in PASSWORD,
                    "password_trimmed": PASSWORD != PASSWORD.strip(),
                    # Recorded rather than assumed: the shape of NPM's expiry
                    # field is unknown, so it is reported as-is.
                    "token_expires": state.get("expires"),
                    "token_age_s": (round(time.time() - state["token_at"])
                                    if state.get("token_at") else None)},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = ("not configured — add the NPM URL, e-mail and password "
                        "in Settings › Sources")
        return out
    try:
        hosts = _get(cfg, "/api/nginx/proxy-hosts") or []
    except urllib.error.HTTPError as exc:
        why = _why(exc)
        out["error"] = (f"NPM answered HTTP {exc.code}"
                        + (f" — {why}" if why else "")
                        + (" — the user needs at least View Only on proxy hosts"
                           if exc.code in (401, 403) and not why else ""))
        return out
    except Exception as exc:
        out["error"] = f"NPM at {cfg['url']}: {exc}"
        return out

    certs = []
    try:
        certs = _get(cfg, "/api/nginx/certificates") or []
    except Exception:
        # A View Only user may be Hidden on certificates. That is a narrower
        # credential, not a failure: skip one check and say nothing.
        certs = []

    entries = db.list_entries()
    ign = db.ignores()
    cert_by_id = {c.get("id"): c for c in certs}

    routes = [{"domain": str(n), "host": str(h.get("forward_host") or "").strip(),
               "port": h.get("forward_port"), "enabled": bool(h.get("enabled", 1))}
              for h in hosts for n in (h.get("domain_names") or [])]
    served = len(routes)
    findings, seen = _proxy.reconcile(P, "NPM", routes, entries)

    # One certificate can serve several proxy hosts, so this walks the
    # certificates rather than the hosts — otherwise one expiry produces one
    # finding per name that uses it, all sharing a key.
    today = dt.date.today()
    users: dict[object, list[str]] = {}
    for h in hosts:
        cid = h.get("certificate_id")
        if cid in cert_by_id:
            users.setdefault(cid, []).extend(
                str(n) for n in (h.get("domain_names") or []))
    for cid, names in users.items():
        when = _expiry(cert_by_id[cid].get("expires_on"))
        if not when:
            continue
        left = (when - today).days
        if left > cfg["cert_days"]:
            continue
        findings.append({
            "type": "cert-expiring", "key": f"{P}:cert:{cid}",
            "label": (f"{', '.join(sorted(set(names))[:3])} — certificate "
                      + (f"expires in {left} day(s)" if left >= 0
                         else f"expired {-left} day(s) ago")),
            "detail": (f"valid until {when.isoformat()}, covering "
                       f"{len(set(names))} name(s). Renewal is automatic until "
                       "it is not, and the failure is silent until a browser "
                       "refuses the page."),
        })

    db.record_sightings(cfg.get("_id", "npm"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "proxy_hosts": len(hosts), "domains": served, "certificates": len(certs),
        "untracked": sum(1 for f in kept if f["type"] == "proxy-untracked"),
        "disabled": sum(1 for f in kept if f["type"] == "proxy-disabled"),
        "orphan": sum(1 for f in kept if f["type"] == "proxy-orphan"),
        "drift": sum(1 for f in kept if f["type"] == "proxy-drift"),
        "cert_expiring": sum(1 for f in kept if f["type"] == "cert-expiring"),
        "ignored": len(findings) - len(kept),
    }
    return out
