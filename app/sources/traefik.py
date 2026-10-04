"""Traefik as a discovery source - the `proxy` role, like NPM.

Reads Traefik's API (the one the dashboard uses), GET only:

  /api/http/routers    each router's rule - the Host(`…`) names it answers
  /api/http/services   where each service forwards: its servers' URLs

and hands the name → target pairs to the reconciliation NPM uses (_proxy.py):
a name nobody tracks, a router switched off, a forward to an address nothing
holds, a forward that disagrees with the entry.

Two differences from NPM. Traefik usually forwards to a *container*
address - with the Docker provider, 172.18.0.5 rather than the host's LAN
address - and that address means nothing to the inventory, so targets inside
"Container networks" are shown but never compared. And the API may be open
(`api.insecure`) or behind Basic auth on the dashboard router; the username
and password are optional for that reason.
"""
import base64
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from .. import db
from . import _http, _proxy, fields

FIELDS = [
    {"key": "url", "label": "API URL", "type": "text", "required": True, "wide": True,
     "placeholder": "http://10.0.0.10:8080", "binds": True},
    {"key": "user", "label": "Username (if the API needs one)", "type": "text",
     "wide": True, "binds": True},
    {"key": "password", "label": "Password", "type": "password", "secret": True,
     "wide": True},
    {"key": "internal", "label": "Container networks (never compared)", "type": "text",
     "wide": True, "default": "172.16.0.0/12"},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox",
     "default": True},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 8},
]

ROLES = ("proxy",)  # see dynamic.ROLES

HOST_RULE = re.compile(r"Host\(([^)]*)\)")
BACKTICK = re.compile(r"`([^`]+)`")


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url"))


def _get(cfg: dict, path: str):
    headers = {"accept": "application/json"}
    if cfg.get("user"):
        auth = base64.b64encode(f"{cfg['user']}:{cfg.get('password', '')}".encode()).decode()
        headers["authorization"] = "Basic " + auth
    req = urllib.request.Request(cfg["url"] + path, headers=headers)
    with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
        return json.loads(r.read())


def test(cfg: dict) -> dict:
    try:
        v = _get(cfg, "/api/version")
        return {"ok": True, "error": None, "version": v.get("Version")}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"Traefik answered HTTP {exc.code}"
                + (" - the API needs a username and password" if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach Traefik at {cfg['url']}: {exc}"}


def hosts_of(rule: str) -> list[str]:
    """The names in a router rule: Host(`a`), Host(`a`,`b`) (v2) and
    Host(`a`) || Host(`b`) (v3). HostRegexp and PathPrefix name nothing."""
    return [n.lower() for m in HOST_RULE.finditer(rule or "")
            for n in BACKTICK.findall(m.group(1))]


def _internal(cfg: dict):
    nets = []
    for part in (cfg.get("internal") or "").split(","):
        try:
            nets.append(ipaddress.ip_network(part.strip(), strict=False))
        except ValueError:
            pass
    return nets


def _routes(cfg: dict, routers: list[dict], services: list[dict]) -> list[dict]:
    by_name = {s.get("name"): s for s in services or []}
    nets = _internal(cfg)
    out = []
    for r in routers or []:
        names = hosts_of(r.get("rule", ""))
        if not names:
            continue
        svc = str(r.get("service") or "")
        if "@" not in svc and r.get("provider"):
            svc = f"{svc}@{r['provider']}"
        s = by_name.get(svc) or {}
        servers = ((s.get("loadBalancer") or {}).get("servers") or [])
        u = urllib.parse.urlsplit(servers[0].get("url", "")) if servers else None
        host, port = (u.hostname or "", u.port) if u else (svc, None)
        try:
            if host and any(ipaddress.ip_address(host) in n for n in nets):
                host = f"{svc} ({host})"         # a container address: shown, not compared
        except ValueError:
            pass
        enabled = str(r.get("status") or "enabled") != "disabled"
        out += [{"domain": n, "host": host, "port": port, "enabled": enabled} for n in names]
    return out


def domains(cfg: dict) -> set[str]:
    """Every name Traefik routes (the `proxy` role's contract)."""
    return {n for r in _get(cfg, "/api/http/routers") or [] for n in hosts_of(r.get("rule", ""))}


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "traefik")          # finding-key prefix; see dynamic.py
    out = {"source": cfg.get("_id", "traefik"), "configured": configured(cfg),
           "scanned_at": db.now(), "host": {"url": cfg.get("url", "")},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = "not configured - add the API URL in Settings › Sources"
        return out
    try:
        routers = _get(cfg, "/api/http/routers") or []
        services = _get(cfg, "/api/http/services") or []
    except urllib.error.HTTPError as exc:
        out["error"] = (f"Traefik answered HTTP {exc.code}"
                        + (" - the API needs a username and password" if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot reach Traefik at {cfg['url']}: {exc}"
        return out

    routes = _routes(cfg, routers, services)
    findings, seen = _proxy.reconcile(P, "Traefik", routes, db.list_entries())
    db.record_sightings(cfg.get("_id", "traefik"), seen)

    ign = db.ignores()
    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {"routers": len(routers), "domains": len(routes),
                     **_proxy.counts(kept), "ignored": len(findings) - len(kept)}
    return out
