"""AdGuard Home as a discovery source — the `dns` role, like Pi-hole.

Reads, over AdGuard Home's own HTTP API, GET only:

  /control/rewrite/list   DNS rewrites — the local records: a name, and the
                          address it answers with
  /control/clients        persistent clients (named by a person) and the
                          runtime clients it has seen

The records go through the same reconciliation as Pi-hole's (see _dns.py):
a rewrite to an address NetMap does not track, or a name the inventory holds
at a different address. Persistent clients with an IP identifier that no
entry holds are reported as untracked; every client it knows is a dot on the
address map.

The credential is the dashboard login (HTTP Basic). AdGuard Home has no
read-only account, so the safeguard is that this module only issues GETs and
nothing in it can construct a write.
"""
import base64
import json
import re
import urllib.error
import urllib.request

from .. import db
from . import _dns, _http, fields

FIELDS = [
    {"key": "url", "label": "Base URL", "type": "text", "required": True, "wide": True,
     "placeholder": "http://10.0.0.53:3000", "binds": True},
    {"key": "user", "label": "Username", "type": "text", "required": True, "wide": True,
     "binds": True},
    {"key": "password", "label": "Password", "type": "password", "secret": True,
     "required": True, "wide": True},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox",
     "default": True},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 8},
]

ROLES = ("dns",)  # see dynamic.ROLES

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("user") and cfg.get("password"))


def _get(cfg: dict, path: str):
    auth = base64.b64encode(f"{cfg['user']}:{cfg['password']}".encode()).decode()
    req = urllib.request.Request(cfg["url"] + path, headers={
        "accept": "application/json", "authorization": "Basic " + auth})
    with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
        return json.loads(r.read())


def test(cfg: dict) -> dict:
    try:
        st = _get(cfg, "/control/status")
        return {"ok": True, "error": None, "version": st.get("version")}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"AdGuard Home answered HTTP {exc.code}"
                + (" — check the username and password" if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach AdGuard Home at {cfg['url']}: {exc}"}


def _records(rewrites: list[dict]) -> list[dict]:
    """Rewrites answering with an address, grouped by it. A rewrite to another
    name (a CNAME) or a disabled one is not a record of where a host lives."""
    by_ip: dict[str, list[str]] = {}
    for r in rewrites or []:
        ans = str(r.get("answer") or "").strip()
        if r.get("enabled", True) is False or not IP_RE.match(ans):
            continue
        by_ip.setdefault(ans, []).append(str(r.get("domain") or "").lower())
    return [{"ip": ip, "names": names} for ip, names in by_ip.items()]


def dns_names(cfg: dict) -> set[str]:
    """Every name AdGuard Home answers locally (the `dns` role's contract)."""
    return {n for r in _records(_get(cfg, "/control/rewrite/list")) for n in r["names"]}


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "adguard")          # finding-key prefix; see dynamic.py
    out = {"source": cfg.get("_id", "adguard"), "configured": configured(cfg),
           "scanned_at": db.now(), "host": {"url": cfg.get("url", "")},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = "not configured — add the URL, username and password in Settings › Sources"
        return out
    try:
        rewrites = _get(cfg, "/control/rewrite/list") or []
        cl = _get(cfg, "/control/clients") or {}
    except urllib.error.HTTPError as exc:
        out["error"] = (f"AdGuard Home answered HTTP {exc.code}"
                        + (" — check the username and password" if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot reach AdGuard Home at {cfg['url']}: {exc}"
        return out

    entries = db.list_entries()
    held = {(e.get("ip") or "").strip() for e in entries}
    records = _records(rewrites)
    findings, seen = _dns.reconcile(P, "AdGuard Home", records, entries)

    # ---- clients -----------------------------------------------------------
    persistent = cl.get("clients") or []
    runtime = cl.get("auto_clients") or []
    presence: dict[str, dict] = {}
    for c in runtime:
        ip = str(c.get("ip") or "").strip()
        if IP_RE.match(ip):
            presence[ip] = {"ip": ip, "label": str(c.get("name") or "").strip(),
                            "mac": "", "detail": f"AdGuard Home client ({c.get('source') or 'seen'})"}
    for c in persistent:
        name = str(c.get("name") or "").strip()
        for ident in c.get("ids") or []:
            ident = str(ident).strip().lower()
            if not IP_RE.match(ident):
                continue
            # A person named this client — that name wins over a runtime one.
            presence[ident] = {"ip": ident, "label": name, "mac": "",
                               "detail": "AdGuard Home persistent client"}
            if ident not in held:
                findings.append({
                    "type": "client-untracked", "key": f"{P}:client:{ident}",
                    "label": f"{name or ident} — AdGuard Home client, not in NetMap",
                    "detail": ("configured as a persistent client, so someone gave it "
                               "its own settings, but no inventory entry records "
                               "what it is"),
                    "draft": _dns.draft(name or ident, ident, "AdGuard Home client",
                                        "AdGuard Home"),
                })
    db.record_presence(cfg.get("_id", "adguard"), list(presence.values()))
    db.record_sightings(cfg.get("_id", "adguard"), seen)

    ign = db.ignores()
    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "rewrites": len(rewrites), "records": len(records),
        "clients": len(persistent), "runtime_clients": len(runtime),
        "dns_drift": sum(1 for f in kept if f["type"] == "dns-drift"),
        "dns_orphan": sum(1 for f in kept if f["type"] == "dns-orphan"),
        "untracked": sum(1 for f in kept if f["type"] == "client-untracked"),
        "ignored": len(findings) - len(kept),
    }
    return out
