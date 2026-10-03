"""Pi-hole as a discovery source.

Pi-hole holds two things NetMap cares about and cannot see for itself:

  /api/config/dns   the local DNS records — what a name resolves to on this LAN
  /api/clients      the clients that carry group assignments, and
  /api/groups       the groups those assignments point at

The DNS half catches a common failure: renumbering
a host is easy, and what breaks is never the host — it is whatever still points
at the old address. A local A record is exactly that kind of pointer.

The group half exists for a failure that is worse because it is silent. A
content-filtering group that stops applying looks like nothing at all: no error,
no unreachable service, just a device quietly no longer filtered. NetMap can
only check that if it is told what to expect, so the expectation is written on
the entry as a `pihole:<Group>` tag and this source verifies it.

Unlike Docker there is no read-only credential here, and unlike OPNsense there
is not even a per-request one: Pi-hole issues a session. This module therefore
does make one POST — `/api/auth`, to log in — and nothing else. Every other
request is a GET, and no code path here can construct a write.
"""
import json
import re
import urllib.error
import urllib.request

from .. import db
from . import _dns, _http, fields

FIELDS = [
    {"key": "url", "label": "API URL", "type": "text", "required": True, "wide": True,
     "placeholder": "http://10.0.0.53", "binds": True, "env": "NETMAP_PIHOLE_URL"},
    {"key": "password", "label": "Password", "type": "password", "secret": True,
     "required": True, "wide": True, "env": "NETMAP_PIHOLE_PASSWORD"},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox",
     "default": True, "env": "NETMAP_PIHOLE_VERIFY"},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 8,
     "env": "NETMAP_PIHOLE_TIMEOUT"},
]

ROLES = ("dns", "leases")  # see dynamic.ROLES

# "Not here" findings — dropped when another pihole source sees the entry.
ABSENCE = {'group-missing'}

TAG_RE = re.compile(r"^pihole:(.+)$", re.I)
MAC_RE = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Pi-hole limits how many sessions may be open at once and extends a session on
# every use, so the sid is kept and reused, in the instance's own state
# (cfg["_state"]["sid"]). Logging in on each scan would burn through that limit
# in a day of background scanning and start being refused. Settings dropping
# the state on any change is what stops an old session riding on to a new
# address or user.


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("password"))


def _login(cfg: dict) -> str:
    """The one POST in this module. Returns a session id."""
    body = json.dumps({"password": cfg["password"]}).encode()
    req = urllib.request.Request(
        cfg["url"] + "/api/auth", data=body, method="POST",
        headers={"content-type": "application/json", "accept": "application/json"})
    with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
        data = json.loads(r.read())
    sid = ((data.get("session") or {}).get("sid")) or ""
    if not sid:
        raise RuntimeError("Pi-hole accepted the request but returned no session id")
    return sid


def _get(cfg: dict, path: str, _retry: bool = True):
    state = cfg.setdefault("_state", {})
    if not state.get("sid"):
        state["sid"] = _login(cfg)
    req = urllib.request.Request(
        cfg["url"] + path, headers={"accept": "application/json", "X-FTL-SID": state["sid"]})
    try:
        with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        # The session expired or was evicted. Log in once more, then give up —
        # retrying forever against a wrong password is how you get locked out.
        if exc.code in (401, 403) and _retry:
            state["sid"] = None
            return _get(cfg, path, _retry=False)
        raise


def test(cfg: dict) -> dict:
    """Log in and read one small thing — cheaper than a scan."""
    try:
        _get(cfg, "/api/groups")
        return {"ok": True, "error": None}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"Pi-hole answered HTTP {exc.code}"
                + (" — check the password" if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach Pi-hole at {cfg['url']}: {exc}"}


def _macs(text: str) -> set[str]:
    return {m.group(1).lower() for m in MAC_RE.finditer(text or "")}


def _ids_of(e: dict) -> set[str]:
    """Everything Pi-hole might call this device by.

    A device identified in Pi-hole by MAC cannot be matched on address alone,
    and a missed match means a filtering group reported as fine when it is not
    being applied. The `mac` field is the reliable source; notes are read too,
    since that is where MACs lived before the field existed.
    """
    out = ({(e.get("ip") or "").strip().lower()}
           | _macs(e.get("mac", "")) | _macs(e.get("notes", "")))
    out.discard("")
    return out


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def dns_names(cfg: dict) -> set[str]:
    """Every name Pi-hole holds a local record for. For other sources to lean
    on; raises if Pi-hole does not answer."""
    conf = _get(cfg, "/api/config/dns")
    out = set()
    for line in (((conf.get("config") or {}).get("dns") or {}).get("hosts") or []):
        parts = (line or "").split()
        if len(parts) >= 2 and IP_RE.match(parts[0]):
            out.update(n.lower() for n in parts[1:])
    return out


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "pihole")          # finding-key prefix; see dynamic.py
    out = {"source": cfg.get("_id", "pihole"), "configured": configured(cfg), "scanned_at": db.now(),
           "host": {"url": cfg.get("url", "")}, "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = "not configured — add the API URL and password in Settings › Sources"
        return out
    try:
        conf = _get(cfg, "/api/config/dns")
        clients = _get(cfg, "/api/clients").get("clients", [])
        groups = _get(cfg, "/api/groups").get("groups", [])
    except urllib.error.HTTPError as exc:
        out["error"] = (f"Pi-hole answered HTTP {exc.code}"
                        + (" — check the password; an app password is "
                           "revoked separately from the web password"
                           if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot reach Pi-hole at {cfg['url']}: {exc}"
        return out

    dns = ((conf.get("config") or {}).get("dns") or {})
    hosts = dns.get("hosts") or []
    entries = db.list_entries()
    by_ip: dict[str, list[dict]] = {}
    for e in entries:
        ip = (e.get("ip") or "").strip()
        if ip:
            by_ip.setdefault(ip, []).append(e)
    ign = db.ignores()

    # ---- local DNS records -------------------------------------------------
    # Each entry is "<ip> <name> [more names]".
    records = []
    for line in hosts:
        parts = (line or "").split()
        if len(parts) >= 2 and IP_RE.match(parts[0]):
            records.append({"ip": parts[0], "names": parts[1:]})
    findings, seen = _dns.reconcile(P, "Pi-hole", records, entries)

    # ---- group assignments -------------------------------------------------
    gname = {g.get("id"): g.get("name") for g in groups}
    known = {(n or "").lower() for n in gname.values()}
    # Pi-hole identifies a client by IP, MAC, hostname or interface; index on
    # the raw value, lowercased, and match entries against the same shapes.
    cl_by_id: dict[str, dict] = {}
    for c in clients:
        cl_by_id[str(c.get("client", "")).strip().lower()] = c

    for e in entries:
        want = [m.group(1).strip() for m in
                (TAG_RE.match(t) for t in (e.get("tags") or [])) if m]
        if not want:
            continue
        ids = _ids_of(e)
        hit = next((cl_by_id[i] for i in ids if i in cl_by_id), None)
        for g in want:
            if g.lower() not in known:
                findings.append({
                    "type": "group-unknown", "key": f"{P}:group:{e['id']}:{g}",
                    "label": f"{e['name']} — no Pi-hole group called \"{g}\"",
                    "detail": (f"tagged pihole:{g}, but Pi-hole has "
                               + (", ".join(sorted(x for x in gname.values() if x))
                                  or "no groups")),
                    "entry": _ref(e),
                })
                continue
            if hit is None:
                findings.append({
                    "type": "group-missing", "key": f"{P}:group:{e['id']}:{g}",
                    "label": f"{e['name']} — not a Pi-hole client at all",
                    "detail": (f"tagged pihole:{g}, but no Pi-hole client matches "
                               f"{', '.join(sorted(ids)) or 'this entry'}. Whatever "
                               "that group does is not being applied to it."),
                    "entry": _ref(e),
                })
                continue
            mine = {(gname.get(i) or "").lower() for i in (hit.get("groups") or [])}
            if g.lower() not in mine:
                findings.append({
                    "type": "group-drift", "key": f"{P}:group:{e['id']}:{g}",
                    "label": f"{e['name']} — not in \"{g}\"",
                    "detail": (f"tagged pihole:{g}, but Pi-hole has this client "
                               f"({hit.get('client')}) in "
                               + (", ".join(sorted(x for x in mine if x)) or "no group")),
                    "entry": _ref(e),
                })

    # ---- clients Pi-hole manages that NetMap has never heard of ------------
    for ident, c in cl_by_id.items():
        if not IP_RE.match(ident) or ident in by_ip:
            continue
        gs = ", ".join(sorted(x for x in
                              ((gname.get(i) or "") for i in (c.get("groups") or [])) if x))
        findings.append({
            "type": "client-untracked", "key": f"{P}:client:{ident}",
            "label": f"{c.get('comment') or ident} — Pi-hole client, not in NetMap",
            "detail": (f"has group assignments ({gs or 'default only'}) but no "
                       "inventory entry, so nothing records what it is or why "
                       "it is filtered that way"),
            "draft": _dns.draft(c.get("comment") or ident, ident, "Pi-hole client", "Pi-hole"),
        })

    # ---- sightings: Pi-hole's clients (its records are in _dns) ---------
    for e in entries:
        hit = next((cl_by_id[i] for i in _ids_of(e) if i in cl_by_id), None)
        if hit is None:
            continue
        gs = sorted(x for x in ((gname.get(i) or "")
                                for i in (hit.get("groups") or [])) if x)
        seen.append({"entry_id": e["id"], "fact": "pihole-client",
                     "value": f"{hit.get('client')} in "
                              + (", ".join(gs) or "default only")})
    # ---- presence: Pi-hole's own client list ------------------------------
    known = []
    for ident, c in cl_by_id.items():
        if not IP_RE.match(ident):
            continue
        gs = ", ".join(sorted(x for x in
                              ((gname.get(i) or "") for i in (c.get("groups") or [])) if x))
        known.append({"ip": ident, "label": (c.get("comment") or "").strip(),
                      "mac": "", "detail": f"Pi-hole client ({gs or 'default'})"})
    db.record_presence(cfg.get("_id", "pihole"), known)

    db.record_sightings(cfg.get("_id", "pihole"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "records": len(records), "clients": len(clients), "groups": len(groups),
        "dns_drift": sum(1 for f in kept if f["type"] == "dns-drift"),
        "dns_orphan": sum(1 for f in kept if f["type"] == "dns-orphan"),
        "group_drift": sum(1 for f in kept if f["type"] == "group-drift"),
        "group_missing": sum(1 for f in kept if f["type"] == "group-missing"),
        "group_unknown": sum(1 for f in kept if f["type"] == "group-unknown"),
        "untracked": sum(1 for f in kept if f["type"] == "client-untracked"),
        "ignored": len(findings) - len(kept),
    }
    return out
