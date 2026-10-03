"""Cloudflare Tunnel as a discovery source.

Every other source answers a question about the LAN. This one answers the
question about the *edge*: which public hostnames actually reach into this
house, where each of them lands, and whether anything is standing in front of
them.

The typical failure: a service is renumbered, its container is rebuilt and
healthy within minutes, and its public hostname stays broken — because the thing
that needed changing was not the host but the tunnel's ingress rule pointing at
it. The
lesson generalises: *the breakage is rarely on the host, it is in whatever
references its address.* Pi-hole's `dns-drift` catches that for local names and
UniFi's `device-drift` for addresses; this catches it for public ones.

Three endpoints, all GET:

  /accounts/{a}/cfd_tunnel                       the tunnels and their health
  /accounts/{a}/cfd_tunnel/{t}/configurations    the ingress rules
  /accounts/{a}/access/apps                      what Access protects

This is the one source whose credential is genuinely least-privilege and
enforced by the issuer: a scoped API token with Read on Cloudflare Tunnel (and
optionally Access) simply cannot write, whatever this code does.
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from .. import db

API = "https://api.cloudflare.com/client/v4"

FIELDS = [
    {"key": "token", "label": "API token", "type": "password", "secret": True,
     "required": True, "wide": True, "env": "NETMAP_CF_TOKEN"},
    {"key": "account", "label": "Account ID", "type": "text", "required": True,
     "wide": True, "binds": True, "env": "NETMAP_CF_ACCOUNT"},
    {"key": "tunnel", "label": "Tunnel (id or name, optional)", "type": "text",
     "wide": True, "env": "NETMAP_CF_TUNNEL"},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 10,
     "env": "NETMAP_CF_TIMEOUT"},
    # Some hostnames are public on purpose. Ignoring them once is the intended
    # route, but the check can be switched off wholesale if it is all noise.
    {"key": "report_open", "label": "Report hostnames with no Access application",
     "type": "checkbox", "default": True, "env": "NETMAP_CF_REPORT_OPEN"},
    # Which domains are "ours" — an entry URL under one of them that the
    # tunnel does not serve is a missing route. Blank: the domains the
    # tunnel's own hostnames are under. An entry pointing at github.com is
    # never a missing route either way.
    {"key": "public_domains", "label": "Public domains (optional, comma separated)",
     "type": "text", "wide": True, "placeholder": "derived from the tunnel's hostnames",
     "env": "NETMAP_PUBLIC_DOMAIN"},
]

ROLES = ("edge",)  # see dynamic.ROLES

# "Not here" findings — dropped when another cloudflare source sees the entry.
ABSENCE = {'route-missing'}

HOST_RE = re.compile(r"https?://([a-z0-9.-]+)(?::(\d+))?", re.I)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# A tunnel with no live connections is not a fault by itself — a tunnel that
# has never been started looks the same — but it is never what you want.
BAD_STATUS = {"down", "degraded", "inactive"}


def configured(cfg: dict) -> bool:
    return bool(cfg.get("token") and cfg.get("account"))


def _get(cfg: dict, path: str):
    req = urllib.request.Request(
        API + path,
        headers={"accept": "application/json",
                 "authorization": f"Bearer {cfg['token']}"})
    with urllib.request.urlopen(req, timeout=cfg["timeout"]) as r:
        return json.loads(r.read())


def _result(cfg: dict, path: str):
    data = _get(cfg, path)
    if not data.get("success", True):
        msgs = "; ".join(str(e.get("message")) for e in (data.get("errors") or []))
        raise RuntimeError(msgs or "Cloudflare returned success=false")
    return data.get("result")


def _origin(service: str) -> tuple[str, str]:
    """`http://10.0.0.10:8087` → ("10.0.0.10", "8087").

    Ingress services are not all URLs — `http_status:404`, `unix:/…` and bare
    `tcp://host:port` all appear — so anything unparseable yields ("", "").
    """
    m = HOST_RE.match((service or "").strip())
    if not m:
        m = re.match(r"^(?:tcp|ssh|rdp)://([a-z0-9.-]+)(?::(\d+))?$",
                     (service or "").strip(), re.I)
    return (m.group(1), m.group(2) or "") if m else ("", "")


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def _draft(hostname: str, service: str) -> dict:
    return {
        "name": hostname.split(".")[0], "category": "Remote Access",
        "kind": "service", "host": "", "ip": "", "ports": "", "protocol": "HTTPS",
        "url": f"https://{hostname}", "zone": "", "tags": "", "mac": "",
        "notes": (f"Published through the Cloudflare Tunnel to {service}. "
                  f"Discovered {db.now()[:10]}."),
        "monitor": False, "verified": False,
    }


def _covered(hostname: str, domains: list[str]) -> tuple[bool, list[str]]:
    """Does any Access application cover this hostname, and which paths are?

    An application's domain may carry a path (`netmap.example.org/private_…`) or
    be a wildcard (`*.example.org`). A path-scoped application protects only that
    path, so it does not cover the hostname — but saying "no Access
    application" when one exists for `/admin` would be wrong in the way that
    gets a finding dismissed, so the paths are returned and reported.
    """
    h = hostname.lower()
    paths = []
    for d in domains:
        d = (d or "").lower().strip()
        if not d:
            continue
        if "/" in d:
            base, _, path = d.partition("/")
            if base == h:
                paths.append("/" + path)
            continue
        if d == h or (d.startswith("*.") and h.endswith(d[1:])):
            return True, []
    return False, paths


def _lan_names() -> set[str]:
    """Hostnames answered inside the house — by any reverse proxy (it serves
    the name) or any local DNS server (it resolves it).

    A public-domain name is published one of two ways: through the tunnel, or
    through a reverse proxy with a local DNS record, which never leaves the
    house. The inventory's `url` field does not distinguish them — and NetMap
    should not need a tag to state what other systems already know. A name
    served or resolved locally is reachable by design, and its absence from
    the tunnel is a decision rather than a fault.

    Best effort: a proxy or DNS server that is not added or does not answer
    simply is not asked. A second system being down must not change what
    this one reports about the first.
    """
    out = set()
    from . import by_role
    for role, ask in (("proxy", "domains"), ("dns", "dns_names")):
        for b in by_role(role):
            try:
                out |= getattr(b.mod, ask)(b.cfg)
            except Exception:
                pass
    return out


def public_domains(cfg: dict, routed) -> set[str]:
    """The domains this estate publishes under: the configured ones, or else
    the parent of every hostname the tunnel routes (plex.example.org →
    example.org)."""
    explicit = {d.strip(". ").lower() for d in (cfg.get("public_domains") or "").split(",")
                if d.strip(". ")}
    return explicit or {h.split(".", 1)[1] for h in routed if h.count(".") >= 2}


def gateway(cfg: dict, entries: list[dict]) -> dict | None:
    """The entry that stands for this tunnel — what a published service is
    `exposed_by`. One whose name says "tunnel" together with "cloudflare" or
    the tunnel's own name; none if that is not exactly one entry."""
    tun = (cfg.get("_state") or {}).get("tunnel_name") or cfg.get("tunnel") or ""
    words = {w for w in ("cloudflare", re.sub(r"[^a-z0-9]+", " ", tun.lower()).strip()) if w}

    def norm(s):
        return re.sub(r"[^a-z0-9]+", " ", (s or "").lower())
    hits = [e for e in entries if "tunnel" in norm(e["name"])
            and any(w in norm(e["name"]) for w in words)]
    return hits[0] if len(hits) == 1 else None


def test(cfg: dict) -> dict:
    try:
        _result(cfg, f"/accounts/{cfg['account']}/cfd_tunnel?is_deleted=false")
        return {"ok": True, "error": None}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"Cloudflare answered HTTP {exc.code}"
                + (" — the token needs Account > Cloudflare Tunnel: Read"
                   if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach the Cloudflare API: {exc}"}


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "cloudflare")          # finding-key prefix; see dynamic.py
    ACCOUNT = cfg.get("account", "")
    TUNNEL = (cfg.get("tunnel") or "").strip()          # id or name; optional
    REPORT_OPEN = cfg.get("report_open", True)
    out = {"source": cfg.get("_id", "cloudflare"), "configured": configured(cfg), "scanned_at": db.now(),
           "host": {"account": ACCOUNT}, "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = ("not configured — add the API token and account ID in "
                        "Settings › Sources")
        return out

    try:
        tunnels = [t for t in (_result(cfg, f"/accounts/{ACCOUNT}/cfd_tunnel"
                                       "?is_deleted=false") or [])
                   if not t.get("deleted_at")]
    except urllib.error.HTTPError as exc:
        out["error"] = (f"Cloudflare answered HTTP {exc.code}"
                        + (" — the token needs Account > Cloudflare Tunnel: Read"
                           if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot reach the Cloudflare API: {exc}"
        return out

    if TUNNEL:
        want = TUNNEL.lower()
        tun = next((t for t in tunnels
                    if want in (str(t.get("id", "")).lower(),
                                str(t.get("name", "")).lower())), None)
        if tun is None:
            out["error"] = (f"no tunnel matching '{TUNNEL}'; "
                            "this account has "
                            + (", ".join(str(t.get("name")) for t in tunnels)
                               or "none"))
            return out
    elif len(tunnels) == 1:
        tun = tunnels[0]
    else:
        out["error"] = ("this account has "
                        + (f"{len(tunnels)} tunnels ("
                           + ", ".join(str(t.get("name")) for t in tunnels)
                           + ") — set the tunnel NetMap should read in Settings › Sources"
                           if tunnels else "no tunnels"))
        return out

    cfg.setdefault("_state", {})["tunnel_name"] = tun.get("name")
    out["host"] = {"account": ACCOUNT, "tunnel": tun.get("name"),
                   "status": tun.get("status")}

    try:
        tcfg = _result(cfg, f"/accounts/{ACCOUNT}/cfd_tunnel/{tun['id']}/configurations")
    except Exception as exc:
        out["error"] = f"cannot read the tunnel configuration: {exc}"
        return out

    config = (tcfg or {}).get("config")
    if not config:
        out["error"] = ("this tunnel is locally managed — its ingress rules live "
                        "in cloudflared's own config file, not in the API, so "
                        "there is nothing here to compare")
        return out

    rules = [r for r in (config.get("ingress") or []) if r.get("hostname")]

    domains: list[str] = []
    access_read = False
    if REPORT_OPEN:
        try:
            apps = _result(cfg, f"/accounts/{ACCOUNT}/access/apps") or []
            domains = [a.get("domain") or "" for a in apps]
            access_read = True
        except Exception:
            # The token may legitimately carry Tunnel: Read and nothing else.
            # That is a narrower token, not a failure — the rest of the scan
            # is unaffected, so say nothing and skip one check.
            access_read = False

    entries = db.list_entries()
    by_ip: dict[str, list[dict]] = {}
    for e in entries:
        ip = (e.get("ip") or "").strip()
        if ip:
            by_ip.setdefault(ip, []).append(e)
    ign = db.ignores()
    findings: list[dict] = []

    # ---- the tunnel itself -------------------------------------------------
    status = str(tun.get("status") or "").lower()
    if status in BAD_STATUS:
        conns = len(tun.get("connections") or [])
        findings.append({
            "type": "tunnel-down", "key": f"{P}:tunnel:{tun['id']}",
            "label": f"Tunnel \"{tun.get('name')}\" is {status}",
            "detail": (f"{conns} live connection(s) to the Cloudflare edge. "
                       "Every hostname below is unreachable from outside while "
                       "this lasts; everything inside the house is unaffected."),
        })

    # ---- hostnames that reach in, and where they land -----------------------
    routed: dict[str, str] = {}
    seen: list[dict] = []
    host_pub: dict[int, list[str]] = {}
    for r in rules:
        host = str(r.get("hostname")).lower()
        svc = str(r.get("service") or "")
        routed.setdefault(host, svc)
        hit = [e for e in entries if host in (e.get("url") or "").lower()]
        oh, op = _origin(svc)

        if not hit:
            findings.append({
                "type": "ingress-orphan", "key": f"{P}:ingress:{host}",
                "label": f"{host} → {svc} — published, not in NetMap",
                "detail": ("a public hostname reaching into this network that "
                           "no inventory entry accounts for"),
                "draft": _draft(host, svc),
            })

        # The origin is the half that goes stale. Most hostnames land on the
        # reverse proxy rather than on the service itself, so comparing the
        # origin with the matched entry's own address would be wrong nearly
        # every time. What is always wrong is an origin address that belongs
        # to nothing at all — that is a renumbering nobody finished.
        # Only when the hostname itself is known: an orphan already says the
        # whole rule is unaccounted for, and saying it twice is noise.
        if hit and oh and IP_RE.match(oh) and oh not in by_ip:
            findings.append({
                "type": "origin-untracked", "key": f"{P}:origin:{host}",
                "label": f"{host} → {oh}{':' + op if op else ''} — nothing at that address",
                "detail": ("the ingress rule points at an address no inventory "
                           "entry holds. After a renumbering this is what stays "
                           "behind, and the hostname fails while the service "
                           "itself looks perfectly healthy."),
                "entry": _ref(hit[0]),
            })

        # ---- sightings: what Cloudflare currently says ---------------------
        val = f'via tunnel "{tun.get("name")}" \u2192 {svc}'
        ok_here = True
        if access_read:
            ok_here, paths = _covered(host, domains)
            val += ("; Access enforced" if ok_here else
                    ("; Access only on " + ", ".join(paths)) if paths else
                    "; no Access application")
        # An address that runs nineteen containers must not hand every one of
        # them its neighbours' hostnames: the host answers all of them, a
        # service owns only the port it listens on.
        targets = list(hit[:1])
        for o in by_ip.get(oh or "", []):
            mine = {int(x) for x in re.findall(r"\d+", str(o.get("ports") or ""))}
            if op and str(op).isdigit() and int(op) in mine:
                targets.append(o)
            elif o.get("kind") in ("hardware", "vm"):
                # The host really does answer all of them; one line saying so
                # beats sixteen rows differing only in the name.
                host_pub.setdefault(o["id"], []).append(
                    host + ("" if access_read and ok_here else " (no Access)"))
        for t in targets:
            seen.append({"entry_id": t["id"], "fact": f"hostname:{host}",
                         "value": val})

        if REPORT_OPEN and access_read:
            ok, paths = _covered(host, domains)
            if not ok:
                findings.append({
                    "type": "access-open", "key": f"{P}:access:{host}",
                    "label": (f"{host} — Access covers only {', '.join(paths)}"
                              if paths else f"{host} — no Access application"),
                    "detail": ("published through the tunnel with nothing in "
                               "front of it: whatever answers at the origin is "
                               "answering the open internet"
                               if not paths else
                               "published through the tunnel; the Access "
                               "application here is scoped to a path, so every "
                               "other path on this hostname is open"),
                    "entry": _ref(hit[0]) if hit else None,
                })

    # ---- entries that claim a public URL the tunnel does not serve ----------
    ours = public_domains(cfg, routed)
    claimed = []
    for e in entries:
        m = HOST_RE.match((e.get("url") or "").lower())
        if (m and m.group(1) not in routed
                and any(m.group(1).endswith("." + d) for d in ours)):
            claimed.append((e, m.group(1)))
    lan = _lan_names() if claimed else set()
    lan_only = 0

    for e, host in claimed:
        if host in lan:
            lan_only += 1
            continue
        findings.append({
            "type": "route-missing", "key": f"{P}:route:{e['id']}:{host}",
            "label": f"{e['name']} — {host} is not routed",
            "detail": ("the inventory publishes this address but neither the "
                       "tunnel nor a local DNS record or reverse proxy serves "
                       "it, so the hostname resolves to nothing at all."),
            "entry": _ref(e),
        })

    for eid, names in host_pub.items():
        names = sorted(set(names))
        bad = sum(1 for n in names if "(no Access)" in n)
        seen.append({"entry_id": eid, "fact": "hostname",
                     "value": f'{len(names)} tunnel hostname'
                              f'{" reaches" if len(names) == 1 else "s reach"} here'
                              + (f", {bad} with no Access application" if bad else "")
                              + ": " + ", ".join(n.replace(" (no Access)", "")
                                                 for n in names[:6])
                              + (f" +{len(names) - 6} more" if len(names) > 6 else "")})
    db.record_sightings(cfg.get("_id", "cloudflare"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    for f in kept:
        if f.get("entry") is None:
            f.pop("entry", None)
    out["findings"] = kept
    out["counts"] = {
        "hostnames": len(routed), "access_apps": len(domains),
        "tunnel_down": sum(1 for f in kept if f["type"] == "tunnel-down"),
        "orphan": sum(1 for f in kept if f["type"] == "ingress-orphan"),
        "origin_untracked": sum(1 for f in kept if f["type"] == "origin-untracked"),
        "route_missing": sum(1 for f in kept if f["type"] == "route-missing"),
        "lan_only": lan_only,
        "access_open": sum(1 for f in kept if f["type"] == "access-open"),
        "ignored": len(findings) - len(kept),
    }
    return out
