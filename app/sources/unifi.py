"""UniFi as a discovery source.

The other three sources describe logical facts - what runs where, what holds an
address, what a name resolves to. UniFi is the only one that knows how things
are physically **connected**: which switch port the NAS is on, which access
point a phone is talking to, what uplinks into what.

That matters because the physical layer in this inventory is hand-maintained.
Switch and AP uplinks were typed in from notes, and nothing tells you when a
cable moves - the edges rot silently. The controller knows the current answer
continuously.

Two endpoints, both GET:

  /api/s/<site>/stat/device   the adopted hardware, with its uplink
  /api/s/<site>/stat/sta      the connected clients, wired and wireless

Authentication is a cookie session (POST /api/login), so this module makes one
POST to log in and nothing else. Unlike OPNsense and Pi-hole, though, UniFi has
real roles: point this at a **local read-only admin** and the restriction lives
in the controller rather than in this file's good behaviour.
"""
import http.cookiejar
import json
import re
import urllib.error
import urllib.request

from .. import db
from . import _http, fields

PORT_RE = re.compile(r"port\s+(\d+)", re.I)

FIELDS = [
    {"key": "url", "label": "Controller URL", "type": "text", "required": True,
     "wide": True, "placeholder": "https://10.0.0.2:8443", "binds": True,
     "env": "NETMAP_UNIFI_URL"},
    {"key": "user", "label": "Username", "type": "text", "required": True, "wide": True,
     "binds": True, "env": "NETMAP_UNIFI_USER"},
    {"key": "password", "label": "Password", "type": "password", "secret": True,
     "required": True, "wide": True, "env": "NETMAP_UNIFI_PASSWORD"},
    {"key": "site", "label": "Site", "type": "text", "default": "default",
     "placeholder": "default", "env": "NETMAP_UNIFI_SITE"},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox",
     "default": True, "env": "NETMAP_UNIFI_VERIFY"},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 8,
     "env": "NETMAP_UNIFI_TIMEOUT"},
    # A wireless client below this is worth mentioning once. Off by default:
    # signal is a weather report, not an inventory fact, and it changes every
    # time someone walks through a doorway.
    {"key": "weak_dbm", "label": "Weak signal threshold (dBm, 0 = off)",
     "type": "number", "integer": True, "default": 0, "env": "NETMAP_UNIFI_WEAK_DBM"},
]

ROLES = ("layer2",)  # see dynamic.ROLES

MAC_RE = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)

# The session is an opener holding the controller's cookie, kept in the
# instance's own state (cfg["_state"]["opener"]); Settings drops it on any
# change, so the next request logs in with what was just saved.


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("user") and cfg.get("password"))


def _login(cfg: dict) -> urllib.request.OpenerDirector:
    """The one POST in this module. Returns an opener holding the session."""
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _http.NoRedirect(),
        urllib.request.HTTPSHandler(context=fields.tls(cfg)))
    body = json.dumps({"username": cfg["user"], "password": cfg["password"]}).encode()
    req = urllib.request.Request(
        cfg["url"] + "/api/login", data=body, method="POST",
        headers={"content-type": "application/json", "accept": "application/json"})
    with op.open(req, timeout=cfg["timeout"]) as r:
        r.read()
    if not len(jar):
        raise RuntimeError("UniFi accepted the login but set no session cookie")
    return op


def _get(cfg: dict, path: str, _retry: bool = True):
    state = cfg.setdefault("_state", {})
    if state.get("opener") is None:
        state["opener"] = _login(cfg)
    req = urllib.request.Request(cfg["url"] + path, headers={"accept": "application/json"})
    try:
        with state["opener"].open(req, timeout=cfg["timeout"]) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403) and _retry:
            state["opener"] = None
            return _get(cfg, path, _retry=False)
        raise


def test(cfg: dict) -> dict:
    try:
        _get(cfg, f"/api/s/{cfg['site']}/stat/device")
        return {"ok": True, "error": None}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"UniFi answered HTTP {exc.code}"
                + (" - check the credentials" if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach UniFi at {cfg['url']}: {exc}"}


def _macs(text: str) -> set[str]:
    return {m.group(1).lower() for m in MAC_RE.finditer(text or "")}


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def _index(entries: list[dict]) -> tuple[dict, dict]:
    """Address and MAC indexes.

    A wired client's `sta` record often carries no IP at all, so the MAC is
    frequently the only identifier there is. The `mac` field is the answer;
    notes are still read as a fallback, because that is where MACs lived
    before the field existed and not every entry has been moved over.
    """
    by_ip: dict[str, list[dict]] = {}
    by_mac: dict[str, dict] = {}
    for e in entries:
        ip = (e.get("ip") or "").strip().lower()
        if ip:
            by_ip.setdefault(ip, []).append(e)
        for m in _macs(e.get("mac", "")) | _macs(e.get("notes", "")):
            by_mac.setdefault(m, e)
    return by_ip, by_mac


def _fetch(cfg: dict) -> tuple[list[dict], list[dict]]:
    devs = _get(cfg, f"/api/s/{cfg['site']}/stat/device").get("data", [])
    stas = _get(cfg, f"/api/s/{cfg['site']}/stat/sta").get("data", [])
    return devs, stas


def _last_mac(port: dict) -> str:
    """The MAC out of a port's `last_connection`, whatever shape it arrives in.

    Seen as a bare string and as a dict whose key name has changed between
    controller versions, so the value is searched for something MAC-shaped
    rather than read from a key this code guessed.
    """
    v = port.get("last_connection")
    if isinstance(v, dict):
        v = " ".join(str(x) for x in v.values())
    found = MAC_RE.findall(str(v or ""))
    return found[0].replace("-", ":").lower() if found else ""


def topology(cfg: dict) -> dict:
    """The physical graph, for `links.py` to derive `connects_to` edges from.

    Returns raw controller facts keyed by MAC - no NetMap ids, no opinions.
    Deliberately separate from `scan()`: a scan reports and never writes, so
    the thing that produces edges is called by derivation, which is an explicit
    action the operator takes.
    """
    out = {"configured": configured(cfg), "devices": [], "clients": [], "error": None}
    if not configured(cfg):
        out["error"] = "not configured"
        return out
    try:
        devs, stas = _fetch(cfg)
    except Exception as exc:
        out["error"] = f"cannot reach UniFi at {cfg['url']}: {exc}"
        return out
    for d in devs:
        up = d.get("uplink") or {}
        out["devices"].append({
            "mac": (d.get("mac") or "").lower(), "name": d.get("name") or "",
            "ip": (d.get("ip") or "").strip(), "model": d.get("model") or "",
            "type": d.get("type") or "", "adopted": bool(d.get("adopted")),
            "state": d.get("state"),
            "uplink_mac": (up.get("uplink_mac") or "").lower(),
            "uplink_port": up.get("uplink_remote_port"),
            # The last device the switch saw on each live port. This
            # controller keeps no per-port MAC table - `port_mac_lists` in a
            # scan comes back empty - so this single MAC is all there is, and
            # it is the only place a bridged host shows up at all: the host has
            # no client record of its own, but its guests' traffic crosses its
            # cable and is what the port reports.
            "ports": [
                {"port": p.get("port_idx"),
                 "uplink": bool(p.get("is_uplink")),
                 "last_mac": _last_mac(p)}
                for p in (d.get("port_table") or [])
                if p.get("up") and _last_mac(p)
            ],
        })
    for c in stas:
        out["clients"].append({
            "mac": (c.get("mac") or "").lower(),
            "ip": (c.get("ip") or "").strip(),
            "name": c.get("name") or c.get("hostname") or "",
            "wired": bool(c.get("is_wired")),
            "sw_mac": (c.get("sw_mac") or "").lower(),
            "sw_port": c.get("sw_port"),
            "ap_mac": (c.get("ap_mac") or "").lower(),
            "essid": c.get("essid") or "",
            "signal": c.get("signal"),
        })
    return out


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "unifi")          # finding-key prefix; see dynamic.py
    out = {"source": cfg.get("_id", "unifi"), "configured": configured(cfg), "scanned_at": db.now(),
           "host": {"url": cfg.get("url", ""), "site": cfg.get("site", "")},
           "findings": [], "counts": {}, "error": None}
    # (the port-field probe below fills host.port_fields once devices are read)
    if not configured(cfg):
        out["error"] = ("not configured - add the controller URL, username and "
                        "password in Settings › Sources")
        return out
    try:
        devs, stas = _fetch(cfg)
    except urllib.error.HTTPError as exc:
        out["error"] = (f"UniFi answered HTTP {exc.code}"
                        + (" - check the credentials; a read-only local admin is "
                           "enough for this source" if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot reach UniFi at {cfg['url']}: {exc}"
        return out

    # What this controller actually returns per switch port. The bridged-host
    # rule in links.py depends on one of these fields and the name varies by
    # controller version, so the controller is asked rather than assumed -
    # guessing the name once already cost a wrong answer.
    #
    # Settled 2026-09-10, by watching the UI itself. The "MAC Table" the web
    # interface shows per port is not fetched from any endpoint: opening it
    # issues only `ports/system-logs` and `ports/port-anomalies`, and the full
    # device record from /api/s/<site>/stat/device/<mac> carries exactly one
    # MAC per port - `last_connection.mac`. The UI assembles that table
    # client-side by grouping the clients from /stat/sta on `sw_mac` +
    # `sw_port`, which is data this source already fetches. There is no
    # endpoint to find, so `port_mac_lists` will stay empty and rule 5 keeps
    # reading `last_connection`; a fuller table can be built from `stas`
    # whenever it is worth doing.
    probe = next((p for d in devs for p in (d.get("port_table") or [])
                  if p.get("up")), None)
    if probe:
        out["host"]["port_fields"] = sorted(probe)
        out["host"]["port_mac_lists"] = sorted(
            k for k, v in probe.items()
            if isinstance(v, list) and v and isinstance(v[0], (str, dict)))

    entries = db.list_entries()
    by_ip, by_mac = _index(entries)
    by_name = {(e["name"] or "").strip().lower(): e for e in entries}
    ign = db.ignores()
    findings: list[dict] = []
    matched = 0

    dev_by_mac = {(d.get("mac") or "").lower(): d for d in devs}

    for d in devs:
        mac = (d.get("mac") or "").lower()
        ip = (d.get("ip") or "").strip()
        name = (d.get("name") or "").strip()
        e = (by_mac.get(mac)
             or by_name.get(name.lower())
             or (by_ip.get(ip.lower(), [None])[0] if ip else None))
        if not e:
            findings.append({
                "type": "device-untracked", "key": f"{P}:device:{mac}",
                "label": f"{name or mac} - adopted UniFi device, not in NetMap",
                "detail": f"{d.get('model')} at {ip or 'no address'}, firmware "
                          f"{d.get('version')}",
                "draft": {
                    "name": name or mac, "category": "Core Network",
                    "kind": "hardware", "host": "", "ip": ip, "ports": "",
                    "protocol": "", "zone": "", "tags": "unifi", "mac": mac,
                    "notes": f"UniFi {d.get('model')}. Discovered from UniFi "
                             f"{db.now()[:10]}.",
                    "monitor": bool(ip), "verified": False,
                },
            })
            continue
        matched += 1
        if not d.get("adopted") or d.get("state") != 1:
            findings.append({
                "type": "device-down", "key": f"{P}:down:{mac}",
                "label": f"{e['name']} - {'not adopted' if not d.get('adopted') else 'offline'}",
                "detail": f"the controller reports state {d.get('state')}",
                "entry": _ref(e),
            })
        elif mac and not _macs(e.get("mac", "")):
            findings.append({
                "type": "mac-missing", "key": f"{P}:mac:{mac}",
                "label": f"{e['name']} - no MAC recorded",
                "detail": (f"the controller reports {mac}. Recording it lets "
                           "this entry be matched when it has no address to "
                           "match on."),
                "entry": _ref(e), "suggest": {"mac": mac},
            })
        elif ip and (e.get("ip") or "").strip() != ip:
            findings.append({
                "type": "device-drift", "key": f"{P}:ip:{mac}",
                "label": f"{e['name']} - address differs",
                "detail": (f"the controller reports {ip}; NetMap records "
                           f"{e.get('ip') or '-'}. A device that fell back to "
                           "DHCP looks exactly like this."),
                "entry": _ref(e), "suggest": {"ip": ip},
            })

    # ---- physical links -----------------------------------------------
    # What the controller says is plugged into what, against the edges NetMap
    # holds. These are reported, never written: creating edges is derivation's
    # job, and derivation is something a person triggers.
    edge_at = {(x["src"], x["dst"], x["type"]): x for x in db.all_edges()}
    have = set(edge_at)
    for d in devs:
        up = (d.get("uplink") or {}).get("uplink_mac", "")
        if not up:
            continue
        src = by_mac.get((d.get("mac") or "").lower()) or by_name.get(
            (d.get("name") or "").strip().lower())
        parent = dev_by_mac.get(up.lower())
        dst = None
        if parent:
            dst = (by_mac.get(up.lower())
                   or by_name.get((parent.get("name") or "").strip().lower()))
        if not src or not dst or src["id"] == dst["id"]:
            continue
        if (src["id"], dst["id"], "connects_to") in have:
            continue
        port = (d.get("uplink") or {}).get("uplink_remote_port")
        findings.append({
            "type": "link-missing", "key": f"{P}:link:{d.get('mac')}",
            "label": f"{src['name']} → {dst['name']} is not recorded",
            "detail": ("the controller reports this uplink"
                       + (f" on port {port}" if port else "")
                       + ". Re-derive links on the Network view to record it."),
            "entry": _ref(src),
        })

    wired = [c for c in stas if c.get("is_wired")]

    # The same question as link-missing, asked about clients rather than about
    # the controller's own gear. `link-missing` only walks UniFi devices, so a
    # NAS or a coordinator plugged into a switch port could sit outside the
    # physical map indefinitely with nothing reporting it - the tree simply
    # listed it under "Not placed" and said nothing about why.
    for c in wired:
        sw = (c.get("sw_mac") or "").lower()
        if not sw:
            continue
        e = (by_mac.get((c.get("mac") or "").lower())
             or by_ip.get((c.get("ip") or "").strip().lower(), [None])[0])
        # Only hardware is on a cable - same reasoning as the derivation rule.
        if not e or e.get("kind") != "hardware":
            continue
        parent = dev_by_mac.get(sw) or {}
        dst = (by_mac.get(sw)
               or by_name.get((parent.get("name") or "").strip().lower()))
        if not dst or dst["id"] == e["id"]:
            continue
        port = c.get("sw_port")
        # Two cables between one pair - a machine's uplink carrying the LAN
        # and a management RJ45 beside it - are one edge, drawn in the
        # direction of the uplink. The management cable having no edge of its
        # own is the design, not a gap, so the reverse link answers this.
        if (dst["id"], e["id"], "connects_to") in have:
            continue
        held = edge_at.get((e["id"], dst["id"], "connects_to"))
        if held is not None:
            # A hand-made edge blocks the derived one permanently - `db.link`
            # is INSERT OR IGNORE, so the version carrying the port can never
            # replace it. Drawing a device on the right switch with the port
            # silently missing is a worse failure than not drawing it, because
            # nothing looks wrong. Report it; do not overwrite a person's edge.
            if (held["derived"] or not port
                    or PORT_RE.search(held.get("note") or "")):
                continue
            findings.append({
                "type": "client-unplaced", "key": f"{P}:client:{c.get('mac')}",
                "label": f"{e['name']} → {dst['name']} - recorded without port {port}",
                "detail": ("the link is hand-made and carries no port, which "
                           "permanently blocks the derived one that does. "
                           "Remove the hand-made link and re-derive."),
                "entry": _ref(e),
            })
            continue
        findings.append({
            "type": "client-unplaced", "key": f"{P}:client:{c.get('mac')}",
            "label": (f"{e['name']} → {dst['name']}"
                      + (f" port {port}" if port else "") + " is not recorded"),
            "detail": ("the controller sees this wired on that port, but "
                       "NetMap holds no link for it, so it does not appear on "
                       "the physical map. Re-derive links to record it."),
            "entry": _ref(e),
            **({"suggest": {"mac": (c.get("mac") or "").lower()}}
               if not _macs(e.get("mac", "")) else {}),
        })

    weak = 0
    WEAK_DBM = cfg["weak_dbm"]
    if WEAK_DBM:
        for c in stas:
            sig = c.get("signal")
            if c.get("is_wired") or sig is None or sig >= WEAK_DBM:
                continue
            e = by_mac.get((c.get("mac") or "").lower()) or (
                by_ip.get((c.get("ip") or "").strip().lower(), [None])[0])
            if not e:
                continue
            weak += 1
            findings.append({
                "type": "weak-signal", "key": f"{P}:weak:{c.get('mac')}",
                "label": f"{e['name']} - {sig} dBm on {c.get('essid')}",
                "detail": "below the weak-signal threshold set in Settings › Sources",
                "entry": _ref(e),
            })

    # ---- sightings: what the controller currently says -------------------
    seen: list[dict] = []
    for c in stas:
        mac = (c.get("mac") or "").lower()
        e = by_mac.get(mac) or by_ip.get((c.get("ip") or "").strip().lower(),
                                         [None])[0]
        if not e:
            continue
        if c.get("is_wired"):
            parent = dev_by_mac.get((c.get("sw_mac") or "").lower()) or {}
            where = (parent.get("name") or "switch").strip()
            port = c.get("sw_port")
            seen.append({"entry_id": e["id"], "fact": "link",
                         "value": f"wired to {where}"
                                  + (f" port {port}" if port else "")})
        else:
            sig = c.get("signal")
            seen.append({"entry_id": e["id"], "fact": "link",
                         "value": f"wifi {c.get('essid') or '?'}"
                                  + (f" {sig} dBm" if sig is not None else "")})
        if mac:
            seen.append({"entry_id": e["id"], "fact": "mac", "value": mac})
        if c.get("ip"):
            seen.append({"entry_id": e["id"], "fact": "ip",
                         "value": str(c.get("ip")).strip()})
    for d in devs:
        e = (by_mac.get((d.get("mac") or "").lower())
             or by_name.get((d.get("name") or "").strip().lower()))
        if not e:
            continue
        up = (d.get("uplink") or {})
        parent = dev_by_mac.get(str(up.get("uplink_mac") or "").lower()) or {}
        if parent:
            port = up.get("uplink_remote_port")
            seen.append({"entry_id": e["id"], "fact": "link",
                         "value": f"uplink to {(parent.get('name') or '?').strip()}"
                                  + (f" port {port}" if port else "")})
        seen.append({"entry_id": e["id"], "fact": "adopted",
                     "value": str(d.get("state") == 1 and "online" or "offline")})
    # ---- presence: every client the controller can see --------------------
    seen_ips = []
    for c in stas:
        a_ip = (c.get("ip") or "").strip()
        if not a_ip:
            continue
        where = ("wired" if c.get("is_wired") else
                 f"wifi {c.get('essid') or '?'}")
        seen_ips.append({
            "ip": a_ip,
            "label": (c.get("name") or c.get("hostname") or "").strip(),
            "mac": (c.get("mac") or "").lower(),
            "detail": where + (f" · {c.get('oui')}" if c.get("oui") else "")})
    db.record_presence(cfg.get("_id", "unifi"), seen_ips)

    db.record_sightings(cfg.get("_id", "unifi"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "devices": len(devs), "matched": matched, "clients": len(stas),
        "wired": len(wired),
        "untracked": sum(1 for f in kept if f["type"] == "device-untracked"),
        "drift": sum(1 for f in kept if f["type"] == "device-drift"),
        "down": sum(1 for f in kept if f["type"] == "device-down"),
        "mac": sum(1 for f in kept if f["type"] == "mac-missing"),
        "unplaced": sum(1 for f in kept if f["type"] == "client-unplaced"),
        "links": sum(1 for f in kept if f["type"] == "link-missing"),
        "weak": weak,
        "ignored": len(findings) - len(kept),
    }
    return out
