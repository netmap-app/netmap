"""OPNsense as a discovery source.

Reads three things over the firewall's REST API, all GET, all read-only:

  /api/dnsmasq/leases/search      what currently holds an address
  /api/dnsmasq/settings/searchHost what is *meant* to hold one (reservations)
  /api/firewall/d_nat/search_rule  the inbound port forwards

The distinction between the first two matters and cost us an hour to learn by
hand: the lease table shows only what is online, so a reservation for a powered
-off machine is invisible there. Reservations are the intent; leases are the
observation; NetMap is the third opinion. Disagreements between them are the
findings.

Unlike the Docker source there is no read-only credential to hand out — an
OPNsense API key carries its user's privileges. The safeguard here is that this
module only ever issues GETs, and nothing in it can construct a write.
"""
import base64
import json
import re
import urllib.error
import urllib.request

from .. import db
from . import _http, fields

MAC_RE = re.compile(r"\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b", re.I)


def _macs(text: str) -> set[str]:
    return {m.replace("-", ":").lower() for m in MAC_RE.findall(str(text or ""))}

FIELDS = [
    {"key": "url", "label": "API URL", "type": "text", "required": True, "wide": True,
     "placeholder": "https://10.0.0.1", "binds": True, "env": "NETMAP_OPNSENSE_URL"},
    {"key": "key", "label": "API key", "type": "text", "required": True, "wide": True,
     "binds": True, "env": "NETMAP_OPNSENSE_KEY"},
    {"key": "secret", "label": "API secret", "type": "password", "secret": True,
     "required": True, "wide": True, "env": "NETMAP_OPNSENSE_SECRET"},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox",
     "default": True, "env": "NETMAP_OPNSENSE_VERIFY"},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 8,
     "env": "NETMAP_OPNSENSE_TIMEOUT"},
    # Every phone and lightbulb on the LAN is an "unknown lease". Off by
    # default; turn it on when you want a sweep of what is out there.
    {"key": "report_unknown", "label": "Report every unknown lease (noisy)",
     "type": "checkbox", "default": False, "env": "NETMAP_OPNSENSE_REPORT_UNKNOWN"},
]

ROLES = ("firewall", "leases")  # see dynamic.ROLES

# "Not here" findings — dropped when another opnsense source sees the entry.
ABSENCE = {'nat-stale'}

PORT_RE = re.compile(r"\b(\d{1,5})\b")


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("key") and cfg.get("secret"))


def _get(cfg: dict, path: str):
    req = urllib.request.Request(
        cfg["url"] + path,
        headers={"accept": "application/json",
                 "authorization": "Basic " + base64.b64encode(
                     f"{cfg['key']}:{cfg['secret']}".encode()).decode()})
    with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
        return json.loads(r.read())


def test(cfg: dict) -> dict:
    try:
        _get(cfg, "/api/dnsmasq/settings/searchHost")
        return {"ok": True, "error": None}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"OPNsense answered HTTP {exc.code}"
                + (" — check the API key and secret" if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach OPNsense at {cfg['url']}: {exc}"}


def _ports(text: str) -> set[int]:
    return {int(m.group(1)) for m in PORT_RE.finditer(text or "")
            if 0 < int(m.group(1)) < 65536}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _is_rule_entry(e: dict) -> bool:
    return (e.get("kind") == "rule"
            or "port-forward" in {t.lower() for t in (e.get("tags") or [])}
            or (e.get("name") or "").strip().lower().startswith("port forward"))


def _draft(name: str, ip: str, mac: str, iface: str, descr: str,
           why: str) -> dict:
    """A ready-to-create entry for something the firewall knows about and
    NetMap does not.

    Deliberately thin. The address is the one fact the firewall is authoritative
    about; the name is its DHCP hostname and the category is a guess nobody
    should have to undo, so it is left blank rather than filed somewhere wrong.
    `zone` comes from OPNsense's own interface name, not from parsing the
    subnet — the firewall is the thing that decides which segment an address is
    on. Everything else is for a person to fill in after the one click.
    """
    note = f"{why}, discovered from OPNsense {db.now()[:10]}."
    if descr:
        note += f" Firewall description: {descr}."
    return {
        "name": name, "category": "Uncategorised", "kind": "hardware",
        "host": "", "ip": ip, "mac": mac, "ports": "", "protocol": "",
        "zone": iface, "tags": "", "notes": note,
        "monitor": False, "verified": False,
    }


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", ""),
            "ports": e.get("ports", "")}


def _machine(here: list[dict]) -> dict | None:
    """The entry a DHCP reservation is really about.

    One entry at the address: that one. Several — a Docker host and the twenty
    containers sharing its IP — the single hardware or VM among them, because
    that is what holds the network interface the reservation names. Two
    machines at one address is a genuine ambiguity and gets nothing.
    """
    if len(here) == 1:
        return here[0]
    hosts = [e for e in here if e.get("kind") in ("hardware", "vm")]
    return hosts[0] if len(hosts) == 1 else None


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "opnsense")          # finding-key prefix; see dynamic.py
    out = {"source": cfg.get("_id", "opnsense"), "configured": configured(cfg), "scanned_at": db.now(),
           "host": {"url": cfg.get("url", "")}, "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = ("not configured — add the API URL, key and secret in "
                        "Settings › Sources")
        return out
    try:
        leases = _get(cfg, "/api/dnsmasq/leases/search").get("rows", [])
        hosts = _get(cfg, "/api/dnsmasq/settings/searchHost").get("rows", [])
        rules = _get(cfg, "/api/firewall/d_nat/search_rule").get("rows", [])
    except urllib.error.HTTPError as exc:
        out["error"] = (f"OPNsense answered HTTP {exc.code}"
                        + (" — check the API key and that its user may reach "
                           "these endpoints" if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot reach OPNsense at {cfg['url']}: {exc}"
        return out

    entries = db.list_entries()
    # Interface per address, straight from the lease table. Used to fill a
    # draft's `zone` — LAN / IoT are OPNsense's own names for the segments, so
    # this is read from the firewall rather than inferred from the subnet.
    iface_of = {(ls.get("address") or "").strip(): (ls.get("if_descr") or "")
                for ls in leases}
    mac_of = {(ls.get("address") or "").strip():
              (ls.get("mac_info") or ls.get("hwaddr") or "") for ls in leases}
    by_ip: dict[str, list[dict]] = {}
    for e in entries:
        ip = (e.get("ip") or "").strip()
        if ip:
            by_ip.setdefault(ip, []).append(e)
    ign = db.ignores()
    findings: list[dict] = []

    # ---- port forwards -------------------------------------------------
    # A NAT rule has two ports — the one the world knocks on and the one it is
    # sent to — and an entry may record either, or both. Matching on only one
    # of them produces the worst possible answer: the same forward reported as
    # both "not in NetMap" and "no such rule", which reads as two problems
    # instead of none. So: match on the target address plus *either* port,
    # then fall back to the description, then to a last unambiguous pairing.
    live = [r for r in rules if not r.get("is_automatic")
            and str(r.get("disabled")) != "1" and str(r.get("nordr")) != "1"]
    rule_entries = [e for e in entries if _is_rule_entry(e)]

    views = []
    for r in live:
        views.append({
            "uuid": r.get("uuid"), "target": (r.get("target") or "").strip(),
            "local": _ports(r.get("local-port") or ""),
            "wan": _ports(r.get("destination.port") or ""),
            "local_raw": r.get("local-port") or "?",
            "wan_raw": r.get("destination.port") or "?",
            "descr": r.get("descr") or "", "iface": r.get("interface", "?"),
            "proto": (r.get("protocol") or "").upper(),
        })

    pairs: list[tuple[dict, dict]] = []
    free_e = list(rule_entries)

    def _take(v, e):
        pairs.append((v, e))
        free_e.remove(e)

    def _at(target):
        return [e for e in free_e if (e.get("ip") or "").strip() == target]

    left = []
    for v in views:                                    # 1. address + either port
        want = v["local"] | v["wan"]
        hits = [e for e in _at(v["target"]) if _ports(e.get("ports")) & want]
        if len(hits) == 1:
            _take(v, hits[0])
        else:
            left.append(v)

    still = []
    for v in left:                                     # 2. address + description
        d = _norm(v["descr"])
        hits = ([e for e in _at(v["target"]) if d and d in _norm(e["name"])]
                if d else [])
        if len(hits) == 1:
            _take(v, hits[0])
        else:
            still.append(v)

    unmatched_rules = []
    for v in still:                                    # 3. the only two left here
        here = _at(v["target"])
        mine = [w for w in still if w["target"] == v["target"]]
        if len(here) == 1 and len(mine) == 1:
            _take(v, here[0])
        else:
            unmatched_rules.append(v)

    for v, e in pairs:
        recorded = _ports(e.get("ports"))
        missing = sorted((v["local"] | v["wan"]) - recorded)
        if missing:
            findings.append({
                "type": "nat-drift", "key": f"{P}:nat:{v['uuid']}",
                "label": f"{e['name']} — recorded ports differ",
                "detail": (f"live rule is WAN {v['wan_raw']} → {v['target']}:"
                           f"{v['local_raw']} ({v['descr'] or 'no description'}); "
                           f"NetMap records '{e.get('ports') or '—'}'"),
                "entry": _ref(e),
                "suggest": {"ports": f"{v['local_raw']} (WAN {v['wan_raw']})"},
            })

    for v in unmatched_rules:
        desc = v["descr"] or "(no description)"
        findings.append({
            "type": "nat-unknown", "key": f"{P}:nat:{v['uuid']}",
            "label": f"inbound rule not in NetMap — {desc}",
            "detail": (f"WAN {v['wan_raw']} → {v['target']}:{v['local_raw']} on "
                       f"{v['iface']}, {v['proto']}. Something is exposed that the "
                       "inventory does not describe."),
            "draft": {
                "name": f"Port forward — {desc}",
                "category": "Remote Access", "kind": "rule",
                "host": "OPNsense", "ip": v["target"],
                "ports": f"{v['local_raw']} (WAN {v['wan_raw']})",
                "protocol": v["proto"], "tags": "port-forward",
                "notes": f"Discovered from OPNsense {db.now()[:10]}. "
                         f"Rule description: {desc}.",
                "monitor": False, "verified": False,
            },
        })

    for e in free_e:
        findings.append({
            "type": "nat-stale", "key": f"{P}:nat-stale:{e['id']}",
            "label": e["name"],
            "detail": "recorded as an inbound rule, but no enabled rule on the "
                      "firewall forwards to that address and port",
            "entry": _ref(e),
        })

    # ---- addresses: intent vs observation ------------------------------
    for ls in leases:
        ip = (ls.get("address") or "").strip()
        here = by_ip.get(ip, [])
        if here and not ls.get("is_reserved"):
            names = ", ".join(e["name"] for e in here[:3])
            findings.append({
                "type": "addr-unreserved", "key": f"{P}:unreserved:{ip}",
                "label": f"{names} — {ip} is not reserved",
                "detail": (f"NetMap records this address as fixed, but it is a "
                           f"dynamic lease (hostname {ls.get('hostname') or '*'}, "
                           f"{ls.get('mac_info') or ls.get('hwaddr')}). It can move "
                           "on the next renewal and the inventory would go stale."),
                "entry": _ref(here[0]),
            })
        elif not here and cfg["report_unknown"]:
            findings.append({
                "type": "lease-unknown", "key": f"{P}:lease:{ls.get('hwaddr')}",
                "label": f"{ls.get('hostname') or '*'} at {ip}",
                "detail": f"on the network ({ls.get('if_descr')}), not in NetMap. "
                          f"{ls.get('mac_info') or ls.get('hwaddr')}",
                "draft": _draft(ls.get("hostname") or ip, ip,
                                ls.get("mac_info") or ls.get("hwaddr") or "",
                                ls.get("if_descr") or "", "",
                                "Seen on the network"),
            })

    # A reservation holds the one thing three sources join on. Copying it into
    # the entry by hand is the sort of work nobody does, and without it a
    # device can sit outside the physical map with nothing explaining why —
    # UniFi identifies a wired client by MAC, and an address the controller
    # never saw handed out gives it nothing else to match on.
    for h in hosts:
        ip = (h.get("ip") or "").strip()
        e = _machine(by_ip.get(ip, []) if ip else [])
        if not e or _macs(e.get("mac", "")):
            continue
        found = MAC_RE.findall(str(h.get("hwaddr") or mac_of.get(ip, "")))
        if not found:
            continue
        mac = found[0].replace("-", ":").lower()
        findings.append({
            "type": "mac-unrecorded", "key": f"{P}:mac:{e['id']}",
            "label": f"{e['name']} — reserved as {mac}, not recorded",
            "detail": ("the DHCP reservation for this address carries a "
                       "hardware address the entry does not. That field is "
                       "what UniFi and Pi-hole match on, so without it the "
                       "entry is invisible to both."),
            "entry": _ref(e), "suggest": {"mac": mac},
        })

    # A reservation that names a MAC nothing at that address uses. This is the
    # quiet twin of `addr-unreserved`: there, the inventory believes an address
    # is fixed when it is a lease; here, a reservation exists and looks correct
    # in both the firewall UI and the inventory, and can never match, because
    # the machine answers with a different interface. Nothing breaks while the
    # address is also set statically on the host or sits outside the DHCP pool
    # — until one of those stops being true, and then the address moves with no
    # warning and every reference to it goes stale at once.
    #
    # Typical case: reserved as ...aa:07 while the bridge answers on ...aa:06,
    # read off the wrong port of a multi-port machine.
    for h in hosts:
        ip = (h.get("ip") or "").strip()
        e = _machine(by_ip.get(ip, []) if ip else [])
        if not e:
            continue
        mine = _macs(e.get("mac", ""))
        # Only an entry that states its MACs can contradict a reservation.
        # Silence is not disagreement — that gap is `mac-unrecorded`'s job.
        if not mine:
            continue
        want = _macs(h.get("hwaddr"))
        if not want or want & mine:
            continue
        findings.append({
            "type": "reservation-mismatch", "key": f"{P}:resmac:{h.get('uuid')}",
            "label": f"{e['name']} — reserved as {', '.join(sorted(want))}, "
                     f"but answers on {', '.join(sorted(mine))}",
            "detail": ("the DHCP reservation for this address names a hardware "
                       "address this machine does not use, so it can never "
                       "match. The address is not actually held by the "
                       "reservation — check whether the host sets it statically, "
                       "and fix the MAC on the firewall. If the machine really "
                       "does have that interface, record it on the entry "
                       "instead."),
            "entry": _ref(e),
        })

    for h in hosts:
        ip = (h.get("ip") or "").strip()
        if ip and ip not in by_ip:
            findings.append({
                "type": "reservation-orphan", "key": f"{P}:host:{h.get('uuid')}",
                "label": f"{h.get('host') or '?'} reserved at {ip}",
                "detail": ("a DHCP reservation with nothing in NetMap at that "
                           "address — either untracked infrastructure, or a "
                           "leftover holding an address hostage"),
                "draft": _draft(h.get("host") or ip, ip,
                                h.get("hwaddr") or mac_of.get(ip, ""),
                                iface_of.get(ip, ""),
                                h.get("descr") or h.get("comments") or "",
                                "DHCP reservation"),
            })

    # ---- sightings: what OPNsense currently says ------------------------
    seen: list[dict] = []
    for v, e in pairs:
        val = f"forwarded from WAN {v['wan_raw']} ({v['proto'] or 'TCP'})"
        seen.append({"entry_id": e["id"], "fact": f"port:{v['local_raw']}",
                     "value": val})
        # The rule entry describes the forward; the service behind it is what
        # someone reading an exposure path actually wants to see it on.
        for o in by_ip.get(v["target"], []):
            if o["id"] != e["id"] and (_ports(o.get("ports") or "") & v["local"]):
                seen.append({"entry_id": o["id"], "fact": f"port:{v['local_raw']}",
                             "value": val})
    for h in hosts:
        ip = (h.get("ip") or "").strip()
        e = _machine(by_ip.get(ip, []) if ip else [])
        if not e:
            continue
        seen.append({"entry_id": e["id"], "fact": "dhcp", "value": f"reserved {ip}"})
        found = MAC_RE.findall(str(h.get("hwaddr") or mac_of.get(ip, "")))
        if found:
            seen.append({"entry_id": e["id"], "fact": "mac",
                         "value": found[0].replace("-", ":").lower()})
    for ls in leases:
        ip = (ls.get("address") or "").strip()
        e = _machine(by_ip.get(ip, []))
        if not e or ls.get("is_reserved"):
            continue
        seen.append({"entry_id": e["id"], "fact": "dhcp",
                     "value": f"dynamic lease {ip}"})
    # ---- presence: who holds an address, tracked or not -------------------
    # Two traps in this payload. `mac_info` is the *vendor* string, not a
    # hardware address — "asustek computer inc." went straight into the mac
    # field the first time. And a lease with no hostname reports "*", which is
    # a placeholder that then outranked UniFi's real name when the two were
    # merged. Both are filtered here rather than in the UI, because every
    # reader would otherwise have to know about them.
    def _label(v) -> str:
        v = (v or "").strip()
        return "" if v in ("*", "-", "?") else v

    def _pair(raw_mac, raw_info) -> tuple[str, str]:
        """(mac, vendor) — whichever of the two fields actually holds which."""
        found = MAC_RE.findall(str(raw_mac or "")) or MAC_RE.findall(str(raw_info or ""))
        mac = found[0].replace("-", ":").lower() if found else ""
        vendor = str(raw_info or "").strip()
        if MAC_RE.findall(vendor) or vendor.lower() == mac:
            vendor = ""
        return mac, vendor

    here: dict[str, dict] = {}
    for ls in leases:
        a_ip = (ls.get("address") or "").strip()
        if not a_ip:
            continue
        mac, vendor = _pair(ls.get("hwaddr"), ls.get("mac_info"))
        here[a_ip] = {
            "ip": a_ip, "label": _label(ls.get("hostname")), "mac": mac,
            "detail": f"DHCP lease on {ls.get('if_descr') or 'LAN'}"
                      + (f" · {vendor}" if vendor else "")}
    for h in hosts:
        a_ip = (h.get("ip") or "").strip()
        if not a_ip:
            continue
        mac, vendor = _pair(h.get("hwaddr"), mac_of.get(a_ip))
        # A reservation's name was typed by a person, so it wins over a lease.
        here[a_ip] = {
            "ip": a_ip, "label": _label(h.get("host")), "mac": mac,
            "detail": "DHCP reservation" + (f" · {vendor}" if vendor else "")}

    db.record_presence(cfg.get("_id", "opnsense"), list(here.values()))

    db.record_sightings(cfg.get("_id", "opnsense"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "leases": len(leases), "reservations": len(hosts),
        "mac_unrecorded": sum(1 for f in kept if f["type"] == "mac-unrecorded"),
        "rules": len(live),
        "nat_unknown": sum(1 for f in kept if f["type"] == "nat-unknown"),
        "nat_stale": sum(1 for f in kept if f["type"] == "nat-stale"),
        "nat_drift": sum(1 for f in kept if f["type"] == "nat-drift"),
        "unreserved": sum(1 for f in kept if f["type"] == "addr-unreserved"),
        "orphan": sum(1 for f in kept if f["type"] == "reservation-orphan"),
        "res_mismatch": sum(1 for f in kept if f["type"] == "reservation-mismatch"),
        "unknown": sum(1 for f in kept if f["type"] == "lease-unknown"),
        "ignored": len(findings) - len(kept),
    }
    return out
