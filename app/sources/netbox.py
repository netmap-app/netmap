"""NetBox as a discovery source - the `intent` role.

For someone who keeps NetBox as the source of truth: what NetBox says should
exist, reconciled against what NetMap tracks. Reads, GET only, following
NetBox's pagination:

  /api/dcim/devices/                       devices, their primary IPv4
  /api/virtualization/virtual-machines/    VMs, their primary IPv4
  /api/dcim/interfaces/                    device interfaces' MAC addresses
  /api/virtualization/interfaces/          VM interfaces' MAC addresses
  /api/ipam/ip-addresses/                  addresses assigned to nothing

Matching: by address first, then by name - an entry's own name, or a host
name mapped to it (host_map). Findings:

  netbox-untracked   an active NetBox device or VM NetMap does not track (draft)
  netbox-ip          a standalone active NetBox address no entry holds (draft)
  netbox-missing     a hardware or VM entry NetBox does not know
  netbox-ip-drift    matched by name, NetBox's primary address differs (suggest)
  netbox-mac-drift   the entry's MAC is none of NetBox's for it (suggest)

Read-only by enforcement: give it a NetBox API token with write disabled
(`write_enabled` off; for v2 tokens, `nbt_…`, the same switch). The module
only issues GETs, never follows a redirect, and refuses a `next` page on
another host, so the token only ever reaches the configured NetBox. There is
no push to NetBox - that would be a write.
"""
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

from .. import db
from . import _http, fields

FIELDS = [
    {"key": "url", "label": "NetBox URL", "type": "text", "required": True, "wide": True,
     "placeholder": "https://netbox.example.com", "binds": True},
    {"key": "token", "label": "API token (read-only)", "type": "password", "secret": True,
     "required": True, "wide": True},
    {"key": "kinds", "label": "Entry kinds NetBox should know (comma separated)",
     "type": "text", "default": "hardware, vm"},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox", "default": True},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 10},
]

ROLES = ("intent",)  # see dynamic.ROLES
ABSENCE = {"netbox-missing"}

PAGE = 500            # objects per request
MAX_PAGES = 200       # 100k objects: enough for a homelab, a stop for a loop


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("token"))


def _auth(token: str) -> str:
    # NetBox 4.5 v2 tokens are "nbt_<key>.<secret>" and use Bearer; the older
    # 40-character tokens use "Token".
    return f"Bearer {token}" if token.startswith("nbt_") else f"Token {token}"


def _get(cfg: dict, url: str):
    req = urllib.request.Request(url, headers={
        "accept": "application/json", "authorization": _auth(cfg["token"])})
    with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
        return json.loads(r.read())


def _list(cfg: dict, path: str) -> list[dict]:
    """Every object of one endpoint, page by page. A `next` link that leaves
    the configured NetBox is refused rather than followed with the token."""
    base = urllib.parse.urlsplit(cfg["url"])
    url = f"{cfg['url']}{path}?limit={PAGE}"
    out: list[dict] = []
    for _ in range(MAX_PAGES):
        page = _get(cfg, url)
        out += page.get("results") or []
        nxt = page.get("next")
        if not nxt:
            return out
        n = urllib.parse.urlsplit(nxt)
        if (n.scheme, n.netloc) != (base.scheme, base.netloc):
            raise ValueError(f"NetBox's next page points at {n.scheme}://{n.netloc}, not "
                             f"{base.scheme}://{base.netloc} - set NetBox's own URL "
                             "(or its BASE_PATH / proxy headers) so the token stays there")
        url = nxt
    raise ValueError(f"more than {MAX_PAGES} pages at {path}")


def test(cfg: dict) -> dict:
    try:
        st = _get(cfg, cfg["url"] + "/api/status/")
        return {"ok": True, "error": None, "version": st.get("netbox-version")}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"NetBox answered HTTP {exc.code}"
                + (" - check the token" if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach NetBox at {cfg['url']}: {exc}"}


def _addr(v) -> str:
    """"10.0.0.5/24" (or {"address": …}) → "10.0.0.5"; "" otherwise."""
    if isinstance(v, dict):
        v = v.get("address")
    try:
        return str(ipaddress.ip_interface(str(v or "")).ip)
    except ValueError:
        return ""


def _status(o: dict) -> str:
    s = o.get("status")
    return str((s or {}).get("value") if isinstance(s, dict) else s or "").lower()


def _label(o: dict) -> str:
    v = o.get("display") or o.get("name") or ""
    return str(v)


def _macs(o: dict) -> set[str]:
    """An interface's MACs: NetBox ≥ 4.2 keeps them as objects
    (primary_mac_address, mac_addresses), earlier ones as a string."""
    out = set()
    for v in [o.get("mac_address"), o.get("primary_mac_address")] + list(o.get("mac_addresses") or []):
        if isinstance(v, dict):
            v = v.get("mac_address")
        for m in db.MAC_RE.findall(str(v or "")):
            out.add(m.replace("-", ":").lower())
    return out


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def _draft(name: str, ip: str, kind: str, macs: set[str], note: str) -> dict:
    return {"name": name or ip, "category": "Uncategorised", "kind": kind, "host": "",
            "ip": ip, "mac": ", ".join(sorted(macs)), "ports": "", "protocol": "",
            "notes": f"{note}, from NetBox {db.now()[:10]}.", "monitor": False,
            "verified": False}


def reconcile(P: str, devices: list[dict], vms: list[dict], dev_ifs: list[dict],
              vm_ifs: list[dict], ips: list[dict], entries: list[dict],
              hmap: dict, kinds: set[str]) -> tuple[list[dict], list[dict], dict]:
    """(findings, sightings, counts) - pure, so the matching can be tested
    without a NetBox."""
    macs: dict[tuple[str, int], set[str]] = {}
    for i in dev_ifs:
        d = (i.get("device") or {}).get("id")
        if d is not None:
            macs.setdefault(("device", d), set()).update(_macs(i))
    for i in vm_ifs:
        v = (i.get("virtual_machine") or {}).get("id")
        if v is not None:
            macs.setdefault(("vm", v), set()).update(_macs(i))

    objs = [("device", o) for o in devices] + [("vm", o) for o in vms]
    by_ip: dict[str, list[dict]] = {}
    by_name: dict[str, dict] = {}
    for e in entries:
        ip = (e.get("ip") or "").strip()
        if ip:
            by_ip.setdefault(ip, []).append(e)
        by_name.setdefault(db.host_key(e["name"]), e)
    for key, row in hmap.items():                  # a host name mapped to an entry
        e = next((x for x in entries if x["id"] == row["entry_id"]), None)
        if e:
            by_name.setdefault(key, e)

    findings, seen, matched = [], [], set()
    for typ, o in objs:
        name, ip = _label(o), _addr(o.get("primary_ip4") or o.get("primary_ip"))
        mine = macs.get((typ, o.get("id")), set())
        what = "device" if typ == "device" else "VM"
        # Address first - but only a machine at that address, not one of the
        # services sharing it; then the name.
        cands = [x for x in by_ip.get(ip, []) if x.get("kind") in (kinds or {"hardware", "vm"})]
        e = cands[0] if len(cands) == 1 else by_name.get(db.host_key(name))
        if not e:
            if _status(o) == "active":
                findings.append({
                    "type": "netbox-untracked", "key": f"{P}:{typ}:{o.get('id')}",
                    "label": f"{name} - NetBox {what}, not in NetMap",
                    "detail": ("active in NetBox" + (f" at {ip}" if ip else "")
                               + ", but no entry matches it by address or name"),
                    "draft": _draft(name, ip, "hardware" if typ == "device" else "vm",
                                    mine, f"NetBox {what}"),
                })
            continue
        matched.add(e["id"])
        role = (o.get("role") or o.get("device_role") or {}).get("name") if typ == "device" else None
        site = (o.get("site") or {}).get("name")
        seen.append({"entry_id": e["id"], "fact": "intent",
                     "value": f"NetBox {what} {name}"
                              + (f" ({', '.join(x for x in (site, role) if x)})" if site or role else "")})
        eip = (e.get("ip") or "").strip()
        if ip and eip and ip != eip:
            findings.append({
                "type": "netbox-ip-drift", "key": f"{P}:ip:{typ}:{o.get('id')}",
                "label": f"{e['name']} - NetBox says {ip}, NetMap {eip}",
                "detail": f"the NetBox {what} {name} has primary address {ip}",
                "entry": _ref(e), "suggest": {"ip": ip},
            })
        emacs = {m.replace("-", ":").lower() for m in db.MAC_RE.findall(e.get("mac") or "")}
        if mine and emacs and not mine & emacs:
            findings.append({
                "type": "netbox-mac-drift", "key": f"{P}:mac:{typ}:{o.get('id')}",
                "label": f"{e['name']} - NetBox has {', '.join(sorted(mine))}",
                "detail": (f"none of the NetBox {what}'s interfaces carries the entry's "
                           f"MAC ({', '.join(sorted(emacs))})"),
                "entry": _ref(e),
                **({"suggest": {"mac": next(iter(mine))}} if len(mine) == 1 else {}),
            })

    # Addresses NetBox records on their own, assigned to no interface.
    held = set(by_ip)
    for a in ips:
        ip = _addr(a.get("address"))
        if not ip or a.get("assigned_object_id") or _status(a) != "active" or ip in held:
            continue
        dns = str(a.get("dns_name") or "").strip()
        findings.append({
            "type": "netbox-ip", "key": f"{P}:addr:{a.get('id')}",
            "label": f"{dns or ip} - NetBox address, not in NetMap",
            "detail": (f"{ip} is active in NetBox IPAM"
                       + (f" as {dns}" if dns else "") + ", and no entry holds it"),
            "draft": _draft(dns or ip, ip, "", set(), "NetBox IP address"),
        })

    for e in entries:
        if e["id"] in matched or e.get("kind") not in kinds:
            continue
        findings.append({
            "type": "netbox-missing", "key": f"{P}:missing:{e['id']}",
            "label": f"{e['name']} - not in NetBox",
            "detail": (f"a {e.get('kind')} entry no NetBox device or VM matches by "
                       "address or name - add it to NetBox, or map its name"),
            "entry": _ref(e),
        })
    counts = {"devices": len(devices), "vms": len(vms), "matched": len(matched)}
    return findings, seen, counts


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "netbox")           # finding-key prefix; see dynamic.py
    out = {"source": cfg.get("_id", "netbox"), "configured": configured(cfg),
           "scanned_at": db.now(), "host": {"url": cfg.get("url", "")},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = "not configured - add the NetBox URL and a read-only token in Settings › Sources"
        return out
    try:
        devices = _list(cfg, "/api/dcim/devices/")
        vms = _list(cfg, "/api/virtualization/virtual-machines/")
        dev_ifs = _list(cfg, "/api/dcim/interfaces/")
        vm_ifs = _list(cfg, "/api/virtualization/interfaces/")
        ips = _list(cfg, "/api/ipam/ip-addresses/")
    except urllib.error.HTTPError as exc:
        out["error"] = (f"NetBox answered HTTP {exc.code}"
                        + (" - check the token" if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot read NetBox at {cfg['url']}: {exc}"
        return out
    kinds = {k.strip().lower() for k in str(cfg.get("kinds") or "").split(",") if k.strip()}
    findings, seen, counts = reconcile(P, devices, vms, dev_ifs, vm_ifs, ips,
                                       db.list_entries(), db.host_map(), kinds)
    db.record_sightings(cfg.get("_id", "netbox"), seen)
    ign = db.ignores()
    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {**counts, "ignored": len(findings) - len(kept)}
    return out
