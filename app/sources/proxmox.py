"""Proxmox VE as a discovery source.

Like every source it is added from Settings › Sources - see
app/sources/dynamic.py. It follows the same rule as the rest of this package:
GET only, and nothing here can construct a write. A read-only credential is a
real option too - Proxmox has a built-in "PVEAuditor" role; a token built from
a user with only that role cannot change anything even if this code tried to.

Reads two things over the cluster's REST API:

  /nodes                     which nodes exist and whether they're up
  /nodes/{node}/qemu         VMs on that node
  /nodes/{node}/lxc          containers on that node

Matching an entry to a VM/container does not use an IP - Proxmox does not
hand one back without an extra per-guest call this module deliberately
avoids making a hundred times a scan. Instead it uses the vmid, which this
inventory can carry in the `host` field by convention ("VM 101",
"CT 107") or in a `proxmox:<vmid>` tag when the name isn't
in that shape.
"""
import json
import re
import ssl
import urllib.error
import urllib.request

from .. import db
from . import _http

VMID_RE = re.compile(r"\b(?:VM|CT)\s*0*(\d+)\b", re.I)
TAG_RE = re.compile(r"proxmox:(\d+)", re.I)

FIELDS = [
    {"key": "url", "label": "API URL", "type": "text", "required": True, "wide": True,
     "placeholder": "https://10.0.0.5:8006", "binds": True},
    {"key": "token_id", "label": "API token ID", "type": "text", "required": True,
     "wide": True, "placeholder": "netmap@pve!ro", "binds": True},
    {"key": "token_secret", "label": "API token secret", "type": "password",
     "secret": True, "required": True, "wide": True},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox",
     "default": False},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 8},
]

ROLES = ("hypervisor",)  # see dynamic.ROLES

# Entries name a guest by vmid ("VM 101"), and two clusters can both have a
# 101 - until an entry can say which cluster, a second one would claim the
# other's guests and report its own as gone.
MULTI = False


def configured(cfg: dict) -> bool:
    return bool((cfg.get("url") or "").strip() and (cfg.get("token_id") or "").strip()
                and (cfg.get("token_secret") or "").strip())


def _ctx(cfg: dict):
    if str(cfg.get("verify_ssl", False)).lower() in ("1", "true", "yes"):
        return None
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _get(cfg: dict, path: str):
    url = cfg["url"].rstrip("/") + "/api2/json" + path
    req = urllib.request.Request(url, headers={
        "accept": "application/json",
        "authorization": f"PVEAPIToken={cfg['token_id']}={cfg['token_secret']}"})
    timeout = float(cfg.get("timeout") or 8)
    with _http.urlopen(req, timeout=timeout, context=_ctx(cfg)) as r:
        return json.loads(r.read())["data"]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _vmid_of(e: dict) -> int | None:
    m = TAG_RE.search(",".join(e.get("tags") or []))
    if not m:
        m = VMID_RE.search(e.get("host") or "")
    return int(m.group(1)) if m else None


def test(cfg: dict) -> dict:
    """A cheap connectivity check for the Settings 'Test' button - one call,
    no findings, no sightings."""
    try:
        nodes = _get(cfg, "/nodes")
        return {"ok": True, "nodes": [n.get("node") for n in nodes]}
    except urllib.error.HTTPError as exc:
        return {"ok": False,
                "error": f"Proxmox answered HTTP {exc.code}"
                        + (" - check the token ID and secret" if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach {cfg.get('url')}: {exc}"}


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "proxmox")          # finding-key prefix; see dynamic.py
    out = {"configured": configured(cfg), "scanned_at": db.now(),
           "host": {"url": cfg.get("url", "")}, "findings": [], "counts": {},
           "error": None}
    if not configured(cfg):
        out["error"] = "not configured - set the API URL, token ID and token secret"
        return out
    try:
        nodes = _get(cfg, "/nodes")
    except urllib.error.HTTPError as exc:
        out["error"] = (f"Proxmox answered HTTP {exc.code}"
                        + (" - check the token ID and secret" if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot reach Proxmox at {cfg.get('url')}: {exc}"
        return out

    guests: list[dict] = []
    for n in nodes:
        node = n.get("node")
        if n.get("status") != "online":
            continue
        try:
            for v in _get(cfg, f"/nodes/{node}/qemu"):
                guests.append({"kind": "vm", "node": node, "vmid": v.get("vmid"),
                               "name": v.get("name") or f"VM {v.get('vmid')}",
                               "status": v.get("status", "")})
            for v in _get(cfg, f"/nodes/{node}/lxc"):
                guests.append({"kind": "container", "node": node, "vmid": v.get("vmid"),
                               "name": v.get("name") or f"CT {v.get('vmid')}",
                               "status": v.get("status", "")})
        except Exception as exc:
            # One node failing (rebooting, unreachable) never hides the rest.
            out.setdefault("node_errors", []).append(f"{node}: {exc}")

    entries = db.list_entries()
    by_vmid: dict[int, dict] = {}
    for e in entries:
        vmid = _vmid_of(e)
        if vmid is not None:
            by_vmid.setdefault(vmid, e)  # first entry wins; duplicates are a data problem, not this scan's

    ign = db.ignores()
    findings: list[dict] = []
    seen: list[dict] = []
    matched_vmids: set[int] = set()

    # Entries that name no vmid can still be matched by name - "VM 101" in
    # `host` or a proxmox:<vmid> tag is a convention, not a requirement.
    # Uniquely only, never an entry that names a different vmid, and only
    # something that could be a guest - not a service that shares its name.
    by_name: dict[str, list[dict]] = {}
    for e in entries:
        if _vmid_of(e) is None and (e.get("kind") or "") in ("vm", "container", ""):
            by_name.setdefault(_norm(e["name"]), []).append(e)

    for g in guests:
        e = by_vmid.get(g["vmid"])
        named = by_name.get(_norm(g["name"]), [])
        if e is None and len(named) == 1:
            e = named[0]
        prefix = "VM" if g["kind"] == "vm" else "CT"
        if e:
            matched_vmids.add(g["vmid"])
            seen.append({"entry_id": e["id"], "fact": g["kind"],
                         "value": f"{g['name']} {g['status']} on {g['node']}"})
            if g["status"] != "running":
                findings.append({
                    "type": "stopped", "key": f"{P}:stopped:{g['vmid']}",
                    "label": f"{e['name']} ({prefix} {g['vmid']}) is {g['status']}",
                    "detail": f"on node {g['node']}",
                    "entry": {"id": e["id"], "name": e["name"]},
                })
        else:
            findings.append({
                "type": "new", "key": f"{P}:new:{g['vmid']}",
                "label": f"{g['name']} ({prefix} {g['vmid']})",
                "detail": f"on node {g['node']}, {g['status']}, not in NetMap",
                "draft": {
                    "name": g["name"], "category": "Uncategorised",
                    "kind": "vm" if g["kind"] == "vm" else "container",
                    "host": f"{prefix} {g['vmid']}", "ip": "", "ports": "",
                    "tags": "proxmox",
                    "notes": f"Discovered from Proxmox {db.now()[:10]}. "
                             f"Node {g['node']}, {prefix.lower()}id {g['vmid']}.",
                    "monitor": False, "verified": False,
                },
            })

    for vmid, e in by_vmid.items():
        if vmid not in matched_vmids:
            findings.append({
                "type": "gone", "key": f"{P}:gone:{vmid}",
                "label": e["name"],
                "detail": f"recorded as Proxmox guest {vmid}, but no VM or "
                          "container with that id exists on the cluster",
                "entry": {"id": e["id"], "name": e["name"]},
            })

    db.record_sightings(cfg.get("_id", "proxmox"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "nodes": len(nodes), "guests": len(guests), "matched": len(matched_vmids),
        "new": sum(1 for f in kept if f["type"] == "new"),
        "gone": sum(1 for f in kept if f["type"] == "gone"),
        "stopped": sum(1 for f in kept if f["type"] == "stopped"),
        "ignored": len(findings) - len(kept),
    }
    return out
