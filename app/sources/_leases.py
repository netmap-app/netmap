"""What the `leases` role implies, written once — as _dns.py is for DNS and
_proxy.py for reverse proxies.

A leases source says which hardware address holds which IP right now: a DHCP
server's lease file, a router's ARP table. It maps its own data onto rows
{ip, mac, label, detail} and calls report(); everything a person sees follows
from those rows:

  presence    every row is a dot on the address map (db.record_presence)
  sightings   `lease` on an entry whose address and MAC the source confirms
  mac-mismatch  an entry that states its MAC(s), at an address this source
                sees held by a different one — the address changed hands, or
                the entry's MAC is wrong
  ip-moved    an entry's MAC is seen at another address, and not at the
              entry's own — the device moved and the inventory did not

Only entries that record a MAC are judged. Services share their host's
address and have no hardware address of their own; silence is not
disagreement.
"""
import ipaddress

from .. import db

MAC_RE = db.MAC_RE


def mac(text) -> str:
    """One canonical hardware address, or ""."""
    found = MAC_RE.findall(str(text or ""))
    return found[0].replace("-", ":").lower() if found else ""


def macs(text) -> set[str]:
    return {m.replace("-", ":").lower() for m in MAC_RE.findall(str(text or ""))}


def ipv4(text) -> str:
    """The address if it is a unicast IPv4 address, else ""."""
    try:
        a = ipaddress.IPv4Address(str(text or "").strip())
    except ValueError:
        return ""
    return "" if a.is_multicast or a.is_unspecified or a.packed == b"\xff" * 4 else str(a)


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def report(cfg: dict, rows: list[dict], what: str, fact: str = "lease") -> tuple[list, dict]:
    """Record presence and sightings for one leases source, and return its
    findings and counts. `what` names the source in a sentence ("the dnsmasq
    lease file", "the router's ARP table")."""
    P, sid = cfg.get("_key", "leases"), cfg.get("_id", "leases")
    rows = [r for r in rows if r.get("ip")]
    by_ip = {r["ip"]: r for r in rows}
    ips_of: dict[str, set[str]] = {}
    for r in rows:
        if r.get("mac"):
            ips_of.setdefault(r["mac"], set()).add(r["ip"])

    findings, seen = [], []
    for e in db.list_entries():
        mine = macs(e.get("mac"))
        ip = (e.get("ip") or "").strip()
        if not mine:
            continue
        at = by_ip.get(ip) if ip else None
        if at and at.get("mac") in mine:
            seen.append({"entry_id": e["id"], "fact": fact,
                         "value": f"{ip} at {at['mac']} ({what})"})
            continue
        if at and at.get("mac"):
            findings.append({
                "type": "mac-mismatch", "key": f"{P}:leasemac:{e['id']}",
                "label": f"{e['name']} — {ip} is held by {at['mac']}",
                "detail": (f"{what} sees {ip} at {at['mac']}"
                           + (f" ({at['label']})" if at.get("label") else "")
                           + f", but the entry records {', '.join(sorted(mine))}. "
                           "Either the address changed hands, or the entry's MAC is wrong."),
                "entry": _ref(e),
            })
            continue
        elsewhere = sorted(set().union(*(ips_of.get(m, set()) for m in mine)))
        if ip and elsewhere:
            findings.append({
                "type": "ip-moved", "key": f"{P}:moved:{e['id']}",
                "label": f"{e['name']} — now at {elsewhere[0]}, not {ip}",
                "detail": (f"{what} sees this entry's MAC at {', '.join(elsewhere)} "
                           f"and nothing of it at {ip}. The device moved; the "
                           "inventory did not."),
                "entry": _ref(e),
                "suggest": {"ip": elsewhere[0]} if len(elsewhere) == 1 else {},
            })
    db.record_presence(sid, [{"ip": r["ip"], "label": r.get("label") or "",
                              "mac": r.get("mac") or "", "detail": r.get("detail") or what}
                             for r in rows])
    db.record_sightings(sid, seen)
    ign = db.ignores()
    kept = [f for f in findings if f["key"] not in ign]
    for f in kept:
        if not f.get("suggest"):
            f.pop("suggest", None)
    return kept, {"addresses": len(rows), "matched": len(seen),
                  "mac_mismatch": sum(1 for f in kept if f["type"] == "mac-mismatch"),
                  "ip_moved": sum(1 for f in kept if f["type"] == "ip-moved"),
                  "ignored": len(findings) - len(kept)}
