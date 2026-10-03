"""What every local DNS server is checked for, whichever product it is.

A DNS driver reads its local records into

    {"ip": "10.0.0.10", "names": ["plex.lan", "plex.example.org"]}

and hands them to reconcile(), which compares them with the inventory the
same way for Pi-hole and AdGuard Home. Renumbering a host is easy; what breaks
is never the host but whatever still points at the old address, and a local
A record is exactly that kind of pointer.
"""
from .. import db


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def draft(name: str, ip: str, why: str, product: str) -> dict:
    return {
        "name": name, "category": "Uncategorised", "kind": "hardware",
        "host": "", "ip": ip, "ports": "", "protocol": "", "zone": "",
        "tags": "", "notes": f"{why}, discovered from {product} {db.now()[:10]}.",
        "mac": "", "monitor": False, "verified": False,
    }


def reconcile(P: str, product: str, records: list[dict], entries: list[dict]
              ) -> tuple[list[dict], list[dict]]:
    """(findings, sightings) for one server's local records. Findings carry
    keys under prefix `P`; nothing is filtered by ignores here."""
    by_ip: dict[str, list[dict]] = {}
    for e in entries:
        ip = (e.get("ip") or "").strip()
        if ip:
            by_ip.setdefault(ip, []).append(e)
    findings: list[dict] = []

    for r in records:
        if by_ip.get(r["ip"]):
            continue
        label = f"{', '.join(r['names'])} → {r['ip']}"
        # Does any entry claim this name at a different address? That is
        # drift, and far more interesting than a merely unknown record.
        moved = []
        for n in r["names"]:
            stem = n.split(".")[0].lower()
            for e in entries:
                if not (e.get("ip") or "").strip():
                    continue
                if stem and (stem == (e["name"] or "").lower()
                             or stem in (e.get("url") or "").lower()):
                    moved.append(e)
        key = f"{P}:dns:{r['ip']}:{r['names'][0]}"
        if moved:
            e = moved[0]
            findings.append({
                "type": "dns-drift", "key": key,
                "label": f"{label} — NetMap has {e['name']} at {e['ip']}",
                "detail": ("a local DNS record and the inventory disagree about "
                           "this name's address. After a renumbering the record "
                           "is usually the stale one."),
                "entry": _ref(e),
            })
        else:
            findings.append({
                "type": "dns-orphan", "key": key, "label": label,
                "detail": "a local DNS record for an address NetMap does not track",
                "draft": draft(r["names"][0], r["ip"], "Local DNS record", product),
            })

    # A name belongs to the entry that claims it. The host that answers all of
    # them gets one line saying so, not twenty-three identical ones — a fact
    # repeated is not a fact confirmed.
    seen: list[dict] = []
    host_names: dict[int, list[str]] = {}
    for r in records:
        for e in by_ip.get(r["ip"], []):
            for n in r["names"]:
                low = n.lower()
                stem = low.split(".")[0]
                if (low in (e.get("url") or "").lower()
                        or stem == (e.get("name") or "").strip().lower()):
                    seen.append({"entry_id": e["id"], "fact": f"dns:{low}",
                                 "value": f"local record → {r['ip']}"})
                elif e.get("kind") in ("hardware", "vm"):
                    host_names.setdefault(e["id"], []).append(low)
    for eid, names in host_names.items():
        names = sorted(set(names))
        seen.append({"entry_id": eid, "fact": "dns",
                     "value": f"{len(names)} local record"
                              f"{' points' if len(names) == 1 else 's point'} here: "
                              + ", ".join(names[:6])
                              + (f" +{len(names) - 6} more" if len(names) > 6 else "")})
    return findings, seen
