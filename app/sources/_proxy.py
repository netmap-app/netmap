"""What every reverse proxy is checked for, whichever product it is.

A proxy driver reads its own API into routes -

    {"domain": "plex.example.org", "host": "10.0.0.10", "port": 32400,
     "enabled": True}

- and hands them to reconcile(), which compares them with the inventory the
same way for NPM and Traefik: a name nobody tracks, a name switched off, a
forward to an address nothing holds, a forward that disagrees with the entry.
The rules and their reasons were learnt on NPM; they are kept here so a second
proxy does not have to learn them again.
"""
import re

from .. import db

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PORT_RE = re.compile(r"\b(\d{2,5})\b")


def _ports(text: str) -> set[int]:
    return {int(m.group(1)) for m in PORT_RE.finditer(text or "")
            if 0 < int(m.group(1)) < 65536}


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def _draft(domain: str, target: str, product: str) -> dict:
    return {
        "name": domain.split(".")[0], "category": "Uncategorised",
        "kind": "service", "host": "", "ip": "", "ports": "", "protocol": "HTTPS",
        "url": f"https://{domain}", "zone": "", "tags": "", "mac": "",
        "notes": f"Proxied by {product} to {target}. Discovered {db.now()[:10]}.",
        "monitor": False, "verified": False,
    }


def reconcile(P: str, product: str, routes: list[dict], entries: list[dict]
              ) -> tuple[list[dict], list[dict]]:
    """(findings, sightings) for one proxy's routes. Findings carry keys
    under prefix `P`; nothing is filtered by ignores here."""
    by_ip: dict[str, list[dict]] = {}
    for e in entries:
        ip = (e.get("ip") or "").strip()
        if ip:
            by_ip.setdefault(ip, []).append(e)
    findings: list[dict] = []
    seen: list[dict] = []
    host_proxy: dict[int, list[str]] = {}

    for r in routes:
        domain = r["domain"].lower()
        fh = str(r.get("host") or "").strip()
        fp = r.get("port")
        target = f"{fh}:{fp}" if fp else fh
        enabled = bool(r.get("enabled", True))

        hit = [e for e in entries if domain in (e.get("url") or "").lower()]
        e = hit[0] if len(hit) == 1 else None

        # ---- sightings: what the proxy currently says ----------------------
        val = f"→ {target}" + ("" if enabled else " (disabled)")
        if e is not None:
            seen.append({"entry_id": e["id"], "fact": f"proxy:{domain}", "value": val})
        for o in by_ip.get(fh, []):
            # An address that runs nineteen containers must not hand every one
            # of them its neighbours' hostnames. A service owns the port it
            # listens on; the host answers all of them and gets one rolled-up
            # line below rather than twenty near-identical rows.
            if fp and int(fp) in _ports(o.get("ports") or ""):
                seen.append({"entry_id": o["id"], "fact": f"proxy:{domain}", "value": val})
            elif o.get("kind") in ("hardware", "vm"):
                host_proxy.setdefault(o["id"], []).append(domain)

        if not enabled and not hit:
            # Switched off and claimed by nobody: nothing is being served and
            # nothing believes otherwise. Drafting an entry would be inventing
            # work.
            continue

        if not hit:
            findings.append({
                "type": "proxy-untracked", "key": f"{P}:host:{domain}",
                "label": f"{domain} → {target} - proxied, not in NetMap",
                "detail": f"{product} serves this name and no inventory entry accounts for it",
                "draft": _draft(domain, target, product),
            })
            continue

        if not enabled:
            findings.append({
                "type": "proxy-disabled", "key": f"{P}:off:{domain}",
                "label": f"{e['name'] if e else domain} - {domain} is disabled in {product}",
                "detail": ("the inventory publishes this address but the proxy "
                           "route is switched off, so the name resolves and then "
                           "answers with nothing"),
                **({"entry": _ref(e)} if e else {}),
            })
            continue

        if e is None or not IP_RE.match(fh):
            continue

        # An entry whose `ip` is a hostname describes the *public* endpoint,
        # not the origin - an entry can hold "ha-mcp.example.org:443" on
        # purpose, so its health check tests the whole path. The proxy's
        # forward target is the far end of that same path: not a
        # disagreement, a different end.
        if not IP_RE.match((e.get("ip") or "").strip()):
            continue

        if fh not in by_ip:
            findings.append({
                "type": "proxy-orphan", "key": f"{P}:orphan:{domain}",
                "label": f"{domain} → {target} - nothing at that address",
                "detail": ("the proxy forwards to an address no inventory entry "
                           "holds. After a renumbering this is what stays "
                           "behind, and the name fails while the service itself "
                           "is perfectly healthy."),
                "entry": _ref(e),
            })
            continue

        mine = _ports(e.get("ports") or "")
        if fh != (e.get("ip") or "").strip() or (fp and mine and int(fp) not in mine):
            findings.append({
                "type": "proxy-drift", "key": f"{P}:drift:{domain}",
                "label": f"{e['name']} - {product} forwards {domain} to {target}",
                "detail": (f"the entry records {e.get('ip')}"
                           + (f":{', '.join(str(p) for p in sorted(mine))}" if mine else "")
                           + ". One of the two is out of date."),
                "entry": _ref(e),
            })

    for eid, names in host_proxy.items():
        names = sorted(set(names))
        seen.append({"entry_id": eid, "fact": "proxy",
                     "value": f"{len(names)} proxied name"
                              f"{' lands' if len(names) == 1 else 's land'} here: "
                              + ", ".join(names[:6])
                              + (f" +{len(names) - 6} more" if len(names) > 6 else "")})
    return findings, seen


def counts(kept: list[dict]) -> dict:
    return {t.replace("proxy-", ""): sum(1 for f in kept if f["type"] == t)
            for t in ("proxy-untracked", "proxy-disabled", "proxy-orphan", "proxy-drift")}
