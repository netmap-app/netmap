"""Derive relationships from the entries themselves.

Most of a homelab's structure is already implicit in the inventory: `host`
says what a thing runs on, a public URL says what exposes it, a port-forward
says what published it. Typing those edges by hand for sixty entries is the
kind of chore that never gets done, so they are inferred here and written with
`derived=1`. Re-deriving clears only derived edges - anything you added by
hand is yours and is never touched.

Deliberately conservative: an ambiguous match produces nothing and is reported,
because a wrong edge in a dependency graph is worse than a missing one. It also
does not derive "everything depends on DNS" - true, useless, and it would bury
the real edges under sixty of its own.
"""
import re

from . import db
from .sources import by_role

PORT_RE = re.compile(r"\b(\d{1,5})\b")


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _index(rows: list[dict]) -> dict:
    by_name, by_ip = {}, {}
    for e in rows:
        by_name.setdefault(_norm(e["name"]), []).append(e)
        if e.get("ip"):
            by_ip.setdefault(e["ip"].strip().lower(), []).append(e)
    return {"name": by_name, "ip": by_ip}


def _machine_first(cands: list[dict]) -> list[dict]:
    """Prefer a machine when several entries answer to one address: a `host`
    that is one machine's address means the box, not the services on it."""
    machines = [e for e in cands if e.get("kind") in ("hardware", "vm")]
    return machines or cands


def resolve_host(text: str, idx: dict, rows: list[dict],
                 hmap: dict | None = None) -> tuple[dict | None, str]:
    """Find the entry a free-text `host` value refers to.

    The explicit map wins: "VM 101" is not a name, an IP or a substring of
    anything, so no amount of cleverness finds it - but one recorded decision
    does, permanently.
    """
    raw = (text or "").strip()
    if not raw:
        return None, "empty"
    key = _norm(raw)

    if hmap:
        m = hmap.get(key)
        if m:
            by_id = {e["id"]: e for e in rows}
            if m["entry_id"] in by_id:
                return by_id[m["entry_id"]], "host map"

    exact = idx["name"].get(key)
    if exact and len(exact) == 1:
        return exact[0], "name"
    if exact:
        return None, "ambiguous name"

    ip = idx["ip"].get(raw.lower())
    if ip:
        pick = _machine_first(ip)
        if len(pick) == 1:
            return pick[0], "ip"
        return None, "ambiguous ip"

    # substring, both directions, but only when exactly one entry matches:
    # "VM 101" finds "docker-host (VM 101)" without also claiming "VM 102".
    hits = [e for e in rows if key and (key in _norm(e["name"]) or _norm(e["name"]) in key)]
    hits = _machine_first(hits)
    if len(hits) == 1:
        return hits[0], "partial name"
    if len(hits) > 1:
        return None, "ambiguous partial"
    return None, "no match"


def _is_rule(e: dict) -> bool:
    return (e.get("kind") == "rule"
            or "port-forward" in {t.lower() for t in (e.get("tags") or [])}
            or (e.get("name") or "").strip().lower().startswith("port forward"))


def plan(rows: list[dict] | None = None) -> dict:
    """Work out every derivable edge. Returns edges plus what it could not resolve."""
    rows = rows if rows is not None else db.list_entries()
    idx = _index(rows)
    hmap = db.host_map()
    by_id = {e["id"]: e for e in rows}
    edges: list[dict] = []
    unresolved: list[dict] = []
    seen: set[tuple[int, int, str]] = set()

    def add(src, dst, type_, why):
        if src == dst:
            return
        k = (src, dst, type_)
        if k in seen:
            return
        seen.add(k)
        edges.append({"src": src, "dst": dst, "type": type_,
                      "src_name": by_id[src]["name"], "dst_name": by_id[dst]["name"],
                      "why": why})

    # 1. host -> runs_on
    for e in rows:
        if not (e.get("host") or "").strip():
            continue
        target, how = resolve_host(e["host"], idx, rows, hmap)
        if target:
            add(e["id"], target["id"], "runs_on", f"host matched by {how}")
        else:
            unresolved.append({"id": e["id"], "name": e["name"],
                               "host": e["host"], "why": how})

    # 2. a published hostname -> exposed_by the edge that publishes it
    # What the edge itself says it publishes (its `hostname:<name>` sightings),
    # not what a URL looks like: a name under the public domain that is only
    # served inside the house is not exposed by anything.
    published = [r for r in db.all_sightings() if r["fact"].startswith("hostname:")]
    for b in by_role("edge"):
        gw = b.mod.gateway(b.cfg, rows) if hasattr(b.mod, "gateway") else None
        if not gw:
            continue
        for r in published:
            # A NAT rule at the same address:port is witnessed too, but it is
            # another way in, not something the tunnel publishes.
            if (r["source"] == b.cfg["_id"] and r["entry_id"] in by_id
                    and not _is_rule(by_id[r["entry_id"]])):
                add(r["entry_id"], gw["id"], "exposed_by", f"published as {r['fact'][9:]}")

    # 3. a port-forward rule -> exposed_by that rule
    for rule in rows:
        if not _is_rule(rule):
            continue
        ip = (rule.get("ip") or "").strip().lower()
        ports = {int(m.group(1)) for m in PORT_RE.finditer(rule.get("ports") or "")
                 if 0 < int(m.group(1)) < 65536}
        if not ip or not ports:
            continue
        for e in rows:
            if e["id"] == rule["id"] or _is_rule(e):
                continue
            if (e.get("ip") or "").strip().lower() != ip:
                continue
            mine = {int(m.group(1)) for m in PORT_RE.finditer(e.get("ports") or "")
                    if 0 < int(m.group(1)) < 65536}
            if ports & mine:
                add(e["id"], rule["id"], "exposed_by", "port-forward to this ip:port")

    # 4. the physical layer, from the switch and Wi-Fi controllers
    # Everything above is inferred from the inventory's own text. This is the
    # one rule that asks another system, because "what is plugged into what"
    # is not written down anywhere in NetMap - it was typed in by hand from
    # notes, and a cable that moves silently invalidates it.
    # Every controller that answers, merged: two sites are two halves of one
    # physical graph, and a controller that fails contributes nothing rather
    # than stopping the others.
    topos = [b.mod.topology(b.cfg) for b in by_role("layer2")]
    topos = [t for t in topos if not t.get("error")]
    if topos:
        topo = {"devices": [d for t in topos for d in t["devices"]],
                "clients": [c for t in topos for c in t["clients"]]}
        by_mac, by_devname = {}, {}
        for e in rows:
            blob = ((e.get("mac") or "") + " " + (e.get("notes") or "")).lower()
            for m in re.findall(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", blob):
                by_mac.setdefault(m, e)
        for e in rows:
            by_devname.setdefault((e["name"] or "").strip().lower(), e)
        suppress: set[tuple[int, int]] = set()
        dev_ip = {d["mac"]: d["ip"] for d in topo["devices"]}
        dev_name = {d["mac"]: d["name"] for d in topo["devices"]}

        def find(mac: str):
            """A UniFi MAC to a NetMap entry: by MAC in the notes, by the
            controller's name for it, then by the address the controller
            reports. Ambiguity resolves to nothing, as everywhere else."""
            mac = (mac or "").lower()
            if not mac:
                return None
            hit = by_mac.get(mac)
            if hit:
                return hit
            hit = by_devname.get((dev_name.get(mac) or "").strip().lower())
            if hit:
                return hit
            ip = (dev_ip.get(mac) or "").strip().lower()
            cands = idx["ip"].get(ip, []) if ip else []
            return cands[0] if len(cands) == 1 else None

        # An uplink is a parent link, including where it leaves the
        # managed fabric. A switch may uplink to a server's SFP+ card,
        # which UniFi does not adopt - but that cable is the whole LAN's
        # path to the router, so it is the truest edge on the map.
        #
        # The trap is that the same pair is cabled *twice*: the SFP+
        # carrying everything, and an RJ45 carrying Proxmox management
        # only. The controller reports the second one as an ordinary
        # wired client, so both passes fire and the pair points at each
        # other - a two-node loop, which a tree cannot hold and which the
        # cycle guard then breaks arbitrarily.
        #
        # So the uplink wins and the management cable is suppressed, not
        # the other way round. Dropping the uplink instead (v1.46.0) kept
        # the tree acyclic but left the map upside down: the switch on
        # top, and the machine that routes for it drawn as one of its
        # clients. The suppressed cable is named in the note.
        adopted = {(d.get("mac") or "").lower() for d in topo["devices"]}
        for d in topo["devices"]:
            up = (d.get("uplink_mac") or "").lower()
            if not up:
                continue
            a, b = find(d["mac"]), find(up)
            if not (a and b):
                continue
            if up in adopted:
                port = d.get("uplink_port")
                add(a["id"], b["id"], "connects_to",
                    "UniFi uplink" + (f", port {port}" if port else ""))
                continue
            local = next((pt.get("port") for pt in (d.get("ports") or [])
                          if pt.get("uplink")), None)
            mgmt = next((c.get("sw_port") for c in topo["clients"]
                         if c.get("wired") and c.get("sw_mac") == d["mac"]
                         and by_mac.get((c.get("mac") or "").lower()) is b),
                        None)
            note = (f"uplink from port {local}" if local else "uplink")
            if mgmt:
                note += f" - second cable: port {mgmt}, management only"
                suppress.add((b["id"], a["id"]))
            add(a["id"], b["id"], "connects_to", note)
        for c in topo["clients"]:
            if not c["wired"] or not c["sw_mac"]:
                continue
            a = (by_mac.get(c["mac"])
                 or (idx["ip"].get(c["ip"].lower(), [None])[0] if c["ip"] else None))
            b = find(c["sw_mac"])
            # Only real hardware is on a cable. A bridged VM or LXC has its
            # own MAC on the host's port, so the controller reports it as a
            # wired client indistinguishable from the machine - and an edge
            # saying a container is plugged into a switch is false in the
            # way that matters: it hides the host that actually is.
            # `runs_on` already says where those live.
            if a is not None and a.get("kind") != "hardware":
                continue
            if a and b and (a["id"], b["id"]) not in suppress:
                add(a["id"], b["id"], "connects_to",
                    f"UniFi switch port {c['sw_port']}"
                    if c.get("sw_port") else "UniFi wired client")

        # A bridged host has no client record of its own. A Proxmox box
        # puts its guests on the wire with their own MACs, so the
        # controller sees six clients and no machine, and the machine that
        # is actually plugged in never reaches the physical map.
        #
        # The switch reports the last device seen on each port, and for
        # such a machine that is always one of its guests. So the rule is
        # narrow on purpose: **only a guest MAC places its host.** A port
        # whose last device is itself a piece of hardware says nothing new
        # - the wired-client pass above already knows where hardware is,
        # and trusting a single last-seen MAC there would happily put a
        # whole downstream switch's worth of devices on one port. Uplinks
        # are skipped for the same reason; the controller describes those
        # itself.
        for d in topo["devices"]:
            b = find(d["mac"])
            if not b:
                continue
            for p in (d.get("ports") or []):
                if p.get("uplink"):
                    continue
                guest = by_mac.get(p.get("last_mac") or "")
                if guest is None or guest.get("kind") == "hardware":
                    continue
                host, _ = resolve_host(guest.get("host") or "",
                                       idx, rows, hmap)
                if (not host or host.get("kind") != "hardware"
                        or host["id"] == b["id"]
                        or (host["id"], b["id"]) in suppress):
                    continue
                port = p.get("port")
                add(host["id"], b["id"], "connects_to",
                    f"UniFi switch port {port} - bridged host, seen via "
                    f"{guest['name']}" if port else
                    f"UniFi switch port - bridged host, seen via {guest['name']}")

    # Group the misses by the distinct host string: a dozen decisions, not
    # one per row. This list is what the UI asks you to answer.
    groups: dict[str, dict] = {}
    for u in unresolved:
        g = groups.setdefault(u["host"].strip(), {
            "host": u["host"].strip(), "why": u["why"], "count": 0, "examples": []})
        g["count"] += 1
        if len(g["examples"]) < 4:
            g["examples"].append(u["name"])
    unmapped = sorted(groups.values(), key=lambda g: (-g["count"], g["host"].lower()))

    return {"edges": edges, "unresolved": unresolved, "unmapped": unmapped,
            "counts": {"edges": len(edges), "unresolved": len(unresolved),
                       "unmapped": len(unmapped)}}


def apply(actor: str = "web") -> dict:
    """Rebuild derived edges. Hand-made edges are never touched."""
    p = plan()
    added = 0
    # Clear-then-rebuild in one transaction: a failure halfway used to leave
    # every derived link deleted and only some re-added.
    with db.transaction():
        removed = db.clear_derived_edges()
        for e in p["edges"]:
            try:
                db.link(e["src"], e["dst"], e["type"], note=e["why"],
                        derived=True, actor=actor)
                added += 1
            except ValueError:
                pass
        db.log(actor, "derive", None, "derived links",
               {"added": added, "replaced": removed,
                "unresolved": len(p["unresolved"])})
    p["applied"] = True
    p["counts"]["replaced"] = removed
    p["counts"]["added"] = added
    return p
