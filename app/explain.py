"""Say, in sentences, what is known about one entry.

Everything here is derived — nothing is stored, nothing is guessed. The
inputs are the entry's own fields, its edges, its live status and the
sightings the sources left behind; the output is the paragraph a
person would write after reading all four, which is exactly the work this
app existed to remove.

Two rules hold the whole file together:

  * Say only what a source or a field actually says. "Nothing observed" is
    a legitimate sentence and appears often; "probably fine" never does.
  * Absence is not evidence. A port nobody scanned is not a closed port, a
    service no source mentions is not a service that does not exist — it is
    a blind spot, and blind spots get their own section rather than being
    silently folded into the good news.

Sections come back as {key, title, text, level}. `level` is one of "ok",
"note", "warn" — the UI colours by it and the MCP client reads it as
severity. It is never "error": a claim that something is broken belongs in
findings, where it can be argued with.
"""
from __future__ import annotations

from . import db
from .sources.dynamic import has_role

HOSTISH = ("hardware", "vm")

# What "is it backed up / where are its credentials" makes no sense for: a
# client device (a phone, a bulb, a speaker — the categories the port sweep
# already leaves alone) and a firewall rule or a network, which hold nothing
# to back up and log in to. Asking anyway turned every one of them into two
# gaps nobody will ever close.
NO_DATA_KINDS = ("rule", "network")


def _holds_nothing(e: dict) -> bool:
    from .sources import by_role, portscan
    b = next(iter(by_role("scanner", configured_only=False)), None)
    skip = b.mod.skip_categories(b.cfg) if b else portscan.skip_categories(None)
    return ((e.get("category") or "").strip().lower() in skip
            or e.get("kind") in NO_DATA_KINDS)


def _fmt_list(items: list[str], limit: int = 4) -> str:
    items = [str(i) for i in items]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) <= limit:
        return ", ".join(items[:-1]) + " and " + items[-1]
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def _chain(entry_id: int, rows: dict, depth: int = 4) -> list[str]:
    """Walk up runs_on / connects_to and name each rung."""
    out, cur, seen = [], entry_id, {entry_id}
    for _ in range(depth):
        r = db.conn().execute(
            "SELECT dst FROM edges WHERE src=? AND type IN ('runs_on','connects_to') "
            "ORDER BY CASE type WHEN 'runs_on' THEN 0 ELSE 1 END, id LIMIT 1",
            (cur,)).fetchone()
        if not r or r["dst"] in seen or r["dst"] not in rows:
            break
        seen.add(r["dst"])
        out.append(rows[r["dst"]]["name"])
        cur = r["dst"]
    return out


def explain(entry_id: int, live: dict | None = None) -> dict | None:
    e = db.get_entry(entry_id)
    if not e:
        return None
    rows = {x["id"]: x for x in db.list_entries()}
    edges = db.edges_for(entry_id)
    sights = db.sightings_for(entry_id)
    live = live or {}

    def facts(prefix: str) -> list[dict]:
        return [s for s in sights if s["fact"] == prefix
                or s["fact"].startswith(prefix + ":")]

    out: list[dict] = []
    kind = e.get("kind") or "entry"
    crit = e.get("criticality") or ""

    # ---- what it is ------------------------------------------------------
    article = "an" if kind[:1].lower() in "aeiou" else "a"
    what = f"{e['name']} is {article} {kind} in {e.get('category') or 'no category'}"
    if crit:
        what += f", marked {crit}"
    chain = _chain(entry_id, rows)
    if chain:
        what += ". It runs on " + " which sits on ".join(chain)
    link = next((s for s in sights if s["fact"] == "link"), None)
    if link:
        what += f". The controller sees it {link['value']}"
    out.append({"key": "what", "title": "What it is", "text": what + ".",
                "level": "note"})

    # ---- where it answers ------------------------------------------------
    addr = (e.get("ip") or "").strip()
    ports = (e.get("ports") or "").strip()
    seen_ports = facts("port")
    open_now = [s for s in seen_ports if has_role(s["source"], "scanner")
                and "open" in (s["value"] or "")]
    shut = [s for s in seen_ports if has_role(s["source"], "scanner")
            and "open" not in (s["value"] or "")]
    if addr or ports:
        text = f"It answers at {addr or 'no recorded address'}"
        text += f" on {ports}" if ports else " with no recorded ports"
        if open_now:
            text += (f". A scan confirms {_fmt_list([s['fact'][5:] for s in open_now])} "
                     + ("is" if len(open_now) == 1 else "are") + " listening")
        if shut:
            text += (f". {_fmt_list([s['fact'][5:] for s in shut])} did not answer "
                     "the scanner")
        if live.get("up") is True:
            text += f". The health check reached {live.get('target')} last run"
        elif live.get("up") is False:
            text += f". The health check got no answer from {live.get('target')}"
        out.append({"key": "reach", "title": "Where it answers", "text": text + ".",
                    "level": "warn" if (shut or live.get("up") is False) else "ok"})

    # ---- who can get to it from outside ----------------------------------
    fwd = [s for s in seen_ports if has_role(s["source"], "firewall")]
    proxy = facts("proxy")
    pub = facts("hostname")
    naked = [s for s in pub if "no Access" in (s["value"] or "")]
    if fwd or proxy or pub:
        bits = []
        if fwd:
            bits.append(f"the firewall forwards {_fmt_list([s['fact'][5:] for s in fwd])} "
                        "from the WAN straight to it")
        if proxy:
            names = [s["fact"][6:] for s in proxy if ":" in s["fact"]]
            bits.append("the reverse proxy serves "
                        + (_fmt_list(names) if names else proxy[0]["value"]))
        if pub:
            names = [s["fact"][9:] for s in pub if ":" in s["fact"]]
            bits.append("the tunnel publishes "
                        + (_fmt_list(names) if names else pub[0]["value"]))
        text = "From outside the network, " + "; ".join(bits) + "."
        if naked:
            text += (" " + _fmt_list([s["fact"][9:] for s in naked])
                     + " has no Access application in front of it, so whatever "
                       "answers there answers the open internet.")
        elif pub:
            text += " Every published name is behind Cloudflare Access."
        out.append({"key": "exposure", "title": "Reachable from outside",
                    "text": text, "level": "warn" if (naked or fwd) else "ok"})
    else:
        from .sources import by_role, dynamic
        seeing = [b for r in ("firewall", "proxy", "edge") for b in by_role(r)]
        if seeing:
            labels = {dynamic.DRIVERS[dynamic.type_of(b.cfg.get("_id", ""))]["label"]
                      if dynamic.type_of(b.cfg.get("_id", "")) in dynamic.DRIVERS
                      else b.cfg.get("_id", "a source") for b in seeing}
            text = ("No source reports a port forward, a proxied name or a tunnel "
                    "hostname pointing at this. As far as "
                    + _fmt_list(sorted(labels))
                    + " can see, it is reachable from the LAN only.")
        else:
            text = ("No firewall, proxy or tunnel source is added, so nothing here "
                    "can say whether this is reachable from outside.")
        out.append({"key": "exposure", "title": "Reachable from outside",
                    "text": text, "level": "ok" if seeing else "note"})

    # ---- what it needs, what needs it ------------------------------------
    ups = [x for x in edges["out"] if x["type"] == "depends_on"]
    downs = [x for x in edges["in"] if x["type"] in ("depends_on", "runs_on")]
    if ups or downs:
        bits = []
        if ups:
            bits.append("It needs " + _fmt_list([x["other_name"] for x in ups]))
        if downs:
            bits.append(("It carries " if kind in HOSTISH else "Depending on it: ")
                        + _fmt_list([x["other_name"] for x in downs])
                        + f" ({len(downs)} in total)")
        out.append({"key": "deps", "title": "What it touches",
                    "text": ". ".join(bits) + ".",
                    "level": "note"})

    # ---- backups and credentials -----------------------------------------
    tags = [t.lower() for t in (e.get("tags") or [])]
    back = [t for t in tags if t.startswith("backup:")]
    care = []
    if back:
        care.append("backup:none" in back
                    and "It is tagged as deliberately not backed up"
                    or "It is backed up to " + _fmt_list(
                        [t.split(":", 1)[1] for t in back if t != "backup:none"]))
    if e.get("secret_ref"):
        care.append(f"Credentials are in {e['secret_ref']}")
    if care:
        out.append({"key": "care", "title": "Backup and credentials",
                    "text": ". ".join(care) + ".", "level": "note"})

    # ---- what nobody can see ---------------------------------------------
    blind = []
    if not sights:
        blind.append("no source has said anything about it — it exists in the "
                     "inventory and nowhere else")
    if not e.get("monitor"):
        blind.append("monitoring is off, so a health check will never fail for it")
    if not e.get("verified"):
        blind.append("nobody has marked it verified")
    if not (e.get("mac") or "").strip() and kind in HOSTISH:
        blind.append("it has no MAC recorded, which is what UniFi and Pi-hole "
                     "match on")
    if not back and not _holds_nothing(e):
        blind.append("nothing records whether it is backed up")
    if not e.get("secret_ref") and not _holds_nothing(e):
        blind.append("nothing records where its credentials live")
    if blind:
        out.append({"key": "blind", "title": "What nobody can see",
                    "text": "The gap here is " + blind[0] + "."
                            if len(blind) == 1 else
                            f"{len(blind)} gaps:",
                    "items": [b[0].upper() + b[1:] + "." for b in blind]
                             if len(blind) > 1 else [],
                    "level": "warn" if not sights else "note"})

    return {
        "entry_id": entry_id, "name": e["name"],
        "sections": out,
        "sources": sorted({s["source"] for s in sights}),
        "sighting_count": len(sights),
    }


def as_text(d: dict) -> str:
    """The same thing as one block of prose, for an MCP client to read out."""
    out = []
    for s in d["sections"]:
        block = f"{s['title']}: {s['text']}"
        for i in s.get("items") or []:
            block += f"\n  - {i}"
        out.append(block)
    return "\n\n".join(out)
