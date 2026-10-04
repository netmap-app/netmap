"""The control room: what needs a person, and nothing else.

The old Overview answered "how much is there" - entries tracked, categories,
a bar chart of the inventory. That is a fine thing to be able to look up and a
poor thing to open every day, because none of it changes and none of it asks
anything of you.

This answers one question instead: **is anything wrong, and what do I do
first**. Everything here is either a problem, the evidence that there is no
problem, or the exposure surface - which is the one standing fact in this
network worth keeping in front of a person, since it is the only part an
attacker also reads.

Three rules:

  * Rank by what it costs to ignore, not by which subsystem produced it. A
    critical service that stopped answering and a hostname with nothing in
    front of it belong in the same queue.
  * A dead source outranks everything it would have reported. If OPNsense has
    not answered in a day, "0 mismatches" is not good news, it is no news, and
    presenting it as good news is the failure this whole app exists to avoid.
  * Silence is a real answer, and it gets said out loud. "Nothing needs you"
    is the most useful sentence this page can produce, so it is produced
    deliberately rather than left as an empty list.
"""
from __future__ import annotations

from . import db, sources
from .sources.dynamic import has_role

# What it costs to ignore. Used to sort the queue and to colour it.
SEV = {"critical": 0, "warn": 1, "note": 2}

# A dismissal is not a mute. It says "I have seen this and it is fine as it
# is", and the moment the situation is no longer the one that was seen, it has
# to come back - otherwise the page slowly becomes a list of things somebody
# once clicked away, which is worse than no page.
#
# So a dismissal stores a fingerprint of what was dismissed, and an item whose
# fingerprint has changed is shown again. Critical items get a 24-hour snooze
# instead of a fingerprint, because "a critical service is down" is not
# something a person should be able to switch off permanently in one click.
DISMISS_SOURCE = "overview"
SNOOZE_HOURS = 24



def _access_ignores() -> dict[str, dict]:
    """Hostnames whose "nothing in front of it" finding was ignored, from
    whichever edge source raised it: "cloudflare:access:<host>" for the first
    Cloudflare, "cloudflare-2:access:<host>" for another."""
    out = {}
    for key, row in db.ignores().items():
        prefix, _, rest = key.partition(":")
        kind, _, host = rest.partition(":")
        if has_role(prefix, "edge") and kind == "access" and host:
            out.setdefault(host, row)
    return out

def _fingerprint(item: dict) -> str:
    """What a dismissal remembers. An item can add to it (`fingerprint`):
    which entries a grouped item is about, when its text alone would not
    change as they do."""
    extra = item.get("fingerprint")
    return f"{item['key']}|{item['title']}|{item.get('detail', '')}" + (f"|{extra}" if extra else "")


def _dismissed(items: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split the queue into what to show and what has been set aside."""
    marks = db.ignores(DISMISS_SOURCE)
    live, hidden = [], []
    for it in items:
        m = marks.get(f"{DISMISS_SOURCE}:{it['key']}")
        if not m:
            live.append(it)
            continue
        if it["level"] == "critical":
            # A snooze, and it wakes up.
            age = _age_hours(m.get("created_at"))
            if age is None or age >= SNOOZE_HOURS:
                it = {**it, "was_snoozed": True}
                live.append(it)
                continue
        elif m.get("reason") != _fingerprint(it):
            # The situation changed since it was set aside.
            live.append({**it, "changed_since_dismissed": True})
            continue
        hidden.append({**it, "dismissed_at": m.get("created_at")})
    return live, hidden


def _age_hours(ts: str | None) -> float | None:
    if not ts:
        return None
    import calendar
    import time as _t
    try:
        t = calendar.timegm(_t.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return None
    return (_t.time() - t) / 3600.0


def dismiss(key: str, item_title: str = "", fingerprint: str = "") -> dict:
    return db.add_ignore(f"{DISMISS_SOURCE}:{key}", DISMISS_SOURCE,
                         item_title, fingerprint, actor="web")


def undismiss(key: str) -> bool:
    return db.clear_ignore(f"{DISMISS_SOURCE}:{key}")


def _rank(item: dict) -> tuple:
    """Worst level, then the item's order, then the widest (a machine with
    twenty services down before one with two), then by title."""
    return (SEV.get(item["level"], 9), item.get("order", 0),
            -len(item.get("entries") or ()), item["title"])


def exposure() -> dict:
    """What can be reached from outside, according to the sources themselves.

    Read from sightings rather than from the inventory's `url` field, because
    the inventory records intent and the sightings record what Cloudflare and
    OPNsense currently say. The gap between those two is the whole point.
    """
    rows = db.all_sightings()
    names = {e["id"]: e["name"] for e in db.list_entries()}

    # Keyed by hostname, not by row. Several entries can legitimately witness
    # the same name - the service and the host it runs on - and a hostname
    # published twice is still one hostname facing the internet. Counting rows
    # here is what turned two open names into twenty-seven.
    published: set[str] = set()
    naked: dict[str, dict] = {}
    for r in rows:
        if not has_role(r["source"], "edge") or not r["fact"].startswith("hostname:"):
            # The bare `hostname` fact is the host rollup ("10 tunnel hostnames
            # reach here…"); the per-service rows below carry the names.
            continue
        host = r["fact"][9:]
        published.add(host)
        if "no Access" in (r["value"] or "") and host not in naked:
            naked[host] = {"host": host, "entry_id": r["entry_id"],
                           "entry": names.get(r["entry_id"], "")}

    forwards = [{"port": r["fact"][5:], "entry_id": r["entry_id"],
                 "entry": names.get(r["entry_id"], ""), "detail": r["value"]}
                for r in rows
                if has_role(r["source"], "firewall") and r["fact"].startswith("port:")]

    # One forward, not two. Since v1.36.1 a port forward is credited to both
    # the rule entry that describes it and the service behind it - deliberately,
    # because a reader of either wants to know - but they are one hole in the
    # firewall and counting both said seven where there are four. Grouped by
    # port, and the service wins the label: "32400 Plex" is what the hole is
    # for, "Port forward - Plex" only says that it exists.
    kinds = {e["id"]: e.get("kind") for e in db.list_entries()}
    best: dict[str, dict] = {}
    for f in sorted(forwards, key=lambda f: (f["entry"], f["port"])):
        cur = best.get(f["port"])
        if cur is None or (kinds.get(cur["entry_id"]) == "rule"
                           and kinds.get(f["entry_id"]) != "rule"):
            best[f["port"]] = f
    uniq = [best[p] for p in sorted(best, key=lambda x: (len(x), x))]

    # Open on purpose? A hostname whose `access-open` finding was ignored is
    # still published with nothing in front of it - that stays a fact on this
    # list - but it is a decision, not news. Say which, with the reason given,
    # so a reader (or an MCP client) can tell the two apart; the attention
    # queue already leaves these out.
    ign = _access_ignores()
    for h, n in naked.items():
        i = ign.get(h)
        n["accepted"] = i is not None
        if i is not None:
            n["reason"] = i.get("reason") or ""

    return {"published": sorted(published),
            "no_access": [naked[h] for h in sorted(naked, key=lambda h: (naked[h]["accepted"], h))],
            "wan_forwards": uniq}


def reached_from_internet() -> list[dict]:
    """Which entries the internet reaches, and how - for the topology graph's
    top node. A public hostname an edge source publishes, or a WAN port a
    firewall forwards; the same sightings exposure() reads."""
    by: dict[int, set[str]] = {}
    for r in db.all_sightings():
        if has_role(r["source"], "edge") and r["fact"].startswith("hostname:"):
            by.setdefault(r["entry_id"], set()).add(r["fact"][9:])
        elif has_role(r["source"], "firewall") and r["fact"].startswith("port:"):
            by.setdefault(r["entry_id"], set()).add(f"WAN port {r['fact'][5:]}")
    return [{"entry_id": i, "via": sorted(v)} for i, v in sorted(by.items())]


def snapshot(status_cache: dict | None = None) -> dict:
    status_cache = status_cache or {}
    entries = db.list_entries()

    def st(i):
        return status_cache.get(i, {}).get("up")

    monitored = [e for e in entries if e.get("monitor")]
    up = [e for e in monitored if st(e["id"]) is True]
    down = [e for e in monitored if st(e["id"]) is False]
    crit_down = [e for e in down if e.get("criticality") == "critical"]

    summary = sources.summary()
    exp = exposure()
    items: list[dict] = []

    # ---- 1. a source that is not answering ------------------------------
    # First, because everything below it is only as true as the sources are.
    for h in summary.get("health", []):
        if not h.get("configured") or h.get("ok"):
            continue
        name = h.get("label") or h["source"]
        if h.get("pending"):
            # Never tried. During the start-up pass that is its turn not
            # having come yet; after it, a source added from Settings since
            # the last scan - worth saying, but it has not failed anything.
            if not sources.FIRST_PASS_DONE:
                continue
            items.append({
                "level": "warn", "order": 3, "key": f"source-pending:{h['source']}",
                "title": f"{name} has not been scanned yet",
                "detail": "configured since the last discovery pass. It is "
                          "scanned on the next one, or now from the Network view.",
            })
            continue
        items.append({
            "level": "critical", "order": 0, "key": f"source:{h['source']}",
            # When it last worked is the honest start of the outage, and the
            # source already records it.
            "since": h.get("last_ok"),
            # The label, not the key: an added source's key is its instance
            # id, and "579f92767f26 is not answering" names nothing.
            "title": f"{name} is not answering",
            "detail": (h.get("error") or "no successful scan recorded")
                      + ". Everything this source would have reported is "
                        "unknown, not clear.",
        })

    # ---- 1b. stored credentials no key can open ---------------------------
    # Every source they belong to has silently lost its password; the source
    # health above may not show it until the next scan.
    from . import crypto
    if crypto.UNDECRYPTABLE:
        n = len(crypto.UNDECRYPTABLE)
        items.append({
            "level": "critical", "order": 0, "key": "secrets-undecryptable",
            "title": f"{n} stored credential{'s' if n != 1 else ''} cannot be decrypted",
            "detail": (", ".join(crypto.UNDECRYPTABLE[:6])
                       + ". NETMAP_SECRET_KEY does not match the key they were saved "
                         "with - restore that key, or re-enter them in Settings › Sources "
                         "and Settings › Notifications."),
            "fingerprint": ",".join(crypto.UNDECRYPTABLE),
        })

    # ---- 2. critical things that stopped answering ----------------------
    def went_down(entry_id: int):
        """`observations` stores transitions only, so the last one for a host
        that is down is the moment it went down - an actual event, not the
        moment this page first noticed."""
        o = db.last_observation(entry_id)
        return o["ts"] if o and o.get("up") is False else None

    # Several entries down at one address are usually one machine down, not
    # a dozen separate failures: one item for the address, a chip per entry.
    # The key keeps the "down:" prefix - notifications send these as entry
    # events of their own, and leave them out of the generic critical ones.
    at: dict[str, list[dict]] = {}
    for e in down:
        at.setdefault((e.get("ip") or "").strip() or f"#{e['id']}", []).append(e)
    for addr, group in at.items():
        crit = [e for e in group if e in crit_down]
        if len(group) == 1:
            e = group[0]
            target = status_cache.get(e["id"], {}).get("target") or ""
            items.append({
                "level": "critical" if crit else "warn", "order": 1 if crit else 2,
                "key": f"down:{e['id']}", "since": went_down(e["id"]),
                "title": f"{e['name']} is not answering",
                "detail": f"marked critical - {target or 'no target'}" if crit else target,
                "entry_id": e["id"],
            })
            continue
        since = sorted(t for t in (went_down(e["id"]) for e in group) if t)
        items.append({
            "level": "critical" if crit else "warn", "order": 1 if crit else 2,
            "key": f"down:@{addr}", "since": since[0] if since else None,
            "title": f"{len(group)} entries at {addr} are not answering",
            "detail": ((f"{len(crit)} marked critical: "
                        + ", ".join(e["name"] for e in crit[:4])
                        + (" …" if len(crit) > 4 else "") + ". ") if crit else "")
                      + "Several at one address usually means the machine itself is down.",
            "entries": [{"id": e["id"], "name": e["name"],
                         "how": status_cache.get(e["id"], {}).get("target") or ""}
                        for e in sorted(group, key=lambda x: (x not in crit, x["name"].lower()))],
            "fingerprint": ",".join(str(e["id"]) for e in sorted(group, key=lambda x: x["id"])),
        })

    # ---- 2b. certificates about to expire --------------------------------
    # Read by the https health checks, so this covers what NetMap probes -
    # not only the certificates a reverse proxy happens to hold. An expired
    # one is critical: every client is already refusing it.
    from . import status as _status
    for c in _status.expiring(entries, status_cache):
        e, days = c["entry"], c["days_left"]
        items.append({
            "level": "critical" if days < 0 else "warn", "order": 2,
            "key": f"cert:{e['id']}",
            "title": (f"The certificate of {e['name']} has expired" if days < 0 else
                      f"The certificate of {e['name']} expires on {(c['not_after'] or '')[:10]}"),
            "detail": f"checked on {c['target'] or '?'} - renew it, or check what serves it",
            "entry_id": e["id"],
        })

    # ---- 3. published with nothing in front of it -----------------------
    # A hostname whose `access-open` finding was ignored is a decision already
    # taken - plex and seerr are open on purpose. Re-raising it here under a
    # different heading would be the same nag wearing a new hat, and would
    # teach the reader that this list is not worth reading. It stays visible
    # under "reachable from outside", which is a statement of fact rather than
    # a request.
    cf_ign = _access_ignores()
    for n in exp["no_access"]:
        if n["host"] in cf_ign:
            continue
        items.append({
            "level": "warn", "order": 3, "key": f"open:{n['host']}",
            "title": f"{n['host']} has no Access application",
            "detail": ("published through the tunnel with nothing in front of "
                       "it: whatever answers there answers the open internet"),
            "entry_id": n["entry_id"],
        })

    # ---- 4. the sources disagree with the inventory ---------------------
    if summary.get("total"):
        items.append({
            "level": "warn", "order": 4, "key": "findings",
            "title": f"{summary['total']} mismatch"
                     f"{'' if summary['total'] == 1 else 'es'} between NetMap "
                     "and the systems it reads",
            "detail": ", ".join(f"{k} {v}" for k, v in
                                sorted(summary.get("by_source", {}).items()) if v),
            "goto": "network",
        })

    # ---- 5. contradictions inside the inventory -------------------------
    from . import conflicts as _conf
    cf = _conf.find(entries)
    if cf:
        high = sum(1 for c in cf if c.get("severity") == "high")
        items.append({
            "level": "warn" if high else "note", "order": 5,
            "key": "conflicts",
            "title": f"{len(cf)} conflict{'' if len(cf) == 1 else 's'} "
                     "in the inventory",
            "detail": "; ".join(c["title"] for c in cf[:3]),
            "goto": "network",
        })

    # ---- 6. critical things nothing is watching -------------------------
    # `monitor: false` is not the same as unwatched. Some things cannot be
    # probed over TCP at all - an HA add-on behind ingress publishes no port -
    # and the answer there was never to switch monitoring on but to name an
    # entity the Home Assistant source can check instead. An entry carrying an
    # `ha:` expectation is watched by something better than a port test, and
    # calling it a blind spot is the sort of false alarm that teaches a reader
    # to stop reading.
    blind = [e for e in entries
             if e.get("criticality") == "critical" and not e.get("monitor")
             and not any(t.lower().startswith("ha:") for t in (e.get("tags") or []))]
    if blind:
        items.append({
            "level": "note", "order": 6, "key": "unmonitored",
            "title": f"{len(blind)} critical entr"
                     f"{'y' if len(blind) == 1 else 'ies'} nothing is watching",
            "detail": ", ".join(e["name"] for e in blind[:4])
                      + ". No health check and no `ha:` expectation, so nothing "
                        "can report these failing.",
        })

    # ---- 6b. entries nothing has seen for a while --------------------------
    # Only ones something confirmed once - see app/stale.py.
    from . import stale as _stale
    gone = _stale.stale(entries, status_cache)
    if gone:
        n = len(gone)
        items.append({
            "level": "note", "order": 6, "key": "stale",
            "title": f"{n} entr{'y' if n == 1 else 'ies'} nothing has seen for "
                     f"{_stale.days()} days",
            "detail": (", ".join(g["name"] for g in gone[:6]) + (" …" if n > 6 else "")
                       + " - no source, address or health check has confirmed "
                         f"{'it' if n == 1 else 'them'} since. Retired, or moved?"),
            "entries": gone,
        })

    unver = [e for e in entries if not e.get("verified")]
    if unver:
        items.append({
            "level": "note", "order": 7, "key": "unverified",
            "title": f"{len(unver)} entr{'y' if len(unver) == 1 else 'ies'} "
                     "not verified",
            # Every one as a chip that opens its card, and the ids for "Mark
            # verified" - a person checks them, then says so in one click.
            "entries": [{"id": e["id"], "name": e["name"]} for e in unver[:12]],
            "more": max(0, len(unver) - 12),
            "verify": [e["id"] for e in unver],
            "fingerprint": ",".join(str(e["id"]) for e in sorted(unver, key=lambda x: x["id"])),
        })

    items.sort(key=_rank)
    items, hidden = _dismissed(items)
    for it in items:
        it["fingerprint"] = _fingerprint(it)
    # Age for the rest. Nothing in the schema knows when "9 entries are not
    # verified" became true, so the clock starts the first time the queue
    # reports it and restarts whenever the situation changes. `since_exact`
    # marks the rows where the timestamp is an event rather than a first
    # sighting, so the interface can be honest about which is which.
    ages = db.attention_age(items)
    for it in items:
        it["since_exact"] = bool(it.get("since"))
        if not it.get("since"):
            it["since"] = ages.get(it.get("key") or "")
    worst = items[0]["level"] if items else "ok"

    # The sentence the page leads with. Written here rather than in the UI so
    # that the MCP client and the web page cannot disagree about the verdict.
    if worst == "ok":
        verdict = (f"Nothing needs you. {len(up)} of {len(monitored)} monitored "
                   f"entries answering, {summary.get('sources_ok', 0)} of "
                   f"{summary.get('sources_total', 0)} sources reporting.")
    elif crit_down:
        verdict = (f"{len(crit_down)} critical "
                   + ("service is" if len(crit_down) == 1 else "services are")
                   + " not answering.")
    elif worst == "critical":
        verdict = items[0]["title"] + "."
    else:
        verdict = (f"{len(items)} thing{'' if len(items) == 1 else 's'} "
                   f"want{'s' if len(items) == 1 else ''} "
                   "attention; nothing critical is down.")

    return {
        "verdict": verdict, "level": worst,
        "attention": items,
        "dismissed": hidden,
        "counts": {
            "entries": len(entries), "monitored": len(monitored),
            "up": len(up), "down": len(down), "critical_down": len(crit_down),
            "unverified": len(unver),
        },
        "sources": {"ok": summary.get("sources_ok", 0),
                    "total": summary.get("sources_total", 0),
                    "health": summary.get("health", []),
                    "scanned_at": summary.get("scanned_at")},
        "exposure": {
            "published": len(exp["published"]),
            "no_access": exp["no_access"],
            "wan_forwards": exp["wan_forwards"],
        },
        "sightings": db.sighting_stats(),
    }
