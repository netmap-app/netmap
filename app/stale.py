"""Stale entries: nothing has confirmed they exist for N days.

An entry that no longer exists — a retired machine, a removed container —
otherwise sits in the inventory for ever. db.entry_seen records when each
entry was last confirmed: a source's sighting, an address a source sees at
its MAC (or, for hardware and VMs, its address), or its health check
answering. Stale means *was* confirmed, and has not been for N days (default
14). Never-confirmed entries are never stale: nothing says any source could
see them, so silence about them is not news.

One Overview note, not a finding per entry. Entries a source already reports
gone by its own check (GONE: Docker's "no container", a NAT rule or tunnel
route or Home Assistant entity that no longer exists) are left out: said once
is enough. Not every ABSENCE type means gone — netbox-missing only says
NetBox does not list it — so the list is explicit.
"""
import calendar
import time

from . import db

DAYS_KEY, DAYS_DEFAULT = "stale_days", 14
BACKFILL_KEY = "stale_backfilled"


def days() -> int:
    try:
        v = int(db.get_setting(DAYS_KEY) or 0)
    except ValueError:
        v = 0
    return v if 1 <= v <= 365 else DAYS_DEFAULT


def set_days(n: int, actor: str = "web") -> int:
    n = int(n)
    if not 1 <= n <= 365:
        raise ValueError("flag entries after 1 to 365 days unseen")
    before = days()
    db.set_setting(DAYS_KEY, str(n))
    if n != before:
        db.log(actor, "setting", None, "stale after", {"from": before, "to": n})
    return n


def backfill() -> int:
    """Once: an entry whose health check stopped answering and never came
    back was last confirmed when it stopped — so a long-dead entry is stale
    from the first day, not fourteen days after this version started."""
    if db.get_setting(BACKFILL_KEY):
        return 0
    c = db.conn()
    n = 0
    for r in c.execute(
            "SELECT o.entry_id, o.ts FROM observations o JOIN "
            "(SELECT entry_id, MAX(id) AS id FROM observations GROUP BY entry_id) l "
            "ON l.id = o.id WHERE o.up = 0 AND EXISTS (SELECT 1 FROM observations p "
            "WHERE p.entry_id = o.entry_id AND p.up = 1 AND p.id < o.id)").fetchall():
        if c.execute("SELECT 1 FROM entry_seen WHERE entry_id=?", (r["entry_id"],)).fetchone():
            continue
        c.execute("INSERT INTO entry_seen (entry_id, last_seen, how) VALUES (?,?,?)",
                  (r["entry_id"], r["ts"], "health check, until it stopped answering"))
        n += 1
    db.set_setting(BACKFILL_KEY, db.now())
    return n


GONE = {"gone", "nat-stale", "route-missing", "ha-missing"}


def _absent_ids() -> set[int]:
    """Entries some source currently reports gone by its own check."""
    from .sources import cached, names
    out = set()
    for name in names():
        for f in (cached(name) or {}).get("findings") or []:
            if f.get("type") in GONE and (f.get("entry") or {}).get("id"):
                out.add(f["entry"]["id"])
    return out


def stale(entries: list[dict], status_cache: dict, now: float | None = None) -> list[dict]:
    """[{id, name, last_seen, how}], longest unseen first."""
    cutoff = (time.time() if now is None else now) - days() * 86400
    seen = db.last_seen()
    absent = _absent_ids()
    out = []
    for e in entries:
        s = seen.get(e["id"])
        if not s or e["id"] in absent or (status_cache.get(e["id"]) or {}).get("up") is True:
            continue
        if calendar.timegm(time.strptime(s["last_seen"], "%Y-%m-%dT%H:%M:%SZ")) < cutoff:
            out.append({"id": e["id"], "name": e["name"], "last_seen": s["last_seen"],
                        "how": s["how"]})
    return sorted(out, key=lambda x: x["last_seen"])
