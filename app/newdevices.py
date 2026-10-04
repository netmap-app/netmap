"""New on the network: what joined this week, without putting phones and
lightbulbs into the inventory (presence stays a layer, not records).

db.presence_seen remembers when each device was first and last seen. A device
first seen within the window that no entry claims is a `new-device` finding,
raised by the source that first saw it - one finding per device, however many
sources see it - with a draft entry built from what is known. Ignore works as
for every finding. What a source saw the first time it reported (a new
install, the upgrade that added this, a source just added) is the baseline,
never new.

Randomised MACs (phones' private Wi-Fi addresses) are left out by default: a
phone that rotates its address would be new every day. Settings can turn them
back on.
"""
import calendar
import time

from . import db, oui

DAYS_KEY, RANDOM_KEY, KEEP_KEY = "newdev_days", "newdev_random", "presence_keep_days"
DAYS_DEFAULT, KEEP_DEFAULT = 7, 90


def _int(key: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(db.get_setting(key) or 0)
    except ValueError:
        v = 0
    return v if lo <= v <= hi else default


def settings() -> dict:
    return {"days": _int(DAYS_KEY, DAYS_DEFAULT, 1, 90),
            "include_random": db.get_setting(RANDOM_KEY) == "1",
            "keep_days": _int(KEEP_KEY, KEEP_DEFAULT, 7, 3650),
            "defaults": {"days": DAYS_DEFAULT, "keep_days": KEEP_DEFAULT}}


def save_settings(days=None, include_random=None, keep_days=None, actor: str = "web") -> dict:
    before = settings()
    if days is not None:
        if not 1 <= int(days) <= 90:
            raise ValueError("new means first seen within 1 to 90 days")
        db.set_setting(DAYS_KEY, str(int(days)))
    if keep_days is not None:
        if not 7 <= int(keep_days) <= 3650:
            raise ValueError("keep device history between 7 and 3650 days")
        db.set_setting(KEEP_KEY, str(int(keep_days)))
    if include_random is not None:
        db.set_setting(RANDOM_KEY, "1" if include_random else "0")
    after = settings()
    changed = {k: [before[k], after[k]] for k in ("days", "include_random", "keep_days")
               if before[k] != after[k]}
    if changed:
        db.log(actor, "setting", None, "new devices", changed)
    return after


def purge() -> int:
    return db.purge_presence_history(settings()["keep_days"])


def _age_days(ts: str) -> float:
    try:
        return (time.time() - calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))) / 86400
    except ValueError:
        return 1e9


def enrich(rows: list[dict]) -> list[dict]:
    """db.presence() rows plus first_seen, last_seen, vendor and randomised."""
    hist = {h["key"]: h for h in db.presence_history()}
    for r in rows:
        h = hist.get(r.get("mac") or "") or hist.get("ip:" + r["ip"]) or {}
        r["first_seen"], r["last_seen"] = h.get("first_seen"), h.get("last_seen")
        r["vendor"] = oui.vendor(r.get("mac"))
        r["randomised"] = oui.randomised(r.get("mac"))
    return rows


def findings(source_id: str, prefix: str) -> list[dict]:
    """New devices this source was the first to see."""
    s = settings()
    entries = db.list_entries()
    claimed_macs = {m for e in entries for m in db.MAC_RE.findall(e.get("mac") or "")}
    claimed_macs = {m.replace("-", ":").lower() for m in claimed_macs}
    claimed_ips = {(e.get("ip") or "").strip() for e in entries}
    hist = db.presence_history()
    # An address a MAC-keyed row explains is the same device seen by a source
    # that knows no MACs; one finding, not two.
    mac_ips = {h["last_ip"] for h in hist if h["mac"]}
    # Watched: a person has seen it and is waiting to know more (app/watch.py).
    from . import watch
    watched = watch.keys()
    out = []
    for h in hist:
        if h["key"] in watched:
            continue
        if h["baseline"] or h["first_source"] != source_id \
                or _age_days(h["first_seen"]) > s["days"]:
            continue
        mac, ip = h["mac"], h["last_ip"]
        if mac and (mac in claimed_macs or (oui.randomised(mac) and not s["include_random"])):
            continue
        if not mac and (ip in claimed_ips or ip in mac_ips):
            continue
        vendor = oui.vendor(mac)
        name = h["label"] or vendor or mac or ip
        what = ("randomised MAC" if oui.randomised(mac) else vendor) if mac else ""
        out.append({
            "type": "new-device", "key": f"{prefix}:new:{h['key']}",
            "label": f"{name} - new on the network at {ip}",
            "detail": (f"first seen {h['first_seen'][:16].replace('T', ' ')} UTC, last "
                       f"{h['last_seen'][:16].replace('T', ' ')}"
                       + (f" · {mac}" if mac else "") + (f" · {what}" if what else "")
                       + ". Not in the inventory - add it, watch it, or ignore it."),
            # Thin, like every draft: the category is a guess nobody should
            # have to undo, so it is left for the person.
            "draft": {"name": name, "category": "Uncategorised", "kind": "hardware",
                      "ip": ip, "mac": mac, "monitor": False, "verified": False,
                      "notes": f"First seen {h['first_seen'][:10]}"
                               + (f"; {vendor}" if vendor else "") + "."},
        })
    return out
