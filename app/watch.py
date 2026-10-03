"""Watching: a device nobody can name yet, kept in sight without adding it to
the inventory and without ignoring it.

A new-device finding offers Watch next to Create entry and Ignore. A watched
device leaves "Needs you" (its finding is not raised while it is watched) and
is listed under Network › Watching: what the sources know of it, whether it
is on the network now, and a note. It stays until a person decides — create
an entry, ignore it, or stop watching — or until it has not been seen for
DROP_DAYS, when it is dropped by itself.

Keyed like presence_seen: the MAC when a source knows it, else
"ip:<address>". Never a write to the inventory; `online` and `last_seen` are
kept here because the device history can be purged sooner than DROP_DAYS.

Notifications (event "watch"): when a watched device comes back after being
away, and when one is dropped. Being on the network when it is watched is not
news.
"""
import calendar
import time

from . import db, oui

DROP_DAYS = 90
NOTE_MAX = 500


def _ts(s: str) -> float:
    try:
        return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    except (TypeError, ValueError):
        return 0.0


def _fmt(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _rows() -> list[dict]:
    return [dict(r) for r in db.conn().execute("SELECT * FROM watch ORDER BY created_at")]


def keys() -> set[str]:
    return {r[0] for r in db.conn().execute("SELECT key FROM watch")}


def _here() -> dict[str, dict]:
    """key -> {ips, sources, label} for every device some source sees now."""
    out: dict[str, dict] = {}
    for r in db.conn().execute("SELECT ip, source, label, mac FROM presence ORDER BY ip"):
        k = r["mac"] or "ip:" + r["ip"]
        d = out.setdefault(k, {"ips": [], "sources": [], "label": ""})
        if r["ip"] not in d["ips"]:
            d["ips"].append(r["ip"])
        if r["source"] not in d["sources"]:
            d["sources"].append(r["source"])
        if not d["label"] and (r["label"] or "").strip() not in ("", "*"):
            d["label"] = r["label"].strip()
    return out


def _claims() -> tuple[set, set]:
    """The MACs and addresses entries describe."""
    entries = db.list_entries()
    macs = {m.replace("-", ":").lower() for e in entries
            for m in db.MAC_RE.findall(e.get("mac") or "")}
    return macs, {(e.get("ip") or "").strip() for e in entries}


def _claimed(key: str, claims: tuple[set, set]) -> bool:
    """An entry now describes it: its MAC, or (for an address-keyed device)
    its address."""
    return key[3:] in claims[1] if key.startswith("ip:") else key in claims[0]


def _name(row: dict, hist: dict, here: dict) -> str:
    key = row["key"]
    mac = "" if key.startswith("ip:") else key
    return (here.get("label") or hist.get("label") or row["label"] or oui.vendor(mac)
            or mac or key[3:])


def add(key: str, note: str = "", actor: str = "web") -> dict:
    """Watch a device. `key` is a presence key, or the new-device finding's
    key ("<source>:new:<presence key>")."""
    key = (key or "").strip()
    finding = ""
    if ":new:" in key:
        finding, key = key, key.split(":new:", 1)[1]
    key = key if key.startswith("ip:") else key.lower()
    hist = next((h for h in db.presence_history() if h["key"] == key), None)
    if hist is None:
        raise ValueError("NetMap has not seen that device")
    if not finding:
        from .sources import key_prefix
        finding = f"{key_prefix(hist['first_source'])}:new:{key}"
    note = _note(note)
    here = _here()
    if key in keys():
        return get(key)
    db.conn().execute(
        "INSERT INTO watch (key, finding, label, note, online, last_seen, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (key, finding, hist["label"], note, 1 if key in here else 0,
         hist["last_seen"], db.now()))
    db._commit()
    db.log(actor, "watch", None, _name({"key": key, "label": hist["label"]}, hist,
                                       here.get(key, {})), {"key": key})
    return get(key)


def _note(note) -> str:
    note = str(note or "").strip()
    if len(note) > NOTE_MAX:
        raise ValueError(f"a note is at most {NOTE_MAX} characters")
    return note


def update(key: str, note, actor: str = "web") -> dict | None:
    note = _note(note)
    cur = db.conn().execute("UPDATE watch SET note=? WHERE key=? AND note != ?",
                            (note, key, note))
    db._commit()
    if cur.rowcount:
        db.log(actor, "watch-note", None, key, {"key": key})
    return get(key)


def remove(key: str, actor: str = "web", why: str = "stopped watching") -> bool:
    cur = db.conn().execute("DELETE FROM watch WHERE key=?", (key,))
    db._commit()
    if cur.rowcount:
        db.log(actor, "unwatch", None, key, {"key": key, "why": why})
    return bool(cur.rowcount)


def ignore(key: str, actor: str = "web") -> bool:
    """Ignore its new-device finding, and stop watching."""
    row = next((r for r in _rows() if r["key"] == key), None)
    if row is None:
        return False
    db.add_ignore(row["finding"], row["finding"].split(":")[0],
                  f"{row['label'] or key} — watched", actor=actor)
    return remove(key, actor, "ignored")


def _view(row: dict, hist: dict, here: dict) -> dict:
    key = row["key"]
    mac = "" if key.startswith("ip:") else key
    last = max(row["last_seen"], hist.get("last_seen") or "")
    if key in here:
        last = max(last, hist.get("last_seen") or "")
    ips = here.get(key, {}).get("ips") or [hist.get("last_ip") or (key[3:] if not mac else "")]
    return {"key": key, "name": _name(row, hist, here.get(key, {})), "mac": mac,
            "vendor": oui.vendor(mac), "randomised": oui.randomised(mac),
            "online": key in here, "ips": [i for i in ips if i],
            "sources": here.get(key, {}).get("sources", []),
            "first_seen": hist.get("first_seen") or row["created_at"],
            "last_seen": last or row["created_at"], "note": row["note"],
            "since": row["created_at"], "finding": row["finding"],
            "drop_on": _fmt(_ts(last or row["created_at"]) + DROP_DAYS * 86400)[:10]}


def get(key: str) -> dict | None:
    row = next((r for r in _rows() if r["key"] == key), None)
    if row is None:
        return None
    hist = next((h for h in db.presence_history() if h["key"] == key), {})
    return _view(row, hist, _here())


def listing() -> list[dict]:
    """Every watched device. One an entry claims is left out at once; the next
    check removes it."""
    hist = {h["key"]: h for h in db.presence_history()}
    here, claims = _here(), _claims()
    return [_view(r, hist.get(r["key"], {}), here) for r in _rows()
            if not _claimed(r["key"], claims)]


def check(now: float | None = None) -> dict:
    """After every scan: who came back, who is in the inventory now, who has
    been gone DROP_DAYS. Sends the notifications; returns what changed."""
    from . import notify
    now = time.time() if now is None else now
    here = _here()
    hist = {h["key"]: h for h in db.presence_history()}
    claims = _claims()
    back, dropped, claimed = [], [], []
    for row in _rows():
        key = row["key"]
        v = _view(row, hist.get(key, {}), here)
        if _claimed(key, claims):
            remove(key, "system", "now in the inventory")
            claimed.append(key)
            continue
        if key in here:
            if not row["online"]:
                back.append(key)
                notify.tell("watch", key, {
                    "title": f"{v['name']} is back on the network at {', '.join(v['ips'])}",
                    "detail": f"a device you are watching — {key}"
                              + (f" · {v['note']}" if v["note"] else ""),
                    "level": "warn"})
            db.conn().execute("UPDATE watch SET online=1, last_seen=? WHERE key=?",
                              (_fmt(now), key))
        elif row["online"]:
            db.conn().execute("UPDATE watch SET online=0 WHERE key=?", (key,))
        elif now - _ts(v["last_seen"]) > DROP_DAYS * 86400:
            remove(key, "system", f"not seen for {DROP_DAYS} days")
            dropped.append(key)
            notify.tell("watch", key + ":dropped", {
                "title": f"Stopped watching {v['name']} — not seen for {DROP_DAYS} days",
                "detail": f"last seen {v['last_seen'][:10]} at {', '.join(v['ips'])}",
                "level": "ok"})
    db._commit()
    return {"back": back, "dropped": dropped, "claimed": claimed}
