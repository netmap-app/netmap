"""Summary notifications: a channel can take its news as one message a day or
a week instead of one per event.

Off by default — every channel delivers immediately until someone chooses
otherwise, and can go back at any time (what was held is then sent at once).
On a summary channel an *urgent* event still goes straight away: one of the
channel's urgent kinds (default: an entry down, a source not answering, a
certificate expired, another critical item) at critical level — and its
all-clear. Everything
else waits in the database (kv `digest_held:<channel>`, so a restart loses
nothing) and is sent as one message at the chosen local hour — and, for a
weekly summary, day. Nothing held, no message.

The hour is local to the time zone set in Settings › Notifications (kv
`timezone`; default the container's TZ, else UTC).
"""
import datetime as _dt
import json
import os
import threading
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import db

MODES = ("off", "daily", "weekly")
URGENT_KINDS = ("entry", "source", "cert", "critical")
DEFAULT = {"mode": "off", "hour": 8, "day": 0, "urgent": list(URGENT_KINDS)}
DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
TZ_KEY, MAX_HELD = "timezone", 500
# The held list is read, changed and written back: by emit (any scan or sweep
# thread), by run (the delivery loop) and by a Settings change. One at a time,
# or an event arriving while a summary is taken is lost.
_LOCK = threading.Lock()


# ---- settings -------------------------------------------------------------------------------
def timezone() -> str:
    for tz in (db.get_setting(TZ_KEY), os.environ.get("TZ"), "UTC"):
        try:
            if tz:
                ZoneInfo(tz)
                return tz
        except (ZoneInfoNotFoundError, ValueError):
            continue
    return "UTC"


def set_timezone(tz: str, actor: str = "web") -> str:
    tz = str(tz or "").strip()
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"{tz!r} is not a time zone — use a name like Europe/Berlin") from None
    before = timezone()
    db.set_setting(TZ_KEY, tz)
    if tz != before:
        db.log(actor, "setting", None, "time zone", {"from": before, "to": tz})
    return tz


def delivery(ch: dict) -> dict:
    return {**DEFAULT, **((ch.get("config") or {}).get("delivery") or {})}


def clean(d) -> dict:
    """A delivery setting from the API, checked. Raises ValueError."""
    d = {**DEFAULT, **(d or {})}
    if d["mode"] not in MODES:
        raise ValueError(f"delivery must be one of {', '.join(MODES)}")
    try:
        hour, day = int(d["hour"]), int(d["day"])
    except (TypeError, ValueError):
        raise ValueError("hour and day must be whole numbers") from None
    if not (0 <= hour <= 23 and 0 <= day <= 6):
        raise ValueError("hour is 0–23, day is 0 (Monday) to 6 (Sunday)")
    bad = [k for k in d["urgent"] or [] if k not in URGENT_KINDS]
    if bad:
        raise ValueError(f"urgent events are among {', '.join(URGENT_KINDS)}")
    return {"mode": d["mode"], "hour": hour, "day": day,
            "urgent": [k for k in URGENT_KINDS if k in (d["urgent"] or [])]}


# ---- holding --------------------------------------------------------------------------------
def urgent(d: dict, msg: dict) -> bool:
    """Sent at once on a summary channel: a critical event of one of the
    channel's urgent kinds — and its all-clear, so "back up" is not left
    waiting for the summary after "down" went straight out."""
    if msg.get("kind") not in d["urgent"]:
        return False
    return msg.get("level") == "critical" or (
        msg.get("level") == "ok" and msg.get("was") == "critical")


def _held_key(cid: str) -> str:
    return f"digest_held:{cid}"


def held(cid: str) -> list[dict]:
    try:
        return json.loads(db.get_setting(_held_key(cid)) or "[]")
    except ValueError:
        return []


def hold(cid: str, msg: dict) -> None:
    with _LOCK:
        rows = (held(cid) + [msg])[-MAX_HELD:]
        db.set_setting(_held_key(cid), json.dumps(rows))


def take(cid: str) -> list[dict]:
    """Everything held for a channel, removed in the same step."""
    with _LOCK:
        rows = held(cid)
        if rows:
            db.delete_setting(_held_key(cid))
        return rows


def drop(cid: str) -> None:
    with _LOCK:
        for k in (_held_key(cid), f"digest_last:{cid}"):
            db.delete_setting(k)


def started(cid: str, now: float | None = None) -> None:
    """A channel switched to a summary: the first one is the next scheduled
    time from now, not whatever time already passed today."""
    db.set_setting(f"digest_last:{cid}", str(time.time() if now is None else now))


# ---- when, and what ---------------------------------------------------------------------------
def last_due(d: dict, now: float) -> float:
    """The most recent scheduled moment at or before `now`, as epoch."""
    tz = ZoneInfo(timezone())
    local = _dt.datetime.fromtimestamp(now, tz)
    at = local.replace(hour=d["hour"], minute=0, second=0, microsecond=0)
    if d["mode"] == "weekly":
        at -= _dt.timedelta(days=(at.weekday() - d["day"]) % 7)
        if at > local:
            at -= _dt.timedelta(days=7)
    elif at > local:
        at -= _dt.timedelta(days=1)
    return at.timestamp()


def compose(rows: list[dict], d: dict) -> dict:
    """One message out of what was held."""
    from .notify import EVENTS
    what = "Daily" if d["mode"] == "daily" else "Weekly"
    lines = []
    for kind in list(EVENTS) + sorted({r.get("kind") for r in rows} - set(EVENTS)):
        titles = [r.get("title", "") for r in rows if r.get("kind") == kind]
        if not titles:
            continue
        head = {"finding": "New findings", "entry": "Entries", "source": "Sources",
                "cert": "Certificates", "critical": "Critical",
                "watch": "Watched devices"}.get(kind, kind.title())
        shown = "; ".join(titles[:6]) + (f"; and {len(titles) - 6} more" if len(titles) > 6 else "")
        lines.append(f"{head} ({len(titles)}): {shown}")
    return {"kind": "summary", "key": "digest", "path": "/", "ts": db.now(),
            "level": "critical" if any(r.get("level") == "critical" for r in rows) else "warn",
            "title": f"NetMap — {what.lower()} summary: {len(rows)} "
                     f"event{'' if len(rows) == 1 else 's'}",
            "detail": "\n".join(lines)}


def run(now: float | None = None) -> list[tuple[str, dict]]:
    """Summaries that are due: [(channel id, message)], held cleared.
    Called by notify's delivery loop."""
    now = time.time() if now is None else now
    out = []
    for ch in db.list_notify_channels():
        d = delivery(ch)
        if not ch["enabled"] or d["mode"] == "off":
            continue
        raw = db.get_setting(f"digest_last:{ch['id']}")
        if raw is None:
            started(ch["id"], now)
            continue
        if float(raw) >= last_due(d, now):
            continue
        started(ch["id"], now)
        rows = take(ch["id"])
        if rows:
            out.append((ch["id"], compose(rows, d)))
    return out


def flush(ch: dict) -> dict | None:
    """Everything held, as one message now — a channel going back to
    immediate delivery keeps what it was holding."""
    rows = take(ch["id"])
    drop(ch["id"])
    return compose(rows, {**delivery(ch), "mode": "daily"}) if rows else None
