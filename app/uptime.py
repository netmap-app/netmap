"""Uptime per entry: the share of the last 30 days its health check answered.

Computed from `observations`, which stores transitions only - no new data is
collected for this. Time is *unknown*, never up, when:

  * the entry was not probed (not monitored, health check `none`) - an
    observation with up = NULL;
  * there is no observation yet (the entry is newer than the window, or its
    history was pruned) - the result then says "since <date>";
  * NetMap itself was not running. Transitions cannot show that: a restart
    that finds the same state records nothing. So every sweep leaves a
    heartbeat, and a silence of more than two sweep intervals found at
    start-up is kept as a gap (kv `uptime_gaps`).

Always computed; where it is *shown* is a rule in Settings (kinds,
categories, criticalities - default critical and important), overridden per
entry by a tag `uptime:on` / `uptime:off`.
"""
import calendar
import json
import time

from . import db

WINDOW_DAYS = 30
RULE_KEY, BEAT_KEY, GAPS_KEY = "uptime_rule", "status_heartbeat", "uptime_gaps"
DEFAULT_RULE = {"kinds": [], "categories": [], "criticalities": ["critical", "important"]}


def _epoch(ts: str) -> float:
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))


def _iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


# ---- when NetMap was not watching -----------------------------------------------------------
def heartbeat() -> None:
    """Called after every status sweep."""
    db.set_setting(BEAT_KEY, db.now())


def note_start(interval: int, now: float | None = None) -> dict | None:
    """At start-up: if the last heartbeat is older than two sweeps, remember
    the silence as a gap. Returns the gap recorded, if any."""
    now = time.time() if now is None else now
    last = db.get_setting(BEAT_KEY)
    if not last:
        return None
    t = _epoch(last)
    if now - t <= 2 * interval + 60:
        return None
    gaps = [g for g in gaps_list() if g[1] > now - (WINDOW_DAYS + 1) * 86400]
    gaps.append([t, now])
    db.set_setting(GAPS_KEY, json.dumps(gaps))
    return {"from": _iso(t), "to": _iso(now)}


def gaps_list() -> list[list[float]]:
    try:
        return json.loads(db.get_setting(GAPS_KEY) or "[]")
    except ValueError:
        return []


# ---- where it is shown ----------------------------------------------------------------------
def rule() -> dict:
    try:
        r = json.loads(db.get_setting(RULE_KEY) or "null")
    except ValueError:
        r = None
    r = r if isinstance(r, dict) else DEFAULT_RULE
    return {k: [str(x) for x in (r.get(k) or [])] for k in DEFAULT_RULE}


def save_rule(r: dict, actor: str = "web") -> dict:
    clean = {k: sorted({str(x).strip() for x in (r.get(k) or []) if str(x).strip()})
             for k in DEFAULT_RULE}
    before = rule()
    db.set_setting(RULE_KEY, json.dumps(clean))
    if clean != before:
        db.log(actor, "setting", None, "uptime shown for", {"from": before, "to": clean})
    return clean


def shown(entry: dict, r: dict | None = None) -> bool:
    """Tag first (`uptime:on` / `uptime:off`), then the rule - which never
    selects an entry that is not monitored: it has no uptime to show, only an
    empty strip saying so."""
    for t in entry.get("tags") or []:
        t = str(t).strip().lower()
        if t in ("uptime:on", "uptime:off"):
            return t == "uptime:on"
    if not entry.get("monitor"):
        return False
    r = r or rule()
    return (entry.get("kind") in r["kinds"] or entry.get("category") in r["categories"]
            or entry.get("criticality") in r["criticalities"])


# ---- the numbers ----------------------------------------------------------------------------
def _segments(before, rows, start: float, end: float, gaps) -> list[list]:
    """[[from, to, state]] covering start..end; state True/False/None."""
    state = None if before is None else (None if before["up"] is None else bool(before["up"]))
    at, out = start, []
    for r in rows:
        t = min(max(_epoch(r["ts"]), start), end)
        if t > at:
            out.append([at, t, state])
        at = max(at, t)
        state = None if r["up"] is None else bool(r["up"])
    if end > at:
        out.append([at, end, state])
    # Cut the gaps out: while NetMap was not running, nothing is known.
    for g0, g1 in gaps:
        cut = []
        for a, b, s in out:
            if b <= g0 or a >= g1:
                cut.append([a, b, s])
                continue
            if a < g0:
                cut.append([a, g0, s])
            cut.append([max(a, g0), min(b, g1), None])
            if b > g1:
                cut.append([g1, b, s])
        out = cut
    merged: list[list] = []
    for a, b, s in out:
        if b <= a:
            continue
        if merged and merged[-1][2] is s and merged[-1][1] == a:
            merged[-1][1] = b
        else:
            merged.append([a, b, s])
    return merged


def _summary(segs: list[list], start: float, end: float) -> dict:
    up = sum(b - a for a, b, s in segs if s is True)
    down = sum(b - a for a, b, s in segs if s is False)
    first = next((a for a, b, s in segs if s is not None), None)
    return {
        "percent": round(100 * up / (up + down), 2) if up + down >= 60 else None,
        "up_s": int(up), "down_s": int(down),
        "unknown_s": int((end - start) - up - down),
        # History that starts inside the window is said, not hidden.
        "since": _iso(first) if first is not None and first > start + 3600 else None,
        "window_days": WINDOW_DAYS,
        "segments": [[_iso(a), _iso(b), "up" if s is True else "down" if s is False else "unknown"]
                     for a, b, s in segs],
    }


def compute_all(entry_ids: list[int], now: float | None = None) -> dict[int, dict]:
    """Uptime for many entries in two queries."""
    end = time.time() if now is None else now
    start = end - WINDOW_DAYS * 86400
    w0 = _iso(start)
    c = db.conn()
    marks = ",".join("?" * len(entry_ids)) or "NULL"
    # SQLite returns the row that holds MAX(id) alongside it: the last
    # transition before the window, i.e. the state the window opens with.
    before = {r["entry_id"]: dict(r) for r in c.execute(
        f"SELECT entry_id, up, MAX(id) AS id FROM observations WHERE ts < ? "
        f"AND entry_id IN ({marks}) GROUP BY entry_id", [w0, *entry_ids])}
    rows: dict[int, list] = {}
    for r in c.execute(f"SELECT entry_id, ts, up FROM observations WHERE ts >= ? "
                       f"AND entry_id IN ({marks}) ORDER BY id", [w0, *entry_ids]):
        rows.setdefault(r["entry_id"], []).append(dict(r))
    gaps = [g for g in gaps_list() if g[1] > start]
    return {i: _summary(_segments(before.get(i), rows.get(i, []), start, end, gaps), start, end)
            for i in entry_ids}


def compute(entry_id: int, now: float | None = None) -> dict:
    return compute_all([entry_id], now)[entry_id]
