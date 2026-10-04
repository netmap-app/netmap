"""Discovery sources.

A source is a module with two functions:

    configured() -> bool     is there enough configuration to try?
    scan()       -> dict     {source, configured, scanned_at, host,
                              findings, counts, error}

and one rule: it never writes to the inventory. A scan reports; a person (or
Claude) decides. Nothing about a finding is stored between scans - findings are
recomputed every time - so the only state is the decision to stop being told
about something, in `db.ignores`.

Findings share a shape so the UI, the ignores table and the MCP tools work for
every source without knowing which one produced them:

    key      stable id, "<source>:<type>:<thing>" - what ignoring records
    type     source-specific, drives the badge
    label    one line, the headline
    detail   one line, the evidence
    entry    {id, name, ...} when the finding is about a known entry
    draft    a ready-to-create entry when the finding is about something new
    suggest  field → value, when the finding proposes an edit

The action buttons follow from which of `entry`, `draft` and `suggest` are
present, so a new source needs no UI work.
"""
import asyncio
import json
import os
import threading
import time
from typing import NamedTuple

from .. import crypto, db

from . import dynamic, fields

# Per-instance working state - login sessions, tokens - keyed by instance id.
# Outlives a registry rebuild (which happens on every call), and is dropped
# whenever the instance is edited or removed, so a session never rides on to
# an address or user it was not opened for.
_STATE: dict[str, dict] = {}

def single(type_: str) -> bool:
    """A type that can be added only once - see MULTI in its driver."""
    return not dynamic.multi(type_)


def _new_id(type_: str) -> str:
    """The type itself for the first instance, so the keys of a source that
    predates instances never change; "<type>-2", "-3"… after that. Ids are
    never reused while taken, and "-" never appears in a type."""
    taken = {i["id"] for i in db.list_source_instances()}
    if type_ not in taken:
        return type_
    n = 2
    while f"{type_}-{n}" in taken:
        n += 1
    return f"{type_}-{n}"


def key_prefix(instance_id: str) -> str:
    t = dynamic.type_of(instance_id)
    return dynamic.LEGACY_PREFIX.get(t, t) if instance_id == t else instance_id


class _Instance:
    """Adapts one source_instances row to the configured()/scan() shape the
    registry uses, decrypting its secrets only for the duration of one call."""

    def __init__(self, inst: dict, driver_mod):
        self._inst = inst
        self._mod = driver_mod

    def cfg(self) -> dict:
        raw = dict(self._inst["config"])
        for key, enc in self._inst["secrets"].items():
            raw[key] = crypto.decrypt(enc)
        cfg = fields.coerce(self._mod.FIELDS, raw)
        iid = self._inst["id"]
        cfg.update(_state=_STATE.setdefault(iid, {}), _id=iid, _key=key_prefix(iid))
        return cfg

    def configured(self) -> bool:
        return self._inst["enabled"] and self._mod.configured(self.cfg())

    def scan(self) -> dict:
        return self._mod.scan(self.cfg())


def _registry() -> dict:
    """Every added source, in driver order. Rebuilt on every call - instances
    rarely change and the list is short, so this is cheaper than keeping it in
    sync by hand."""
    order = {t: i for i, t in enumerate(dynamic.DRIVERS)}
    combined = {}
    for inst in sorted(db.list_source_instances(),
                       key=lambda i: (order.get(i["type"], len(order)), i["created_at"])):
        driver = dynamic.DRIVERS.get(inst["type"])
        if not driver:
            continue
        combined[inst["id"]] = {"mod": _Instance(inst, driver["mod"]),
                                "label": inst["name"], "hint": driver["hint"]}
    return combined


class Bound(NamedTuple):
    mod: object
    cfg: dict


def bound_all(type_: str, configured_only: bool = True) -> list[Bound]:
    """Every instance of a type as (driver module, cfg), for code outside a
    scan that needs other sources' answers - links asking each UniFi
    controller for its topology, Cloudflare asking every NPM which names it
    serves. With configured_only, only those set up and enabled."""
    driver = dynamic.DRIVERS.get(type_)
    if not driver:
        return []
    out = []
    for inst in db.list_source_instances(type_):
        i = _Instance(inst, driver["mod"])
        if configured_only and not i.configured():
            continue
        out.append(Bound(driver["mod"], i.cfg()))
    return out


def by_role(role: str, configured_only: bool = True) -> list[Bound]:
    """Every instance of every type that declares `role` - how shared code
    asks for "the DNS servers" or "the reverse proxies" without naming one.
    See dynamic.ROLES for what each role promises."""
    return [b for t in dynamic.types_with(role) for b in bound_all(t, configured_only)]


def bound(type_: str, configured_only: bool = True) -> Bound | None:
    """The first of bound_all() - for a single-instance type."""
    b = bound_all(type_, configured_only)
    return b[0] if b else None


# How often the background refresh re-scans every configured source. This
# exists so the UI can show a finding count without scanning on every page
# load - a badge that costs three HTTP calls to the firewall every time
# somebody switches tabs is a badge that gets removed. Findings themselves are
# still never stored; this is a cache of the last scan, nothing more.
# Daily, not quarter-hourly. Discovery is reconciliation, not monitoring:
# nothing it detects - DNS drift, a stale rule, an undeclared port - changes
# on a fifteen-minute timescale, and "is it up" is the status check's job.
# The port sweep in particular is ~2,000 TCP connects against machines we do
# not own, which is not a thing to do ninety-six times a day.
INTERVAL = int(os.environ.get("NETMAP_DISCOVERY_INTERVAL", "86400"))   # the default

# Settings › Sources can change it without a restart; stored in kv. Five
# minutes is the floor: every pass includes the port sweep, and a pass every
# few seconds would be monitoring, which is the status check's job.
INTERVAL_KEY = "discovery_interval"
MIN_INTERVAL, MAX_INTERVAL = 300, 7 * 86400
NEXT_RUN: float | None = None     # epoch seconds of the next automatic pass
START_DELAY = 5                   # seconds after start-up before the first pass
_WAKE: asyncio.Event | None = None
_LOOP: asyncio.AbstractEventLoop | None = None


def interval() -> int:
    """Seconds between automatic passes: the saved setting, else the default."""
    try:
        v = int(db.get_setting(INTERVAL_KEY) or 0)
    except ValueError:
        v = 0
    return v if MIN_INTERVAL <= v <= MAX_INTERVAL else INTERVAL


def set_interval(seconds: int, actor: str = "web") -> int:
    seconds = int(seconds)
    if not MIN_INTERVAL <= seconds <= MAX_INTERVAL:
        raise ValueError("the automatic scan interval must be between 5 minutes "
                         "and 7 days")
    before = interval()
    db.set_setting(INTERVAL_KEY, str(seconds))
    db.log(actor, "setting", None, "automatic scan interval",
           {"from": before, "to": seconds})
    # The loop is asleep until the old deadline; wake it to work out the new
    # one. A shorter interval that is already overdue scans straight away.
    if _LOOP and _WAKE:
        _LOOP.call_soon_threadsafe(_WAKE.set)
    return seconds


# When a source's chip turns amber: its last good answer is older than this.
# A fixed number of hours, not a multiple of the interval - a daily scan
# that last answered ten hours ago is exactly what a person wants to notice.
STALE_KEY, STALE_DEFAULT, STALE_MAX = "source_stale_hours", 5, 720


def stale_hours() -> int:
    try:
        v = int(db.get_setting(STALE_KEY) or 0)
    except ValueError:
        v = 0
    return v if 1 <= v <= STALE_MAX else STALE_DEFAULT


def set_stale_hours(hours: int, actor: str = "web") -> int:
    hours = int(hours)
    if not 1 <= hours <= STALE_MAX:
        raise ValueError(f"a source is stale after 1 to {STALE_MAX} hours")
    before = stale_hours()
    db.set_setting(STALE_KEY, str(hours))
    if hours != before:
        db.log(actor, "setting", None, "source stale after",
               {"from": before, "to": hours})
    return hours


def schedule() -> dict:
    """What Settings shows: the interval, its bounds, and the next pass."""
    import datetime as _dt
    nxt = (_dt.datetime.fromtimestamp(NEXT_RUN, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
           if NEXT_RUN else None)
    return {"interval": interval(), "default": INTERVAL, "min": MIN_INTERVAL,
            "max": MAX_INTERVAL, "next_scan": nxt,
            "stale_hours": stale_hours(), "stale_default": STALE_DEFAULT}
_CACHE: dict[str, dict] = {}

# Whether each source is *working*, which is not the same as whether it has
# findings. NPM's token expired and the source was dead for days while the
# Overview cheerfully showed zero findings - zero because nothing could be
# read, and nothing recorded the difference. A long scan interval makes this
# worse, so the two changes belong together.
_HEALTH: dict[str, dict] = {}

# Whether the start-up pass over every source has finished. Until it has, a
# source with no attempt recorded is waiting its turn - the pass is sequential
# and the port sweep alone takes seconds - not failing. Reporting it as "not
# answering" made every restart raise a critical alert that cleared itself
# half a minute later.
FIRST_PASS_DONE = False


def _mark(name: str, error: str | None) -> None:
    h = _HEALTH.setdefault(name, {"last_ok": None, "last_try": None,
                                  "error": None, "fails": 0})
    h["last_try"] = db.now()
    if error:
        h["error"] = error
        h["fails"] += 1
    else:
        h["error"] = None
        h["fails"] = 0
        h["last_ok"] = h["last_try"]


def health() -> list[dict]:
    """Per-source: configured, working, when it last succeeded."""
    out = []
    for name, s in _registry().items():
        h = _HEALTH.get(name, {})
        configured_ = s["mod"].configured()
        out.append({
            "source": name, "label": s["label"], "type": dynamic.type_of(name),
            "roles": list(dynamic.roles_of(dynamic.type_of(name))),
            "configured": configured_,
            # Configured, never tried: waiting for its first scan.
            "pending": configured_ and h.get("last_try") is None,
            "ok": h.get("error") is None and h.get("last_ok") is not None,
            "last_ok": h.get("last_ok"), "last_try": h.get("last_try"),
            "error": h.get("error"), "fails": h.get("fails", 0),
        })
    return out


def names() -> list[str]:
    return list(_registry())


def configured(name: str | None = None) -> bool:
    """One source, or - with no argument - whether any source is set up."""
    if name is None:
        return any(s["mod"].configured() for s in _registry().values())
    s = _registry().get(name)
    return bool(s and s["mod"].configured())


# One scan per source at a time. Two at once - the nightly pass and a click,
# two open tabs, an MCP client and the UI - doubled the calls to a firewall or
# controller and raced on the modules' shared login sessions (NPM's token,
# Pi-hole's sid, UniFi's cookie jar). A request that arrives mid-scan now
# waits for that scan and gets its result. "Scan everything" also reuses a
# result younger than REUSE seconds - nine systems per click is the call a
# refresh-happy page should not be able to repeat every second. A single
# source asked for by name is always scanned fresh (after ignoring a finding,
# the rescan must not hand back the finding), just never twice at once.
REUSE = 30
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()
_FINISHED: dict[str, float] = {}


def _lock(name: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(name, threading.Lock())


def scan(name: str, max_age: float = 0) -> dict:
    """Scan one source. Unknown names are an error, not an empty result -
    a typo should not look like agreement. `max_age` is how old a cached
    result may be and still be returned instead; 0 (the default) always
    scans, though never alongside a scan of the same source already running."""
    s = _registry().get(name)
    if not s:
        d = dynamic.DRIVERS.get(name)
        if d:
            # A known kind of source that has not been added: an answer, not
            # an error - the MCP scan_* tools exist whether or not it is.
            return {"source": name, "label": d["label"], "hint": d["hint"],
                    "configured": False, "scanned_at": db.now(), "host": {},
                    "findings": [], "counts": {},
                    "error": f"not added - add {d['label']} in Settings › Sources"}
        raise KeyError(name)
    lock = _lock(name)
    if not lock.acquire(blocking=False):
        # Someone is scanning this source right now: wait, then share.
        with lock:
            pass
        if name in _CACHE:
            return {**_CACHE[name], "shared": True}
        lock.acquire()
    try:
        fresh = _FINISHED.get(name)
        if max_age > 0 and fresh and time.monotonic() - fresh < max_age and name in _CACHE:
            return {**_CACHE[name], "cached": True}
        return _scan_now(name, s)
    finally:
        _FINISHED[name] = time.monotonic()
        lock.release()


def _scan_now(name: str, s: dict) -> dict:
    try:
        out = s["mod"].scan()
    except Exception as exc:
        # A source that raises is a broken source, not an absent one. Record
        # it and hand back the same shape everything else consumes.
        _mark(name, f"{type(exc).__name__}: {exc}")
        out = {"source": name, "configured": s["mod"].configured(),
               "scanned_at": db.now(), "host": {}, "findings": [],
               "counts": {}, "error": f"{type(exc).__name__}: {exc}"}
        out["label"] = s["label"]; out["hint"] = s["hint"]
        _CACHE[name] = out
        _notify(name, s, out)
        return out
    _mark(name, out.get("error") if s["mod"].configured() else None)
    out["source"] = name
    _shadow(name, out)
    out["label"] = s["label"]
    out["hint"] = s["hint"]
    _new_devices(name, out)
    _watch(out)
    for f in out.get("findings", []):
        f["source"] = name
    _CACHE[name] = out
    _notify(name, s, out)
    return out


def _new_devices(name: str, out: dict) -> None:
    """Devices this source was the first to see, this week - see
    app/newdevices.py. Only a scan that worked says anything."""
    if out.get("error"):
        return
    from .. import newdevices
    ign = db.ignores()
    new = [f for f in newdevices.findings(name, key_prefix(name)) if f["key"] not in ign]
    if new:
        out.setdefault("findings", []).extend(new)
        out.setdefault("counts", {})["new_devices"] = len(new)


def _watch(out: dict) -> None:
    """Watched devices against what the sources see now - see app/watch.py.
    Never breaks the scan."""
    if out.get("error"):
        return
    try:
        from .. import watch
        watch.check()
    except Exception as exc:
        print(f"[watch] {exc}", flush=True)


def _notify(name: str, s: dict, out: dict) -> None:
    """Tell app/notify.py what this scan found; it decides what is news. A
    source that is disabled or not set up has nothing to report."""
    if s["mod"].configured():
        from .. import notify
        notify.after_scan(name, s["label"], out)


def _shadow(name: str, out: dict) -> None:
    """Two Docker hosts, two tunnels, two Home Assistants: each sees only its
    own part of the estate, so one saying an entry is *missing* is not news
    when a sibling of the same type sees it. Such a finding - a type the
    driver lists in ABSENCE, about an entry another instance of the same type
    has a sighting for - is dropped and counted as `shadowed`. Uses the
    siblings' last scan; nothing is re-scanned for it."""
    type_ = dynamic.type_of(name)
    absence = getattr(dynamic.DRIVERS.get(type_, {}).get("mod"), "ABSENCE", set())
    if not absence or not out.get("findings"):
        return
    siblings = {i["id"] for i in db.list_source_instances(type_)} - {name}
    if not siblings:
        return
    seen = {r["entry_id"] for r in db.all_sightings() if r["source"] in siblings}
    keep = [f for f in out["findings"] if not (
        f.get("type") in absence and (f.get("entry") or {}).get("id") in seen)]
    dropped = len(out["findings"]) - len(keep)
    if dropped:
        out["findings"] = keep
        out.setdefault("counts", {})["shadowed"] = dropped


def scan_type(type_: str) -> dict:
    """Every instance of one type - what the MCP scan_<type> tools answer.
    One instance (or none): exactly the shape of scan(). Several: their
    results under `sources`, with the findings counted across them."""
    ids = [i["id"] for i in db.list_source_instances(type_)]
    if len(ids) <= 1:
        return scan(ids[0] if ids else type_)
    results = [scan(i) for i in ids]
    return {"type": type_, "sources": results,
            "findings": sum(len(r.get("findings", [])) for r in results),
            "errors": sum(1 for r in results if r.get("error"))}


def cached(name: str) -> dict | None:
    return _CACHE.get(name)


def summary() -> dict:
    """Finding counts from the last scan of each source. Never scans - this is
    what the nav badge and the Overview read, so it must stay free.

    `scanned_at` is the *oldest* source's timestamp, because the summary is
    only as fresh as its stalest part.
    """
    reg = _registry()
    by, errors, oldest = {}, [], None
    for name, s in reg.items():
        r = _CACHE.get(name)
        if r is None:
            continue
        if r.get("error"):
            errors.append(name)
            continue
        by[name] = len(r.get("findings", []))
        at = r.get("scanned_at")
        if at and (oldest is None or at < oldest):
            oldest = at
    hs = health()
    # A source waiting for its first scan is neither working nor failing, so
    # it counts on neither side of "N of M sources reporting".
    live = [h for h in hs if h["configured"] and not h["pending"]]
    return {"total": sum(by.values()), "by_source": by, "errors": errors,
            "scanned_at": oldest, "health": hs,
            "sources_ok": sum(1 for h in live if h["ok"]),
            "sources_total": len(live),
            "sources_pending": sum(1 for h in hs if h["pending"]),
            "interval": interval(),
            "next_scan": schedule()["next_scan"],
            # A source whose last good answer is older than this is stale.
            "stale_hours": stale_hours(),
            "configured": [n for n, s in reg.items() if s["mod"].configured()]}


def scan_all(include_unconfigured: bool = False) -> dict:
    """Every configured source, in registry order.

    Findings stay grouped by source rather than merged into one list: the same
    service can be reported by two sources for different reasons, and flattening
    them would read as duplication rather than corroboration.
    """
    reg = _registry()
    results, total, errors = [], 0, 0
    for name, s in reg.items():
        if not s["mod"].configured() and not include_unconfigured:
            results.append({"source": name, "label": s["label"], "hint": s["hint"],
                            "configured": False, "findings": [], "counts": {},
                            "error": None, "skipped": True})
            continue
        r = scan(name, REUSE)
        total += len(r.get("findings", []))
        errors += 1 if r.get("error") else 0
        results.append(r)
    return {"sources": results, "findings": total, "errors": errors,
            "configured": [n for n, s in reg.items() if s["mod"].configured()]}


async def refresh() -> None:
    """Re-scan every configured source into the cache. One source failing is
    recorded in its own result and never stops the others."""
    for name, s in _registry().items():
        if not s["mod"].configured():
            _CACHE.pop(name, None)
            continue
        try:
            await asyncio.to_thread(scan, name)
        except Exception as exc:                     # pragma: no cover
            print(f"[discovery] {name} scan failed: {exc}", flush=True)


async def loop() -> None:
    # A short first delay so start-up is not slowed by reaching out to the
    # firewall, but the badge is still populated before anyone looks.
    global FIRST_PASS_DONE, NEXT_RUN, _WAKE, _LOOP
    _LOOP, _WAKE = asyncio.get_running_loop(), asyncio.Event()
    await asyncio.sleep(START_DELAY)
    while True:
        try:
            await refresh()
        except Exception as exc:                     # never kill the loop
            print(f"[discovery] refresh failed: {exc}", flush=True)
        FIRST_PASS_DONE = True
        last = time.time()
        # Sleep until the next pass is due - re-reading the interval whenever
        # Settings changes it, so a new value applies now, not after the old
        # (possibly day-long) wait.
        while True:
            NEXT_RUN = last + interval()
            wait = NEXT_RUN - time.time()
            if wait <= 0:
                break
            _WAKE.clear()
            try:
                await asyncio.wait_for(_WAKE.wait(), timeout=wait)
            except asyncio.TimeoutError:
                pass


# --------------------------------------------------------------------------
# Settings › Sources - CRUD over app.db.source_instances. See
# app/sources/dynamic.py for what a driver is.
# --------------------------------------------------------------------------
def rotate_secrets() -> dict:
    """Re-encrypt every stored secret with the current key; see app/crypto.py.

    Run once at start-up. With NETMAP_SECRET_KEY set, this moves secrets
    written under the database's own key onto the environment's key, and then
    deletes the database key - but only if nothing still needs it. Secrets no
    known key opens are left as they are and reported in crypto.UNDECRYPTABLE.
    """
    bad: list[str] = []
    rotated = 0
    with db.transaction():
        for inst in db.list_source_instances():
            secrets, changed = dict(inst["secrets"]), False
            for key, tok in inst["secrets"].items():
                new = crypto.rotate(tok)
                if new is None:
                    bad.append(f"{inst['name']}.{key}")
                elif new != tok:
                    secrets[key], changed = new, True
                    rotated += 1
            if changed:
                db.conn().execute("UPDATE source_instances SET secrets=? WHERE id=?",
                                  (json.dumps(secrets), inst["id"]))
        # Notification channels hold secrets too (bot tokens, webhook URLs),
        # under the same key.
        for ch in db.list_notify_channels():
            secrets, changed = dict(ch["secrets"]), False
            for key, tok in ch["secrets"].items():
                new = crypto.rotate(tok)
                if new is None:
                    bad.append(f"{ch['name']} (notifications).{key}")
                elif new != tok:
                    secrets[key], changed = new, True
                    rotated += 1
            if changed:
                db.set_notify_secrets(ch["id"], secrets)
    crypto.UNDECRYPTABLE[:] = bad
    forgot = not bad and crypto.forget_stored_key()
    return {"rotated": rotated, "undecryptable": bad, "stored_key_removed": forgot}


# The seed runs once per database, ever. Afterwards Settings is the only place
# a source is configured: an environment variable changed later does nothing,
# and a source removed in Settings stays removed across restarts.
SEEDED_KEY = "sources_seeded"


def migrate_legacy() -> dict:
    """Turn pre-1.75 configuration into instances, once.

    Before 1.75 the eight original sources were configured by NETMAP_*
    environment variables, overridden field by field from Settings (the
    source_settings table). Each type with anything set becomes an instance
    whose id is its type - so finding keys, ignores and sightings, all keyed
    by that name, carry on unchanged. Settings overrides win over the
    environment, as they did. A type with nothing set, or not enough to
    scan, is not created. The existing Proxmox instance is renamed to the
    same scheme.

    Run at start-up before rotate_secrets(). Returns what it did.
    """
    out = {"created": [], "renamed": [], "skipped": False}
    with db.transaction():
        existing = db.list_source_instances()
        ids = {i["id"] for i in existing}
        for inst in existing:
            t = inst["type"]
            if dynamic.type_of(inst["id"]) != t and t not in ids:
                db.rename_source_instance(inst["id"], t)
                ids.add(t)
                out["renamed"].append(t)
                _STATE.pop(inst["id"], None)
        if db.get_setting(SEEDED_KEY) is not None:
            out["skipped"] = True
            # Seeded on an earlier start; the legacy overrides were kept for a
            # rollback to 1.74 until 1.79.0. Nothing reads them now.
            out["legacy_dropped"] = db.drop_source_settings()
            return out
        have = {i["type"] for i in db.list_source_instances()}
        for type_, d in dynamic.DRIVERS.items():
            if type_ in have:
                continue
            defs = d["mod"].FIELDS
            raw: dict = {}
            for f in defs:
                env = f.get("env")
                if env and os.environ.get(env, "").strip() != "":
                    raw[f["key"]] = os.environ[env]
            overrides = db.get_source_settings(type_)
            for f in defs:
                if f["key"] not in overrides:
                    continue
                v = overrides[f["key"]]
                if f.get("secret"):
                    v = crypto.decrypt(v)
                    if not v:
                        continue
                raw[f["key"]] = v
            # A value that does not cast is dropped, not fatal: the field's
            # default is what the old code fell back to as well.
            for f in defs:
                if f["key"] in raw and not f.get("secret"):
                    try:
                        raw[f["key"]] = fields.cast(f, raw[f["key"]])
                    except ValueError:
                        print(f"[sources] ignoring {f.get('env') or f['key']}: "
                              f"not a valid value for {d['label']}", flush=True)
                        del raw[f["key"]]
            # A source that an environment variable alone used to switch on.
            switch, on = getattr(d["mod"], "LEGACY_SWITCH", None), False
            if switch and os.environ.get(switch, "").strip() != "":
                try:
                    on = fields.as_bool(os.environ[switch])
                except ValueError:
                    on = False
                if not on:
                    continue                        # switched off: not added
            if not (raw or on) or not d["mod"].configured(fields.coerce(defs, raw)):
                continue
            config, secrets = _split(type_, raw)
            db.create_source_instance(
                type_, d["label"], config, secrets, True, actor="system",
                iid=type_, action="source-migrate", detail={"fields": sorted(raw)})
            out["created"].append(type_)
        db.set_setting(SEEDED_KEY, db.now())
        out["legacy_dropped"] = db.drop_source_settings()
    if out["created"]:
        print(f"[sources] configured {', '.join(out['created'])} from the environment "
              "and earlier Settings, once. From now on sources are managed in "
              "Settings › Sources; the NETMAP_* source variables are ignored.",
              flush=True)
    return out


PINNED_KEY = "defaults_pinned"


def fold_scan_switch() -> list[str]:
    """Before 1.93.0 the Open ports source had an "Enabled" field of its own,
    beside the switch every source has. One switch now: a source paused with
    the old field stays paused. Idempotent - the field is removed once read."""
    done = []
    for inst in db.list_source_instances("ports"):
        if "enabled" not in inst["config"]:
            continue
        cfg = {k: v for k, v in inst["config"].items() if k != "enabled"}
        on = fields.as_bool(inst["config"]["enabled"]) if not fields.blank(
            inst["config"]["enabled"]) else True
        db.update_source_instance(inst["id"], config=cfg,
                                  enabled=inst["enabled"] and on, actor="system",
                                  detail={"fields": ["enabled"]})
        _STATE.pop(inst["id"], None)
        if not on:
            done.append(inst["id"])
    return done


def pin_defaults() -> list[str]:
    """Once: an existing Open ports source that left "Categories never swept"
    blank relied on the old default; write it in, so changing the default
    (1.92.1) does not start sweeping what was skipped. Returns the ids."""
    if db.get_setting(PINNED_KEY) is not None:
        return []
    from . import portscan
    done = []
    for inst in db.list_source_instances("ports"):
        if fields.blank(inst["config"].get("skip")):
            db.update_source_instance(inst["id"], config={**inst["config"],
                                      "skip": portscan.LEGACY_SKIP},
                                      actor="system", detail={"fields": ["skip"]})
            _STATE.pop(inst["id"], None)
            done.append(inst["id"])
    db.set_setting(PINNED_KEY, db.now())
    return done


def drivers() -> list[dict]:
    """Every source type Settings can add, with its form. `can_add` is false
    for a single-instance type that already has its instance."""
    have = {i["type"] for i in db.list_source_instances()}
    return [{"type": t, "label": d["label"], "hint": d["hint"],
             "roles": list(dynamic.roles_of(t)),
             "single": single(t), "can_add": not (single(t) and t in have),
             "fields": _form(d["mod"].FIELDS)}
            for t, d in dynamic.DRIVERS.items()]


def roles() -> dict:
    """Every role, its label and what it promises - for Settings."""
    return {r: {"label": label, "contract": contract}
            for r, (label, contract) in dynamic.ROLES.items()}


def _form(defs: list[dict]) -> list[dict]:
    """A driver's FIELDS for the browser - without the legacy env name."""
    return [{k: v for k, v in f.items() if k != "env"} for f in defs]


def _describe(inst: dict) -> dict:
    """One instance for the Settings list - secrets never leave this process
    as plaintext, only as "is one set" plus a last-four-characters preview."""
    driver = dynamic.DRIVERS.get(inst["type"], {})
    field_defs = driver["mod"].FIELDS if driver.get("mod") else []
    secrets = {}
    for f in field_defs:
        if f.get("secret"):
            enc = inst["secrets"].get(f["key"], "")
            secrets[f["key"]] = {"set": bool(enc),
                                 "preview": crypto.mask(crypto.decrypt(enc)) if enc else ""}
    h = _HEALTH.get(inst["id"], {})
    configured_ = bool(driver.get("mod")) and _Instance(inst, driver["mod"]).configured()
    return {
        "id": inst["id"], "type": inst["type"], "name": inst["name"],
        "label": driver.get("label", inst["type"]), "hint": driver.get("hint", ""),
        "roles": list(dynamic.roles_of(inst["type"])),
        "config": inst["config"], "secrets": secrets, "enabled": inst["enabled"],
        "configured": configured_,
        "ok": h.get("error") is None and h.get("last_ok") is not None,
        "last_ok": h.get("last_ok"), "error": h.get("error"),
        "created_at": inst["created_at"], "updated_at": inst["updated_at"],
    }


def list_instances() -> list[dict]:
    order = {t: i for i, t in enumerate(dynamic.DRIVERS)}
    rows = sorted(db.list_source_instances(),
                  key=lambda i: (order.get(i["type"], len(order)), i["created_at"]))
    return [_describe(i) for i in rows]


def _split(type_: str, fields_in: dict) -> tuple[dict, dict]:
    """A form submission into (config, encrypted secrets) - see fields.split."""
    config, secrets = fields.split(dynamic.fields(type_), fields_in)
    return config, {k: crypto.encrypt(v) for k, v in secrets.items()}


def _require(type_: str, config: dict, secret_keys) -> None:
    fields.require(dynamic.fields(type_), config, secret_keys)


def create_instance(type_: str, name: str, fields_in: dict, enabled: bool = True,
                    actor: str = "web") -> dict:
    if type_ not in dynamic.DRIVERS:
        raise ValueError(f"unknown source type '{type_}' - "
                         f"have {', '.join(dynamic.DRIVERS)}")
    label = dynamic.DRIVERS[type_]["label"]
    existing = db.list_source_instances(type_)
    if single(type_) and existing:
        raise ValueError(f"only one {label} source is supported. Edit the "
                         "existing one instead.")
    config, secrets = _split(type_, fields_in)
    _require(type_, config, secrets)
    iid = _new_id(type_)
    default = label if not existing else f"{label} {iid.rsplit('-', 1)[-1]}"
    inst = db.create_source_instance(type_, (name or "").strip() or default, config,
                                     secrets, enabled, actor=actor, iid=iid,
                                     detail={"fields": sorted({**config, **secrets})})
    _STATE.pop(inst["id"], None)
    return _describe(inst)


def update_instance(instance_id: str, name: str | None = None,
                    fields_in: dict | None = None, enabled: bool | None = None,
                    actor: str = "web") -> dict | None:
    before = db.get_source_instance(instance_id)
    if not before:
        return None
    config = secrets = None
    if fields_in is not None:
        config, secrets = _split(before["type"], fields_in)
        fields.check_rebind(dynamic.fields(before["type"]), before, config, secrets)
        config = {**before["config"], **config}
        _require(before["type"], config, {**before["secrets"], **secrets})
    changed = sorted(k for k in (fields_in or {}) if k in {f["key"] for f in
                                                            dynamic.fields(before["type"])})
    if enabled is not None and bool(enabled) != bool(before["enabled"]):
        changed.append("enabled")
    inst = db.update_source_instance(instance_id, name=name, config=config,
                                     secrets=secrets, enabled=enabled, actor=actor,
                                     detail={"fields": changed} if changed else None)
    # Any change drops the session: the next scan logs in with what was just
    # saved rather than riding an old one until it expires.
    _STATE.pop(instance_id, None)
    return _describe(inst) if inst else None


def delete_instance(instance_id: str, actor: str = "web") -> bool:
    # What it saw goes with it; what a person decided to ignore stays, and
    # applies again if a source with the same id is added back.
    ok = db.delete_source_instance(instance_id, actor=actor)
    if ok:
        db.record_sightings(instance_id, [])
        db.record_presence(instance_id, [])
        for d in (_CACHE, _HEALTH, _FINISHED, _STATE):
            d.pop(instance_id, None)
        from .. import notify
        notify.forget(f"source:{instance_id}", f"finding:{instance_id}")
    return ok


def _test(mod, cfg: dict) -> dict:
    if not mod.configured(cfg):
        return {"ok": False, "error": "fill in the required fields first"}
    try:
        if hasattr(mod, "test"):
            return mod.test(cfg)
        r = mod.scan(cfg)
        return {"ok": not r.get("error"), "error": r.get("error")}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def test_fields(type_: str, fields_in: dict) -> dict:
    """Test connection details before they are saved anywhere - the "Test"
    button on the Add-source form, which has no instance id yet."""
    driver = dynamic.DRIVERS.get(type_)
    if not driver:
        raise ValueError(f"unknown source type '{type_}' - "
                         f"have {', '.join(dynamic.DRIVERS)}")
    cfg = fields.coerce(driver["mod"].FIELDS, dict(fields_in or {}))
    cfg["_state"] = {}
    return _test(driver["mod"], cfg)


def test_instance(instance_id: str) -> dict:
    """A connectivity check with a fresh session, independent of enabled and
    of the cache - the button in Settings you press to see whether what is
    saved works."""
    inst = db.get_source_instance(instance_id)
    if not inst:
        raise KeyError(instance_id)
    driver = dynamic.DRIVERS.get(inst["type"])
    if not driver:
        raise ValueError(f"unknown source type '{inst['type']}'")
    cfg = _Instance(inst, driver["mod"]).cfg()
    cfg["_state"] = {}
    return _test(driver["mod"], cfg)
