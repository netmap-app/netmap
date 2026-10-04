"""Notifications: what already reaches the Overview, delivered to a person who
is not looking at it. Nothing here detects anything - the scans and the status
sweep hand over what they found, and this decides whether it is news.

News is a change of state, never a repetition of one. Every caller describes
the problems that are true *now* for one scope (one source's findings, one
source's health, the watched entries); `sync` compares that with what was true
last time, sends what is new, and - where it means something - says when a
problem cleared. That state lives in the `kv` table, so a restart compares
against the state before it: nothing is re-sent, and nothing that changed
while NetMap was down is lost. The first time a scope is ever seen (a new
install, a source just added) is recorded and not sent: what was already true
before anyone was listening is not news.

Channels are stored like sources - `notify_channels`, config plain, secrets
encrypted - and delivery never raises into the scan or sweep that emitted it:
a failure is logged and shown on the channel's row in Settings.
"""
import asyncio
import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque

from . import crypto, db, digest
from .sources import fields
from .sources._http import urlopen

VERSION = ""          # set by main, for the webhook payload and the User-Agent
TIMEOUT = 10          # seconds per delivery
WINDOW = 600          # the rate limit counts messages in this many seconds
STATE_KEY = "notify_state"

EVENTS = {
    "finding": "A new finding - a source disagrees with the inventory",
    "entry": "A critical or important entry stops answering, or answers again",
    "source": "A source stops answering, or answers again",
    "cert": "A certificate a health check reads expires soon",
    "critical": "Any other critical Overview item appears",
    "watch": "A device you are watching is back on the network, or is dropped "
             "after 90 days unseen",
}
# Events added after 1.82.0. A channel that had every event then gets these
# too, once (see upgrade_events); one that chose a few keeps its choice.
_NEW_EVENTS = {"cert": {"finding", "entry", "source", "critical"},
               "watch": {"finding", "entry", "source", "cert", "critical"}}

_LINK = {"key": "link", "label": "Link back to NetMap", "type": "text", "wide": True,
         "placeholder": "https://netmap.example.com"}
_RATE = {"key": "rate_limit", "label": "At most this many messages per 10 minutes",
         "type": "number", "integer": True, "default": 10}

# `binds` on an address: changing it needs every stored secret typed again,
# as for sources. A webhook's URL is itself the secret (Discord and Slack put
# the token in it), so the check below also treats a new URL as a new address.
TYPES = {
    "ntfy": {"label": "ntfy", "hint": "Publishes to a topic on an ntfy server "
             "(ntfy.sh or your own). The token is only needed for a protected topic.",
             "fields": [
                 {"key": "url", "label": "Server", "type": "text", "wide": True,
                  "default": "https://ntfy.sh", "binds": True},
                 {"key": "topic", "label": "Topic", "type": "text", "required": True},
                 {"key": "token", "label": "Access token", "type": "password",
                  "secret": True, "wide": True},
                 _LINK, _RATE]},
    "gotify": {"label": "Gotify", "hint": "Sends to a Gotify server with an "
               "application token (Apps › Create application).",
               "fields": [
                   {"key": "url", "label": "Server", "type": "text", "wide": True,
                    "required": True, "placeholder": "https://gotify.example.com",
                    "binds": True},
                   {"key": "token", "label": "Application token", "type": "password",
                    "secret": True, "required": True, "wide": True},
                   _LINK, _RATE]},
    "telegram": {"label": "Telegram", "hint": "A bot you create with @BotFather "
                 "writes to a chat. Send the bot a message first, then read the "
                 "chat id from the Bot API's getUpdates.",
                 "fields": [
                     {"key": "token", "label": "Bot token", "type": "password",
                      "secret": True, "required": True, "wide": True,
                      "placeholder": "123456:ABC-…"},
                     {"key": "chat_id", "label": "Chat id", "type": "text",
                      "required": True, "placeholder": "123456789, -100… or @channel"},
                     {"key": "thread_id", "label": "Topic id (forum groups only)",
                      "type": "text"},
                     {"key": "api_url", "label": "Bot API server", "type": "text",
                      "wide": True, "default": "https://api.telegram.org", "binds": True},
                     _LINK, _RATE]},
    "webhook": {"label": "Webhook", "hint": "POSTs JSON {kind, key, title, detail, "
                "url, ts, version} to a URL - an Apprise API, Home Assistant or "
                "anything else that takes a webhook.",
                "fields": [
                    {"key": "url", "label": "Webhook URL", "type": "password",
                     "secret": True, "required": True, "wide": True,
                     "placeholder": "https://…"},
                    {"key": "token", "label": "Bearer token", "type": "password",
                     "secret": True, "wide": True},
                    _LINK, _RATE]},
}

_LOCK = threading.Lock()                        # the state read-modify-write
_QLOCK = threading.Lock()                       # the queue and the counters
_QUEUE: deque = deque()                         # (channel id, message)
_HELD: dict[str, list] = {}                     # over the rate limit, waiting
_SENT_AT: dict[str, deque] = {}                 # delivery times per channel
_STATUS: dict[str, dict] = {}                   # last try / ok / error per channel
_WAKE: asyncio.Event | None = None
_LOOP: asyncio.AbstractEventLoop | None = None


# --------------------------------------------------------------------------
# What is news
# --------------------------------------------------------------------------
def _load() -> dict:
    try:
        return json.loads(db.get_setting(STATE_KEY) or "{}")
    except ValueError:
        return {}


def sync(kind: str, scope: str, current: dict[str, dict], known: set | None = None,
         keep: set | None = None, resolved=None) -> list[dict]:
    """Compare what is wrong now in one scope with last time; send the new.

    current   key -> {title, detail, level} for every problem true now
    known     keys whose state was actually checked this time (None: all of
              them). A key not checked is neither new nor cleared - a source
              waiting for its first scan has not recovered.
    keep      keys that can still exist; an unchecked key outside it (an
              entry deleted, or no longer critical) is dropped without a word
    resolved  key, stored -> message when a cleared problem is worth saying

    Returns the messages sent, for tests and callers that want to know."""
    out: list[dict] = []
    with _LOCK:
        state = _load()
        first = scope not in state
        prev = state.get(scope, {})
        now = {}
        for k, m in current.items():
            if k in prev:
                now[k] = prev[k]
                continue
            now[k] = {"since": db.now(), "title": m.get("title", ""),
                      "level": m.get("level", "warn")}
            if not first:
                out.append(_message(kind, k, m))
        for k, stored in prev.items():
            if k in current:
                continue
            if known is not None and k not in known:
                if keep is None or k in keep:
                    now[k] = stored
                continue
            m = resolved(k, stored) if resolved else None
            if m:
                # `was`: how bad it was - a summary channel sends the all-clear
                # of an urgent problem as urgently as the problem itself.
                out.append({**_message(kind, k, {"level": "ok", **m}),
                            "was": stored.get("level", "")})
        if first or now != prev:
            state[scope] = now
            db.set_setting(STATE_KEY, json.dumps(state, sort_keys=True))
    for m in out:
        emit(m)
    return out


def forget(*scopes: str) -> None:
    """Drop what was recorded for a scope - a source that was removed."""
    with _LOCK:
        state = _load()
        if any(s in state for s in scopes):
            for s in scopes:
                state.pop(s, None)
            db.set_setting(STATE_KEY, json.dumps(state, sort_keys=True))


def _message(kind: str, key: str, m: dict) -> dict:
    return {"kind": kind, "key": f"{kind}:{key}", "title": m.get("title", ""),
            "detail": m.get("detail", ""), "level": m.get("level", "warn"),
            "path": m.get("path", "/"), "ts": db.now()}


def tell(kind: str, key: str, m: dict) -> None:
    """One message that is news by construction - the caller already knows
    it is a change (a watched device coming back)."""
    emit(_message(kind, key, m))


def after_scan(source_id: str, label: str, result: dict) -> None:
    """A source was scanned: its health, and its findings if it answered."""
    try:
        err = result.get("error")
        sync("source", f"source:{source_id}",
             {source_id: {"title": f"{label} is not answering", "detail": err,
                          "level": "critical"}} if err else {},
             resolved=lambda k, s: {"title": f"{label} is answering again",
                                    "detail": "its findings are current again"})
        if err:
            return    # nothing was read, so no finding has cleared either
        ign = db.ignores()
        sync("finding", f"finding:{source_id}",
             {f["key"]: {"title": f"{label}: {f.get('label', '')}",
                         "detail": f.get("detail", ""), "path": "/"}
              for f in result.get("findings", []) if f.get("key") and f["key"] not in ign})
    except Exception as exc:                      # never break the scan
        print(f"[notify] {source_id}: {exc}", flush=True)


def after_sweep(entries: list[dict], cache: dict) -> None:
    """The status sweep finished: critical and important entries that went
    down or came back, and critical Overview items."""
    try:
        watch = {str(e["id"]): e for e in entries if e.get("monitor")
                 and e.get("criticality") in ("critical", "important")}
        known = {k for k in watch if cache.get(int(k), {}).get("up") is not None}
        down = {k: {"title": f"{e['name']} is not answering",
                    "detail": f"{e['criticality']} - "
                              f"{cache.get(int(k), {}).get('target') or 'no target'}",
                    "level": "critical" if e["criticality"] == "critical" else "warn"}
                for k, e in watch.items() if cache.get(int(k), {}).get("up") is False}
        sync("entry", "entry", down, known=known, keep=set(watch),
             resolved=lambda k, s: {"title": f"{watch[k]['name']} is answering again",
                                    "detail": f"down since {s.get('since', '?')}"})
        from . import status
        sync("cert", "cert",
             {str(c["entry"]["id"]): {
                 "title": (f"The certificate of {c['entry']['name']} has expired"
                           if c["days_left"] < 0 else
                           f"The certificate of {c['entry']['name']} expires in "
                           f"{c['days_left']} day{'' if c['days_left'] == 1 else 's'}"),
                 "detail": f"{c['target']} - valid until {(c['not_after'] or '?')[:10]}",
                 "level": "critical" if c["days_left"] < 0 else "warn"}
              for c in status.expiring(entries, cache)},
             known={str(e["id"]) for e in entries if (cache.get(e["id"]) or {}).get("tls")},
             keep={str(e["id"]) for e in entries})
        # The rest of the Overview's critical items. Sources and entries have
        # their own events above; this is what is left (a secret no key opens).
        from . import overview
        items = overview.snapshot(cache)["attention"]
        sync("critical", "critical",
             {it["key"]: {"title": it["title"], "detail": it.get("detail", ""),
                          "level": "critical"}
              for it in items if it["level"] == "critical"
              and not it["key"].startswith(("source:", "down:", "cert:"))})
    except Exception as exc:                      # never break the sweep
        print(f"[notify] sweep: {exc}", flush=True)


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------
def emit(msg: dict) -> None:
    """Queue one message for every enabled channel that wants its kind - or,
    on a summary channel, hold it for the summary unless it is urgent (see
    app/digest.py)."""
    from . import digest
    with _QLOCK:
        for ch in db.list_notify_channels():
            if not (ch["enabled"] and msg["kind"] in ch["events"]):
                continue
            d = digest.delivery(ch)
            if d["mode"] != "off" and not digest.urgent(d, msg):
                digest.hold(ch["id"], msg)
            else:
                _QUEUE.append((ch["id"], msg))
    if _LOOP and _WAKE:
        _LOOP.call_soon_threadsafe(_WAKE.set)


def deliver() -> int:
    """Send what is queued, within each channel's rate limit. Anything over
    the limit is held and later sent as one "and N more" message. Returns how
    many deliveries were attempted."""
    with _QLOCK:
        batch = list(_QUEUE)
        _QUEUE.clear()
    by: dict[str, list] = {}
    for cid, m in batch:
        by.setdefault(cid, []).append(m)
    sent = 0
    for ch in db.list_notify_channels():
        cid = ch["id"]
        with _QLOCK:
            pending = _HELD.pop(cid, []) + by.get(cid, [])
            if not pending or not ch["enabled"]:
                continue
            cfg = _cfg(ch)
            limit = max(1, int(cfg.get("rate_limit") or 10))
            times = _SENT_AT.setdefault(cid, deque())
            while times and times[0] < time.time() - WINDOW:
                times.popleft()
            room = limit - len(times)
            if room <= 0:
                _HELD[cid] = pending
                continue
            if len(pending) > room:
                rest = pending[room - 1:]
                pending = pending[:room - 1] + [_summary(rest)]
            for _ in pending:
                times.append(time.time())
        for m in pending:
            _send(ch, cfg, m)
            sent += 1
    return sent


def _summary(rest: list[dict]) -> dict:
    titles = [m["title"] for m in rest]
    return {"kind": "summary", "key": "summary", "level": "warn", "path": "/",
            "ts": db.now(), "title": f"and {len(rest)} more",
            "detail": "; ".join(titles[:5]) + ("; …" if len(titles) > 5 else "")}


def _send(ch: dict, cfg: dict, m: dict) -> dict:
    st = _STATUS.setdefault(ch["id"], {"last_ok": None, "last_try": None, "error": None})
    st["last_try"] = db.now()
    try:
        SENDERS[ch["type"]](cfg, m)
        st["last_ok"], st["error"] = st["last_try"], None
        return {"ok": True, "error": None}
    except Exception as exc:
        st["error"] = _scrub(cfg, _why(exc))
        print(f"[notify] {ch['name']}: delivery failed: {st['error']}", flush=True)
        return {"ok": False, "error": st["error"]}


def _why(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read(400).decode("utf-8", "replace")
            desc = json.loads(body).get("description") or json.loads(body).get("error")
        except Exception:
            desc = ""
        return f"HTTP {exc.code}" + (f": {desc}" if desc else f" {exc.reason}")
    if isinstance(exc, urllib.error.URLError):
        return f"cannot reach it: {exc.reason}"
    return f"{type(exc).__name__}: {exc}"


def _scrub(cfg: dict, text: str) -> str:
    """No secret in an error message: a Telegram bot token is part of the URL."""
    for f in TYPES.get(cfg.get("_type"), {}).get("fields", []):
        v = cfg.get(f["key"])
        if f.get("secret") and v:
            text = text.replace(str(v), "•••")
    return text


async def loop() -> None:
    """Deliver as messages arrive, and every half minute for held ones."""
    global _WAKE, _LOOP
    _LOOP, _WAKE = asyncio.get_running_loop(), asyncio.Event()
    from . import digest
    while True:
        try:
            due = await asyncio.to_thread(digest.run)
            with _QLOCK:
                _QUEUE.extend(due)
            await asyncio.to_thread(deliver)
        except Exception as exc:                  # never kill the loop
            print(f"[notify] delivery pass failed: {exc}", flush=True)
        _WAKE.clear()
        try:
            await asyncio.wait_for(_WAKE.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass


# --------------------------------------------------------------------------
# Channel types. Each takes (cfg, message) and raises on failure.
# --------------------------------------------------------------------------
def _post(url: str, body: dict, headers: dict | None = None) -> None:
    req = urllib.request.Request(
        url, method="POST", data=json.dumps(body).encode(),
        headers={"content-type": "application/json",
                 "user-agent": f"NetMap/{VERSION or 'dev'}", **(headers or {})})
    with urlopen(req, timeout=TIMEOUT) as r:
        r.read(4096)


def _link(cfg: dict, m: dict) -> str:
    base = str(cfg.get("link") or "").strip().rstrip("/")
    return base + m.get("path", "/") if base else ""


def _bearer(cfg: dict) -> dict:
    return {"authorization": f"Bearer {cfg['token']}"} if cfg.get("token") else {}


def _urgent(m: dict) -> bool:
    return m["level"] == "critical"


def _ntfy(cfg: dict, m: dict) -> None:
    body = {"topic": cfg["topic"], "title": m["title"],
            "message": m["detail"] or m["title"], "priority": 4 if _urgent(m) else 3,
            "tags": ["rotating_light" if _urgent(m) else
                     "white_check_mark" if m["level"] == "ok" else "warning"]}
    if _link(cfg, m):
        body["click"] = _link(cfg, m)
    _post(cfg["url"], body, _bearer(cfg))


def _gotify(cfg: dict, m: dict) -> None:
    body = {"title": m["title"], "message": m["detail"] or m["title"],
            "priority": 8 if _urgent(m) else 5}
    if _link(cfg, m):
        body["extras"] = {"client::notification": {"click": {"url": _link(cfg, m)}}}
    _post(cfg["url"] + "/message", body, {"x-gotify-key": cfg["token"]})


def _telegram(cfg: dict, m: dict) -> None:
    # Plain text, no parse_mode: an entry name with a "_" or "*" in it would
    # otherwise be refused as broken Markdown.
    icon = "🔴" if _urgent(m) else "🟢" if m["level"] == "ok" else "🟠"
    text = "\n".join(x for x in (f"{icon} {m['title']}", m["detail"], _link(cfg, m)) if x)
    body = {"chat_id": cfg["chat_id"], "text": text[:4000],
            "disable_web_page_preview": True}
    if str(cfg.get("thread_id") or "").strip():
        body["message_thread_id"] = int(str(cfg["thread_id"]).strip())
    api = str(cfg.get("api_url") or "https://api.telegram.org").strip().rstrip("/")
    _post(f"{api}/bot{cfg['token']}/sendMessage", body)


def _webhook(cfg: dict, m: dict) -> None:
    _post(cfg["url"].strip(), {"kind": m["kind"], "key": m["key"], "title": m["title"],
                       "detail": m["detail"], "url": _link(cfg, m), "ts": m["ts"],
                       "level": m["level"], "version": VERSION}, _bearer(cfg))


SENDERS = {"ntfy": _ntfy, "gotify": _gotify, "telegram": _telegram, "webhook": _webhook}


# --------------------------------------------------------------------------
# Settings › Notifications
# --------------------------------------------------------------------------
def _defs(type_: str) -> list[dict]:
    if type_ not in TYPES:
        raise ValueError(f"unknown channel type '{type_}' - have {', '.join(TYPES)}")
    return TYPES[type_]["fields"]


def _cfg(ch: dict) -> dict:
    raw = dict(ch["config"])
    for k, enc in ch["secrets"].items():
        raw[k] = crypto.decrypt(enc)
    cfg = fields.coerce(_defs(ch["type"]), raw)
    cfg["_type"] = ch["type"]
    return cfg


def _check_urls(type_: str, config: dict, secrets: dict) -> None:
    """What would otherwise be accepted on save and then fail every delivery."""
    for f in _defs(type_):
        v = str({**config, **secrets}.get(f["key"]) or "").strip()
        if v and f["key"] in ("url", "api_url", "link") and not v.lower().startswith(
                ("http://", "https://")):
            raise ValueError(f"{f['label']} must start with http:// or https://")
        if v and f["key"] == "thread_id" and not v.isdigit():
            raise ValueError(f"{f['label']} must be a number, or empty")


def _events(events) -> list[str]:
    if events is None:
        return list(EVENTS)
    bad = [e for e in events if e not in EVENTS]
    if bad:
        raise ValueError(f"unknown event {', '.join(map(str, bad))} - have {', '.join(EVENTS)}")
    return [e for e in EVENTS if e in events]


def upgrade_events() -> None:
    """Once per new event: channels that had every event before it existed
    get it too. Run at start-up."""
    done = set(json.loads(db.get_setting("notify_events_seen") or "[]"))
    todo = {e: before for e, before in _NEW_EVENTS.items() if e not in done}
    if not todo:
        return
    for ch in db.list_notify_channels():
        add = [e for e, before in todo.items() if before <= set(ch["events"])
               and e not in ch["events"]]
        if add:
            db.save_notify_channel(ch["id"], ch["type"], ch["name"], ch["config"],
                                   ch["secrets"], _events(ch["events"] + add),
                                   ch["enabled"], actor="system",
                                   detail={"events_added": add})
    db.set_setting("notify_events_seen", json.dumps(sorted(done | set(todo))))


def types() -> dict:
    return {"types": [{"type": t, "label": d["label"], "hint": d["hint"],
                       "fields": d["fields"]} for t, d in TYPES.items()],
            "events": EVENTS}


def describe(ch: dict) -> dict:
    """One channel for Settings - secrets only as "set" and a last-four preview."""
    secrets = {f["key"]: {"set": bool(ch["secrets"].get(f["key"])),
                          "preview": crypto.mask(crypto.decrypt(ch["secrets"].get(f["key"], "")))}
               for f in TYPES.get(ch["type"], {}).get("fields", []) if f.get("secret")}
    st = _STATUS.get(ch["id"], {})
    return {"id": ch["id"], "type": ch["type"], "name": ch["name"],
            "label": TYPES.get(ch["type"], {}).get("label", ch["type"]),
            "config": ch["config"], "secrets": secrets, "events": ch["events"],
            "enabled": ch["enabled"], "last_ok": st.get("last_ok"),
            "last_try": st.get("last_try"), "error": st.get("error"),
            "held": len(_HELD.get(ch["id"], [])),
            "delivery": digest.delivery(ch), "waiting": len(digest.held(ch["id"]))}


def list_channels() -> list[dict]:
    return [describe(c) for c in db.list_notify_channels()]


def create(type_: str, name: str, fields_in: dict, events=None, enabled: bool = True,
           actor: str = "web", delivery=None) -> dict:
    defs = _defs(type_)
    config, plain = fields.split(defs, fields_in)
    config["delivery"] = digest.clean(delivery)
    fields.require(defs, config, plain)
    _check_urls(type_, config, plain)
    ch = db.save_notify_channel(
        None, type_, (name or "").strip() or TYPES[type_]["label"], config,
        {k: crypto.encrypt(v) for k, v in plain.items()}, _events(events), enabled,
        actor=actor, detail={"fields": sorted({**config, **plain})})
    if config["delivery"]["mode"] != "off":
        digest.started(ch["id"])
    return describe(ch)


def update(channel_id: str, name: str | None = None, fields_in: dict | None = None,
           events=None, enabled: bool | None = None, actor: str = "web",
           delivery=None) -> dict | None:
    before = db.get_notify_channel(channel_id)
    if not before:
        return None
    defs = _defs(before["type"])
    config, secrets = dict(before["config"]), dict(before["secrets"])
    changed: list[str] = []
    if fields_in is not None:
        new_config, plain = fields.split(defs, fields_in)
        fields.check_rebind(defs, before, new_config, plain)
        # A webhook's URL is a secret, and a bearer token entered for one URL
        # is not sent to another.
        if "url" in plain and before["secrets"].get("url") and before["secrets"].get("token") \
                and "token" not in plain \
                and plain["url"].strip() != crypto.decrypt(before["secrets"]["url"]).strip():
            raise ValueError("changing Webhook URL needs Bearer token entered again - a "
                             "stored secret is never sent to an address it was not entered for")
        config.update(new_config)
        fields.require(defs, config, {**secrets, **plain})
        _check_urls(before["type"], config, plain)
        secrets.update({k: crypto.encrypt(v) for k, v in plain.items()})
        changed = sorted(k for k in fields_in if k in {f["key"] for f in defs})
    was = digest.delivery(before)
    if delivery is not None:
        config["delivery"] = digest.clean(delivery)
        if config["delivery"] != was:
            changed.append("delivery")
    ch = db.save_notify_channel(
        channel_id, before["type"],
        before["name"] if name is None else (name.strip() or before["name"]),
        config, secrets, before["events"] if events is None else _events(events),
        before["enabled"] if enabled is None else bool(enabled), actor=actor,
        detail={"fields": changed} if changed else None)
    now = digest.delivery(ch)
    if now["mode"] == "off" and was["mode"] != "off":
        msg = digest.flush(ch)                 # back to immediate: send what was held
        if msg:
            with _QLOCK:
                _QUEUE.append((ch["id"], msg))
    elif now["mode"] != "off" and (was["mode"], was["hour"], was["day"]) != \
            (now["mode"], now["hour"], now["day"]):
        digest.started(ch["id"])
    return describe(ch)


def delete(channel_id: str, actor: str = "web") -> bool:
    ok = db.delete_notify_channel(channel_id, actor=actor)
    if ok:
        digest.drop(channel_id)
        with _QLOCK:
            for d in (_HELD, _SENT_AT, _STATUS):
                d.pop(channel_id, None)
    return ok


def _test_message() -> dict:
    return {"kind": "test", "key": "test", "level": "ok", "path": "/", "ts": db.now(),
            "title": "NetMap test message",
            "detail": "If you can read this, this channel works."}


def test(channel_id: str) -> dict:
    """The Send-test button: one message now, outside the rate limit."""
    ch = db.get_notify_channel(channel_id)
    if not ch:
        raise KeyError(channel_id)
    return _send(ch, _cfg(ch), _test_message())


def test_fields(type_: str, fields_in: dict) -> dict:
    """Send a test with details not saved yet (the Add form)."""
    defs = _defs(type_)
    config, plain = fields.split(defs, fields_in)
    try:
        fields.require(defs, config, plain)
        _check_urls(type_, config, plain)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    cfg = fields.coerce(defs, {**config, **plain})
    cfg["_type"] = type_
    try:
        SENDERS[type_](cfg, _test_message())
        return {"ok": True, "error": None}
    except Exception as exc:
        return {"ok": False, "error": _scrub(cfg, _why(exc))}
