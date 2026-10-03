"""Notifications (app/notify.py): a change of state is sent once, a restart
sends nothing, a burst collapses, secrets never come back out, and a failed
delivery never breaks the scan or sweep that caused it. Every target is a
local HTTP server; nothing leaves the machine."""
import asyncio
import http.server
import json
import socket
import threading

import pytest

TOKEN = {"authorization": "Bearer full-token"}
BOT = "123456:SECRET-bot-token-wxyz"


class Hook:
    """A local HTTP server that records every POST: path, headers, JSON body."""

    def __init__(self):
        self.got: list[dict] = []
        self.status, self.reply = 200, b'{"ok": true}'
        hook = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                hook.got.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                 "body": json.loads(self.rfile.read(n) or b"null")})
                self.send_response(hook.status)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(hook.reply)

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def titles(self):
        return [g["body"].get("title") or g["body"].get("text") for g in self.got]


@pytest.fixture
def hook():
    h = Hook()
    yield h
    h.srv.shutdown()


class FakeSource:
    """A driver whose findings and error a test sets directly."""
    FIELDS: list = []

    def __init__(self):
        self.findings: list[dict] = []
        self.error = None

    def configured(self, cfg):
        return True

    def scan(self, cfg):
        return {"source": cfg["_id"], "findings": [dict(f) for f in self.findings],
                "counts": {}, "error": self.error, "scanned_at": "now", "configured": True}


def finding(key, label="port 8080 is open"):
    return {"key": f"fake:open:{key}", "type": "open", "label": label, "detail": "seen"}


@pytest.fixture
def env(make_app, monkeypatch, hook):
    """An app with one fake source and one ntfy channel pointing at `hook`."""
    def start():
        _, c = make_app(NETMAP_API_TOKEN="full-token")
        from app.sources import dynamic
        monkeypatch.setitem(dynamic.DRIVERS, "fake", {"mod": src, "label": "Fake", "hint": ""})
        return c

    src = FakeSource()
    c = start()
    from app import sources
    sources.create_instance("fake", "Fake", {})
    r = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "ntfy", "name": "phone",
        "fields": {"url": hook.url, "topic": "netmap", "link": "https://nm.example"}})
    assert r.status_code == 201, r.text
    return {"c": c, "src": src, "restart": start}


def scan_and_deliver():
    from app import notify, sources
    out = sources.scan("fake")
    notify.deliver()
    return out


# ---- what is news -------------------------------------------------------------------------
def test_the_same_finding_over_two_scans_is_sent_once(env, hook):
    scan_and_deliver()                      # the source's first scan ever: recorded, not sent
    env["src"].findings = [finding("a")]
    scan_and_deliver()
    scan_and_deliver()
    assert hook.titles() == ["Fake: port 8080 is open"]
    body = hook.got[0]["body"]
    assert body["topic"] == "netmap" and body["click"] == "https://nm.example/"

    env["src"].findings = []                # gone, then back: new again
    scan_and_deliver()
    env["src"].findings = [finding("a")]
    scan_and_deliver()
    assert len(hook.got) == 2


def test_what_was_true_before_anyone_listened_is_not_sent(env, hook):
    env["src"].findings = [finding("a"), finding("b")]
    scan_and_deliver()
    assert hook.got == []


def test_a_restart_sends_nothing_and_loses_nothing(env, hook):
    scan_and_deliver()
    env["src"].findings = [finding("a")]
    scan_and_deliver()
    assert len(hook.got) == 1

    env["restart"]()                        # same database, fresh process state
    scan_and_deliver()
    assert len(hook.got) == 1               # still true: not news
    env["src"].findings = [finding("a"), finding("b")]
    scan_and_deliver()
    assert len(hook.got) == 2               # new since the restart: news


def test_an_ignored_finding_is_not_sent(env, hook):
    scan_and_deliver()
    from app import db
    db.add_ignore("fake:open:a", "fake")
    env["src"].findings = [finding("a")]
    scan_and_deliver()
    assert hook.got == []


def test_a_source_that_stops_and_starts_answering(env, hook):
    scan_and_deliver()
    env["src"].error = "HTTP 401"
    scan_and_deliver()
    scan_and_deliver()
    env["src"].error = None
    scan_and_deliver()
    assert hook.titles() == ["Fake is not answering", "Fake is answering again"]
    assert hook.got[0]["body"]["priority"] == 4


def test_a_channel_hears_only_the_events_it_chose(env, hook):
    c = env["c"]
    cid = c.get("/api/notify/channels", headers=TOKEN).json()[0]["id"]
    assert c.put(f"/api/notify/channels/{cid}", headers=TOKEN,
                 json={"events": ["source"]}).status_code == 200
    scan_and_deliver()
    env["src"].findings = [finding("a")]
    scan_and_deliver()
    assert hook.got == []
    assert c.put(f"/api/notify/channels/{cid}", headers=TOKEN,
                 json={"events": ["nonsense"]}).status_code == 400


def test_removing_a_source_forgets_its_state(env, hook):
    scan_and_deliver()
    env["src"].findings = [finding("a")]
    scan_and_deliver()
    from app import notify, sources
    sources.delete_instance("fake")
    assert not any(k.endswith(":fake") for k in notify._load())


# ---- critical entries, over Telegram --------------------------------------------------------
def test_a_critical_entry_going_down_and_up_reaches_telegram(make_app, hook):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    r = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "telegram", "name": "chat", "events": ["entry"],
        "fields": {"token": BOT, "chat_id": "-1001", "thread_id": "7",
                   "api_url": hook.url}})
    assert r.status_code == 201, r.text

    lsn = socket.socket()
    lsn.bind(("127.0.0.1", 0))
    lsn.listen()
    port = lsn.getsockname()[1]
    from app import db, notify, status
    db.create_entry({"name": "NAS_1", "ip": "127.0.0.1", "ports": str(port),
                     "criticality": "critical", "monitor": True})
    db.create_entry({"name": "toy", "ip": "127.0.0.1", "ports": "1",
                     "criticality": "normal", "monitor": True})

    def sweep():
        asyncio.run(status.sweep())
        notify.deliver()

    sweep()                                 # up; the first sweep ever records only
    lsn.close()
    sweep()                                 # down
    sweep()                                 # still down: nothing new
    lsn = socket.socket()
    lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsn.bind(("127.0.0.1", port))
    lsn.listen()
    sweep()                                 # back
    lsn.close()

    assert [g["path"] for g in hook.got] == [f"/bot{BOT}/sendMessage"] * 2
    texts = [g["body"]["text"] for g in hook.got]
    assert texts[0].startswith("🔴 NAS_1 is not answering")   # plain text, "_" intact
    assert texts[1].startswith("🟢 NAS_1 is answering again")
    assert hook.got[0]["body"]["chat_id"] == "-1001"
    assert hook.got[0]["body"]["message_thread_id"] == 7
    assert "parse_mode" not in hook.got[0]["body"]


# ---- rate limit -------------------------------------------------------------------------------
def test_a_burst_collapses_into_and_n_more(env, hook):
    c = env["c"]
    cid = c.get("/api/notify/channels", headers=TOKEN).json()[0]["id"]
    c.put(f"/api/notify/channels/{cid}", headers=TOKEN, json={"fields": {"rate_limit": 3}})
    from app import notify
    for i in range(6):
        notify.emit({"kind": "finding", "key": f"k{i}", "title": f"t{i}", "detail": "",
                     "level": "warn", "path": "/", "ts": "now"})
    assert notify.deliver() == 3
    assert hook.titles() == ["t0", "t1", "and 4 more"]
    assert "t2; t3; t4; t5" in hook.got[2]["body"]["message"]

    notify.emit({"kind": "finding", "key": "k9", "title": "t9", "detail": "",
                 "level": "warn", "path": "/", "ts": "now"})
    assert notify.deliver() == 0            # over the limit: held, not dropped
    assert c.get("/api/notify/channels", headers=TOKEN).json()[0]["held"] == 1


# ---- secrets ----------------------------------------------------------------------------------
def test_a_secret_is_never_returned(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    r = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "telegram", "fields": {"token": BOT, "chat_id": "1"}})
    assert r.status_code == 201 and BOT not in r.text
    listed = c.get("/api/notify/channels", headers=TOKEN)
    assert BOT not in listed.text
    assert listed.json()[0]["secrets"]["token"] == {"set": True, "preview": "•" * 8 + "wxyz"}
    from app import db
    raw = db.conn().execute("SELECT config, secrets FROM notify_channels").fetchone()
    assert BOT not in raw["config"] and BOT not in raw["secrets"]
    audit = c.get("/api/audit", headers=TOKEN).text
    assert BOT not in audit


def test_a_blank_secret_on_save_keeps_the_stored_one(make_app, hook):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    cid = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "telegram", "fields": {"token": BOT, "chat_id": "1",
                                       "api_url": hook.url}}).json()["id"]
    r = c.put(f"/api/notify/channels/{cid}", headers=TOKEN,
              json={"fields": {"token": "", "chat_id": "2"}})
    assert r.status_code == 200, r.text
    assert c.post(f"/api/notify/channels/{cid}/test", headers=TOKEN).json()["ok"]
    assert hook.got[-1]["path"] == f"/bot{BOT}/sendMessage"
    assert hook.got[-1]["body"]["chat_id"] == "2"


def test_a_stored_secret_is_not_sent_to_a_new_address(make_app, hook):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    tg = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "telegram", "fields": {"token": BOT, "chat_id": "1"}}).json()["id"]
    r = c.put(f"/api/notify/channels/{tg}", headers=TOKEN,
              json={"fields": {"api_url": "https://evil.example"}})
    assert r.status_code == 400 and "Bot token" in r.json()["detail"]

    wh = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "webhook", "fields": {"url": hook.url + "/a", "token": "bearer-1"}}).json()["id"]
    r = c.put(f"/api/notify/channels/{wh}", headers=TOKEN,
              json={"fields": {"url": "https://evil.example/b"}})
    assert r.status_code == 400 and "Bearer token" in r.json()["detail"]
    r = c.put(f"/api/notify/channels/{wh}", headers=TOKEN,
              json={"fields": {"url": "https://other.example/b", "token": "bearer-2"}})
    assert r.status_code == 200


def test_urls_must_be_http(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    r = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "webhook", "fields": {"url": "file:///etc/passwd"}})
    assert r.status_code == 400
    r = c.post("/api/notify/channels", headers=TOKEN, json={"type": "gotify", "fields": {}})
    assert r.status_code == 400 and "required" in r.json()["detail"]


def test_secret_key_rotation_covers_channels(make_app):
    from cryptography.fernet import Fernet
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "telegram", "fields": {"token": BOT, "chat_id": "1"}})
    make_app(NETMAP_API_TOKEN="full-token", NETMAP_SECRET_KEY=Fernet.generate_key().decode())
    from app import crypto, db, sources
    r = sources.rotate_secrets()
    assert r["rotated"] == 1 and r["stored_key_removed"]
    assert crypto.decrypt(db.list_notify_channels()[0]["secrets"]["token"]) == BOT


# ---- failures -----------------------------------------------------------------------------------
def test_a_failed_delivery_does_not_break_the_scan(env, hook):
    hook.status, hook.reply = 500, b"{}"
    scan_and_deliver()
    env["src"].findings = [finding("a")]
    out = scan_and_deliver()
    assert out["error"] is None and len(out["findings"]) == 1
    row = env["c"].get("/api/notify/channels", headers=TOKEN).json()[0]
    assert row["error"] == "HTTP 500 Internal Server Error" and row["last_ok"] is None


def test_an_error_message_never_carries_the_token(make_app, hook):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    hook.status = 400
    hook.reply = json.dumps({"ok": False, "description": f"Bad Request: chat not found {BOT}"}).encode()
    cid = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "telegram", "fields": {"token": BOT, "chat_id": "1",
                                       "api_url": hook.url}}).json()["id"]
    r = c.post(f"/api/notify/channels/{cid}/test", headers=TOKEN).json()
    assert r["ok"] is False and r["error"].startswith("HTTP 400: Bad Request: chat not found")
    assert BOT not in json.dumps(r)
    assert BOT not in c.get("/api/notify/channels", headers=TOKEN).text


def test_unsaved_details_can_be_tested(make_app, hook):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    r = c.post("/api/notify/test", headers=TOKEN, json={
        "type": "webhook", "fields": {"url": hook.url + "/in", "token": "b-1"}}).json()
    assert r == {"ok": True, "error": None}
    got = hook.got[0]
    assert got["path"] == "/in" and got["headers"]["authorization"] == "Bearer b-1"
    assert set(got["body"]) == {"kind", "key", "title", "detail", "url", "ts",
                                "level", "version"}
    assert got["body"]["version"]


def test_a_short_secret_shows_no_characters_and_no_length():
    from app import crypto
    assert crypto.mask("abc123") == "•" * 8
    assert crypto.mask("a-rather-long-token-wxyz") == "•" * 8 + "wxyz"
    assert crypto.mask("") == ""


def test_a_telegram_topic_id_must_be_a_number(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    r = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "telegram", "fields": {"token": BOT, "chat_id": "1", "thread_id": "abc"}})
    assert r.status_code == 400 and "number" in r.json()["detail"]


def test_editing_a_channel_keeps_what_the_rate_limit_held(env, hook):
    c = env["c"]
    cid = c.get("/api/notify/channels", headers=TOKEN).json()[0]["id"]
    c.put(f"/api/notify/channels/{cid}", headers=TOKEN, json={"fields": {"rate_limit": 1}})
    from app import notify
    for i in range(3):
        notify.emit({"kind": "finding", "key": f"k{i}", "title": f"t{i}", "detail": "",
                     "level": "warn", "path": "/", "ts": "now"})
    notify.deliver()
    notify.emit({"kind": "finding", "key": "k9", "title": "t9", "detail": "",
                 "level": "warn", "path": "/", "ts": "now"})
    notify.deliver()
    assert c.get("/api/notify/channels", headers=TOKEN).json()[0]["held"] == 1
    c.put(f"/api/notify/channels/{cid}", headers=TOKEN, json={"name": "renamed"})
    assert c.get("/api/notify/channels", headers=TOKEN).json()[0]["held"] == 1
