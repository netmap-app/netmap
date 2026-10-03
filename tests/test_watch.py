"""Watching a device (app/watch.py): it leaves the new-device findings while
watched, keeps a note, says when it comes back, is dropped after 90 days
unseen, ends when an entry claims it, and Ignore ignores its finding."""
import time

import pytest

from test_newdevices import SYNOLOGY, TOKEN, Seer, new  # noqa: F401


@pytest.fixture
def env(make_app, monkeypatch):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import notify, sources
    from app.sources import dynamic
    a = Seer()
    monkeypatch.setitem(dynamic.DRIVERS, "seera", {"mod": a, "label": "A", "hint": ""})
    sources.create_instance("seera", "A", {})
    sources.scan("seera")                           # the baseline: an empty network
    sent: list[dict] = []
    monkeypatch.setattr(notify, "emit",
                        lambda m: sent.append(m) if m["kind"] == "watch" else None)
    a.rows = [{"ip": "10.0.0.5", "mac": SYNOLOGY, "label": "nas01"}]
    (f,) = new("seera")
    return {"c": c, "a": a, "finding": f, "sent": sent}


def watch_it(env, note=""):
    r = env["c"].post("/api/watch", headers=TOKEN,
                      json={"key": env["finding"]["key"], "note": note})
    assert r.status_code == 201, r.text
    return r.json()


def test_watching_takes_it_out_of_the_findings(env):
    w = watch_it(env, "in the cupboard?")
    assert w["key"] == SYNOLOGY and w["online"] and w["ips"] == ["10.0.0.5"]
    assert w["name"] == "nas01" and w["vendor"] == "Synology Incorporated"
    assert w["sources"] == ["seera"] and w["note"] == "in the cupboard?"
    assert new("seera") == []
    (row,) = env["c"].get("/api/watch", headers=TOKEN).json()["watching"]
    assert row["key"] == SYNOLOGY and row["finding"] == env["finding"]["key"]
    assert env["sent"] == []                         # on the network when watched: not news


def test_stop_watching_brings_the_finding_back(env):
    watch_it(env)
    r = env["c"].delete("/api/watch", headers=TOKEN, params={"key": SYNOLOGY})
    assert r.status_code == 200
    assert [f["key"] for f in new("seera")] == [env["finding"]["key"]]
    assert env["c"].delete("/api/watch", headers=TOKEN,
                           params={"key": SYNOLOGY}).status_code == 404


def test_ignore_from_watching_ignores_the_finding(env):
    from app import db
    watch_it(env)
    r = env["c"].delete("/api/watch", headers=TOKEN, params={"key": SYNOLOGY, "ignore": True})
    assert r.status_code == 200 and r.json()["ignored"]
    assert env["finding"]["key"] in db.ignores()
    assert new("seera") == [] and env["c"].get("/api/watch", headers=TOKEN).json()["watching"] == []


def test_the_note_is_kept_and_bounded(env):
    watch_it(env)
    r = env["c"].patch("/api/watch", headers=TOKEN, json={"key": SYNOLOGY, "note": "  printer? "})
    assert r.status_code == 200 and r.json()["note"] == "printer?"
    r = env["c"].patch("/api/watch", headers=TOKEN, json={"key": SYNOLOGY, "note": "x" * 501})
    assert r.status_code == 400
    r = env["c"].patch("/api/watch", headers=TOKEN, json={"key": "aa:bb", "note": ""})
    assert r.status_code == 404


def test_an_unknown_device_cannot_be_watched(env):
    r = env["c"].post("/api/watch", headers=TOKEN, json={"key": "seera:new:00:00:00:00:00:01"})
    assert r.status_code == 400 and "not seen" in r.json()["detail"]


def test_coming_back_is_news_once(env):
    from app import sources
    watch_it(env, "the box by the TV")
    env["a"].rows = []
    sources.scan("seera")                            # gone
    assert env["sent"] == []
    assert env["c"].get("/api/watch", headers=TOKEN).json()["watching"][0]["online"] is False
    env["a"].rows = [{"ip": "10.0.0.9", "mac": SYNOLOGY, "label": ""}]
    sources.scan("seera")                            # back, at another address
    sources.scan("seera")                            # still there: no second message
    (m,) = env["sent"]
    assert m["kind"] == "watch" and "back on the network at 10.0.0.9" in m["title"]
    assert "the box by the TV" in m["detail"]


def test_dropped_after_90_days_unseen(env):
    from app import db, sources, watch
    watch_it(env)
    env["a"].rows = []
    sources.scan("seera")
    assert watch.check(time.time() + 89 * 86400)["dropped"] == []
    assert watch.check(time.time() + 91 * 86400)["dropped"] == [SYNOLOGY]
    (m,) = env["sent"]
    assert m["kind"] == "watch" and "not seen for 90 days" in m["title"]
    assert watch.listing() == []
    assert db.conn().execute("SELECT COUNT(*) FROM audit WHERE action='unwatch'").fetchone()[0] == 1


def test_an_entry_claiming_it_ends_the_watch(env):
    from app import sources
    watch_it(env)
    r = env["c"].post("/api/entries", headers=TOKEN, json={
        "name": "NAS", "category": "Storage", "ip": "10.0.0.5", "mac": SYNOLOGY.upper()})
    assert r.status_code == 201, r.text
    sources.scan("seera")
    assert env["c"].get("/api/watch", headers=TOKEN).json()["watching"] == []
    assert env["sent"] == []


def test_watch_is_a_notification_event(env):
    from app import notify
    assert "watch" in notify.EVENTS
    r = env["c"].post("/api/notify/channels", headers=TOKEN, json={
        "type": "ntfy", "name": "p", "fields": {"url": "http://127.0.0.1:9", "topic": "t"}})
    assert "watch" in r.json()["events"]
