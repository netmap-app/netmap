"""Stale entries (app/stale.py, db.entry_seen): what confirms an entry, that
only once-confirmed entries go stale, what is left out, the backfill from
health-check history, and the one Overview note."""
import asyncio
import time

import pytest

TOKEN = {"authorization": "Bearer full-token"}
DAY = 86400


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


@pytest.fixture
def app(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    return c


def mk(**kw):
    from app import db
    return db.create_entry({"name": "x", **kw})


def seen_at(eid, t, how="test"):
    from app import db
    db.conn().execute("INSERT OR REPLACE INTO entry_seen VALUES (?,?,?)", (eid, iso(t), how))
    db.conn().commit()


# ---- what confirms an entry --------------------------------------------------------------------
def test_sightings_confirm_except_closed_ports_and_intent(app):
    from app import db
    a, b, c = mk(name="a"), mk(name="b"), mk(name="c")
    db.record_sightings("docker", [{"entry_id": a["id"], "fact": "container", "value": "running"}])
    db.record_sightings("ports", [{"entry_id": b["id"], "fact": "port:22", "value": "closed"}])
    db.record_sightings("netbox", [{"entry_id": c["id"], "fact": "intent", "value": "NetBox device c"}])
    seen = db.last_seen()
    assert seen[a["id"]]["how"] == "seen by docker"
    assert b["id"] not in seen and c["id"] not in seen


def test_presence_confirms_by_mac_or_a_machines_address(app):
    from app import db
    nas = mk(name="nas", ip="10.0.0.5", kind="hardware")
    svc = mk(name="svc", ip="10.0.0.5", kind="container")
    phone = mk(name="phone", mac="aa:bb:cc:00:00:07")
    db.record_presence("lan", [{"ip": "10.0.0.5", "mac": ""},
                               {"ip": "10.0.0.77", "mac": "AA:BB:CC:00:00:07"}])
    seen = db.last_seen()
    assert {nas["id"], phone["id"]} <= set(seen) and svc["id"] not in seen


def test_a_health_check_answering_confirms(app):
    import socket
    from app import db, status
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    try:
        e = mk(name="up", ip="127.0.0.1", ports=str(s.getsockname()[1]))
        asyncio.run(status.sweep())
        assert db.last_seen()[e["id"]]["how"] == "health check answered"
    finally:
        s.close()


# ---- what is stale -------------------------------------------------------------------------------
def test_only_once_confirmed_and_long_unseen_entries_are_stale(app):
    from app import stale
    now = time.time()
    old, recent, never, up = mk(name="old"), mk(name="recent"), mk(name="never"), mk(name="up")
    seen_at(old["id"], now - 20 * DAY)
    seen_at(recent["id"], now - 2 * DAY)
    seen_at(up["id"], now - 30 * DAY)
    from app import db
    rows = stale.stale(db.list_entries(), {up["id"]: {"up": True}})
    assert [r["name"] for r in rows] == ["old"]
    stale.set_days(1)
    assert {r["name"] for r in stale.stale(db.list_entries(), {})} == {"old", "recent", "up"}


def test_an_entry_a_source_reports_gone_is_left_out(app, monkeypatch):
    from app import db, sources, stale
    e = mk(name="dead container")
    seen_at(e["id"], time.time() - 40 * DAY)
    monkeypatch.setattr(sources, "names", lambda: ["docker"])
    monkeypatch.setattr(sources, "cached", lambda n: {"findings": [
        {"type": "gone", "entry": {"id": e["id"]}}]})
    assert stale.stale(db.list_entries(), {}) == []


def test_the_backfill_starts_from_when_the_check_stopped_answering(app):
    from app import db, stale
    dead, never_up, fine = mk(name="dead"), mk(name="never up"), mk(name="fine")
    rows = [(dead["id"], iso(time.time() - 60 * DAY), 1), (dead["id"], iso(time.time() - 50 * DAY), 0),
            (never_up["id"], iso(time.time() - 50 * DAY), 0),
            (fine["id"], iso(time.time() - 50 * DAY), 0), (fine["id"], iso(time.time() - 40 * DAY), 1)]
    db.conn().executemany("INSERT INTO observations (entry_id, ts, up) VALUES (?,?,?)", rows)
    db.conn().commit()
    assert stale.backfill() == 1
    seen = db.last_seen()
    assert set(seen) == {dead["id"]} and seen[dead["id"]]["last_seen"] == rows[1][1]
    assert stale.backfill() == 0                                      # once only
    assert [r["name"] for r in stale.stale(db.list_entries(), {})] == ["dead"]


def test_one_overview_note_with_the_entries(app):
    from app import overview
    a, b = mk(name="Old NAS"), mk(name="test-vm")
    seen_at(a["id"], time.time() - 30 * DAY, "seen by docker")
    seen_at(b["id"], time.time() - 20 * DAY)
    items = {i["key"]: i for i in overview.snapshot({})["attention"]}
    it = items["stale"]
    assert it["level"] == "note" and it["title"] == "2 entries nothing has seen for 14 days"
    assert it["detail"].startswith("Old NAS, test-vm")
    assert [x["name"] for x in it["entries"]] == ["Old NAS", "test-vm"]


def test_settings_and_the_card(app):
    assert app.get("/api/settings/stale", headers=TOKEN).json()["days"] == 14
    assert app.put("/api/settings/stale", headers=TOKEN, json={"days": 0}).status_code == 400
    assert app.put("/api/settings/stale", headers=TOKEN, json={"days": "x"}).status_code == 400
    assert app.put("/api/settings/stale", headers=TOKEN, json={"days": 30}).json()["days"] == 30
    e = mk(name="card")
    seen_at(e["id"], time.time() - DAY, "seen by unifi")
    ctx = app.get(f"/api/entries/{e['id']}/context", headers=TOKEN).json()
    assert ctx["last_seen"]["how"] == "seen by unifi"
