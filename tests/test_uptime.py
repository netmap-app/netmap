"""Uptime per entry (app/uptime.py): 30 days from the stored transitions,
with unknown time - not monitored, no history yet, NetMap not running -
kept out of the figure, and where it is shown decided by a rule and a tag."""
import time

import pytest

TOKEN = {"authorization": "Bearer full-token"}
DAY = 86400
NOW = 1790000000.0


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


@pytest.fixture
def app(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    return c


def entry(**kw):
    from app import db
    return db.create_entry({"name": "x", "ip": "10.0.0.1", "ports": "22", **kw})


def obs(eid, t, up):
    from app import db
    db.conn().execute("INSERT INTO observations (entry_id, ts, up) VALUES (?,?,?)",
                      (eid, iso(t), None if up is None else int(up)))
    db.conn().commit()


def test_one_down_day_in_thirty(app):
    from app import uptime
    e = entry()
    obs(e["id"], NOW - 40 * DAY, True)              # before the window: it opens up
    obs(e["id"], NOW - 10 * DAY, False)
    obs(e["id"], NOW - 9 * DAY, True)
    u = uptime.compute(e["id"], NOW)
    assert u["percent"] == round(100 * 29 / 30, 2)
    assert u["down_s"] == DAY and u["since"] is None
    assert [s[2] for s in u["segments"]] == ["up", "down", "up"]


def test_unmonitored_time_is_unknown_not_up(app):
    from app import uptime
    e = entry()
    obs(e["id"], NOW - 40 * DAY, True)
    obs(e["id"], NOW - 20 * DAY, None)              # monitoring switched off
    obs(e["id"], NOW - 10 * DAY, False)             # on again, and down
    u = uptime.compute(e["id"], NOW)
    assert u["up_s"] == 10 * DAY and u["down_s"] == 10 * DAY and u["unknown_s"] == 10 * DAY
    assert u["percent"] == 50.0


def test_a_young_entry_says_since_when(app):
    from app import uptime
    e = entry()
    obs(e["id"], NOW - 5 * DAY, True)
    u = uptime.compute(e["id"], NOW)
    assert u["percent"] == 100.0 and u["since"] == iso(NOW - 5 * DAY)
    assert uptime.compute(entry(name="new")["id"], NOW)["percent"] is None      # no data


def test_netmap_not_running_is_unknown(app):
    from app import db, uptime
    e = entry()
    obs(e["id"], NOW - 40 * DAY, False)             # down, and stays down…
    db.set_setting(uptime.BEAT_KEY, iso(NOW - 3 * DAY))
    assert uptime.note_start(120, NOW) == {"from": iso(NOW - 3 * DAY), "to": iso(NOW)}
    u = uptime.compute(e["id"], NOW)
    assert u["down_s"] == 27 * DAY and u["unknown_s"] == 3 * DAY  # …but not while NetMap was off
    db.set_setting(uptime.BEAT_KEY, iso(NOW - 100))
    assert uptime.note_start(120, NOW) is None       # a normal restart is no gap


def test_the_sweep_leaves_a_heartbeat(app):
    import asyncio
    from app import db, status, uptime
    asyncio.run(status.sweep())
    assert db.get_setting(uptime.BEAT_KEY)


def test_where_it_is_shown(app):
    from app import uptime
    assert uptime.shown({"monitor": 1, "criticality": "critical"})
    # Not monitored: nothing to show, whatever the rule - unless a tag asks.
    assert not uptime.shown({"monitor": 0, "criticality": "critical"})
    assert uptime.shown({"monitor": 0, "tags": ["uptime:on"]})
    assert uptime.shown({"monitor": 1, "criticality": "important"})
    assert not uptime.shown({"monitor": 1, "criticality": "normal"})
    assert not uptime.shown({"monitor": 1, "criticality": "critical", "tags": ["uptime:off"]})
    assert uptime.shown({"monitor": 1, "criticality": "", "tags": ["Uptime:ON"]})
    r = app.put("/api/settings/uptime", headers=TOKEN,
                json={"kinds": ["vm"], "categories": ["Media"], "criticalities": []})
    assert r.status_code == 200 and r.json()["kinds"] == ["vm"]
    assert uptime.shown({"monitor": 1, "kind": "vm"}) and uptime.shown({"monitor": 1, "category": "Media"})
    assert not uptime.shown({"monitor": 1, "criticality": "critical"})
    assert app.put("/api/settings/uptime", headers=TOKEN, json={"kinds": "vm"}).status_code == 400


def test_the_api_carries_it_where_shown(app):
    shown = entry(name="router", criticality="critical")
    hidden = entry(name="toy", criticality="normal")
    obs(shown["id"], time.time() - 2 * DAY, True)
    obs(hidden["id"], time.time() - 2 * DAY, True)
    rows = {r["name"]: r for r in app.get("/api/entries", headers=TOKEN).json()}
    assert rows["router"]["uptime"] == 100.0 and rows["toy"]["uptime"] is None
    ctx = app.get(f"/api/entries/{hidden['id']}/context", headers=TOKEN).json()
    assert ctx["uptime"]["shown"] is False and ctx["uptime"]["percent"] == 100.0
