"""Summary notifications (app/digest.py): off by default; on a summary
channel an urgent event still goes at once and everything else waits in the
database until the chosen local hour, then goes as one message. Every target
is a local HTTP server; nothing leaves the machine."""
import datetime as dt
from zoneinfo import ZoneInfo

import pytest

from test_notify import TOKEN, hook  # noqa: F401  (fixture)


def msg(kind="finding", level="warn", title="port 8080 is open", key="k"):
    return {"kind": kind, "key": key, "title": title, "detail": "", "level": level,
            "path": "/", "ts": "now"}


def at(y, mo, d, h, mi=0, tz="Europe/Berlin"):
    return dt.datetime(y, mo, d, h, mi, tzinfo=ZoneInfo(tz)).timestamp()


@pytest.fixture
def app(make_app, hook):  # noqa: F811
    def start():
        _, c = make_app(NETMAP_API_TOKEN="full-token")
        return c
    c = start()
    r = c.put("/api/settings/timezone", headers=TOKEN, json={"timezone": "Europe/Berlin"})
    assert r.status_code == 200, r.text
    r = c.post("/api/notify/channels", headers=TOKEN, json={
        "type": "ntfy", "name": "phone", "fields": {"url": hook.url, "topic": "netmap"}})
    assert r.status_code == 201, r.text
    return {"c": c, "id": r.json()["id"], "restart": start}


def set_delivery(app, **d):
    r = app["c"].put(f"/api/notify/channels/{app['id']}", headers=TOKEN, json={"delivery": d})
    assert r.status_code == 200, r.text
    return r.json()


def test_a_new_channel_delivers_immediately(app, hook):  # noqa: F811
    from app import notify
    ch = app["c"].get("/api/notify/channels", headers=TOKEN).json()[0]
    assert ch["delivery"]["mode"] == "off" and ch["waiting"] == 0
    notify.emit(msg())
    notify.deliver()
    assert hook.titles() == ["port 8080 is open"]


def test_a_summary_holds_everything_but_urgent_events(app, hook):  # noqa: F811
    from app import digest, notify
    set_delivery(app, mode="daily", hour=8)
    notify.emit(msg())
    notify.emit(msg("entry", "critical", "NAS is not answering", "e"))
    notify.emit(msg("entry", "warn", "printer is not answering", "p"))
    notify.deliver()
    assert hook.titles() == ["NAS is not answering"]
    assert len(digest.held(app["id"])) == 2
    assert app["c"].get("/api/notify/channels", headers=TOKEN).json()[0]["waiting"] == 2


def test_an_urgent_kind_can_be_switched_off(app, hook):  # noqa: F811
    from app import digest, notify
    set_delivery(app, mode="daily", urgent=["source"])
    notify.emit(msg("entry", "critical", "NAS is not answering", "e"))
    notify.deliver()
    assert hook.got == [] and len(digest.held(app["id"])) == 1


def test_the_summary_goes_once_at_the_chosen_hour(app, hook):  # noqa: F811
    from app import digest, notify
    set_delivery(app, mode="daily", hour=8)
    digest.started(app["id"], at(2026, 9, 29, 7, 0))
    notify.emit(msg(title="a", key="a"))
    notify.emit(msg(title="b", key="b"))
    notify.emit(msg("cert", "warn", "nas.example expires in 5 days", "c"))

    assert digest.run(at(2026, 9, 29, 7, 59)) == []        # not yet
    due = digest.run(at(2026, 9, 29, 8, 1))
    assert len(due) == 1
    cid, m = due[0]
    assert cid == app["id"]
    assert m["title"] == "NetMap - daily summary: 3 events"
    assert "New findings (2): a; b" in m["detail"]
    assert "Certificates (1): nas.example expires in 5 days" in m["detail"]
    assert digest.held(app["id"]) == []
    assert digest.run(at(2026, 9, 29, 8, 30)) == []        # once per day
    notify._QUEUE.extend(due)
    notify.deliver()
    assert hook.titles() == ["NetMap - daily summary: 3 events"]


def test_nothing_held_means_no_message(app):
    from app import digest
    set_delivery(app, mode="daily", hour=8)
    digest.started(app["id"], at(2026, 9, 28, 9, 0))
    assert digest.run(at(2026, 9, 29, 8, 5)) == []


def test_the_hour_is_local_time(app):
    from app import digest, notify
    set_delivery(app, mode="daily", hour=8)
    digest.started(app["id"], at(2026, 9, 29, 5, 0))
    notify.emit(msg())
    # 08:00 in Berlin (CEST) is 06:00 UTC
    assert digest.run(at(2026, 9, 29, 6, 30, "UTC")) != []


def test_a_weekly_summary_waits_for_its_day(app):
    from app import digest, notify
    set_delivery(app, mode="weekly", hour=9, day=4)          # Friday
    digest.started(app["id"], at(2026, 9, 28, 12, 0))         # a Monday
    notify.emit(msg())
    assert digest.run(at(2026, 10, 1, 10, 0)) == []           # Thursday
    assert digest.run(at(2026, 10, 2, 8, 59)) == []           # Friday, too early
    (_, m), = digest.run(at(2026, 10, 2, 9, 0))
    assert m["title"] == "NetMap - weekly summary: 1 event"


def test_what_is_held_survives_a_restart(app):
    from app import notify
    set_delivery(app, mode="daily")
    notify.emit(msg())
    app["restart"]()
    from app import digest
    assert len(digest.held(app["id"])) == 1


def test_going_back_to_immediate_sends_what_was_held(app, hook):  # noqa: F811
    from app import digest, notify
    set_delivery(app, mode="daily")
    notify.emit(msg(title="a", key="a"))
    notify.deliver()
    assert hook.got == []
    set_delivery(app, mode="off")
    notify.deliver()
    assert hook.titles() == ["NetMap - daily summary: 1 event"]
    assert digest.held(app["id"]) == []


def test_bad_delivery_settings_are_refused(app):
    c = app["c"]
    for bad, word in [({"mode": "hourly"}, "delivery"), ({"mode": "daily", "hour": 24}, "hour"),
                      ({"mode": "weekly", "day": 7}, "day"), ({"urgent": ["finding"]}, "urgent")]:
        r = c.put(f"/api/notify/channels/{app['id']}", headers=TOKEN, json={"delivery": bad})
        assert r.status_code == 400 and word in r.json()["detail"], (bad, r.text)


def test_the_time_zone_must_be_real(app):
    c = app["c"]
    r = c.put("/api/settings/timezone", headers=TOKEN, json={"timezone": "Mars/Olympus"})
    assert r.status_code == 400 and "Europe/Berlin" in r.json()["detail"]
    assert c.get("/api/settings/timezone", headers=TOKEN).json()["timezone"] == "Europe/Berlin"


def test_deleting_a_channel_forgets_what_it_held(app):
    from app import db, digest, notify
    set_delivery(app, mode="daily")
    notify.emit(msg())
    assert app["c"].delete(f"/api/notify/channels/{app['id']}", headers=TOKEN).status_code in (200, 204)
    assert db.get_setting(f"digest_held:{app['id']}") is None
    assert digest.held(app["id"]) == []


def test_the_all_clear_of_an_urgent_event_is_urgent_too(app, hook):  # noqa: F811
    from app import digest, notify
    set_delivery(app, mode="daily")
    notify.sync("entry", "entry", {})       # the scope's first sight: recorded only
    notify.sync("entry", "entry", {"1": {"title": "NAS is not answering", "level": "critical"}})
    notify.sync("entry", "entry", {}, resolved=lambda k, s: {"title": "NAS is answering again"})
    notify.sync("entry", "entry", {"2": {"title": "printer is not answering", "level": "warn"}})
    notify.sync("entry", "entry", {}, resolved=lambda k, s: {"title": "printer is answering again"})
    notify.deliver()
    assert hook.titles() == ["NAS is not answering", "NAS is answering again"]
    assert [m["title"] for m in digest.held(app["id"])] == [
        "printer is not answering", "printer is answering again"]


def test_taking_the_summary_clears_exactly_what_it_sent(app):
    from app import digest, notify
    set_delivery(app, mode="daily")
    notify.emit(msg(title="a", key="a"))
    assert [m["title"] for m in digest.take(app["id"])] == ["a"]
    assert digest.held(app["id"]) == [] and digest.take(app["id"]) == []
