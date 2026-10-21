"""An entry counts as down only after N failed checks in a row (a setting,
default 2); one good answer brings it back up at once. The Overview and the
notifications read the same state, so a single blip reaches neither."""
import asyncio

TOKEN = {"authorization": "Bearer full-token"}


def _run(status, e, results):
    """Feed check_entry a sequence of probe results; return the states it kept."""
    seq = iter(results)

    async def fake(entry):
        up = next(seq)
        return {"up": up, "latency_ms": 1 if up else None, "checked_at": "now",
                "target": "10.0.0.9:80", "check": "tcp", "summary": "probe"}
    status.run_check, real = fake, status.run_check
    try:
        return [asyncio.run(status.check_entry(e))["up"] for _ in results]
    finally:
        status.run_check = real


def _entry(db):
    return db.create_entry({"name": "Wiki", "ip": "10.0.0.9", "ports": "80", "monitor": True,
                            "criticality": "critical"})


def test_default_is_two_failures_and_up_is_immediate(make_app):
    make_app()
    from app import db, status
    e = _entry(db)
    assert status.down_after() == 2
    states = _run(status, e, [True, False, False, False, True, False, True])
    assert states == [True, True, False, False, True, True, True]
    ups = [o["up"] for o in reversed(db.observations(e["id"]))]
    assert ups == [True, False, True]                       # transitions only, no blips


def test_held_result_says_how_many_checks_failed(make_app):
    make_app()
    from app import db, status
    e = _entry(db)
    _run(status, e, [True, False])
    st = status.CACHE[e["id"]]
    assert st["up"] is True and (st["failing"], st["failing_of"]) == (1, 2)
    assert "failed 1 of 2 checks before it counts as down" in st["summary"]


def test_threshold_is_a_setting(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import db, status
    r = c.get("/api/settings/checks", headers=TOKEN).json()
    assert (r["down_after"], r["down_after_default"]) == (2, 2)
    r = c.put("/api/settings/checks", headers=TOKEN, json={"down_after": 3})
    assert r.status_code == 200 and r.json()["down_after"] == 3
    assert r.json()["tls_warn_days"] == status.TLS_WARN_DEFAULT       # left alone
    for bad in (0, 11, "x"):
        assert c.put("/api/settings/checks", headers=TOKEN, json={"down_after": bad}).status_code == 400
    assert c.put("/api/settings/checks", headers=TOKEN, json={}).status_code == 400
    e = _entry(db)
    assert _run(status, e, [True, False, False, False]) == [True, True, True, False]
    c.put("/api/settings/checks", headers=TOKEN, json={"down_after": 1})
    e2 = db.create_entry({"name": "Other", "ip": "10.0.0.10", "ports": "80", "monitor": True})
    assert _run(status, e2, [True, False]) == [True, False]          # 1 = act at once
    audit = c.get("/api/audit?limit=5", headers=TOKEN).json()
    assert any(a["name"] == "down after failed checks" for a in audit)


def test_a_restart_does_not_restart_the_count_for_something_already_down(make_app):
    """After a restart the cache is empty; an entry whose last stored state is
    down stays down on its first failure instead of being held as unknown."""
    make_app()
    from app import db, status
    e = _entry(db)
    _run(status, e, [True, False, False])
    status.CACHE.clear()
    status.FAILS.clear()
    assert _run(status, e, [False]) == [False]


def test_a_new_entry_is_not_known_until_the_threshold(make_app):
    make_app()
    from app import db, status
    e = _entry(db)
    assert _run(status, e, [False, False]) == [None, False]
    assert [o["up"] for o in db.observations(e["id"])] == [False]


def test_a_single_failure_sends_no_notification(make_app):
    make_app()
    from app import db, notify, status
    e = _entry(db)
    events = []
    notify.emit, real = (lambda msg: events.append(msg)), notify.emit
    try:
        for up in (True, False):
            _run(status, e, [up])
            notify.after_sweep([db.get_entry(e["id"])], status.CACHE)
        assert not [m for m in events if "not answering" in m.get("title", "")]
        _run(status, e, [False])
        notify.after_sweep([db.get_entry(e["id"])], status.CACHE)
        assert [m for m in events if "not answering" in m.get("title", "")]
    finally:
        notify.emit = real


def test_a_held_failure_is_not_counted_as_an_answer(make_app):
    """The sweep marks entries whose check answered as seen (app/stale.py);
    one held as up while its failure is counted did not answer."""
    make_app()
    from app import db, status
    e = _entry(db)
    confirmed = []
    db_confirm, db.confirm = db.confirm, (lambda ids, why: confirmed.append(list(ids)))
    seq = iter([True, False])

    async def fake(entry):
        up = next(seq)
        return {"up": up, "latency_ms": None, "checked_at": "now", "target": "t",
                "check": "tcp", "summary": "probe"}
    real, status.run_check = status.run_check, fake
    db_list, db.list_entries = db.list_entries, (lambda *a, **k: [db.get_entry(e["id"])])
    try:
        asyncio.run(status.sweep())
        asyncio.run(status.sweep())
    finally:
        status.run_check, db.confirm, db.list_entries = real, db_confirm, db_list
    assert confirmed[0] == [e["id"]] and confirmed[1] == []
