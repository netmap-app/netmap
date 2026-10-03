"""When a source counts as stale: a fixed number of hours (default 5),
set in Settings › Sources and sent with the summary the chips read."""

TOKEN = {"authorization": "Bearer full-token"}


def test_stale_hours_default_set_and_bounds(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    assert c.get("/api/discovery/summary", headers=TOKEN).json()["stale_hours"] == 5
    r = c.get("/api/settings/scan", headers=TOKEN).json()
    assert r["stale_hours"] == 5 and r["stale_default"] == 5
    r = c.put("/api/settings/scan", headers=TOKEN, json={"stale_hours": 12})
    assert r.status_code == 200 and r.json()["stale_hours"] == 12
    assert c.get("/api/discovery/summary", headers=TOKEN).json()["stale_hours"] == 12
    for bad in (0, 721, "x"):
        r = c.put("/api/settings/scan", headers=TOKEN, json={"stale_hours": bad})
        assert r.status_code == 400, bad
    assert c.put("/api/settings/scan", headers=TOKEN, json={}).status_code == 400
    # the interval alone still works, and leaves the stale hours alone
    r = c.put("/api/settings/scan", headers=TOKEN, json={"interval": 3600})
    assert r.status_code == 200 and r.json()["stale_hours"] == 12
