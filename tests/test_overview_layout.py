"""The Overview's cards: which show and in what order, one layout for the
instance. The status strip is not in the list and cannot be hidden."""
import json

TOKEN = {"authorization": "Bearer full-token"}
DEFAULT = ["exposure", "hardware", "categories", "quicklinks", "changes", "addresses"]


def _ids(r):
    return [c["id"] for c in r.json()["cards"]]


def test_default_layout_shows_every_card(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    r = c.get("/api/settings/overview", headers=TOKEN)
    assert _ids(r) == DEFAULT
    assert all(x["show"] and x["label"] for x in r.json()["cards"])


def test_order_and_visibility_are_saved_and_logged(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    cards = [{"id": i, "show": i != "addresses"} for i in reversed(DEFAULT)]
    r = c.put("/api/settings/overview", headers=TOKEN, json={"cards": cards})
    assert r.status_code == 200 and _ids(r) == list(reversed(DEFAULT))
    got = c.get("/api/settings/overview", headers=TOKEN).json()["cards"]
    assert [x["show"] for x in got] == [False, True, True, True, True, True]
    audit = c.get("/api/audit?limit=5", headers=TOKEN).json()
    assert any(a["action"] == "setting" and a["name"] == "overview layout" for a in audit)


def test_bad_layouts_are_refused(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    for cards in ([{"id": "nope", "show": True}],
                  [{"id": "changes", "show": True}, {"id": "changes", "show": False}],
                  [{"id": "changes", "show": "yes"}],
                  [{"id": "status", "show": False}],
                  "changes"):
        r = c.put("/api/settings/overview", headers=TOKEN, json={"cards": cards})
        assert r.status_code == 400, cards
    assert _ids(c.get("/api/settings/overview", headers=TOKEN)) == DEFAULT


def test_a_card_missing_from_the_saved_layout_appears_after_its_default_neighbour(make_app):
    """A card added in a later release is shown, next to the card it follows
    by default, without anyone saving the layout again."""
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import db
    db.set_setting("overview_layout", json.dumps(
        [{"id": "addresses", "show": True}, {"id": "exposure", "show": False},
         {"id": "categories", "show": True}, {"id": "quicklinks", "show": True}]))
    got = c.get("/api/settings/overview", headers=TOKEN).json()["cards"]
    assert [x["id"] for x in got] == ["addresses", "exposure", "hardware", "categories",
                                      "quicklinks", "changes"]
    assert [x["show"] for x in got] == [True, False, True, True, True, True]


def test_reset_restores_the_default(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    c.put("/api/settings/overview", headers=TOKEN,
          json={"cards": [{"id": "changes", "show": False}]})
    r = c.put("/api/settings/overview", headers=TOKEN, json={"reset": True})
    assert _ids(r) == DEFAULT and all(x["show"] for x in r.json()["cards"])


def test_summary_and_overview_carry_the_next_scan(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    assert "next_scan" in c.get("/api/discovery/summary", headers=TOKEN).json()
    assert "next_scan" in c.get("/api/overview", headers=TOKEN).json()["sources"]


def test_inventory_filters_by_exact_ip(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    for name, ip in (("One", "10.0.0.1"), ("Fifteen", "10.0.0.15"), ("Also one", " 10.0.0.1 ")):
        c.post("/api/entries", headers=TOKEN, json={"name": name, "ip": ip})
    names = sorted(e["name"] for e in c.get("/api/entries?ip=10.0.0.1", headers=TOKEN).json())
    assert names == ["Also one", "One"]
