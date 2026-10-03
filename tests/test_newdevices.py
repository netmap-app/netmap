"""New on the network (app/newdevices.py, db.presence_seen): first seen
survives rescans, a device is new once however many sources see it, a claim
by an entry ends it, randomised MACs stay out unless asked for, a source's
first report is a baseline, and old history is purged."""
import pytest

TOKEN = {"authorization": "Bearer full-token"}
SYNOLOGY = "00:11:32:00:00:01"
PHONE = "72:4e:46:96:69:8e"               # locally administered: randomised


class Seer:
    """A driver that records whatever presence rows a test gives it."""
    FIELDS: list = []

    def __init__(self):
        self.rows: list[dict] = []

    def configured(self, cfg):
        return True

    def scan(self, cfg):
        from app import db
        db.record_presence(cfg["_id"], self.rows)
        return {"findings": [], "counts": {}, "error": None}


@pytest.fixture
def env(make_app, monkeypatch):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import sources
    from app.sources import dynamic
    a, b = Seer(), Seer()
    monkeypatch.setitem(dynamic.DRIVERS, "seera", {"mod": a, "label": "A", "hint": ""})
    monkeypatch.setitem(dynamic.DRIVERS, "seerb", {"mod": b, "label": "B", "hint": ""})
    sources.create_instance("seera", "A", {})
    sources.create_instance("seerb", "B", {})
    # The first report of each is the baseline; start from an empty network.
    sources.scan("seera")
    sources.scan("seerb")
    return {"c": c, "a": a, "b": b}


def new(source: str) -> list[dict]:
    from app import sources
    return [f for f in sources.scan(source)["findings"] if f["type"] == "new-device"]


def test_first_seen_survives_rescans(make_app):
    make_app()
    from app import db
    db.record_presence("x", [{"ip": "10.0.0.5", "mac": SYNOLOGY, "label": ""}])
    db.conn().execute("UPDATE presence_seen SET first_seen='2026-01-01T00:00:00Z', "
                      "last_seen='2026-01-01T00:00:00Z'")
    db.record_presence("x", [{"ip": "10.0.0.6", "mac": SYNOLOGY, "label": "nas"}])
    db.record_presence("x", [{"ip": "10.0.0.6", "mac": SYNOLOGY, "label": ""}])
    (h,) = db.presence_history()
    assert h["first_seen"] == "2026-01-01T00:00:00Z" and h["last_seen"] > h["first_seen"]
    assert h["last_ip"] == "10.0.0.6" and h["label"] == "nas"    # a blank name keeps the last
    assert h["key"] == SYNOLOGY and h["baseline"] == 1


def test_vendor_lookup_and_randomised_macs():
    from app import oui
    assert oui.vendor(SYNOLOGY) == "Synology Incorporated"
    assert oui.vendor("00-11-32-AA-BB-CC") == "Synology Incorporated"
    assert oui.randomised(PHONE) and oui.vendor(PHONE) == ""
    assert not oui.randomised(SYNOLOGY)
    assert oui.vendor("not a mac") == "" and oui.vendor("") == ""


def test_a_new_device_is_one_finding_until_an_entry_claims_it(env):
    env["a"].rows = [{"ip": "10.0.0.5", "mac": SYNOLOGY, "label": "nas01"}]
    env["b"].rows = [{"ip": "10.0.0.5", "mac": SYNOLOGY, "label": ""},
                     {"ip": "10.0.0.5", "mac": "", "label": "nas01.lan"}]   # no MAC here
    (f,) = new("seera")
    assert new("seerb") == []                          # seen first by A: A reports it
    assert f["key"] == f"seera:new:{SYNOLOGY}" and "nas01" in f["label"]
    assert "Synology Incorporated" in f["detail"]
    assert f["draft"]["mac"] == SYNOLOGY and f["draft"]["ip"] == "10.0.0.5"
    assert f["draft"]["category"] == "Uncategorised"
    assert len(new("seera")) == 1                      # not again and again

    from app import db
    db.create_entry({"name": "NAS", "ip": "10.0.0.99", "mac": SYNOLOGY.upper()})
    assert new("seera") == []


def test_randomised_macs_are_left_out_unless_asked_for(env):
    env["a"].rows = [{"ip": "10.0.0.7", "mac": PHONE, "label": "iPhone"}]
    assert new("seera") == []
    r = env["c"].put("/api/settings/newdevices", headers=TOKEN, json={"include_random": True})
    assert r.status_code == 200 and r.json()["include_random"] is True
    (f,) = new("seera")
    assert "randomised MAC" in f["detail"]


def test_a_sources_first_report_is_the_baseline(make_app, monkeypatch):
    make_app()
    from app import sources
    from app.sources import dynamic
    s = Seer()
    s.rows = [{"ip": "10.0.0.8", "mac": SYNOLOGY, "label": ""}]
    monkeypatch.setitem(dynamic.DRIVERS, "seer", {"mod": s, "label": "S", "hint": ""})
    sources.create_instance("seer", "S", {})
    assert new("seer") == []                           # already there
    s.rows.append({"ip": "10.0.0.9", "mac": "00:11:32:00:00:09", "label": ""})
    assert [f["draft"]["ip"] for f in new("seer")] == ["10.0.0.9"]


def test_only_within_the_window(env):
    from app import db
    env["a"].rows = [{"ip": "10.0.0.5", "mac": SYNOLOGY, "label": ""}]
    assert len(new("seera")) == 1
    db.conn().execute("UPDATE presence_seen SET first_seen='2026-01-01T00:00:00Z'")
    db.conn().commit()
    assert new("seera") == []


def test_an_ignored_new_device_stays_quiet(env):
    from app import db
    env["a"].rows = [{"ip": "10.0.0.5", "mac": SYNOLOGY, "label": ""}]
    db.add_ignore(f"seera:new:{SYNOLOGY}", "seera")
    assert new("seera") == []


def test_old_history_is_purged(make_app):
    make_app()
    from app import db, newdevices
    db.record_presence("x", [{"ip": "10.0.0.5", "mac": SYNOLOGY, "label": ""},
                             {"ip": "10.0.0.6", "mac": "", "label": ""}])
    db.conn().execute("UPDATE presence_seen SET last_seen='2020-01-01T00:00:00Z' "
                      "WHERE key=?", (SYNOLOGY,))
    db.conn().commit()
    assert newdevices.purge() == 1
    assert [h["key"] for h in db.presence_history()] == ["ip:10.0.0.6"]


def test_settings_have_bounds(env):
    c = env["c"]
    assert c.get("/api/settings/newdevices", headers=TOKEN).json()["days"] == 7
    assert c.put("/api/settings/newdevices", headers=TOKEN, json={"days": 0}).status_code == 400
    assert c.put("/api/settings/newdevices", headers=TOKEN, json={"keep_days": 3}).status_code == 400
    assert c.put("/api/settings/newdevices", headers=TOKEN, json={"days": "x"}).status_code == 400
    r = c.put("/api/settings/newdevices", headers=TOKEN, json={"days": 14, "keep_days": 30})
    assert r.json()["days"] == 14 and r.json()["keep_days"] == 30


def test_the_map_gets_first_seen_and_vendor(env):
    env["a"].rows = [{"ip": "10.0.0.5", "mac": SYNOLOGY, "label": "nas01"},
                     {"ip": "10.0.0.7", "mac": PHONE, "label": ""}]
    new("seera")
    rows = {r["ip"]: r for r in env["c"].get("/api/presence", headers=TOKEN).json()["presence"]}
    assert rows["10.0.0.5"]["vendor"] == "Synology Incorporated"
    assert rows["10.0.0.5"]["first_seen"] and rows["10.0.0.5"]["last_seen"]
    assert rows["10.0.0.7"]["randomised"] is True and rows["10.0.0.7"]["vendor"] == ""
