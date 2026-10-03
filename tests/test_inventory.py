"""Entries and the Overview: what the inventory refuses to store, and how the
control-room snapshot reports sources and exposure. See app/db.py and
app/overview.py."""
import os

import pytest

TOKEN = {"authorization": "Bearer full-token"}


@pytest.fixture
def api(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    return c


# ---- entries ----------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["javascript:alert(1)", " data:text/html,x", "vbscript:x",
                                 "ftp://files.example", "https://has space.example"])
def test_non_web_urls_are_refused(api, url):
    assert api.post("/api/entries", headers=TOKEN, json={"name": "x", "url": url}).status_code == 400


def test_web_urls_are_accepted(api):
    for url in ("https://netmap.example.org", "HTTP://192.168.10.15:8087/x"):
        assert api.post("/api/entries", headers=TOKEN, json={"name": url, "url": url}).status_code == 201


def test_update_refuses_bad_url_and_empty_name(api):
    eid = api.post("/api/entries", headers=TOKEN, json={"name": "ok"}).json()["id"]
    assert api.patch(f"/api/entries/{eid}", headers=TOKEN, json={"url": "javascript:x"}).status_code == 400
    assert api.patch(f"/api/entries/{eid}", headers=TOKEN, json={"name": "   "}).status_code == 400


def test_import_reports_bad_rows_instead_of_failing(api):
    r = api.post("/api/import?dry_run=true", headers=TOKEN, json={"entries": [
        {"name": "fine", "url": "https://ok.example"},
        {"name": "bad", "url": "javascript:x"}]})
    assert r.status_code == 200
    counts = r.json()["counts"]
    assert counts["create"] == 1 and counts["problems"] == 1


# ---- overview: sources ---------------------------------------------------------------------
@pytest.fixture
def ov(make_app):
    make_app(NETMAP_PORTSCAN="1")           # one configured source, never scanned
    from app import overview, sources
    return overview, sources


def attention(overview):
    return {i["key"]: i for i in overview.snapshot({})["attention"]}


def test_unscanned_source_is_pending_not_failing(ov):
    overview, sources = ov
    h = {x["source"]: x for x in sources.health()}["ports"]
    assert h["pending"] and not h["ok"]
    snap = overview.snapshot({})
    assert not [k for k in attention(overview) if k.startswith("source")]
    assert (snap["sources"]["ok"], snap["sources"]["total"]) == (0, 0)


def test_pending_after_first_pass_is_a_warning_by_label(ov):
    overview, sources = ov
    sources.FIRST_PASS_DONE = True
    item = attention(overview)["source-pending:ports"]
    assert item["level"] == "warn"
    assert item["title"] == "Open ports has not been scanned yet"


def test_failing_source_is_critical_by_label(ov):
    overview, sources = ov
    sources._mark("ports", "boom")
    item = attention(overview)["source:ports"]
    assert item["level"] == "critical" and item["title"] == "Open ports is not answering"


def test_summary_reports_scan_interval(ov):
    _, sources = ov
    assert sources.summary()["interval"] == sources.INTERVAL


# ---- overview: exposure ----------------------------------------------------------------------
def test_open_hostnames_marked_accepted_when_ignored(make_app):
    make_app()
    from app import db, overview
    a = db.create_entry({"name": "Plex"})["id"]
    b = db.create_entry({"name": "Mystery"})["id"]
    db.record_sightings("cloudflare", [
        {"entry_id": a, "fact": "hostname:plex.example.org", "value": "via tunnel; no Access"},
        {"entry_id": b, "fact": "hostname:new.example.org", "value": "via tunnel; no Access"}])
    db.add_ignore("cloudflare:access:plex.example.org", "cloudflare", reason="Public on purpose")

    no_access = overview.exposure()["no_access"]
    assert [n["host"] for n in no_access] == ["new.example.org", "plex.example.org"]  # unreviewed first
    new, plex = no_access
    assert not new["accepted"] and "reason" not in new
    assert plex["accepted"] and plex["reason"] == "Public on purpose"
    # The queue raises only the one nobody has decided about.
    keys = attention(overview)
    assert "open:new.example.org" in keys and "open:plex.example.org" not in keys


# ---- data directory ----------------------------------------------------------------------
@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anything")
def test_unwritable_data_dir_is_explained(make_app, tmp_path):
    make_app()
    from app import db
    assert db.unwritable_reason() is None
    os.chmod(db.DB_PATH, 0o444)
    try:
        why = db.unwritable_reason()
        assert why and f"uid {os.getuid()}" in why and "chown" in why
    finally:
        os.chmod(db.DB_PATH, 0o644)


# ---- search -------------------------------------------------------------------------------
def test_tag_filter_matches_whole_tags(make_app):
    make_app()
    from app import db
    db.create_entry({"name": "a", "tags": "ha"})
    db.create_entry({"name": "b", "tags": "alpha, ha-addon"})
    db.create_entry({"name": "c", "tags": "docker, HA"})
    assert sorted(e["name"] for e in db.list_entries(tag="ha")) == ["a", "c"]
    assert [e["name"] for e in db.list_entries(tag="ha-addon")] == ["b"]


def test_search_wildcards_are_literal(make_app):
    make_app()
    from app import db
    db.create_entry({"name": "plain"})
    db.create_entry({"name": "snake_case"})
    db.create_entry({"name": "100% cpu"})
    assert [e["name"] for e in db.list_entries("_")] == ["snake_case"]
    assert [e["name"] for e in db.list_entries("%")] == ["100% cpu"]
    assert len(db.list_entries("a")) == 3


# ---- transactions --------------------------------------------------------------------------
def test_failed_import_rolls_back_everything(api, monkeypatch):
    from app import db
    keep = api.post("/api/entries", headers=TOKEN, json={"name": "keep-me"}).json()["id"]
    before = (db.count(), len(db.audit(1000)))
    real = db.create_entry
    calls = {"n": 0}

    def flaky(data, actor="web"):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("disk on fire")
        return real(data, actor=actor)

    monkeypatch.setattr(db, "create_entry", flaky)
    r = api.post("/api/import?dry_run=false&mode=replace", headers=TOKEN,
                 json={"entries": [{"name": f"new-{i}"} for i in range(5)]})
    assert r.status_code == 500 and "rolled back" in r.json()["detail"]
    assert db.count() == before[0]                     # no new entries …
    assert db.get_entry(keep)                          # … and replace deleted nothing
    audit = db.audit(1000)
    assert len(audit) == before[1] + 1 and audit[0]["action"] == "import-failed"


def test_successful_import_commits(api):
    from app import db
    r = api.post("/api/import?dry_run=false", headers=TOKEN,
                 json={"entries": [{"name": "a"}, {"name": "b"}],
                       "edges": [{"src_name": "a", "dst_name": "b", "type": "runs_on"}]})
    assert r.status_code == 200 and r.json()["relations"]["links"] == 1
    assert {e["name"] for e in db.list_entries()} >= {"a", "b"}


def test_transactions_nest_and_roll_back_together(make_app):
    make_app()
    from app import db
    with pytest.raises(RuntimeError):
        with db.transaction():
            db.create_entry({"name": "outer"})
            with db.transaction():
                db.create_entry({"name": "inner"})
            raise RuntimeError("boom")
    assert db.count() == 0
    with db.transaction():
        db.create_entry({"name": "kept"})
    assert db.count() == 1


def test_derive_links_is_atomic(make_app, monkeypatch):
    make_app()
    from app import db, links
    host = db.create_entry({"name": "Host"})["id"]
    db.create_entry({"name": "App", "host": "Host"})
    links.apply()
    assert len(db.all_edges()) == 1
    monkeypatch.setattr(db, "link", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError):
        links.apply()
    assert len(db.all_edges()) == 1                    # the old links survived


def test_service_context_same_for_rest_and_mcp(api):
    from app import main
    eid = api.post("/api/entries", headers=TOKEN, json={"name": "svc"}).json()["id"]
    r = api.get(f"/api/entries/{eid}/context", headers=TOKEN)
    assert r.status_code == 200
    assert r.json().keys() == main.service_context(eid).keys()
    assert api.get("/api/entries/99999/context", headers=TOKEN).status_code == 404


# ---- change log --------------------------------------------------------------------------
def test_sign_ins_hidden_from_changes_unless_asked(api):
    from app import db
    db.log("admin", "login", None, "admin", {"client": "x"})
    api.post("/api/entries", headers=TOKEN, json={"name": "real-change"})
    actions = [r["action"] for r in api.get("/api/audit", headers=TOKEN).json()]
    assert "login" not in actions and "create" in actions
    actions = [r["action"] for r in api.get("/api/audit?logins=1", headers=TOKEN).json()]
    assert "login" in actions


# ---- entry explanation -------------------------------------------------------------------
def test_backup_and_credential_gaps_skip_things_that_hold_neither(make_app):
    make_app()
    from app import db, explain, sources
    # Which category holds phones is the inventory's own naming: the port
    # scan's skip list says so.
    sources.create_instance("ports", "Open ports", {"skip": "Client / IoT Devices"})
    def gaps(data):
        d = explain.explain(db.create_entry(data)["id"], {})
        blind = next((s for s in d["sections"] if s["key"] == "blind"), None)
        return " ".join([blind["text"]] + blind["items"]) if blind else ""
    phone = gaps({"name": "iPhone", "category": "Client / IoT Devices", "kind": "hardware"})
    rule = gaps({"name": "Port forward — X", "kind": "rule"})
    server = gaps({"name": "Some service", "category": "Media", "kind": "container"})
    for g in (phone, rule):
        assert "backed up" not in g and "credentials" not in g
    assert "backed up" in server and "credentials" in server


def test_criticality_is_one_of_four_and_old_spellings_are_normalised(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    h = {"authorization": "Bearer full-token"}
    r = c.post("/api/entries", headers=h, json={"name": "a", "criticality": " Critical "})
    assert r.status_code == 201 and r.json()["criticality"] == "critical"
    r = c.post("/api/entries", headers=h, json={"name": "b", "criticality": "urgent"})
    assert r.status_code == 400 and "criticality" in r.json()["detail"]
    from app import db
    db.conn().execute("UPDATE entries SET criticality='Important' WHERE name='a'")
    db.conn().commit()
    db.init()
    assert db.list_entries()[0]["criticality"] == "important"


# ---- the Overview groups what is down at one address ----------------------------------------
def test_entries_down_at_one_address_are_one_item_with_chips(make_app):
    make_app()
    from app import db, overview
    mk = lambda name, ip, crit="": db.create_entry(                              # noqa: E731
        {"name": name, "ip": ip, "ports": "80", "monitor": True, "criticality": crit})
    a, b, c = mk("Alpha", "10.0.0.5", "critical"), mk("Beta", "10.0.0.5"), mk("Gamma", "10.0.0.5")
    lone = mk("Lone", "10.0.0.9")
    cache = {e["id"]: {"up": False, "target": f"{e['ip']}:80"} for e in (a, b, c, lone)}
    items = overview.snapshot(cache)["attention"]
    down = [i for i in items if i["key"].startswith("down:")]
    assert len(down) == 2
    group = next(i for i in down if i["key"] == "down:@10.0.0.5")
    assert group["level"] == "critical" and group["title"] == "3 entries at 10.0.0.5 are not answering"
    assert [x["name"] for x in group["entries"]] == ["Alpha", "Beta", "Gamma"]   # critical first
    assert "Alpha" in group["detail"]
    # The widest group first among the same level.
    w1, w2 = mk("W1", "10.0.0.7"), mk("W2", "10.0.0.7")
    cache.update({w1["id"]: {"up": False}, w2["id"]: {"up": False}})
    order = [i["key"] for i in overview.snapshot(cache)["attention"] if i["key"].startswith("down:@")]
    assert order == ["down:@10.0.0.5", "down:@10.0.0.7"]
    cache.pop(w1["id"]); cache.pop(w2["id"])
    single = next(i for i in down if i["key"] == f"down:{lone['id']}")
    assert single["title"] == "Lone is not answering" and single["level"] == "warn"
    # A different set of entries is a different item for a dismissal.
    fp = group["fingerprint"]
    cache[c["id"]] = {"up": True}
    d = mk("Delta", "10.0.0.5"); cache[d["id"]] = {"up": False}
    again = next(i for i in overview.snapshot(cache)["attention"] if i["key"] == "down:@10.0.0.5")
    assert again["title"] == group["title"] and again["fingerprint"] != fp


def test_the_explanation_names_what_can_see_exposure(make_app):
    make_app()
    from app import db, explain
    e = db.create_entry({"name": "Thing", "kind": "container"})
    x = explain.explain(e["id"], {})
    what = next(s for s in x["sections"] if s["key"] == "what")
    assert "is a container" in what["text"]
    exp = next(s for s in x["sections"] if s["key"] == "exposure")
    assert "No firewall, proxy or tunnel source is added" in exp["text"]
    assert "eight" not in explain.as_text(x)
    o = db.create_entry({"name": "Other", "kind": "otter"})
    assert "is an otter" in next(s for s in explain.explain(o["id"], {})["sections"]
                                 if s["key"] == "what")["text"]


def test_not_verified_names_every_entry_and_gives_their_ids(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    ids = [c.post("/api/entries", headers=TOKEN, json={
        "name": f"e{i}", "category": "Network", "verified": False}).json()["id"] for i in range(14)]
    ov = c.get("/api/overview", headers=TOKEN).json()
    (it,) = [x for x in ov["attention"] if x["key"] == "unverified"]
    assert len(it["entries"]) == 12 and it["more"] == 2 and sorted(it["verify"]) == sorted(ids)
    assert ov["verdict"].startswith(f"{len(ov['attention'])} thing")
    if len(ov["attention"]) == 1:
        assert "1 thing wants attention" in ov["verdict"]
