"""Several sources of one type: ids, finding keys and ignores per instance,
"missing" findings a sibling can answer, and what removing a source takes with
it. See app/sources/__init__.py and dynamic.py."""
import pytest

TOKEN = {"authorization": "Bearer full-token"}


@pytest.fixture
def api(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    return c


def add(c, type_, **fields):
    return c.post("/api/sources/instances", headers=TOKEN,
                  json={"type": type_, "fields": fields})


def docker(c, ip):
    return add(c, "docker", url=f"http://{ip}:2375", host_ip=ip)


@pytest.fixture
def two_dockers(api, monkeypatch):
    """Two Docker hosts, each running one container NetMap has never heard of."""
    from app.sources import docker as mod
    running = {"http://10.0.0.1:2375": "alpha", "http://10.0.0.2:2375": "beta"}
    monkeypatch.setattr(mod, "fetch_containers", lambda cfg: [
        {"Names": ["/" + running[cfg["url"]]], "Image": "x", "State": "running", "Ports": []}])
    docker(api, "10.0.0.1")
    docker(api, "10.0.0.2")
    return api


# ---- ids ------------------------------------------------------------------------------------
def test_first_instance_is_named_by_type_then_numbered(two_dockers):
    from app import sources
    rows = sources.list_instances()
    assert [(r["id"], r["name"]) for r in rows] == [("docker", "Docker"), ("docker-2", "Docker 2")]
    sources.delete_instance("docker")
    assert docker(two_dockers, "10.0.0.3").json()["id"] == "docker"   # free again


@pytest.mark.parametrize("type_, fields", [
    ("proxmox", {"url": "https://pve:8006", "token_id": "a@pve!ro", "token_secret": "s"}),
    ("ports", {"enabled": True})])
def test_single_instance_types_stay_single(api, type_, fields):
    assert add(api, type_, **fields).status_code == 201
    r = add(api, type_, **fields)
    assert r.status_code == 400 and "only one" in r.json()["detail"]


@pytest.mark.parametrize("source, type_", [("pihole", "pihole"), ("pihole-2", "pihole"),
                                           ("ha", "homeassistant"),
                                           ("homeassistant-3", "homeassistant")])
def test_type_of(source, type_):
    from app.sources.dynamic import type_of
    assert type_of(source) == type_


# ---- keys, sightings, ignores -----------------------------------------------------------------
def test_each_instance_keys_its_own_findings(two_dockers):
    from app import sources
    a, b = sources.scan("docker"), sources.scan("docker-2")
    assert [f["key"] for f in a["findings"]] == ["docker:new:alpha"]
    assert [f["key"] for f in b["findings"]] == ["docker-2:new:beta"]
    assert (a["source"], b["source"]) == ("docker", "docker-2")


def test_ignoring_one_instances_finding_leaves_the_other(two_dockers):
    from app import db, sources
    two_dockers.post("/api/discovery/ignores", headers=TOKEN, json={"key": "docker-2:new:beta"})
    assert db.ignores()["docker-2:new:beta"]["source"] == "docker-2"
    assert sources.scan("docker-2")["findings"] == []
    assert len(sources.scan("docker")["findings"]) == 1


def test_sightings_are_recorded_per_instance(two_dockers):
    from app import db, sources
    e = db.create_entry({"name": "beta", "ip": "10.0.0.2", "kind": "container"})
    sources.scan("docker-2")
    assert {s["source"] for s in db.sightings_for(e["id"])} == {"docker-2"}


def test_removing_a_source_takes_what_it_saw_not_what_was_decided(two_dockers):
    from app import db, sources
    e = db.create_entry({"name": "beta", "ip": "10.0.0.2", "kind": "container"})
    sources.scan("docker-2")
    db.add_ignore("docker-2:new:x", "docker-2")
    sources.delete_instance("docker-2")
    assert db.sightings_for(e["id"]) == []
    assert "docker-2:new:x" in db.ignores()


def test_home_assistant_ignores_apply(api, monkeypatch):
    """Its keys start "ha:", and ignores used to be looked up as
    "homeassistant" - so ignoring one never took."""
    from app import db, sources
    from app.sources import homeassistant as mod
    monkeypatch.setattr(mod, "_get", lambda cfg, path: [])
    add(api, "homeassistant", url="http://ha:8123", token="t")
    e = db.create_entry({"name": "Sensor", "tags": "ha:sensor.x"})
    key = f"ha:missing:{e['id']}:sensor.x"
    assert [f["key"] for f in sources.scan("homeassistant")["findings"]] == [key]
    api.post("/api/discovery/ignores", headers=TOKEN, json={"key": key})
    assert sources.scan("homeassistant")["findings"] == []


# ---- a sibling answers "missing" --------------------------------------------------------------
class _Half:
    """A source that sees some entries and reports the rest as missing."""
    FIELDS = [{"key": "sees", "label": "Sees", "type": "text"}]
    ABSENCE = {"missing"}

    def configured(self, cfg):
        return True

    def scan(self, cfg):
        from app import db
        sees = {int(x) for x in cfg["sees"].split(",") if x}
        db.record_sightings(cfg["_id"], [{"entry_id": i, "fact": "here", "value": "y"}
                                         for i in sees])
        return {"findings": [{"type": "missing", "key": f"{cfg['_key']}:missing:{e['id']}",
                              "label": e["name"], "entry": {"id": e["id"]}}
                             for e in db.list_entries() if e["id"] not in sees],
                "counts": {}, "error": None}


def test_missing_here_but_seen_by_a_sibling_is_dropped(make_app, monkeypatch):
    make_app()
    from app import db, sources
    from app.sources import dynamic
    monkeypatch.setitem(dynamic.DRIVERS, "half", {"mod": _Half(), "label": "H", "hint": ""})
    one = db.create_entry({"name": "one"})["id"]
    two = db.create_entry({"name": "two"})["id"]
    sources.create_instance("half", "", {"sees": str(one)})
    sources.create_instance("half", "", {"sees": str(two)})
    sources.scan("half-2")                                  # half-2 sees "two"
    r = sources.scan("half")                                # half: "two" is missing
    assert r["findings"] == [] and r["counts"]["shadowed"] == 1
    r = sources.scan("half-2")                              # half-2: "one" is missing,
    assert r["findings"] == [] and r["counts"]["shadowed"] == 1   # but half sees it


def test_missing_everywhere_is_still_reported(make_app, monkeypatch):
    make_app()
    from app import db, sources
    from app.sources import dynamic
    monkeypatch.setitem(dynamic.DRIVERS, "half", {"mod": _Half(), "label": "H", "hint": ""})
    lost = db.create_entry({"name": "lost"})["id"]
    sources.create_instance("half", "", {"sees": ""})
    sources.create_instance("half", "", {"sees": ""})
    sources.scan("half-2")
    assert [f["key"] for f in sources.scan("half")["findings"]] == [f"half:missing:{lost}"]


# ---- per-type answers --------------------------------------------------------------------------
def test_scan_type_one_instance_keeps_its_shape(api, monkeypatch):
    from app import sources
    from app.sources import docker as mod
    monkeypatch.setattr(mod, "fetch_containers", lambda cfg: [])
    docker(api, "10.0.0.1")
    r = sources.scan_type("docker")
    assert r["source"] == "docker" and "sources" not in r


def test_scan_type_several_instances(two_dockers):
    from app import sources
    r = sources.scan_type("docker")
    assert [s["source"] for s in r["sources"]] == ["docker", "docker-2"]
    assert (r["findings"], r["errors"]) == (2, 0)


def test_open_hostname_ignored_on_a_second_tunnel_counts_as_accepted(make_app):
    make_app()
    from app import db, overview
    e = db.create_entry({"name": "Blog"})["id"]
    db.record_sightings("cloudflare-2", [
        {"entry_id": e, "fact": "hostname:blog.example.org", "value": "via tunnel; no Access"}])
    db.add_ignore("cloudflare-2:access:blog.example.org", "cloudflare-2", reason="public")
    item = overview.exposure()["no_access"][0]
    assert item["host"] == "blog.example.org" and item["accepted"]


# ---- MCP ---------------------------------------------------------------------------------------
def test_mcp_lists_and_scans_any_source(two_dockers):
    import anyio
    from app import main
    listed = anyio.run(main.list_sources)
    assert [(s["source"], s["type"], s["roles"]) for s in listed] == [
        ("docker", "docker", ["containers"]), ("docker-2", "docker", ["containers"])]
    assert all("secrets" not in s and "config" not in s for s in listed)
    assert anyio.run(main.scan_source, "docker-2")["source"] == "docker-2"
    with pytest.raises(ValueError, match="have docker, docker-2"):
        anyio.run(main.scan_source, "nope")
