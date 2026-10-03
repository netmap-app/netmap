"""Roles: shared code asks for "the DNS servers" or "the public edge", never
for a product, so a new driver that keeps its role's contract is understood
everywhere. See dynamic.ROLES."""
import pytest

TOKEN = {"authorization": "Bearer full-token"}

# The function a driver must provide for each role that has one.
CONTRACT = {"dns": "dns_names", "proxy": "domains", "layer2": "topology",
            "scanner": "skip_categories"}


def test_every_driver_declares_known_roles_and_keeps_their_contract(make_app):
    make_app()
    from app.sources import dynamic
    for t, d in dynamic.DRIVERS.items():
        roles = dynamic.roles_of(t)
        assert roles, f"{t} declares no role"
        for r in roles:
            assert r in dynamic.ROLES, f"{t}: unknown role {r}"
            if r in CONTRACT:
                assert callable(getattr(d["mod"], CONTRACT[r], None)), f"{t} lacks {CONTRACT[r]}"


class _Stub:
    """A product NetMap has never heard of, known only by its role."""
    FIELDS = [{"key": "url", "label": "URL", "type": "text"}]

    def __init__(self, *roles, **answers):
        self.ROLES = roles
        for k, v in answers.items():
            setattr(self, k, lambda cfg, v=v: v)

    def configured(self, cfg):
        return True

    def scan(self, cfg):
        return {"findings": [], "counts": {}, "error": None}


@pytest.fixture
def register(make_app, monkeypatch):
    make_app()
    from app import sources
    from app.sources import dynamic

    def _reg(type_, stub):
        monkeypatch.setitem(dynamic.DRIVERS, type_, {"mod": stub, "label": type_, "hint": ""})
        return sources.create_instance(type_, "", {"url": "http://x"})["id"]
    return _reg


def test_a_new_dns_server_answers_cloudflares_lan_question(register):
    register("adguard", _Stub("dns", dns_names={"nas.home.example"}))
    register("traefik", _Stub("proxy", domains={"app.home.example"}))
    from app.sources import cloudflare
    assert {"nas.home.example", "app.home.example"} <= cloudflare._lan_names()


def test_exposure_reads_any_edge_and_any_firewall(register):
    register("tailscale", _Stub("edge"))
    register("pfsense", _Stub("firewall"))
    from app import db, overview
    e = db.create_entry({"name": "Wiki", "ports": "8080"})["id"]
    db.record_sightings("tailscale", [
        {"entry_id": e, "fact": "hostname:wiki.example.org", "value": "funnel; no Access"}])
    db.record_sightings("pfsense", [
        {"entry_id": e, "fact": "port:8080", "value": "forwarded from WAN 443 (TCP)"}])
    db.add_ignore("tailscale:access:wiki.example.org", "tailscale", reason="public wiki")
    x = overview.exposure()
    assert x["published"] == ["wiki.example.org"]
    assert x["no_access"][0]["accepted"]
    assert [f["port"] for f in x["wan_forwards"]] == ["8080"]


def test_a_source_without_the_role_is_not_counted(register):
    register("inventorydb", _Stub("health"))
    from app import db, overview
    e = db.create_entry({"name": "Wiki"})["id"]
    db.record_sightings("inventorydb", [
        {"entry_id": e, "fact": "hostname:wiki.example.org", "value": "no Access"}])
    assert overview.exposure()["published"] == []


def test_topology_comes_from_every_layer2_source(register):
    topo = {"devices": [], "clients": [], "error": None}
    register("omada", _Stub("layer2", topology=topo))
    from app.sources import by_role
    assert [b.mod.topology(b.cfg) for b in by_role("layer2")] == [topo]


def test_port_page_rows_say_what_their_source_is(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import db
    e = db.create_entry({"name": "Plex", "ports": "32400"})["id"]
    db.record_sightings("opnsense", [{"entry_id": e, "fact": "port:32400", "value": "forwarded"}])
    db.record_sightings("ports", [{"entry_id": e, "fact": "port:32400", "value": "open"}])
    rows = c.get("/api/ports/32400", headers=TOKEN).json()["observed"]
    assert {r["source"]: r["roles"] for r in rows} == {"opnsense": ["firewall", "leases"],
                                                          "ports": ["scanner"]}


def test_settings_lists_roles(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    r = c.get("/api/sources/drivers", headers=TOKEN).json()
    assert r["roles"]["dns"]["label"] == "DNS"
    assert {d["type"]: d["roles"] for d in r["drivers"]}["npm"] == ["proxy"]
