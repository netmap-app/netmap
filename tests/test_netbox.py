"""NetBox as a source (app/sources/netbox.py): pagination, the token staying on
NetBox, and matching - by address, by name, by a mapped host name - into the
five findings. API pages are canned; one test talks to a local HTTP server."""
import http.server
import json
import threading

import pytest

BASE = "http://netbox.test"

DEVICES = [
    {"id": 1, "name": "core-switch", "status": {"value": "active"}, "primary_ip4": {"address": "10.0.0.2/24"},
     "site": {"name": "Home"}, "role": {"name": "Switch"}},
    {"id": 2, "name": "nas", "status": {"value": "active"}, "primary_ip4": {"address": "10.0.0.22/24"}},
    {"id": 3, "name": "new-ap", "status": {"value": "active"}, "primary_ip4": {"address": "10.0.0.6/24"}},
    {"id": 4, "name": "future-box", "status": {"value": "planned"}, "primary_ip4": None},
    {"id": 5, "name": "Pve Host", "status": {"value": "active"}, "primary_ip4": None},
]
VMS = [{"id": 11, "name": "docker-vm", "status": {"value": "active"},
        "primary_ip4": {"address": "10.0.0.15/24"}}]
DEV_IFS = [
    {"id": 100, "device": {"id": 1}, "mac_address": "AA:BB:CC:00:00:02"},                # NetBox < 4.2
    {"id": 101, "device": {"id": 2}, "primary_mac_address": {"mac_address": "aa:bb:cc:00:00:99"}},
    {"id": 102, "device": {"id": 3}, "mac_addresses": [{"mac_address": "aa:bb:cc:00:00:06"}]},
]
VM_IFS = [{"id": 200, "virtual_machine": {"id": 11}, "mac_address": None}]
IPS = [
    {"id": 50, "address": "10.0.0.2/24", "assigned_object_id": 100, "status": {"value": "active"}},
    {"id": 51, "address": "10.0.0.80/24", "assigned_object_id": None, "status": {"value": "active"},
     "dns_name": "printer.home.example"},
    {"id": 52, "address": "10.0.0.81/24", "assigned_object_id": None, "status": {"value": "reserved"}},
    {"id": 53, "address": "10.0.0.15/24", "assigned_object_id": None, "status": {"value": "active"}},
]


def pages(path, items, size=2, host=BASE):
    """NetBox-style pages of `size` for one endpoint, keyed by request URL."""
    out, url = {}, f"{BASE}{path}?limit=500"
    for i in range(0, max(len(items), 1), size):
        nxt = f"{host}{path}?limit=500&offset={i + size}" if i + size < len(items) else None
        out[url] = {"count": len(items), "next": nxt, "results": items[i:i + size]}
        url = nxt
    return out


API = {**pages("/api/dcim/devices/", DEVICES), **pages("/api/virtualization/virtual-machines/", VMS),
       **pages("/api/dcim/interfaces/", DEV_IFS), **pages("/api/virtualization/interfaces/", VM_IFS),
       **pages("/api/ipam/ip-addresses/", IPS)}


@pytest.fixture
def nb(make_app, monkeypatch):
    make_app()
    from app import db, sources
    from app.sources import netbox
    asked = []
    monkeypatch.setattr(netbox, "_get", lambda cfg, url: asked.append(url) or API[url])
    e = {
        "switch": db.create_entry({"name": "Core Switch", "ip": "10.0.0.2", "kind": "hardware",
                                   "mac": "aa:bb:cc:00:00:02"}),
        "nas": db.create_entry({"name": "NAS", "ip": "10.0.0.23", "kind": "hardware",
                                "mac": "aa:bb:cc:00:00:22"}),
        "vm": db.create_entry({"name": "docker-host", "ip": "10.0.0.15", "kind": "vm"}),
        "app": db.create_entry({"name": "Wiki", "ip": "10.0.0.15", "kind": "container"}),
        "pve": db.create_entry({"name": "MS-01", "ip": "10.0.0.41", "kind": "hardware"}),
        "old": db.create_entry({"name": "Old server", "ip": "10.0.0.99", "kind": "hardware"}),
    }
    db.set_host_map("Pve Host", e["pve"]["id"])
    iid = sources.create_instance("netbox", "", {"url": BASE, "token": "0123456789abcdef"})["id"]
    return sources, iid, e, asked


def test_every_page_is_read(nb):
    sources, iid, _, asked = nb
    r = sources.scan(iid)
    assert r["error"] is None
    assert sum(1 for u in asked if "/api/dcim/devices/" in u) == 3          # 5 devices, 2 a page
    assert r["counts"]["devices"] == 5 and r["counts"]["vms"] == 1


def test_findings(nb):
    sources, iid, e, _ = nb
    r = sources.scan(iid)
    by = {}
    for f in r["findings"]:
        by.setdefault(f["type"], []).append(f)
    # matched by address (switch, docker-vm - not the container sharing it),
    # by name (nas, whose address drifted), by a mapped host name (Pve Host)
    assert r["counts"]["matched"] == 4
    assert [f["draft"]["name"] for f in by["netbox-untracked"]] == ["new-ap"]   # planned: not news
    assert by["netbox-untracked"][0]["draft"]["mac"] == "aa:bb:cc:00:00:06"
    assert [f["draft"]["ip"] for f in by["netbox-ip"]] == ["10.0.0.80"]        # reserved / held: no
    assert by["netbox-ip"][0]["draft"]["name"] == "printer.home.example"
    assert [f["entry"]["id"] for f in by["netbox-missing"]] == [e["old"]["id"]]
    (drift,) = by["netbox-ip-drift"]
    assert drift["entry"]["id"] == e["nas"]["id"] and drift["suggest"] == {"ip": "10.0.0.22"}
    (mac,) = by["netbox-mac-drift"]
    assert mac["entry"]["id"] == e["nas"]["id"] and mac["suggest"] == {"mac": "aa:bb:cc:00:00:99"}
    assert len(r["findings"]) == 5


def test_matched_entries_get_an_intent_sighting(nb):
    sources, iid, e, _ = nb
    sources.scan(iid)
    from app import db
    facts = {s["fact"]: s["value"] for s in db.sightings_for(e["switch"]["id"])}
    assert facts["intent"] == "NetBox device core-switch (Home, Switch)"
    assert not db.sightings_for(e["app"]["id"])


def test_only_the_chosen_kinds_are_expected_in_netbox(nb):
    sources, iid, e, _ = nb
    sources.update_instance(iid, fields_in={"kinds": "vm"})
    r = sources.scan(iid)
    assert not [f for f in r["findings"] if f["type"] == "netbox-missing"]


def test_a_next_page_on_another_host_is_refused(make_app, monkeypatch):
    make_app()
    from app import sources
    from app.sources import netbox
    evil = {**API, **pages("/api/dcim/devices/", DEVICES, host="http://elsewhere.test")}
    asked = []
    monkeypatch.setattr(netbox, "_get", lambda cfg, url: asked.append(url) or evil[url])
    iid = sources.create_instance("netbox", "", {"url": BASE, "token": "t"})["id"]
    r = sources.scan(iid)
    assert "elsewhere.test" in r["error"] and not [u for u in asked if "elsewhere" in u]


def test_the_matching_is_pure():
    from app.sources import netbox
    f, seen, counts = netbox.reconcile("nb", [], [], [], [], [], [], {}, {"hardware"})
    assert (f, seen, counts) == ([], [], {"devices": 0, "vms": 0, "matched": 0})


class NetBoxStub:
    def __init__(self):
        self.auth = []
        me = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                me.auth.append(self.headers.get("authorization"))
                body = json.dumps({"netbox-version": "4.5.1"}).encode()
                self.send_response(200 if self.path == "/api/status/" else 404)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


@pytest.mark.parametrize("token,header", [
    ("0123456789abcdef0123456789abcdef01234567", "Token 0123456789abcdef0123456789abcdef01234567"),
    ("nbt_abc.def", "Bearer nbt_abc.def")])
def test_connection_test_and_token_styles(token, header):
    from app.sources import netbox
    s = NetBoxStub()
    try:
        r = netbox.test({"url": s.url, "token": token, "timeout": 3, "verify_ssl": True})
        assert r == {"ok": True, "error": None, "version": "4.5.1"}
        assert s.auth == [header]
    finally:
        s.srv.shutdown()
