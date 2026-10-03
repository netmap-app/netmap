"""The drivers added for other people's networks — AdGuard Home and Traefik —
and the parts that no longer assume this homelab: public domains, the edge's
gateway entry, Proxmox guests matched by name. No network: each driver's
HTTP call is replaced by the payload its API documents."""
import pytest


@pytest.fixture
def app_(make_app):
    make_app()
    from app import db, sources
    return db, sources


def _add(sources, type_, **fields):
    return sources.create_instance(type_, "", fields)["id"]


# ---- AdGuard Home ---------------------------------------------------------------------------
ADGUARD = {
    "/control/rewrite/list": [
        {"domain": "nas.lan", "answer": "10.0.0.5", "enabled": True},
        {"domain": "old.lan", "answer": "10.0.0.99"},
        {"domain": "plex.lan", "answer": "10.0.0.77"},
        {"domain": "alias.lan", "answer": "nas.lan"},                 # a CNAME: not a record
        {"domain": "off.lan", "answer": "10.0.0.66", "enabled": False},
    ],
    "/control/clients": {
        "clients": [{"name": "TV", "ids": ["10.0.0.48", "aa:bb:cc:dd:ee:ff"]},
                    {"name": "NAS", "ids": ["10.0.0.5"]}],
        "auto_clients": [{"ip": "10.0.0.30", "name": "phone", "source": "DHCP"}],
    },
}


@pytest.fixture
def adguard(app_, monkeypatch):
    db, sources = app_
    from app.sources import adguard as mod
    monkeypatch.setattr(mod, "_get", lambda cfg, path: ADGUARD[path])
    nas = db.create_entry({"name": "nas", "ip": "10.0.0.5", "kind": "hardware"})
    db.create_entry({"name": "plex", "ip": "10.0.0.7"})
    _add(sources, "adguard", url="http://ag:3000", user="u", password="p")
    return db, sources, nas


def test_adguard_rewrites_are_reconciled_like_local_records(adguard):
    db, sources, nas = adguard
    r = sources.scan("adguard")
    by = {f["type"]: f for f in r["findings"]}
    assert by["dns-orphan"]["key"] == "adguard:dns:10.0.0.99:old.lan"
    assert "NetMap has plex at 10.0.0.7" in by["dns-drift"]["label"]
    assert by["client-untracked"]["key"] == "adguard:client:10.0.0.48"
    assert r["counts"]["records"] == 3                       # CNAME and disabled left out
    assert {s["fact"] for s in db.sightings_for(nas["id"])} == {"dns:nas.lan"}


def test_adguard_clients_are_on_the_address_map(adguard):
    db, sources, _ = adguard
    sources.scan("adguard")
    seen = {p["ip"]: p for p in db.presence(untracked_only=False) if "adguard" in p["sources"]}
    assert seen["10.0.0.48"]["label"] == "TV" and seen["10.0.0.30"]["label"] == "phone"


def test_adguard_keeps_the_dns_contract(adguard):
    from app.sources import adguard as mod, bound
    assert mod.dns_names(bound("adguard").cfg) == {"nas.lan", "old.lan", "plex.lan"}


# ---- Traefik ---------------------------------------------------------------------------------
@pytest.mark.parametrize("rule, names", [
    ("Host(`a.example.org`)", ["a.example.org"]),
    ("Host(`a.example.org`, `b.example.org`)", ["a.example.org", "b.example.org"]),
    ("Host(`a.example.org`) || Host(`B.example.org`)", ["a.example.org", "b.example.org"]),
    ("Host(`a.example.org`) && PathPrefix(`/api`)", ["a.example.org"]),
    ("HostRegexp(`{sub:[a-z]+}.example.org`)", []),
])
def test_traefik_rule_names(rule, names):
    from app.sources.traefik import hosts_of
    assert hosts_of(rule) == names


TRAEFIK = {
    "/api/http/routers": [
        {"name": "plex@docker", "rule": "Host(`plex.example.org`)", "service": "plex",
         "provider": "docker", "status": "enabled"},
        {"name": "nas@file", "rule": "Host(`nas.example.org`)", "service": "nas@file",
         "provider": "file", "status": "enabled"},
        {"name": "new@file", "rule": "Host(`new.example.org`)", "service": "nas@file",
         "provider": "file", "status": "enabled"},
        {"name": "wiki@file", "rule": "Host(`wiki.example.org`)", "service": "wiki@file",
         "provider": "file", "status": "disabled"},
    ],
    "/api/http/services": [
        {"name": "plex@docker", "loadBalancer": {"servers": [{"url": "http://172.18.0.5:32400"}]}},
        {"name": "nas@file", "loadBalancer": {"servers": [{"url": "http://10.0.0.99:5000"}]}},
        {"name": "wiki@file", "loadBalancer": {"servers": [{"url": "http://10.0.0.8:80"}]}},
    ],
}


def test_traefik_routes_are_reconciled_like_npm(app_, monkeypatch):
    db, sources = app_
    from app.sources import traefik as mod
    monkeypatch.setattr(mod, "_get", lambda cfg, path: TRAEFIK[path])
    db.create_entry({"name": "Plex", "ip": "10.0.0.7", "url": "https://plex.example.org"})
    db.create_entry({"name": "NAS", "ip": "10.0.0.5", "url": "https://nas.example.org"})
    db.create_entry({"name": "Wiki", "ip": "10.0.0.8", "url": "https://wiki.example.org"})
    _add(sources, "traefik", url="http://traefik:8080")
    by = {f["key"]: f["type"] for f in sources.scan("traefik")["findings"]}
    assert by == {"traefik:orphan:nas.example.org": "proxy-orphan",      # 10.0.0.99: nothing there
                  "traefik:host:new.example.org": "proxy-untracked",
                  "traefik:off:wiki.example.org": "proxy-disabled"}
    # Plex forwards to a container address: shown, never called an orphan.
    assert mod.domains(sources.bound("traefik").cfg) >= {"plex.example.org"}


# ---- no hard-coded domain ------------------------------------------------------------------------
def test_public_domains_come_from_the_tunnel_or_the_setting():
    from app.sources.cloudflare import public_domains
    routed = {"plex.example.org": "", "a.b.example.net": "", "localhost": ""}
    assert public_domains({}, routed) == {"example.org", "b.example.net"}
    assert public_domains({"public_domains": "Example.com, ."}, routed) == {"example.com"}


def test_published_names_link_to_the_edge_gateway(app_):
    db, sources = app_
    from app import links
    tunnel = db.create_entry({"name": "Cloudflare Tunnel"})["id"]
    plex = db.create_entry({"name": "Plex", "url": "https://plex.example.org"})["id"]
    db.create_entry({"name": "LAN only", "url": "https://lan.example.org"})
    rule = db.create_entry({"name": "Port forward — Plex", "kind": "rule"})["id"]
    _add(sources, "cloudflare", token="t", account="a")
    db.record_sightings("cloudflare", [
        {"entry_id": plex, "fact": "hostname:plex.example.org", "value": "via tunnel"},
        {"entry_id": rule, "fact": "hostname:plex.example.org", "value": "via tunnel"}])
    got = [(e["src"], e["dst"], e["why"]) for e in links.plan()["edges"]
           if e["type"] == "exposed_by"]
    assert got == [(plex, tunnel, "published as plex.example.org")]


def test_no_gateway_when_it_is_ambiguous(app_):
    db, _ = app_
    from app.sources.cloudflare import gateway
    rows = [{"name": "Cloudflare Tunnel", "id": 1}, {"name": "Old cloudflare tunnel", "id": 2}]
    assert gateway({}, rows) is None
    assert gateway({"_state": {"tunnel_name": "homelab"}}, [{"name": "homelab tunnel", "id": 3}])["id"] == 3


# ---- Proxmox guests by name -------------------------------------------------------------------
def test_proxmox_matches_a_guest_by_name_when_no_vmid_is_recorded(app_, monkeypatch):
    db, sources = app_
    from app.sources import proxmox as mod
    api = {"/nodes": [{"node": "pve", "status": "online"}],
           "/nodes/pve/qemu": [{"vmid": 101, "name": "gitea", "status": "running"}],
           "/nodes/pve/lxc": [{"vmid": 102, "name": "grafana", "status": "running"}]}
    monkeypatch.setattr(mod, "_get", lambda cfg, path: api[path])
    gitea = db.create_entry({"name": "Gitea", "kind": "vm"})["id"]
    db.create_entry({"name": "Grafana", "kind": "service"})       # a service, not the guest
    _add(sources, "proxmox", url="https://pve:8006", token_id="a@pve!ro", token_secret="s")
    r = sources.scan("proxmox")
    assert [f["key"] for f in r["findings"]] == ["proxmox:new:102"]
    assert {s["fact"] for s in db.sightings_for(gitea)} == {"vm"}


# ---- Open ports: never probe what a probe breaks ----------------------------------------------
@pytest.mark.parametrize("text, anywhere, pairs", [
    ("6789", {6789}, set()),
    ("192.168.10.10:6789, 22", {22}, {("192.168.10.10", 6789)}),
    ("nas:6789, 70000, , x", set(), set()),                  # unreadable: ignored, not guessed
])
def test_never_probe_parsing(text, anywhere, pairs):
    from app.sources.portscan import never_probe
    assert never_probe({"never_probe": text}) == (anywhere, pairs)


def test_sweep_never_touches_a_listed_port(app_, monkeypatch):
    db, sources = app_
    from app.sources import portscan as mod
    touched = []
    monkeypatch.setattr(mod, "_probe", lambda ip, port, timeout: touched.append((ip, port)) or
                        ("open" if port in (8443, 6789) else "closed"))
    e = db.create_entry({"name": "UniFi", "ip": "192.168.10.10", "ports": "8443, 6789"})
    _add(sources, "ports", enabled=True, never_probe="192.168.10.10:6789")
    r = sources.scan("ports")
    assert ("192.168.10.10", 6789) not in touched and ("192.168.10.10", 8443) in touched
    assert not [f for f in r["findings"] if "6789" in f["key"]]
    facts = {s["fact"]: s["value"] for s in db.sightings_for(e["id"])}
    assert facts["port:6789"] == "not probed (Never probe)" and facts["port:8443"] == "open"


def test_deep_scan_skips_listed_ports(app_, monkeypatch):
    db, sources = app_
    from app import deepscan
    touched = []
    monkeypatch.setattr(deepscan, "_probe", lambda ip, port: touched.append(port) or "closed")
    _add(sources, "ports", enabled=True, never_probe="6789")
    deepscan.start("192.168.10.10", 6780, 6799)
    import time
    for _ in range(50):
        if deepscan.status()["state"] != "running":
            break
        time.sleep(0.05)
    job = deepscan.status()
    assert 6789 not in touched and job["skipped"] == [6789] and job["total"] == 19
    assert "Not probed (Never probe): 6789" in deepscan.summarise(job)
