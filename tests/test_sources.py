"""Source configuration: every source is an instance added from Settings; a
stored secret only goes where it was entered for, sessions reset on a change,
no credential follows a redirect, and what the Docker source counts as
published. See app/sources/. The one-time seed from the environment is in
test_migrate.py."""
import http.server
import json
import threading
import urllib.error
import urllib.request

import pytest

TOKEN = {"authorization": "Bearer full-token"}


@pytest.fixture
def api(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    return c


def add(c, type_, name="", **fields):
    return c.post("/api/sources/instances", headers=TOKEN,
                  json={"type": type_, "name": name, "fields": fields})


def put(c, iid, **fields):
    return c.put(f"/api/sources/instances/{iid}", headers=TOKEN, json={"fields": fields})


def cfg_of(type_):
    from app.sources import bound
    return bound(type_, configured_only=False).cfg


@pytest.fixture
def opn(api):
    assert add(api, "opnsense", url="https://192.168.10.1", key="k", secret="s").status_code == 201
    return api


# ---- binding, casting, sessions ----------------------------------------------------------
def test_url_change_without_secret_is_refused(opn):
    r = put(opn, "opnsense", url="https://evil.example")
    assert r.status_code == 400 and "entered again" in r.json()["detail"]
    assert cfg_of("opnsense")["url"] == "https://192.168.10.1"


def test_unchanged_url_with_trailing_slash_saves(opn):
    r = put(opn, "opnsense", url="https://192.168.10.1/", key="k", secret="", timeout="9")
    assert r.status_code == 200 and cfg_of("opnsense")["timeout"] == 9.0


def test_url_change_with_new_secret_saves(opn):
    assert put(opn, "opnsense", url="https://10.0.0.1", secret="new").status_code == 200
    c = cfg_of("opnsense")
    assert (c["url"], c["secret"]) == ("https://10.0.0.1", "new")


def test_audit_records_field_names_not_values(api):
    from app import db
    add(api, "pihole", url="http://pi", password="old")
    put(api, "pihole", password="brand-new-secret")
    last = db.audit(1)[0]
    assert last["action"] == "source-update"
    assert last["detail"]["fields"] == ["password"]
    assert "gAAAA" not in str(db.audit(5)) and "brand-new" not in str(db.audit(5))


def test_settings_change_resets_cached_session(api):
    from app import sources
    add(api, "npm", url="http://n", user="u", password="p")
    sources._STATE["npm"] = {"token": "cached"}
    assert cfg_of("npm")["_state"]["token"] == "cached"
    put(api, "npm", timeout="5")
    assert "token" not in cfg_of("npm")["_state"]


def test_required_fields_are_enforced(api):
    r = add(api, "pihole", url="http://pi")
    assert r.status_code == 400 and "Password is required" in r.json()["detail"]
    add(api, "docker", url="http://proxy:2375", host_ip="192.168.10.15")
    r = put(api, "docker", host_ip="")
    assert r.status_code == 400 and "Host IP is required" in r.json()["detail"]


def test_bad_number_is_refused(api):
    r = add(api, "pihole", url="http://pi", password="p", timeout="soon")
    assert r.status_code == 400 and "must be a number" in r.json()["detail"]


def test_driver_list_says_what_can_still_be_added(api):
    def can(t):
        r = api.get("/api/sources/drivers", headers=TOKEN).json()
        return {d["type"]: d for d in r["drivers"]}[t]
    assert can("proxmox")["can_add"] and can("proxmox")["single"]
    add(api, "proxmox", url="https://pve:8006", token_id="a@pve!ro", token_secret="s")
    assert not can("proxmox")["can_add"]
    add(api, "pihole", url="http://pi", password="p")
    assert can("pihole")["can_add"] and not can("pihole")["single"]
    assert all("env" not in f for f in can("pihole")["fields"])


# ---- redirects ---------------------------------------------------------------------------
def test_credentialed_request_does_not_follow_redirects():
    from app.sources import _http

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://evil.invalid/steal")
            self.end_headers()

        def log_message(self, *_):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_port}/api",
                                     headers={"authorization": "Basic secret"})
        with pytest.raises(urllib.error.URLError, match="redirect to http://evil.invalid/steal refused"):
            _http.urlopen(req, timeout=3)
    finally:
        srv.shutdown()


# ---- Docker: what counts as published -----------------------------------------------------
@pytest.mark.parametrize("ports, published", [
    ([{"IP": "127.0.0.1", "PrivatePort": 8087, "PublicPort": 8087}], []),
    ([{"IP": "::1", "PrivatePort": 5000, "PublicPort": 5000}], []),
    ([{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 80},
      {"IP": "::", "PrivatePort": 80, "PublicPort": 80}], [80]),
    ([{"IP": "127.0.0.1", "PrivatePort": 9000, "PublicPort": 9000},
      {"IP": "0.0.0.0", "PrivatePort": 3000, "PublicPort": 3001}], [3001]),
    ([{"IP": "", "PrivatePort": 2375}], []),
])
def test_docker_ignores_loopback_only_ports(ports, published):
    from app.sources.docker import _container_view
    assert _container_view({"Names": ["/x"], "Ports": ports})["published"] == published


def test_docker_label_matches_entry():
    from app.sources.docker import _match
    entries = [{"id": 59, "name": "NetMap (this app)", "ports": ""},
               {"id": 73, "name": "netmap-docker-proxy", "ports": ""}]
    view = {"name": "netmap", "published": [], "netmap_id": 59}
    assert _match(view, entries, {e["id"]: e for e in entries}, entries)["id"] == 59
    # Without the label the name is ambiguous — two entries contain it.
    assert _match({**view, "netmap_id": None}, entries,
                  {e["id"]: e for e in entries}, entries) is None


# ---- scans do not overlap --------------------------------------------------------------------
class _SlowSource:
    """A stand-in driver whose scan takes a moment and counts its calls."""
    FIELDS: list = []

    def __init__(self):
        self.calls = 0

    def configured(self, cfg):
        return True

    def scan(self, cfg):
        import time
        self.calls += 1
        time.sleep(0.3)
        return {"source": "slow", "findings": [], "counts": {}, "error": None,
                "scanned_at": "now", "configured": True}


@pytest.fixture
def slow(make_app, monkeypatch):
    make_app()
    from app import sources
    from app.sources import dynamic
    src = _SlowSource()
    monkeypatch.setitem(dynamic.DRIVERS, "slow", {"mod": src, "label": "Slow", "hint": ""})
    sources.create_instance("slow", "Slow", {})
    return sources, src


def test_concurrent_scans_of_one_source_run_once(slow):
    sources, src = slow
    results = []
    threads = [threading.Thread(target=lambda: results.append(sources.scan("slow")))
               for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert src.calls == 1
    assert len(results) == 5 and sum(1 for r in results if r.get("shared")) == 4


def test_named_scan_is_always_fresh(slow):
    sources, src = slow
    sources.scan("slow")
    sources.scan("slow")
    assert src.calls == 2


def test_scan_all_reuses_a_recent_result(slow, monkeypatch):
    sources, src = slow
    sources.scan_all()
    r = sources.scan_all()
    assert src.calls == 1
    assert r["sources"][0].get("cached")
    monkeypatch.setattr(sources, "REUSE", 0)
    sources.scan_all()
    assert src.calls == 2


# ---- checkbox values ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw, want", [("false", False), ("False", False), ("0", False),
                                       ("off", False), (False, False), ("true", True),
                                       ("1", True), (True, True), ("yes", True)])
def test_checkbox_values_parse(api, raw, want):
    add(api, "pihole", url="http://pi", password="p")
    assert put(api, "pihole", verify_ssl=raw).status_code == 200
    assert cfg_of("pihole")["verify_ssl"] is want


def test_checkbox_nonsense_is_refused(api):
    add(api, "pihole", url="http://pi", password="p")
    r = put(api, "pihole", verify_ssl="maybe")
    assert r.status_code == 400 and "yes/no" in r.json()["detail"]


# ---- one Proxmox source ------------------------------------------------------------------------
def test_second_proxmox_source_is_refused(api):
    body = {"type": "proxmox", "name": "pve",
            "fields": {"url": "https://pve:8006", "token_id": "a@pve!ro", "token_secret": "s"}}
    assert api.post("/api/sources/instances", headers=TOKEN, json=body).status_code == 201
    r = api.post("/api/sources/instances", headers=TOKEN, json={**body, "name": "pve2"})
    assert r.status_code == 400 and "only one Proxmox VE source" in r.json()["detail"]


# ---- secret key ---------------------------------------------------------------------------------
def _store_two_secrets(c):
    add(c, "pihole", url="http://pi", password="pihole-pass")
    c.post("/api/sources/instances", headers=TOKEN, json={
        "type": "proxmox", "name": "pve",
        "fields": {"url": "https://pve:8006", "token_id": "a@pve!ro", "token_secret": "pve-secret"}})


def _plain_secrets():
    from app import crypto, db
    return (crypto.decrypt(db.get_source_instance("pihole")["secrets"]["password"]),
            crypto.decrypt(db.list_source_instances("proxmox")[0]["secrets"]["token_secret"]))


def test_setting_secret_key_moves_secrets_off_the_database_key(make_app):
    from cryptography.fernet import Fernet
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    _store_two_secrets(c)
    from app import db
    assert db.get_setting("source_secret_key")             # started with the key in the db

    make_app(NETMAP_API_TOKEN="full-token", NETMAP_SECRET_KEY=Fernet.generate_key().decode())
    from app import crypto, db, sources
    r = sources.rotate_secrets()
    assert r == {"rotated": 2, "undecryptable": [], "stored_key_removed": True}
    assert db.get_setting("source_secret_key") is None      # the key left the database
    assert _plain_secrets() == ("pihole-pass", "pve-secret")
    assert crypto.key_location() == "environment"


def test_wrong_secret_key_is_reported_not_silent(make_app):
    from cryptography.fernet import Fernet
    _, c = make_app(NETMAP_API_TOKEN="full-token", NETMAP_SECRET_KEY=Fernet.generate_key().decode())
    _store_two_secrets(c)

    make_app(NETMAP_API_TOKEN="full-token", NETMAP_SECRET_KEY=Fernet.generate_key().decode())
    from app import crypto, overview, sources
    r = sources.rotate_secrets()
    assert sorted(r["undecryptable"]) == ["Pi-hole.password", "pve.token_secret"]
    assert crypto.UNDECRYPTABLE
    item = {i["key"]: i for i in overview.snapshot({})["attention"]}["secrets-undecryptable"]
    assert item["level"] == "critical" and "2 stored credentials" in item["title"]


def test_invalid_secret_key_stops_start_up(make_app):
    make_app(NETMAP_SECRET_KEY="not-a-fernet-key")
    from app import crypto
    with pytest.raises(SystemExit, match="not a valid Fernet key"):
        crypto.encrypt("x")


def test_rotation_leaves_current_secrets_alone(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    _store_two_secrets(c)
    from app import sources
    assert sources.rotate_secrets()["rotated"] == 0
    assert sources.rotate_secrets()["rotated"] == 0


def test_one_source_scan_can_reuse_a_recent_result(make_app, monkeypatch):
    _, c = make_app(NETMAP_AUTH="off")
    from app import sources
    from app.sources import dynamic
    src = _SlowSource()
    monkeypatch.setitem(dynamic.DRIVERS, "slow", {"mod": src, "label": "Slow", "hint": ""})
    sources.create_instance("slow", "Slow", {})
    assert not c.get("/api/discovery/slow?max_age=30").json().get("cached")
    assert c.get("/api/discovery/slow?max_age=30").json().get("cached")     # reused
    c.get("/api/discovery/slow")                                           # 0: always fresh
    assert src.calls == 2


# ---- how often sources are scanned by themselves -------------------------------------------------
def test_scan_interval_is_a_setting_with_bounds(make_app):
    _, c = make_app(NETMAP_AUTH="off")
    from app import db, sources
    assert c.get("/api/settings/scan").json()["interval"] == sources.INTERVAL == 86400
    for bad in (60, 8 * 86400, "soon"):
        assert c.put("/api/settings/scan", json={"interval": bad}).status_code == 400
    r = c.put("/api/settings/scan", json={"interval": 5400})
    assert r.status_code == 200 and r.json()["interval"] == 5400
    assert sources.summary()["interval"] == 5400          # what "stale" is measured against
    last = db.audit(1)[0]
    assert (last["action"], last["detail"]) == ("setting", {"from": 86400, "to": 5400})


def test_a_new_interval_applies_without_waiting_out_the_old_one(make_app, monkeypatch):
    import asyncio
    import threading
    import time
    make_app()
    from app import sources
    passes = []

    async def refresh():
        passes.append(time.time())
        await asyncio.sleep(0)
    monkeypatch.setattr(sources, "refresh", refresh)
    monkeypatch.setattr(sources, "START_DELAY", 0)
    monkeypatch.setattr(sources, "MIN_INTERVAL", 1)     # seconds, for the test's sake

    async def run():
        task = asyncio.create_task(sources.loop())
        await asyncio.sleep(0.2)
        assert len(passes) == 1 and sources.NEXT_RUN - time.time() > 80000   # a day away
        # Changed from another thread, as the API does: the loop must not sleep
        # out the day it had already started waiting.
        threading.Thread(target=sources.set_interval, args=(1,)).start()
        await asyncio.sleep(1.5)
        task.cancel()
        assert 0 < sources.NEXT_RUN - time.time() <= 1
    asyncio.run(run())
    assert len(passes) >= 2


def test_the_port_scan_skips_nothing_until_told(make_app):
    make_app()
    from app.sources import portscan
    assert portscan.skip_categories({"skip": ""}) == set()
    assert portscan.skip_categories({"skip": "Phones, IoT"}) == {"phones", "iot"}


def test_an_existing_port_scan_keeps_the_old_skip_default(make_app):
    make_app()
    from app import db, sources
    sources.create_instance("ports", "Open ports", {})
    db.delete_setting(sources.PINNED_KEY)                  # as on a database from before
    assert sources.pin_defaults() == ["ports"]
    assert db.get_source_instance("ports")["config"]["skip"] == "Client / IoT Devices"
    assert sources.pin_defaults() == []                   # once


def test_one_switch_pauses_a_source_and_the_old_scan_switch_folds_into_it(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    h = {"authorization": "Bearer full-token"}
    from app import db, sources
    sources.create_instance("ports", "Open ports", {})
    # As a database from before 1.93.0: the sweep paused with its own field.
    inst = db.get_source_instance("ports")
    db.update_source_instance("ports", config={**inst["config"], "enabled": False})
    assert sources.fold_scan_switch() == ["ports"]
    inst = db.get_source_instance("ports")
    assert not inst["enabled"] and "enabled" not in inst["config"]
    assert sources.fold_scan_switch() == []                       # once
    assert "ports" not in [x["source"] for x in sources.health() if x["configured"]]
    # The form's switch turns it back on, and the change is in the history.
    r = c.put("/api/sources/instances/ports", headers=h, json={"enabled": True})
    assert r.status_code == 200 and r.json()["enabled"]
    last = c.get("/api/audit", headers=h).json()[0]
    assert last["action"] == "source-update" and "enabled" in json.dumps(last["detail"])
