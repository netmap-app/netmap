"""The one-time seed: pre-1.75 configuration (NETMAP_* environment variables and
Settings overrides) becomes source instances once, and never again. See
sources.migrate_legacy()."""
import pytest

PIHOLE = {"NETMAP_PIHOLE_URL": "http://pi/", "NETMAP_PIHOLE_PASSWORD": "env-pw",
          "NETMAP_PIHOLE_VERIFY": "false", "NETMAP_PIHOLE_TIMEOUT": "3"}


def _inst(iid):
    from app import db
    return db.get_source_instance(iid)


def test_environment_becomes_an_instance_named_by_type(make_app):
    make_app(**PIHOLE)
    from app import crypto, db, sources
    inst = _inst("pihole")
    assert inst["type"] == "pihole" and inst["name"] == "Pi-hole"
    assert inst["config"] == {"url": "http://pi", "verify_ssl": False, "timeout": 3.0}
    assert inst["secrets"]["password"] != "env-pw"
    assert crypto.decrypt(inst["secrets"]["password"]) == "env-pw"
    assert sources.names() == ["pihole"]          # finding keys and ignores stay "pihole:…"
    row = next(a for a in db.audit(10) if a["action"] == "source-migrate")
    assert row["actor"] == "system" and "password" in row["detail"]["fields"]
    assert "env-pw" not in str(db.audit(10))


def test_settings_override_wins_over_environment(make_app):
    make_app()
    from app import crypto, db, sources
    import json
    db.conn().execute(db.LEGACY_SETTINGS_DDL)
    db.conn().execute("INSERT INTO source_settings VALUES (?,?,?)", ("npm", json.dumps(
        {"timeout": 5, "password": crypto.encrypt("override-pw")}), db.now()))
    db.delete_setting(sources.SEEDED_KEY)      # a 1.74 database: overrides, never seeded
    make_app(NETMAP_NPM_URL="http://npm:81", NETMAP_NPM_USER="me@example.com",
             NETMAP_NPM_PASSWORD="env-pw", NETMAP_NPM_TIMEOUT="9")
    from app.sources import bound
    cfg = bound("npm").cfg
    assert (cfg["timeout"], cfg["password"], cfg["user"]) == (5.0, "override-pw", "me@example.com")
    assert db.get_source_settings("npm") == {}                  # read once, then dropped


def test_seed_runs_once(make_app):
    make_app(**PIHOLE)
    make_app(**{**PIHOLE, "NETMAP_PIHOLE_URL": "http://elsewhere"})
    assert _inst("pihole")["config"]["url"] == "http://pi"      # later env changes nothing
    from app import sources
    sources.delete_instance("pihole")
    make_app(**PIHOLE)
    assert _inst("pihole") is None                             # removed stays removed


@pytest.mark.parametrize("env", [{"NETMAP_PIHOLE_URL": "http://pi"},   # no password
                                 {"NETMAP_PORTSCAN": "0"},
                                 {}])
def test_nothing_to_scan_creates_nothing(make_app, env):
    make_app(**env)
    from app import sources
    assert sources.list_instances() == []


def test_portscan_seeded_only_when_switched_on(make_app):
    make_app(NETMAP_PORTSCAN="1", NETMAP_PORTSCAN_PER_HOST="4")
    from app.sources import bound
    assert bound("ports").cfg["per_host"] == 4


def test_invalid_env_value_falls_back_to_default(make_app):
    make_app(**{**PIHOLE, "NETMAP_PIHOLE_TIMEOUT": "soon"})
    from app.sources import bound
    assert bound("pihole").cfg["timeout"] == 8.0


def test_existing_proxmox_instance_gets_its_type_as_id(make_app):
    make_app()
    from app import db, sources
    old = db.create_source_instance("proxmox", "pve", {"url": "https://pve:8006",
                                                       "token_id": "a@pve!ro"}, {})
    assert old["id"] != "proxmox"
    assert sources.migrate_legacy()["renamed"] == ["proxmox"]
    assert _inst("proxmox")["name"] == "pve" and _inst(old["id"]) is None


def test_fresh_install_has_no_sources_and_says_so(make_app):
    make_app()
    from app import sources
    s = sources.summary()
    assert (s["sources_total"], s["configured"]) == (0, [])
    r = sources.scan("pihole")
    assert not r["configured"] and "Settings › Sources" in r["error"]
    with pytest.raises(KeyError):
        sources.scan("nonsense")


# ---- per-instance state ------------------------------------------------------------------
class _Counter:
    FIELDS = [{"key": "url", "label": "URL", "type": "text"}]

    def configured(self, cfg):
        return True

    def scan(self, cfg):
        cfg["_state"]["n"] = cfg["_state"].get("n", 0) + 1
        return {"findings": [], "counts": {"n": cfg["_state"]["n"]}, "error": None}


def test_instances_never_share_state(make_app, monkeypatch):
    make_app()
    from app import sources
    from app.sources import dynamic
    monkeypatch.setitem(dynamic.DRIVERS, "count", {"mod": _Counter(), "label": "C", "hint": ""})
    a = sources.create_instance("count", "a", {"url": "http://a"})["id"]
    b = sources.create_instance("count", "b", {"url": "http://b"})["id"]
    assert (a, b) == ("count", "count-2")
    sources.scan(a)
    assert sources.scan(a)["counts"]["n"] == 2
    assert sources.scan(b)["counts"]["n"] == 1
    sources.update_instance(a, fields_in={"url": "http://a2"})
    assert sources.scan(a)["counts"]["n"] == 1          # an edit drops the session
