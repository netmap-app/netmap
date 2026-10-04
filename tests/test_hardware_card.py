"""Hardware & blast radius: per physical host, what runs on it (through VMs
and containers), how much a check watches, and the notes that are risks."""
TOKEN = {"authorization": "Bearer full-token"}


def _entry(c, **kw):
    r = c.post("/api/entries", headers=TOKEN, json=kw)
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def test_dependents_coverage_and_notes(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import db
    box = _entry(c, name="Box", kind="hardware", ip="10.0.0.2", tags="backup:none")
    vm = _entry(c, name="VM", kind="vm", ip="10.0.0.3", monitor=True, criticality="critical")
    dns = _entry(c, name="DNS", kind="service", ip="10.0.0.3", criticality="critical",
                 monitor=False)
    fw = _entry(c, name="Firewall", kind="service", ip="10.0.0.2", monitor=True, criticality="critical")
    rule = _entry(c, name="NAT 443", kind="rule")
    lone = _entry(c, name="Spare", kind="hardware")                 # nothing runs on it
    for src, dst in ((vm, box), (dns, vm), (fw, box), (rule, box)):
        db.link(src, dst, "runs_on")
    db.create_source_instance("opnsense", "OPNsense", {"url": "https://10.0.0.2"}, {})
    db.create_source_instance("pihole", "Pi-hole", {"url": "http://10.0.0.3/admin"}, {})

    h = c.get("/api/overview/hardware", headers=TOKEN).json()
    (host,) = h["hosts"]
    assert host["id"] == box and lone not in [x["id"] for x in h["hosts"]]
    assert host["dependents"] == 4                  # VM, DNS through the VM, firewall, rule
    assert (host["monitored"], host["checkable"]) == (2, 3)   # the rule has nothing to probe
    notes = {n["text"]: n["risk"] for n in host["notes"]}
    assert notes == {"OPNsense and Pi-hole share this host": True,
                     "3 critical entries depend on it": True, "backup:none": True}


def test_one_source_alone_is_not_a_shared_host(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import db
    box = _entry(c, name="Box", kind="hardware", ip="10.0.0.2")
    db.link(_entry(c, name="App", kind="service", criticality="critical"), box, "runs_on")
    db.create_source_instance("opnsense", "OPNsense", {"url": "https://10.0.0.2"}, {})
    (host,) = c.get("/api/overview/hardware", headers=TOKEN).json()["hosts"]
    assert host["notes"] == [{"text": "1 critical entry depends on it", "risk": False}]


def test_network_gear_counts_only_what_is_monitored_as_up(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    _entry(c, name="Switch", kind="hardware", category="Core Network", monitor=False)
    _entry(c, name="Modem", kind="hardware", category="Core Network", monitor=True)
    _entry(c, name="Laptop", kind="hardware", category="Client / IoT Devices")
    g = c.get("/api/overview/hardware", headers=TOKEN).json()["gear"]
    assert (g["total"], g["monitored"]) == (2, 1)
    assert g["up"] == 0                             # never checked is not up
    assert [i["name"] for i in g["items"]] == ["Modem", "Switch"]
