"""What the Overview's status strip reads from /api/overview: a one-word type
per queue item, the edge finding an exposure item can accept, and how many
entries that could have a health check have none."""
TOKEN = {"authorization": "Bearer full-token"}


def test_types_are_read_from_the_key(make_app):
    make_app()
    from app import overview
    assert [overview._type(k) for k in (
        "source:npm", "source-pending:docker-2", "secrets-undecryptable", "down:4", "down:@10.0.0.5",
        "cert:7", "open:x.example.org", "findings", "conflicts", "unmonitored", "stale",
        "unverified", "something-new")] == [
        "source", "source", "source", "down", "down", "certificate", "exposure", "mismatch",
        "conflict", "coverage", "coverage", "verify", "other"]


def test_unmonitored_counts_only_what_a_check_could_probe(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    for name, kind, monitor, tags in (
            ("Box", "hardware", False, ""), ("App", "service", False, ""),
            ("Watched", "service", True, ""), ("Via HA", "service", False, "ha:sensor.x"),
            ("NAT rule", "rule", False, ""), ("VLAN", "network", False, "")):
        r = c.post("/api/entries", headers=TOKEN,
                   json={"name": name, "kind": kind, "monitor": monitor, "tags": tags})
        assert r.status_code in (200, 201), r.text
    counts = c.get("/api/overview", headers=TOKEN).json()["counts"]
    assert counts["entries"] == 6 and counts["unmonitored"] == 2


def test_an_open_hostname_carries_the_finding_to_accept(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import db
    e = c.post("/api/entries", headers=TOKEN, json={"name": "Wiki"}).json()["id"]
    db.record_sightings("cloudflare", [{"entry_id": e, "fact": "hostname:wiki.example.org",
                                        "value": "tunnel, no Access"}])
    items = c.get("/api/overview", headers=TOKEN).json()["attention"]
    (it,) = [i for i in items if i["key"] == "open:wiki.example.org"]
    assert it["type"] == "exposure" and it["accept"] == "cloudflare:access:wiki.example.org"
    # Accepting it is ignoring that finding: the item leaves the queue.
    r = c.post("/api/discovery/ignores", headers=TOKEN,
               json={"key": it["accept"], "label": "wiki.example.org", "reason": "on purpose"})
    assert r.status_code == 201
    keys = [i["key"] for i in c.get("/api/overview", headers=TOKEN).json()["attention"]]
    assert "open:wiki.example.org" not in keys
