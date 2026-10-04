"""GET /metrics (app/metrics.py): valid Prometheus text, every label value
escaped, and behind authentication - with a token that opens nothing else."""
import re

import pytest

TOKEN = {"authorization": "Bearer full-token"}
SCRAPE = {"authorization": "Bearer scrape-token"}

SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (NaN|[+-]?Inf|-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\[\\"n])*)"(,|$)')


def parse(text: str) -> dict[str, list[tuple[dict, str]]]:
    """A strict little reader for the text format: every sample belongs to a
    family declared by HELP and TYPE before it, and every label parses."""
    assert text.endswith("\n")
    fams: dict[str, list] = {}
    declared, typed = set(), set()
    for line in text.rstrip("\n").split("\n"):
        if line.startswith("# HELP "):
            declared.add(line.split()[2])
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split()
            assert kind == "gauge" and name in declared
            typed.add(name)
            fams.setdefault(name, [])
            continue
        m = SAMPLE.match(line)
        assert m, f"not a sample: {line!r}"
        name, raw, value = m.groups()
        assert name in typed, f"{name} has no TYPE"
        labels, pos = {}, 0
        while raw and pos < len(raw):
            lm = LABEL.match(raw, pos)
            assert lm, f"bad labels in {line!r}"
            labels[lm.group(1)] = (lm.group(2).replace("\\n", "\n").replace('\\"', '"')
                                   .replace("\\\\", "\\"))
            pos = lm.end()
        fams[name].append((labels, value))
    return fams


@pytest.fixture
def app(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token", NETMAP_METRICS_TOKEN="scrape-token",
                    NETMAP_SUMMARY_TOKEN="summary-token")
    return c


def test_metrics_need_a_token(app):
    assert app.get("/metrics").status_code == 401
    assert app.get("/metrics", headers={"authorization": "Bearer summary-token"}).status_code == 401
    r = app.get("/metrics", headers=TOKEN)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain; version=0.0.4")


def test_the_metrics_token_opens_metrics_and_nothing_else(app):
    assert app.get("/metrics", headers=SCRAPE).status_code == 200
    assert app.get("/api/entries", headers=SCRAPE).status_code == 401
    assert app.get("/api/summary", headers=SCRAPE).status_code == 401
    assert app.post("/api/entries", headers=SCRAPE, json={"name": "x"}).status_code == 401


def test_an_empty_install_is_valid_and_says_its_version(app):
    fams = parse(app.get("/metrics", headers=SCRAPE).text)
    from app import main
    assert fams["netmap_build_info"] == [({"version": main.VERSION}, "1")]
    assert fams["netmap_entry_up"] == [] and fams["netmap_source_up"] == []


def test_entries_sources_and_findings(app, monkeypatch):
    from app import db, discovery, sources, status
    a = db.create_entry({"name": 'odd "name" \\ with\nnewline', "ip": "10.0.0.1",
                         "ports": "80", "criticality": "critical"})
    b = db.create_entry({"name": "twin", "ip": "10.0.0.2", "ports": "80"})
    c = db.create_entry({"name": "twin", "ip": "10.0.0.3", "ports": "80"})
    db.create_entry({"name": "unwatched", "monitor": False})
    status.CACHE.update({
        a["id"]: {"up": True, "latency_ms": 12, "check": "https",
                  "tls": {"not_after": "2026-12-01T00:00:00Z", "days_left": 60}},
        b["id"]: {"up": False, "latency_ms": None, "check": "tcp"},
    })

    class Fake:
        FIELDS: list = []

        def configured(self, cfg):
            return True

        def scan(self, cfg):
            return {"findings": [{"key": "k1", "type": "open"}, {"key": "k2", "type": "open"},
                                 {"key": "k3", "type": "dns"}], "error": None}
    from app.sources import dynamic
    monkeypatch.setitem(dynamic.DRIVERS, "fake", {"mod": Fake(), "label": "Fake", "hint": ""})
    sources.create_instance("fake", "Fake", {})
    discovery.scan("fake")

    fams = parse(app.get("/metrics", headers=SCRAPE).text)
    up = {int(l["id"]): (l, v) for l, v in fams["netmap_entry_up"]}
    assert set(up) == {a["id"], b["id"], c["id"]}               # monitored only
    assert up[a["id"]][0]["entry"] == 'odd "name" \\ with\nnewline'
    assert up[a["id"]][0]["criticality"] == "critical" and up[a["id"]][0]["check"] == "https"
    assert up[a["id"]][1] == "1" and up[b["id"]][1] == "0" and up[c["id"]][1] == "NaN"
    assert fams["netmap_entry_latency_ms"] == [({"id": str(a["id"]), "entry": a["name"]}, "12")]
    assert fams["netmap_cert_expiry_timestamp_seconds"][0][1] == "1796083200"
    assert fams["netmap_source_up"] == [({"source": "fake", "type": "fake"}, "1")]
    assert sorted(fams["netmap_findings"], key=lambda x: x[0]["type"]) == [
        ({"source": "fake", "type": "dns"}, "1"), ({"source": "fake", "type": "open"}, "2")]
    assert fams["netmap_source_findings"] == [({"source": "fake"}, "3")]
    assert fams["netmap_source_last_success_timestamp_seconds"][0][0] == {"source": "fake"}


def test_a_failing_source_is_down_and_reports_no_finding_counts(app, monkeypatch):
    from app import discovery, sources
    from app.sources import dynamic

    class Broken:
        FIELDS: list = []

        def configured(self, cfg):
            return True

        def scan(self, cfg):
            return {"findings": [], "error": "HTTP 401"}
    monkeypatch.setitem(dynamic.DRIVERS, "broken", {"mod": Broken(), "label": "B", "hint": ""})
    sources.create_instance("broken", "B", {})
    fams = parse(app.get("/metrics", headers=SCRAPE).text)
    assert fams["netmap_source_up"] == [({"source": "broken", "type": "broken"}, "NaN")]
    discovery.scan("broken")
    fams = parse(app.get("/metrics", headers=SCRAPE).text)
    assert fams["netmap_source_up"] == [({"source": "broken", "type": "broken"}, "0")]
    assert fams["netmap_source_findings"] == []                 # unknown, not zero
    assert fams["netmap_source_last_success_timestamp_seconds"] == []
