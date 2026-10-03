"""What answers on an open port (app/fingerprint.py): rules against canned
answers, real probes of local servers — HTTP, HTTPS, a greeting, a web
manifest — the private-address guard, and both scanners using it. Every
server is on 127.0.0.1."""
import http.server
import json
import re
import socket
import ssl
import threading
import time

import pytest


class Web:
    """A local HTTP(S) server: / answers `page` with `headers`; /manifest.json
    answers `manifest` when set, else 404."""

    def __init__(self, page="", headers=None, manifest=None, tls=None):
        self.page, self.headers, self.manifest, self.paths = page, headers or {}, manifest, []
        me = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                me.paths.append(self.path)
                if self.path == "/manifest.json" and me.manifest is not None:
                    body, ctype = json.dumps(me.manifest).encode(), "application/json"
                elif self.path == "/":
                    body, ctype = me.page.encode(), "text/html; charset=utf-8"
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("content-type", ctype)
                for k, v in me.headers.items():
                    self.send_header(k, v)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def greeter(line: bytes):
    """A TCP server that speaks first, as SSH does."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()

    def serve():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            try:
                c.sendall(line)
                time.sleep(0.2)
            finally:
                c.close()
    threading.Thread(target=serve, daemon=True).start()
    return s, s.getsockname()[1]


# ---- rules -------------------------------------------------------------------------------------
def test_rules_match_canned_answers():
    from app import fingerprint as fp
    assert fp.identify({"title": "Grafana"})["name"] == "Grafana"
    assert fp.identify({"title": "Grafana"})["icon"] == "grafana"
    assert fp.identify({"headers": {"x-plex-protocol": "1.0"}})["name"] == "Plex"
    assert fp.identify({"banner": "SSH-2.0-OpenSSH_9.6"}) == {"name": "SSH", "protocol": "ssh",
                                                             "icon": ""}
    assert fp.identify({"body": "Ollama is running"})["name"] == "Ollama"
    assert fp.identify({"title": "Proxmox Backup Server"})["name"] == "Proxmox Backup Server"
    assert fp.identify({"title": "Some page", "server": "nginx"}) == {}


def test_the_rules_file_is_sane():
    from app import fingerprint as fp, icons
    names = set()
    for r in fp.rules():
        assert r["name"] and r["_c"], r
        assert not r.get("icon") or icons.SLUG_RE.match(r["icon"]), r["icon"]
        names.add(r["name"])
    assert len(names) > 40


def test_parse_http():
    from app import fingerprint as fp
    r = fp.parse_http(b"HTTP/1.1 302 Found\r\nServer: nginx/1.25\r\nLocation: /web/\r\n\r\n"
                      b"<html><title>\n  Jelly &amp; fin </title></html>")
    assert r["status"] == 302 and r["server"] == "nginx/1.25" and r["location"] == "/web/"
    assert r["title"] == "Jelly & fin"
    assert fp.parse_http(b"SSH-2.0-x\r\n") is None


# ---- probing -----------------------------------------------------------------------------------
def test_an_http_app_is_named_by_its_title():
    from app import fingerprint as fp
    w = Web("<html><head><title>Grafana</title></head></html>", {"Server": "nginx"})
    try:
        r = fp.probe("127.0.0.1", w.port)
        assert r["identified"] and r["name"] == "Grafana" and r["protocol"] == "http"
        assert r["icon"] == "grafana" and r["url"] == f"http://127.0.0.1:{w.port}/"
        assert fp.label(r) == "Grafana (HTTP)"
        assert w.paths == ["/"]                                   # nothing else asked
    finally:
        w.close()


def test_an_https_port_is_asked_over_tls(tmp_path):
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from test_checks import self_signed
    from app import fingerprint as fp
    w = Web("<title>Uptime Kuma</title>", tls=self_signed(tmp_path, 30))
    try:
        r = fp.probe("127.0.0.1", w.port)
        assert r["name"] == "Uptime Kuma" and r["protocol"] == "https"
        assert r["url"].startswith("https://")
    finally:
        w.close()


def test_a_greeting_is_read_before_anything_is_sent():
    from app import fingerprint as fp
    s, port = greeter(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
    try:
        r = fp.probe("127.0.0.1", port)
        assert r["name"] == "SSH" and r["protocol"] == "ssh" and r["identified"]
        assert r["banner"].startswith("SSH-2.0-OpenSSH")
    finally:
        s.close()


def test_an_unknown_app_names_itself_in_its_manifest():
    from app import fingerprint as fp
    w = Web("<title>Loading…</title>", manifest={"name": "Homebox", "short_name": "HB"})
    try:
        r = fp.probe("127.0.0.1", w.port)
        assert r["name"] == "Homebox" and r["identified"]
        assert w.paths == ["/", "/manifest.json"]
    finally:
        w.close()


def test_without_a_rule_or_manifest_the_title_is_said_not_claimed():
    from app import fingerprint as fp
    w = Web("<title>My Dashboard</title>", {"Server": "lighttpd/1.4"})
    try:
        r = fp.probe("127.0.0.1", w.port)
        assert r["name"] == "My Dashboard" and not r["identified"]
        assert r["server"] == "lighttpd/1.4"
    finally:
        w.close()


def test_public_addresses_are_never_contacted(monkeypatch):
    from app import fingerprint as fp

    def refuse(*a, **k):
        raise AssertionError("contacted a public address")
    monkeypatch.setattr(fp.socket, "create_connection", refuse)
    r = fp.probe("8.8.8.8", 80)
    assert r["name"] == "HTTP" and not r["identified"]


# ---- the scanners ------------------------------------------------------------------------------
def test_the_sweep_names_an_undeclared_port_and_drafts_an_entry(make_app, monkeypatch):
    make_app()
    from app import db, sources
    from app.sources import portscan
    w = Web("<title>Grafana</title>")
    try:
        monkeypatch.setattr(portscan, "_probe", lambda ip, port, t: "open" if port == w.port else "closed")
        host = db.create_entry({"name": "Docker host", "ip": "127.0.0.1", "kind": "vm",
                                "ports": "22"})
        sources.create_instance("ports", "", {"enabled": True, "extra_ports": str(w.port)})
        r = sources.scan("ports")
        (f,) = [f for f in r["findings"] if f["type"] == "port-undeclared"]
        assert f["label"] == f"Grafana (HTTP) on 127.0.0.1:{w.port} — not in NetMap"
        assert 'title "Grafana"' in f["detail"] and f["entry"]["id"] == host["id"]
        d = f["draft"]
        assert d["name"] == "Grafana" and d["ports"] == str(w.port) and d["host"] == "Docker host"
        assert d["tags"] == "icon:grafana" and d["url"] == f"http://127.0.0.1:{w.port}/"
        assert r["counts"]["identified"] == 1
        facts = {s["fact"]: s["value"] for s in db.sightings_for(host["id"])}
        assert facts[f"port:{w.port}"] == "open — Grafana (HTTP)"
        e = db.create_entry(d)                                    # the draft is valid as it is
        assert e["tags"] == ["icon:grafana"]
    finally:
        w.close()


def test_fingerprinting_can_be_switched_off(make_app, monkeypatch):
    make_app()
    from app import db, fingerprint, sources
    from app.sources import portscan
    monkeypatch.setattr(portscan, "_probe", lambda ip, port, t: "open" if port == 3000 else "closed")
    monkeypatch.setattr(fingerprint, "probe", lambda *a: pytest.fail("probed"))
    db.create_entry({"name": "Box", "ip": "127.0.0.1"})
    sources.create_instance("ports", "", {"enabled": True, "fingerprint": False})
    (f,) = [f for f in sources.scan("ports")["findings"] if f["type"] == "port-undeclared"]
    assert f["label"] == "Box — 127.0.0.1:3000 is open (HTTP app)"


def test_the_deep_scan_says_what_answers(make_app):
    make_app()
    from app import deepscan
    w = Web("<title>Home Assistant</title>")
    try:
        deepscan.start("127.0.0.1", w.port, w.port)
        for _ in range(100):
            if deepscan.status()["state"] != "running":
                break
            time.sleep(0.05)
        job = deepscan.status()
        assert job["results"] == [{"port": w.port, "service": "Home Assistant (HTTP)",
                                   "identified": True, "url": f"http://127.0.0.1:{w.port}/",
                                   "declared": False}]
        assert re.search(rf"{w.port}\s+Home Assistant \(HTTP\)", deepscan.summarise(job))
    finally:
        w.close()
