"""The Docker source against every way an engine is reached — a socket proxy or
plain TCP (http://), the TLS port with a client certificate (https://), a
mounted socket (unix://) — and the containers Compose, Swarm and macvlan make.
Every engine here is a local fake that answers /containers/json; nothing
leaves the machine."""
import datetime as dt
import http.server
import ipaddress
import json
import os
import socketserver
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CONTAINERS = [
    {"Names": ["/plex"], "Image": "plexinc/pms", "State": "running", "Status": "Up 2 days",
     "Ports": [{"IP": "0.0.0.0", "PrivatePort": 32400, "PublicPort": 32400, "Type": "tcp"},
               {"IP": "::", "PrivatePort": 32400, "PublicPort": 32400, "Type": "tcp"}],
     "Labels": {}, "HostConfig": {"NetworkMode": "bridge"},
     "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}}},
]


class Engine(http.server.BaseHTTPRequestHandler):
    status, body, seen = 200, CONTAINERS, []

    def do_GET(self):
        Engine.seen.append((self.command, self.path))
        data = json.dumps(Engine.body).encode()
        self.send_response(Engine.status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass

    def address_string(self):                     # a Unix socket has no address
        return "local"


@pytest.fixture(autouse=True)
def reset():
    Engine.status, Engine.body, Engine.seen = 200, CONTAINERS, []


def serve(srv):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def app_(make_app):
    make_app()
    from app import db
    from app.sources import docker
    return db, docker


def cfg(url, **kw):
    return {"url": url, "host_ip": "10.0.0.10", "host": "box", "timeout": 3,
            "verify_ssl": True, "_id": "docker", "_key": "docker", **kw}


# ---- the ways in -----------------------------------------------------------------------------
def test_http_a_proxy_or_the_plain_port(app_):
    _, docker = app_
    srv = serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Engine))
    try:
        c = cfg(f"http://127.0.0.1:{srv.server_address[1]}")
        assert docker.test(c) == {"ok": True, "error": None, "containers": 1}
        out = docker.scan(c)
        assert out["error"] is None and [f["label"] for f in out["findings"]] == ["plex"]
        assert all(m == "GET" for m, _ in Engine.seen)                 # read-only, checkably
    finally:
        srv.shutdown()


def test_a_mounted_socket(app_, tmp_path):
    _, docker = app_
    path = str(tmp_path / "docker.sock")

    class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
    srv = serve(UnixServer(path, Engine))
    try:
        assert docker.test(cfg(f"unix://{path}"))["ok"]
        assert "no socket at" in docker.test(cfg(f"unix://{tmp_path}/nope.sock"))["error"]
    finally:
        srv.shutdown()


def _pki(tmp_path):
    """A private CA, a server certificate for 127.0.0.1 and a client one."""
    now = dt.datetime.now(dt.timezone.utc)

    def cert(name, key, issuer, issuer_key, ca=False, ip=None):
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
             .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if ip:
            b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
        return b.sign(issuer_key, hashes.SHA256())

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
    ca = cert("test CA", ca_key, ca_name, ca_key, ca=True)
    keys = {n: ec.generate_private_key(ec.SECP256R1()) for n in ("server", "client")}
    certs = {"server": cert("server", keys["server"], ca_name, ca_key, ip="127.0.0.1"),
             "client": cert("client", keys["client"], ca_name, ca_key)}
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()          # noqa: E731
    kpem = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,  # noqa: E731
                                     serialization.NoEncryption()).decode()
    files = {}
    for n, text in (("ca", pem(ca)), ("server", pem(certs["server"])), ("server.key", kpem(keys["server"]))):
        files[n] = tmp_path / f"{n}.pem"
        files[n].write_text(text)
    return files, pem(ca), pem(certs["client"]), kpem(keys["client"])


def test_the_tls_port_with_a_client_certificate(app_, tmp_path, monkeypatch):
    _, docker = app_
    files, ca, ccert, ckey = _pki(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))   # where the key passes through
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(files["server"], files["server.key"])
    ctx.load_verify_locations(files["ca"])
    ctx.verify_mode = ssl.CERT_REQUIRED                   # dockerd --tlsverify
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Engine)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    serve(srv)
    url = f"https://127.0.0.1:{srv.server_address[1]}"
    try:
        # The daemon's certificate is signed by a CA nobody else trusts.
        assert "did not verify" in docker.test(cfg(url))["error"]
        # Trusting it is not enough: the daemon wants to know who is asking.
        assert "client certificate" in docker.test(cfg(url, ca_cert=ca))["error"]
        # A key pasted into a password field arrives without its line breaks.
        one_line = " ".join(ckey.splitlines())
        assert docker.test(cfg(url, ca_cert=ca, client_cert=ccert, client_key=one_line))["ok"]
        # Not checking the daemon's certificate still presents ours.
        assert docker.test(cfg(url, verify_ssl=False, client_cert=ccert, client_key=ckey))["ok"]
        assert "needs its key" in docker.test(cfg(url, ca_cert=ca, client_cert=ccert))["error"]
        assert "not PEM" in docker.test(cfg(url, ca_cert="nonsense"))["error"]
    finally:
        srv.shutdown()
    assert os.listdir(scratch) == []                   # the key did not stay on disk


def test_the_key_is_a_secret_and_the_address_binds_it(make_app):
    _, c = make_app(NETMAP_API_TOKEN="t")
    h = {"authorization": "Bearer t"}
    r = c.post("/api/sources/instances", headers=h, json={"type": "docker", "fields": {
        "url": "https://10.0.0.10:2376", "host_ip": "10.0.0.10", "client_key": "-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----"}})
    assert r.status_code == 201 and "BEGIN" not in r.text
    r = c.put("/api/sources/instances/docker", headers=h, json={"fields": {"url": "https://10.9.9.9:2376"}})
    assert r.status_code == 400 and "Client key" in r.json()["detail"]


def test_errors_speak_of_the_way_in(app_):
    _, docker = app_
    srv = serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Engine))
    try:
        c = cfg(f"http://127.0.0.1:{srv.server_address[1]}")
        Engine.status = 403
        assert "CONTAINERS=1" in docker.test(c)["error"]
        Engine.status = 404
        assert "does not lead to a Docker API" in docker.test(c)["error"]
    finally:
        srv.shutdown()


# ---- what Compose, Swarm and macvlan make ------------------------------------------------------
def _scan(app_, monkeypatch, containers):
    db, docker = app_
    monkeypatch.setattr(docker, "fetch_containers", lambda cfg: containers)
    return docker.scan(cfg("http://x"))


def test_a_compose_service_name_matches_its_entry(app_, monkeypatch):
    db, _ = app_
    db.create_entry({"name": "Vaultwarden", "ip": "10.0.0.10", "kind": "container"})
    out = _scan(app_, monkeypatch, [{"Names": ["/pwstack-vaultwarden-1"], "Image": "vw", "State": "running",
                                     "Labels": {"com.docker.compose.service": "vaultwarden"}}])
    assert out["findings"] == [] and out["counts"]["matched"] == 1


def test_swarm_replicas_are_one_service_with_a_stable_key(app_, monkeypatch):
    task = lambda n: {"Names": [f"/web.{n}.x{n}abc"], "Image": "nginx", "State": "running",   # noqa: E731
                      "Labels": {"com.docker.swarm.service.name": "web"}}
    out = _scan(app_, monkeypatch, [task(1), task(2), task(3)])
    assert [f["key"] for f in out["findings"]] == ["docker:new:web"]
    assert out["findings"][0]["draft"]["name"] == "web"


def test_a_macvlan_container_matches_at_its_own_address(app_, monkeypatch):
    db, _ = app_
    db.create_entry({"name": "Pi-hole (DNS)", "ip": "10.0.0.53", "kind": "container"})
    out = _scan(app_, monkeypatch, [{"Names": ["/dns"], "Image": "pihole", "State": "running",
                                     "NetworkSettings": {"Networks": {"lan": {"IPAddress": "10.0.0.53"}}}}])
    assert out["findings"] == [] and out["counts"]["matched"] == 1
