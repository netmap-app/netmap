"""Health checks beyond "port open" (app/status.py): the grammar, an HTTP(S)
GET with an expected status, the certificate an https check reads - and that
an empty check is exactly the TCP connect it always was. Every target is a
local server."""
import asyncio
import datetime as dt
import http.server
import ipaddress
import socket
import ssl
import threading

import pytest

TOKEN = {"authorization": "Bearer full-token"}


class Web:
    """A local HTTP(S) server: /health answers `status`, and every request's
    Host header is recorded."""

    def __init__(self, certfile=None, keyfile=None):
        self.status, self.hosts = 200, []
        web = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                web.hosts.append(self.headers.get("host"))
                self.send_response(web.status if self.path == "/health" else 200)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def self_signed(tmp_path, days: float):
    """A certificate for localhost / 127.0.0.1 that expires in `days`."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=30))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
            .sign(key, hashes.SHA256()))
    c, k = tmp_path / f"c{days}.pem", tmp_path / f"k{days}.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return str(c), str(k)


@pytest.fixture
def app(make_app):
    main, c = make_app(NETMAP_API_TOKEN="full-token")
    return c


@pytest.fixture
def web():
    w = Web()
    yield w
    w.close()


def check(entry: dict) -> dict:
    from app import status
    return asyncio.run(status.run_check({"monitor": True, **entry}))


# ---- the grammar -------------------------------------------------------------------------------
@pytest.mark.parametrize("spec", ["", "tcp", "tcp:22", "http", "https:8443/health=200",
                                  "http/ready", "https=204", "ping", "none", " PING "])
def test_valid_checks_are_accepted(app, spec):
    r = app.post("/api/entries", headers=TOKEN, json={"name": "x", "healthcheck": spec})
    assert r.status_code == 201, r.text
    assert r.json()["healthcheck"] == spec.strip()


@pytest.mark.parametrize("spec", ["ftp", "tcp/health", "https:0", "https:70000",
                                  "http:80/a b", "https=99", "ping:1", "tcp:x"])
def test_bad_checks_are_refused(app, spec):
    r = app.post("/api/entries", headers=TOKEN, json={"name": "x", "healthcheck": spec})
    assert r.status_code == 400 and "health check" in r.json()["detail"]


# ---- empty and tcp -----------------------------------------------------------------------------
def test_an_empty_check_is_the_tcp_connect_it_always_was(web):
    from app import status
    e = {"monitor": True, "ip": "127.0.0.1", "ports": f"{web.port}, 22"}
    assert status.plan(e) == {"kind": "tcp", "host": "127.0.0.1", "port": web.port}
    assert status.target_for(e) == ("127.0.0.1", web.port)
    r = check(e)
    assert r["up"] is True and r["target"] == f"127.0.0.1:{web.port}"
    assert r["summary"].startswith(f"TCP 127.0.0.1:{web.port} in ")
    assert web.hosts == []                                  # a connect, not a request


def test_tcp_with_a_port_probes_that_port(web):
    r = check({"ip": "127.0.0.1", "ports": "1", "healthcheck": f"tcp:{web.port}"})
    assert r["up"] is True and r["target"] == f"127.0.0.1:{web.port}"


def test_none_is_monitored_but_not_probed():
    r = check({"ip": "127.0.0.1", "ports": "1", "healthcheck": "none"})
    assert r["up"] is None and r["check"] == "none" and "not probed" in r["summary"]


# ---- http --------------------------------------------------------------------------------------
def test_http_up_below_500_and_down_on_503(web):
    e = {"ip": "127.0.0.1", "healthcheck": f"http:{web.port}/health"}
    web.status = 404
    r = check(e)
    assert r["up"] is True and r["http_status"] == 404
    web.status = 503
    r = check(e)
    assert r["up"] is False and r["http_status"] == 503
    assert r["summary"].startswith(f"HTTP 127.0.0.1:{web.port}/health → 503 in ")


def test_http_with_an_expected_code(web):
    e = {"ip": "127.0.0.1", "healthcheck": f"http:{web.port}/health=204"}
    r = check(e)
    assert r["up"] is False and r["http_status"] == 200
    assert "→ 200 (want 204)" in r["summary"]
    web.status = 204
    assert check(e)["up"] is True


def test_the_url_names_the_host_and_gives_the_port(web):
    r = check({"ip": "127.0.0.1", "url": f"http://svc.example:{web.port}/",
               "healthcheck": "http/health"})
    assert r["up"] is True and web.hosts == ["svc.example"]


def test_nothing_listening_is_down_with_a_reason():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = check({"ip": "127.0.0.1", "healthcheck": f"http:{port}"})
    assert r["up"] is False and r["http_status"] is None
    assert "ConnectionRefused" in r["summary"]


# ---- https and certificates --------------------------------------------------------------------
def test_https_503_is_down_while_the_port_is_open(tmp_path):
    """The plan's "done when": the port answers, the service does not."""
    w = Web(*self_signed(tmp_path, 200))
    try:
        w.status = 503
        e = {"ip": "127.0.0.1", "ports": str(w.port), "healthcheck": f"https:{w.port}/health=200"}
        assert check({**e, "healthcheck": ""})["up"] is True     # TCP says fine
        r = check(e)
        assert r["up"] is False and r["http_status"] == 503
        w.status = 200
        assert check(e)["up"] is True
    finally:
        w.close()


def test_an_untrusted_certificate_is_its_own_state_not_down(tmp_path):
    w = Web(*self_signed(tmp_path, 200))
    try:
        r = check({"ip": "127.0.0.1", "healthcheck": f"https:{w.port}/health"})
        assert r["up"] is True
        assert r["tls"]["valid"] is False and "self" in r["tls"]["error"].lower()
        assert 198 <= r["tls"]["days_left"] <= 200 and r["tls"]["soon"] is False
        assert "TLS invalid" in r["summary"]
    finally:
        w.close()


def test_a_certificate_close_to_expiry_reaches_the_overview(make_app, tmp_path):
    make_app(NETMAP_API_TOKEN="full-token")
    soon, gone = Web(*self_signed(tmp_path, 5)), Web(*self_signed(tmp_path, -1))
    try:
        from app import db, overview, status
        a = db.create_entry({"name": "Vault", "ip": "127.0.0.1", "healthcheck": f"https:{soon.port}"})
        b = db.create_entry({"name": "Wiki", "ip": "127.0.0.1", "healthcheck": f"https:{gone.port}"})
        db.create_entry({"name": "Plain", "ip": "127.0.0.1", "ports": str(soon.port)})
        asyncio.run(status.sweep())
        assert status.CACHE[a["id"]]["tls"]["soon"] is True
        items = {i["key"]: i for i in overview.snapshot(status.CACHE)["attention"]}
        assert items[f"cert:{a['id']}"]["level"] == "warn"
        assert "expires on" in items[f"cert:{a['id']}"]["title"]
        assert items[f"cert:{b['id']}"]["level"] == "critical"
        assert "has expired" in items[f"cert:{b['id']}"]["title"]
        assert len([k for k in items if k.startswith("cert:")]) == 2

        status.set_tls_warn_days(3)                          # 5 days out is fine now
        asyncio.run(status.sweep())
        items = {i["key"] for i in overview.snapshot(status.CACHE)["attention"]}
        assert f"cert:{a['id']}" not in items and f"cert:{b['id']}" in items
    finally:
        soon.close()
        gone.close()


def test_the_warning_window_is_a_setting_with_bounds(app):
    assert app.get("/api/settings/checks", headers=TOKEN).json()["tls_warn_days"] == 21
    assert app.put("/api/settings/checks", headers=TOKEN,
                   json={"tls_warn_days": 0}).status_code == 400
    assert app.put("/api/settings/checks", headers=TOKEN,
                   json={"tls_warn_days": "x"}).status_code == 400
    r = app.put("/api/settings/checks", headers=TOKEN, json={"tls_warn_days": 30})
    assert r.status_code == 200 and r.json()["tls_warn_days"] == 30


# ---- ping --------------------------------------------------------------------------------------
def test_ping_not_permitted_is_unknown_not_down(monkeypatch):
    from app import status

    real = socket.socket

    def refuse_icmp(family=-1, type=-1, proto=-1, *a):
        if proto == socket.IPPROTO_ICMP:
            raise PermissionError(1, "Operation not permitted")
        return real(family, type, proto, *a)
    monkeypatch.setattr(status.socket, "socket", refuse_icmp)
    r = check({"ip": "127.0.0.1", "healthcheck": "ping"})
    assert r["up"] is None and "ping_group_range" in r["summary"]


def test_ping_localhost_when_the_system_allows_it():
    try:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP).close()
    except OSError:
        pytest.skip("unprivileged ping sockets are not allowed here")
    r = check({"ip": "127.0.0.1", "healthcheck": "ping"})
    assert r["up"] is True and r["summary"].startswith("ping 127.0.0.1 in ")


# ---- records and notifications -----------------------------------------------------------------
def test_a_transition_records_what_was_checked(make_app, web):
    make_app(NETMAP_API_TOKEN="full-token")
    from app import db, status
    e = db.create_entry({"name": "api", "ip": "127.0.0.1",
                         "healthcheck": f"http:{web.port}/health"})
    web.status = 503
    asyncio.run(status.check_entry(e))
    o = db.last_observation(e["id"])
    assert o["up"] is False and "→ 503" in o["detail"]


def test_channels_that_had_every_event_also_get_certificates(make_app):
    make_app(NETMAP_API_TOKEN="full-token")
    from app import db, notify
    everything = db.save_notify_channel(None, "webhook", "all", {}, {},
                                        ["finding", "entry", "source", "critical"], True)
    few = db.save_notify_channel(None, "webhook", "few", {}, {}, ["entry"], True)
    notify.upgrade_events()
    notify.upgrade_events()                                  # once only
    assert "cert" in db.get_notify_channel(everything["id"])["events"]
    assert db.get_notify_channel(few["id"])["events"] == ["entry"]
    assert "cert" in notify.create("webhook", "new", {"url": "http://x"})["events"]
