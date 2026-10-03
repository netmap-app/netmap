"""What answers on an open port — "Grafana on :3000", not "port 3000 open".

Used by both scanners: the scheduled sweep (sources/portscan.py), for the
ports nothing in the inventory accounts for, and the on-demand deep scan
(deepscan.py). Each open port gets one short conversation:

  1. wait briefly for a greeting — SSH, SMTP, FTP and VNC speak first;
  2. otherwise GET / over plain HTTP, and over TLS when the answer says the
     port wants it;
  3. when the page is an app nobody's rule names, GET /manifest.json, where
     a web app states its own name.

Every request is a GET of / or /manifest.json: nothing that can change
anything. At most a few KB are read. Only private and loopback addresses are
ever contacted — the same line deepscan.py draws.

The rules live in app/fingerprints.json so adding one needs no code. When
none matches, the name is guessed from the port number (PORT_NAMES), which is
a label to think with, not evidence.
"""
import html
import ipaddress
import json
import os
import re
import socket
import ssl

TIMEOUT = 1.5
READ = 8192

# What a port number usually means — the one table both scanners use.
# Deliberately short: a wrong confident name is worse than none.
PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    81: "HTTP (alt)", 110: "POP3", 111: "rpcbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 548: "AFP",
    587: "SMTP", 631: "IPP", 873: "rsync", 902: "VMware", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1883: "MQTT", 2049: "NFS",
    2375: "Docker API (plain)", 2376: "Docker API (TLS)", 3000: "HTTP app",
    3128: "SPICE / proxy", 3306: "MySQL", 3389: "RDP", 5000: "DSM / HTTP",
    5001: "DSM HTTPS", 5432: "PostgreSQL", 5357: "WS-Discovery", 5580: "Matter",
    5900: "VNC", 6379: "Redis", 8006: "Proxmox VE", 8007: "PBS",
    8080: "HTTP (alt)", 8081: "HTTP (alt)", 8083: "HTTP (alt)", 8123: "Home Assistant",
    8181: "HTTP (alt)", 8443: "HTTPS (alt)", 9090: "Cockpit",
    9100: "printer / node-exporter", 10000: "Webmin", 11211: "memcached",
    27017: "MongoDB", 32400: "Plex", 51820: "WireGuard", 61208: "Glances",
}

_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fingerprints.json")
_RULES: list[dict] | None = None
_FIELDS = ("title", "server", "location", "body", "banner")


def rules() -> list[dict]:
    global _RULES
    if _RULES is None:
        with open(_RULES_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)["rules"]
        _RULES = []
        for r in raw:
            c = {k: re.compile(r[k], re.I) for k in _FIELDS if k in r}
            if "header" in r:
                name, _, pat = r["header"].partition(":")
                c["header"] = (name.strip().lower(), re.compile(pat.strip(), re.I))
            _RULES.append({**r, "_c": c})
    return _RULES


def private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return a.version == 4 and (a.is_private or a.is_loopback)


def identify(seen: dict) -> dict:
    """The first rule every one of whose patterns matches what was seen:
    {name, protocol, icon}, or {}."""
    for r in rules():
        c = r["_c"]
        ok = True
        for k in _FIELDS:
            if k in c and not c[k].search(seen.get(k) or ""):
                ok = False
                break
        if ok and "header" in c:
            name, pat = c["header"]
            ok = bool(pat.search((seen.get("headers") or {}).get(name, "")))
        if ok and len(c):
            return {"name": r["name"], "protocol": r.get("protocol", ""), "icon": r.get("icon", "")}
    return {}


# ---- talking to a port ----------------------------------------------------------------------
def _read(sock, limit: int = READ) -> bytes:
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(limit - len(data))
            if not chunk:
                break
            data += chunk
    except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
        pass
    return data


def _connect(ip: str, port: int, tls: bool):
    s = socket.create_connection((ip, port), timeout=TIMEOUT)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE           # we want the name, not trust
        s = ctx.wrap_socket(s, server_hostname=None)
    s.settimeout(TIMEOUT)
    return s


def _get(ip: str, port: int, path: str, tls: bool, limit: int = READ) -> bytes:
    with _connect(ip, port, tls) as s:
        host = ip if (tls and port == 443) or (not tls and port == 80) else f"{ip}:{port}"
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: NetMap fingerprint\r\nAccept: */*\r\n"
                   "Connection: close\r\n\r\n").encode())
        return _read(s, limit)


def parse_http(raw: bytes) -> dict | None:
    """status, headers (lowercased names), title, body text — or None."""
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", raw)
    if not m:
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.decode("latin-1").partition(":")
        if k.strip():
            headers[k.strip().lower()] = v.strip()
    text = body.decode("utf-8", "replace")
    t = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = " ".join(html.unescape(t.group(1)).split())[:80] if t else ""
    return {"status": int(m.group(1)), "headers": headers, "title": title,
            "server": headers.get("server", ""), "location": headers.get("location", ""),
            "body": text}


def _manifest_name(ip: str, port: int, tls: bool) -> str:
    try:
        r = parse_http(_get(ip, port, "/manifest.json", tls, 4096))
        if r and r["status"] == 200:
            doc = json.loads(r["body"][r["body"].index("{"):])
            return str(doc.get("name") or doc.get("short_name") or "").strip()[:60]
    except Exception:
        pass
    return ""


def probe(ip: str, port: int) -> dict:
    """What answers at ip:port: {port, protocol, name, identified, title,
    server, banner, icon, url}. Never raises; an unreadable port comes back
    with only a guess from the port number."""
    out = {"port": port, "protocol": "", "name": "", "identified": False, "title": "",
           "server": "", "banner": "", "icon": "", "url": ""}
    if not private(ip):
        out["name"] = PORT_NAMES.get(port, "")
        return out
    seen: dict = {}
    try:
        with _connect(ip, port, False) as s:
            s.settimeout(0.8)
            greet = _read(s, 512)
        if greet and not greet.startswith(b"HTTP/"):
            seen["banner"] = greet.decode("utf-8", "replace").split("\n")[0].strip()[:200]
    except OSError:
        pass
    tls = False
    if not seen.get("banner"):
        r = None
        try:
            r = parse_http(_get(ip, port, "/", False))
        except OSError:
            pass
        # An HTTPS port asked in plain HTTP answers garbage, nothing, or a
        # 400 that says so.
        if r is None or (r["status"] == 400 and "https" in r["body"].lower()):
            try:
                r2 = parse_http(_get(ip, port, "/", True))
                if r2:
                    r, tls = r2, True
            except (OSError, ssl.SSLError):
                pass
        if r:
            seen.update(r)
            out["protocol"] = "https" if tls else "http"
            out["url"] = f"{'https' if tls else 'http'}://{ip}:{port}/"
    out["title"], out["server"] = seen.get("title", ""), seen.get("server", "")
    out["banner"] = seen.get("banner", "")
    hit = identify(seen)
    if not hit and out["protocol"] and "html" in (seen.get("headers") or {}).get("content-type", ""):
        name = _manifest_name(ip, port, tls)
        if name:
            hit = identify({"title": name}) or {"name": name}
    if hit:
        out.update(name=hit["name"], identified=True, icon=hit.get("icon", ""))
        out["protocol"] = hit.get("protocol") or out["protocol"]
    else:
        # Say what is known: a page title, a server header, a banner — or the
        # port number's usual meaning, marked as a guess by `identified`.
        out["name"] = (out["title"] or out["server"].split("/")[0]
                       or out["banner"][:40] or PORT_NAMES.get(port, ""))
    if not out["protocol"] and out["banner"]:
        out["protocol"] = "tcp"
    return out


def label(fp: dict) -> str:
    """"Grafana (HTTP)", "nginx (HTTPS)", "SSH" — for a finding's headline."""
    if not fp.get("name"):
        return ""
    proto = fp.get("protocol", "")
    return fp["name"] + (f" ({proto.upper()})" if proto in ("http", "https")
                         and fp["name"].upper() not in ("HTTP", "HTTPS") else "")


def many(ip: str, ports: list[int], workers: int = 8) -> dict[int, dict]:
    """probe() for several ports of one host, a few at a time."""
    from concurrent.futures import ThreadPoolExecutor
    if not ports:
        return {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports)))) as pool:
        return dict(zip(ports, pool.map(lambda p: probe(ip, p), ports)))
