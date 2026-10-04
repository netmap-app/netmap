"""Docker (or Podman) as a discovery source.

One read-only call - `GET /containers/json?all=1` on the Docker Engine API -
over whichever way the host offers it:

  http://docker-proxy:2375    a socket proxy (recommended: the proxy is what
                              refuses every write verb) or a daemon's plain
                              TCP port (no authentication - avoid)
  https://host:2376           the daemon's TLS port; optional CA certificate,
                              and the client certificate and key a daemon
                              started with --tlsverify demands
  unix:///var/run/docker.sock a socket mounted into the container - Docker,
                              rootless Docker or Podman's API service

Mounting the socket itself is the least safe of the three: `:ro` restricts the
file, not the API verbs, so anything holding it can create a privileged
container, which is root on the host. This module only ever sends GET, and
that promise is checkable by reading this one file - but a proxy makes it true
whatever the code does.

Nothing here writes to the inventory. A scan returns findings; a person (or
Claude) decides. What persists between scans is only the decision to stop being
told about something - `db.ignores`.
"""
import http.client
import json
import os
import re
import socket
import ssl
import tempfile
import urllib.error
import urllib.request

from .. import db
from . import _http

FIELDS = [
    {"key": "url", "label": "Docker API URL", "type": "text", "required": True,
     "wide": True, "placeholder": "http://docker-proxy:2375, https://host:2376 or unix:///var/run/docker.sock",
     "binds": True, "env": "NETMAP_DOCKER_URL"},
    # host goes in a drafted entry's `host`, host_ip in its `ip` - and host_ip
    # is what scopes this source to the entries on that machine.
    {"key": "host", "label": "Host label (shown on entries)", "type": "text",
     "wide": True, "placeholder": "docker-host", "env": "NETMAP_DOCKER_HOST"},
    {"key": "host_ip", "label": "Host IP", "type": "text", "required": True,
     "placeholder": "10.0.0.10", "env": "NETMAP_DOCKER_HOST_IP"},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 6,
     "env": "NETMAP_DOCKER_TIMEOUT"},
    # https:// only. A daemon started with --tlsverify wants a client
    # certificate; its own certificate is often signed by a private CA.
    {"key": "verify_ssl", "label": "Verify TLS certificate (https)", "type": "checkbox",
     "default": True},
    {"key": "ca_cert", "label": "CA certificate, PEM (https, optional)", "type": "text",
     "wide": True, "placeholder": "-----BEGIN CERTIFICATE----- …"},
    {"key": "client_cert", "label": "Client certificate, PEM (https, optional)",
     "type": "text", "wide": True, "placeholder": "-----BEGIN CERTIFICATE----- …"},
    {"key": "client_key", "label": "Client key, PEM (https, optional)", "type": "password",
     "secret": True, "wide": True, "placeholder": "-----BEGIN PRIVATE KEY----- …"},
]

ROLES = ("containers",)  # see dynamic.ROLES

# No ABSENCE: "gone" is already limited to entries at this host's address, and
# another host running a container of that name is a different fact - the
# entry's address is wrong - not a reason to stay quiet.

PORT_RE = re.compile(r"\b(\d{1,5})\b")
ID_LABEL = "netmap.id"
# Labels Docker Compose (and podman-compose) and Swarm put on every container:
# the service a container belongs to, which outlives the container's own name.
COMPOSE_SERVICE = "com.docker.compose.service"
SWARM_SERVICE = "com.docker.swarm.service.name"


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("host_ip"))


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _ports_of(text: str) -> set[int]:
    return {int(m.group(1)) for m in PORT_RE.finditer(text or "")
            if 0 < int(m.group(1)) < 65536}


# ---- talking to the engine ------------------------------------------------------------------
PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)


def pem(text: str, what: str) -> str:
    """A PEM block as typed or pasted. A password field drops the line breaks
    of a pasted key, so the body is re-wrapped rather than trusted."""
    blocks = []
    for m in PEM_RE.finditer(text or ""):
        body = re.sub(r"\s+", "", m.group(2))
        lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
        blocks.append(f"-----BEGIN {m.group(1)}-----\n{lines}\n-----END {m.group(1)}-----\n")
    if not blocks:
        raise ValueError(f"the {what} is not PEM - paste it from -----BEGIN to -----END")
    return "".join(blocks)


def _tls(cfg: dict) -> ssl.SSLContext:
    if cfg.get("ca_cert"):
        ctx = ssl.create_default_context(cadata=pem(cfg["ca_cert"], "CA certificate"))
    else:
        ctx = ssl.create_default_context()
    if not cfg.get("verify_ssl", True):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    cert, key = cfg.get("client_cert"), cfg.get("client_key")
    if bool(cert) != bool(key):
        raise ValueError("a client certificate needs its key, and the other way round")
    if cert:
        # ssl takes the chain from files only. A private directory, gone again
        # as soon as the context holds it.
        with tempfile.TemporaryDirectory() as d:
            cp, kp = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
            for path, text, what in ((cp, cert, "client certificate"), (kp, key, "client key")):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(pem(text, what))
            ctx.load_cert_chain(cp, kp)
    return ctx


class _UnixHTTP(http.client.HTTPConnection):
    """HTTP over a Unix socket - the Docker API's own transport."""

    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def _get(cfg: dict, path: str):
    """GET one API path. The only request this module can make."""
    base = str(cfg["url"]).strip()
    if base.startswith("unix://"):
        sock = base[len("unix://"):] or "/var/run/docker.sock"
        conn = _UnixHTTP(sock, cfg["timeout"])
        try:
            conn.request("GET", path, headers={"accept": "application/json", "host": "docker"})
            r = conn.getresponse()
            body = r.read()
            if r.status >= 400:
                raise urllib.error.HTTPError(base + path, r.status, r.reason, r.headers, None)
            return json.loads(body)
        finally:
            conn.close()
    ctx = _tls(cfg) if base.lower().startswith("https://") else None
    req = urllib.request.Request(base.rstrip("/") + path, headers={"accept": "application/json"})
    with _http.urlopen(req, timeout=cfg["timeout"], context=ctx) as resp:
        return json.loads(resp.read())


def fetch_containers(cfg: dict) -> list[dict]:
    """Every container, running or not.

    all=1 on purpose: a stopped container is a different fact from a missing
    one, and reporting a restart as "this no longer exists" would cry wolf.
    """
    return _get(cfg, "/containers/json?all=1")


def _why(cfg: dict, exc: Exception) -> str:
    """What went wrong, in the terms of whichever way the engine is reached."""
    where = cfg.get("url", "")
    if isinstance(exc, urllib.error.HTTPError):
        return {
            401: "the Docker API wants credentials (HTTP 401) - NetMap can present a TLS "
                 "client certificate over https://",
            403: "the Docker API refused (HTTP 403) - behind a socket proxy, allow "
                 "CONTAINERS=1 on it",
            404: f"HTTP 404 - {where} does not lead to a Docker API (it should answer "
                 "/containers/json)",
        }.get(exc.code, f"the Docker API answered HTTP {exc.code}")
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, Exception):
        exc = exc.reason
    if isinstance(exc, ssl.SSLCertVerificationError):
        return (f"the certificate at {where} did not verify ({exc.verify_message}) - add "
                "its CA certificate, or switch off Verify TLS")
    if isinstance(exc, ssl.SSLError):
        return (f"TLS with {where} failed ({exc.reason or exc}) - a daemon started with "
                "--tlsverify needs a client certificate and key")
    if isinstance(exc, ValueError):
        return str(exc)
    if where.startswith("unix://") and isinstance(exc, FileNotFoundError):
        return f"no socket at {where[7:]} - mount it into the container"
    if where.startswith("unix://") and isinstance(exc, PermissionError):
        return (f"cannot open {where[7:]} - NetMap runs as uid {os.getuid()}; give that "
                "user access, or use a socket proxy")
    return f"cannot reach the Docker API at {where}: {exc}"


LOOPBACK = {"127.0.0.1", "::1"}


def _container_view(c: dict) -> dict:
    name = (c.get("Names") or ["/?"])[0].lstrip("/")
    # Published means reachable at the host's address - what an entry's
    # ip:ports claims. A port bound only to loopback (NetMap's own,
    # "127.0.0.1:8087:8087") is published to the host itself and nobody else,
    # so counting it would contradict the port sweep, which finds it closed.
    published = sorted({p["PublicPort"] for p in (c.get("Ports") or [])
                        if p.get("PublicPort") and p.get("IP") not in LOOPBACK})
    image = c.get("Image", "")
    labels = c.get("Labels") or {}
    # A Swarm task is called web.1.x7a3…, and the suffix changes with every
    # redeploy: the service is the stable name, for matching and for the
    # finding's key alike.
    swarm = (labels.get(SWARM_SERVICE) or "").strip()
    compose = (labels.get(COMPOSE_SERVICE) or "").strip()
    nets = ((c.get("NetworkSettings") or {}).get("Networks") or {}).values()
    return {
        "name": swarm or name,
        "container": name,
        "aliases": list(dict.fromkeys(a for a in (swarm, name, compose) if a)),
        "image": image,
        "state": c.get("State", ""),           # running | exited | paused …
        "status": c.get("Status", ""),
        "published": published,
        "host_network": (c.get("HostConfig") or {}).get("NetworkMode") == "host",
        # Its own addresses: on a macvlan or ipvlan network a container is a
        # machine on the LAN, recorded at its own IP rather than the host's.
        "ips": sorted({n.get("IPAddress") for n in nets if n and n.get("IPAddress")}),
        "netmap_id": _int_or_none(labels.get(ID_LABEL)),
    }


def _int_or_none(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _is_rule(e: dict) -> bool:
    """A NAT / firewall rule. It names an address:port that belongs to a
    service, so it will collide with that service in any port lookup - and it
    is never what a container is."""
    return (e.get("kind") == "rule"
            or "port-forward" in {t.lower() for t in (e.get("tags") or [])}
            or (e.get("name") or "").strip().lower().startswith("port forward"))


def _match(view: dict, entries: list[dict], by_id: dict,
           here: list[dict]) -> dict | None:
    """Label, then name, then the container's own address, then a published
    port on this host. Several matchers because no one of them covers
    everything: a host-network container publishes no ports the API can see,
    a macvlan container publishes none on the host's address, and plenty of
    containers are named nothing like their entry. A name is any of the
    container's: its own, its Compose service, its Swarm service.

    Port matching is scoped to entries at this host's address. Ports repeat
    across a homelab - 3001 is Homepage on one host and Uptime Kuma on another - and
    an unscoped search finds both, refuses to choose, and reports one false
    "new" and one false "gone". A published port on this host can only belong
    to something recorded at this host.
    """
    if view["netmap_id"] and view["netmap_id"] in by_id:
        return by_id[view["netmap_id"]]

    names = [_norm(a) for a in view.get("aliases") or [view["name"]]]
    for n in names:
        hits = [e for e in entries if _norm(e["name"]) == n]
        if len(hits) == 1:
            return hits[0]

    # Containment, uniquely: the container `nginx-proxy-manager` and the entry
    # "NPM (Nginx Proxy Manager)" are plainly the same thing, but neither
    # normalises to the other. Only accept it when exactly one entry contains
    # the container's name - and only on this host, so a substring cannot
    # reach across the estate.
    for n in names:
        if len(n) >= 5:
            hits = [e for e in here if n in _norm(e["name"]) or _norm(e["name"]) in n]
            if len(hits) == 1:
                return hits[0]

    # Its own address - a container on a macvlan or ipvlan network is a
    # machine of its own, and is recorded at that address.
    own = set(view.get("ips") or ())
    if own:
        hits = [e for e in entries if (e.get("ip") or "").strip() in own and not _is_rule(e)]
        if len(hits) == 1:
            return hits[0]

    if view["published"]:
        pset = set(view["published"])
        hits = [e for e in here if _ports_of(e["ports"]) & pset]
        if len(hits) == 1:
            return hits[0]
    return None


def test(cfg: dict) -> dict:
    try:
        n = len(fetch_containers(cfg))
        return {"ok": True, "error": None, "containers": n}
    except Exception as exc:
        return {"ok": False, "error": _why(cfg, exc)}


def scan(cfg: dict) -> dict:
    """Compare running containers with the inventory. Read-only, both ways."""
    P = cfg.get("_key", "docker")          # finding-key prefix; see dynamic.py
    DOCKER_HOST, DOCKER_HOST_IP = cfg.get("host", ""), cfg.get("host_ip", "")
    out = {"source": cfg.get("_id", "docker"), "configured": configured(cfg), "scanned_at": db.now(),
           "host": {"host": DOCKER_HOST, "ip": DOCKER_HOST_IP, "url": cfg.get("url", "")},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = ("not configured - add the Docker API URL and host IP in "
                        "Settings › Sources")
        return out
    try:
        raw = fetch_containers(cfg)
    except Exception as exc:
        out["error"] = _why(cfg, exc)
        return out

    views = [_container_view(c) for c in raw]
    all_entries = db.list_entries()
    # The entries this source is allowed to speak about: things recorded as
    # living on this host. Anything else is none of Docker's business.
    # Everything recorded at this address, minus the NAT rules. A rule shares
    # its target's ip:port by definition, so leaving them in makes every
    # published port ambiguous - the matcher then refuses to choose and
    # reports one false "new" plus one false "gone" for the same service.
    here = [e for e in all_entries
            if (e["ip"] or "").strip() == DOCKER_HOST_IP and not _is_rule(e)]
    # The narrower set this source may declare *missing*: containers on this
    # host. A service or VM at the same address is not Docker's to judge.
    mine = [e for e in here
            if "docker" in {t.lower() for t in e["tags"]} or e["kind"] == "container"]
    by_id = {e["id"]: e for e in all_entries}
    ign = db.ignores()

    matched_ids: set[int] = set()
    findings: list[dict] = []
    seen: list[dict] = []
    stopped = 0

    for v in views:
        e = _match(v, all_entries, by_id, here)
        if e:
            matched_ids.add(e["id"])
            # What Docker says about this entry, agreement included. The
            # container's own state and every port it publishes - so a screen
            # can name Docker as a witness rather than only hearing from it
            # when something is wrong.
            seen.append({"entry_id": e["id"], "fact": "container",
                         "value": f"{v['name']} {v['state']}"})
            if v["host_network"]:
                seen.append({"entry_id": e["id"], "fact": "network",
                             "value": "host network"})
            for p in v["published"]:
                seen.append({"entry_id": e["id"], "fact": f"port:{p}",
                             "value": "published"})
            if v["state"] != "running":
                stopped += 1
                findings.append({
                    "type": "stopped", "key": f"{P}:stopped:{v['name']}",
                    "label": f"{v['name']} is {v['state']}",
                    "detail": v["status"],
                    "entry": {"id": e["id"], "name": e["name"]}, "container": v,
                })
                continue
            if v["published"] and not v["host_network"]:
                listed = _ports_of(e["ports"])
                extra = sorted(set(v["published"]) - listed)
                missing = sorted(listed - set(v["published"]))
                if extra or missing:
                    findings.append({
                        "type": "ports", "key": f"{P}:ports:{v['name']}",
                        "label": f"{e['name']} - ports differ",
                        "detail": (f"container publishes {', '.join(map(str, v['published']))}; "
                                   f"NetMap says {e['ports'] or '-'}"),
                        "entry": {"id": e["id"], "name": e["name"], "ports": e["ports"]},
                        "container": v,
                        "suggest": {"ports": ", ".join(str(p) for p in v["published"])},
                    })
        else:
            findings.append({
                "type": "new", "key": f"{P}:new:{v['name']}",
                "label": v["name"],
                "detail": ((f"container {v['container']} · " if v["container"] != v["name"] else "")
                           + f"{v['image']} · "
                           + (", ".join(map(str, v["published"])) if v["published"]
                              else ("host network" if v["host_network"] else "no published port"))
                           + ("" if v["state"] == "running" else f" · {v['state']}")),
                "container": v,
                "draft": {
                    "name": v["name"],
                    "category": "Uncategorised",
                    "host": DOCKER_HOST,
                    "ip": DOCKER_HOST_IP,
                    "ports": ", ".join(str(p) for p in v["published"]),
                    "protocol": "HTTP" if v["published"] else "",
                    "kind": "container",
                    "tags": "docker",
                    "notes": f"Discovered from Docker {db.now()[:10]}. Image {v['image']}.",
                    "monitor": bool(v["published"]),
                    "verified": False,
                },
            })

    for e in mine:
        if e["id"] not in matched_ids:
            findings.append({
                "type": "gone", "key": f"{P}:gone:{e['id']}",
                "label": e["name"],
                "detail": "recorded on this host, but no container answers to it",
                "entry": {"id": e["id"], "name": e["name"], "ports": e["ports"]},
            })

    # Swarm replicas of one service on this node are one finding, not three.
    keys: set[str] = set()
    findings = [f for f in findings if not (f["key"] in keys or keys.add(f["key"]))]

    db.record_sightings(cfg.get("_id", "docker"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "containers": len(views),
        "matched": len(matched_ids),
        "new": sum(1 for f in kept if f["type"] == "new"),
        "gone": sum(1 for f in kept if f["type"] == "gone"),
        "ports": sum(1 for f in kept if f["type"] == "ports"),
        "stopped": sum(1 for f in kept if f["type"] == "stopped"),
        "ignored": len(findings) - len(kept),
        "tracked_here": len(mine),
    }
    return out
