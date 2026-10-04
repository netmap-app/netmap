"""Background reachability checks.

By default a TCP connect to an entry's first port. An entry's `healthcheck`
field (grammar in db.HEALTHCHECK_RE) asks for more, because "port open" is not
"service works": an HTTP(S) GET with an expected status, an ICMP echo for a
device with no port, or nothing at all. An https check also reads the
certificate, so its expiry reaches the Overview before the browser warning.
"""
import asyncio
import datetime as _dt
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse

from . import db

INTERVAL = int(os.environ.get("NETMAP_CHECK_INTERVAL", "120"))
TIMEOUT = float(os.environ.get("NETMAP_CHECK_TIMEOUT", "2.5"))

# entry_id -> {"up": bool|None, "latency_ms": int|None, "checked_at": str,
#              "target": str, "check": str, "summary": str,
#              "http_status": int (http checks), "tls": {...} (https checks)}
CACHE: dict[int, dict] = {}
LAST_SWEEP: str | None = None

# How close to expiry a certificate is worth a warning. Settings can change
# it; stored in kv.
TLS_WARN_KEY = "tls_warn_days"
TLS_WARN_DEFAULT = 21

_PORT_RE = re.compile(r"\b(\d{1,5})\b")


def tls_warn_days() -> int:
    try:
        v = int(db.get_setting(TLS_WARN_KEY) or 0)
    except ValueError:
        v = 0
    return v if 1 <= v <= 365 else TLS_WARN_DEFAULT


def set_tls_warn_days(days: int, actor: str = "web") -> int:
    days = int(days)
    if not 1 <= days <= 365:
        raise ValueError("warn between 1 and 365 days before a certificate expires")
    before = tls_warn_days()
    db.set_setting(TLS_WARN_KEY, str(days))
    db.log(actor, "setting", None, "certificate warning", {"from": before, "to": days})
    return days


def _host(entry: dict) -> str | None:
    host = (entry.get("ip") or "").strip()
    if not host or host.startswith(("-", "\u2014")) or " " in host:
        # allow a hostname in the ip field, reject free text
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", host or ""):
            return None
    return host or None


def target_for(entry: dict) -> tuple[str, int] | None:
    """Pick a host:port to probe for an entry, or None if not probeable."""
    if not entry.get("monitor"):
        return None
    host = _host(entry)
    url = (entry.get("url") or "").strip()
    ports = (entry.get("ports") or "")
    m = _PORT_RE.search(ports)
    port = None
    if m:
        p = int(m.group(1))
        if 0 < p < 65536:
            port = p
    if port is None and url:
        mu = re.search(r":(\d{2,5})", url)
        if mu:
            port = int(mu.group(1))
        elif url.startswith("https"):
            port = 443
        elif url.startswith("http"):
            port = 80
    if port is None or not host:
        return None
    return host, port


def plan(entry: dict) -> dict | None:
    """What to probe for an entry: {kind, host, port, path, expect, name},
    or None when there is nothing to probe."""
    if not entry.get("monitor"):
        return None
    try:
        spec = db.parse_healthcheck(entry.get("healthcheck") or "")
    except ValueError:
        spec = None                         # stored before validation: fall back
    if spec is None or spec["kind"] == "tcp":
        tgt = target_for(entry)
        if spec and spec["port"] and _host(entry):
            tgt = (_host(entry), spec["port"])
        return {"kind": "tcp", "host": tgt[0], "port": tgt[1]} if tgt else None
    if spec["kind"] == "none":
        return {"kind": "none"}
    url = urllib.parse.urlsplit((entry.get("url") or "").strip())
    host = _host(entry) or url.hostname
    if not host:
        return None
    if spec["kind"] == "ping":
        return {"kind": "ping", "host": host}
    # The address to connect to is the entry's; the name spoken to it (TLS SNI,
    # the certificate's name, the Host header) is the URL's when there is one,
    # so a service behind a name-based proxy answers as itself.
    port = spec["port"] or (url.port if url.scheme == spec["kind"] else None) \
        or (443 if spec["kind"] == "https" else 80)
    return {"kind": spec["kind"], "host": host, "port": port, "path": spec["path"],
            "expect": spec["expect"], "name": url.hostname or host}


async def probe(host: str, port: int) -> tuple[bool, int | None]:
    t0 = time.perf_counter()
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, int((time.perf_counter() - t0) * 1000)
    except Exception:
        return False, None


def _cert_info(der: bytes | None) -> dict:
    if not der:
        return {}
    from cryptography import x509
    na = x509.load_der_x509_certificate(der).not_valid_after_utc
    days = (na - _dt.datetime.now(_dt.timezone.utc)).total_seconds() / 86400
    return {"not_after": na.strftime("%Y-%m-%dT%H:%M:%SZ"), "days_left": int(days // 1)}


async def _http_once(p: dict, ctx) -> dict:
    t0 = time.perf_counter()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(
        p["host"], p["port"], ssl=ctx,
        server_hostname=p["name"] if ctx else None), timeout=TIMEOUT)
    try:
        der = None
        if ctx:
            der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        name = p["name"] if ":" not in p["name"] else f"[{p['name']}]"
        writer.write((f"GET {p['path']} HTTP/1.1\r\nHost: {name}\r\n"
                      "User-Agent: NetMap health check\r\nAccept: */*\r\n"
                      "Connection: close\r\n\r\n").encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=TIMEOUT * 2)
        m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", line)
        if not m:
            raise ValueError("no HTTP status line in the answer")
        return {"code": int(m.group(1)), "ms": int((time.perf_counter() - t0) * 1000),
                "der": der}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def probe_http(p: dict) -> dict:
    """GET the path; up when the status is the expected one (or below 500).
    For https the certificate is verified against the URL's name; a failure
    there is its own state - the service answered, the certificate did not
    hold up - so the request is repeated unverified to learn the rest."""
    https = p["kind"] == "https"
    tls: dict = {}
    try:
        try:
            r = await _http_once(p, ssl.create_default_context() if https else None)
            if https:
                tls = {"valid": True}
        except ssl.SSLCertVerificationError as exc:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            r = await _http_once(p, ctx)
            tls = {"valid": False, "error": exc.verify_message or str(exc)}
    except Exception as exc:
        why = "timed out" if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) \
            else f"{type(exc).__name__}: {exc}"[:160]
        return {"up": False, "latency_ms": None, "http_status": None, "error": why}
    if https:
        try:
            tls.update(_cert_info(r["der"]))
            if "days_left" in tls:
                tls["soon"] = tls["days_left"] < tls_warn_days()
        except Exception as exc:
            tls["error"] = tls.get("error") or f"certificate not readable: {exc}"
    up = r["code"] == p["expect"] if p["expect"] else r["code"] < 500
    out = {"up": up, "latency_ms": r["ms"], "http_status": r["code"]}
    if https:
        out["tls"] = tls
    return out


def _checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _ping(host: str) -> tuple[bool | None, int | None, str]:
    """One ICMP echo over an unprivileged ping socket - no ping binary, no
    root: Docker allows these by default (net.ipv4.ping_group_range)."""
    try:
        addr = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError as exc:
        return False, None, f"cannot resolve {host}: {exc}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as exc:
        return None, None, (f"ping is not permitted here ({exc.strerror or exc}) - "
                            "allow it with the sysctl net.ipv4.ping_group_range")
    with s:
        s.settimeout(TIMEOUT)
        pkt = struct.pack("!BBHHH", 8, 0, 0, 0, 1) + b"netmap"
        pkt = pkt[:2] + struct.pack("!H", _checksum(pkt)) + pkt[4:]
        t0 = time.perf_counter()
        try:
            s.sendto(pkt, (addr, 0))
            while True:
                data, _ = s.recvfrom(1024)
                if data and data[0] == 0:              # echo reply
                    return True, int((time.perf_counter() - t0) * 1000), ""
        except (socket.timeout, TimeoutError):
            return False, None, "no echo reply"
        except OSError as exc:
            return False, None, str(exc)


def _summary(p: dict, r: dict) -> str:
    """One line for the status dot's tooltip and the service card."""
    ms = f" in {r['latency_ms']} ms" if r.get("latency_ms") is not None else ""
    if p["kind"] == "tcp":
        return f"TCP {p['host']}:{p['port']}" + (ms if r["up"] else " - no answer")
    if p["kind"] == "ping":
        return f"ping {p['host']}" + (ms if r["up"] else f" - {r.get('error') or 'no reply'}")
    head = f"{p['kind'].upper()} {p['host']}:{p['port']}{p['path']}"
    if r.get("http_status") is None:
        return f"{head} - {r.get('error') or 'no answer'}"
    want = f" (want {p['expect']})" if p["expect"] and not r["up"] else ""
    text = f"{head} → {r['http_status']}{want}{ms}"
    tls = r.get("tls") or {}
    if tls.get("valid") is False:
        text += f" · TLS invalid: {tls.get('error')}"
    return text


async def run_check(entry: dict) -> dict:
    """Probe one entry as its health check says. The result, not stored."""
    p = plan(entry)
    now = db.now()
    if not p:
        return {"up": None, "latency_ms": None, "checked_at": now, "target": None,
                "check": None, "summary": "not monitored"}
    if p["kind"] == "none":
        return {"up": None, "latency_ms": None, "checked_at": now, "target": None,
                "check": "none", "summary": "not probed - the health check is none"}
    if p["kind"] == "tcp":
        up, ms = await probe(p["host"], p["port"])
        r = {"up": up, "latency_ms": ms, "target": f"{p['host']}:{p['port']}"}
    elif p["kind"] == "ping":
        up, ms, err = await asyncio.to_thread(_ping, p["host"])
        r = {"up": up, "latency_ms": ms, "target": p["host"], "error": err}
    else:
        r = await probe_http(p)
        r["target"] = f"{p['host']}:{p['port']}{p['path']}"
    r.update(checked_at=now, check=p["kind"], summary=_summary(p, r))
    r.pop("error", None)
    return r


async def check_entry(entry: dict) -> dict:
    res = await run_check(entry)
    before = CACHE.get(entry["id"])
    CACHE[entry["id"]] = res
    # Store transitions only. Every sweep would be 46 rows a minute of noise;
    # a change of state is the thing anyone ever wants to look back at.
    # The in-memory cache is empty after a restart, so fall back to the last
    # stored row there - otherwise every restart would log 60 false changes.
    try:
        if before is None:
            prev = await asyncio.to_thread(db.last_observation, entry["id"])
            changed = prev is None or prev["up"] is not res["up"]
        else:
            changed = before.get("up") is not res["up"]
        if changed:
            await asyncio.to_thread(
                db.record_observation, entry["id"], res["up"],
                res["latency_ms"], res["target"], res.get("summary", ""))
    except Exception as exc:
        print(f"[status] could not record observation: {exc}", flush=True)
    return res


def expiring(entries: list[dict], cache: dict) -> list[dict]:
    """Checked certificates that expire within the warning window, soonest
    first: {entry, days_left, not_after, target}."""
    warn = tls_warn_days()
    out = []
    for e in entries:
        st = cache.get(e["id"]) or {}
        tls = st.get("tls") or {}
        if tls.get("days_left") is not None and tls["days_left"] < warn:
            out.append({"entry": e, "days_left": tls["days_left"],
                        "not_after": tls.get("not_after"), "target": st.get("target")})
    return sorted(out, key=lambda x: x["days_left"])


async def sweep() -> None:
    global LAST_SWEEP
    entries = await asyncio.to_thread(db.list_entries)
    sem = asyncio.Semaphore(24)

    async def one(e):
        async with sem:
            await check_entry(e)

    await asyncio.gather(*(one(e) for e in entries))
    # An entry that answered its check exists - see app/stale.py.
    await asyncio.to_thread(db.confirm, [i for i, r in CACHE.items() if r.get("up") is True],
                            "health check answered")
    for stale in set(CACHE) - {e["id"] for e in entries}:
        CACHE.pop(stale, None)
    LAST_SWEEP = db.now()
    from . import uptime
    await asyncio.to_thread(uptime.heartbeat)     # "NetMap was watching" - see uptime.py
    # Critical and important entries that changed state reach whoever is not
    # looking; app/notify.py decides what is news.
    from . import notify
    await asyncio.to_thread(notify.after_sweep, entries, CACHE)
    try:
        await asyncio.to_thread(db.prune_observations)
    except Exception:
        pass


async def loop() -> None:
    while True:
        try:
            await sweep()
        except Exception as exc:  # never kill the loop
            print(f"[status] sweep failed: {exc}", flush=True)
        await asyncio.sleep(INTERVAL)
