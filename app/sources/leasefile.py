"""A DHCP lease file as a discovery source — the `leases` role.

For a network whose DHCP server is not OPNsense or UniFi: dnsmasq (and
everything built on it — Pi-hole's DHCP, OpenWrt, many routers), ISC dhcpd, or
Kea's memfile CSV. The file is mounted read-only into the container, e.g.

    volumes:
      - /var/lib/misc/dnsmasq.leases:/leases/dnsmasq.leases:ro

and named here by its path inside the container. No network access at all:
the module opens one file for reading, and nothing in it can write anywhere.
Only IPv4 leases that are still current are read.
"""
import csv
import io
import os
import re
import time

from .. import db
from . import _leases

FIELDS = [
    {"key": "path", "label": "Lease file (path inside the container)", "type": "text",
     "required": True, "wide": True, "placeholder": "/leases/dnsmasq.leases"},
    {"key": "format", "label": "Format — auto, dnsmasq, isc or kea", "type": "text",
     "default": "auto", "placeholder": "auto"},
]

ROLES = ("leases",)  # see dynamic.ROLES
ABSENCE = {"ip-moved"}

FORMATS = ("auto", "dnsmasq", "isc", "kea")
MAX_BYTES = 20 * 1024 * 1024


def configured(cfg: dict) -> bool:
    return bool(str(cfg.get("path") or "").strip())


def detect(text: str) -> str:
    head = text.lstrip()[:4000]
    if head.lower().startswith("address,hwaddr"):
        return "kea"
    if re.search(r"^\s*lease\s+\S+\s*\{", head, re.M):
        return "isc"
    return "dnsmasq"


def parse_dnsmasq(text: str, now: float) -> list[dict]:
    """`<expiry> <mac> <ip> <hostname|*> <client-id|*>` per line; expiry 0 is
    an infinite lease. The `duid` line and IPv6 leases after it are skipped."""
    out = []
    for line in text.splitlines():
        p = line.split()
        if len(p) < 4 or not p[0].isdigit():
            continue
        exp, m, ip, host = int(p[0]), _leases.mac(p[1]), _leases.ipv4(p[2]), p[3]
        if not ip or (exp and exp < now):
            continue
        out.append({"ip": ip, "mac": m, "label": "" if host == "*" else host,
                    "detail": "dnsmasq lease" + (" (infinite)" if not exp else "")})
    return out


_ISC_BLOCK = re.compile(r"lease\s+(\S+)\s*\{(.*?)\}", re.S)


def parse_isc(text: str, now: float) -> list[dict]:
    """dhcpd.leases: one block per lease, appended as they change — the last
    block for an address is the current one. Only `binding state active`
    (or no binding state, as older servers write) that has not ended."""
    last: dict[str, dict] = {}
    for ip, body in _ISC_BLOCK.findall(text):
        ip = _leases.ipv4(ip)
        if not ip:
            continue
        state = re.search(r"^\s*binding state (\w+);", body, re.M)
        ends = re.search(r"^\s*ends \d (\d{4}/\d\d/\d\d \d\d:\d\d:\d\d);", body, re.M)
        m = re.search(r"hardware ethernet ([0-9a-fA-F:]+);", body)
        host = re.search(r'client-hostname "([^"]*)";', body)
        active = (state is None or state.group(1) == "active")
        if ends:
            active = active and _utc(ends.group(1), "%Y/%m/%d %H:%M:%S") >= now
        last[ip] = {"ip": ip, "mac": _leases.mac(m.group(1)) if m else "",
                    "label": host.group(1) if host else "", "detail": "ISC dhcpd lease",
                    "_active": active}
    return [{k: v for k, v in r.items() if k != "_active"} for r in last.values() if r["_active"]]


def parse_kea(text: str, now: float) -> list[dict]:
    """kea-leases4.csv: appended as leases change, the last row per address
    wins. state 0 is a live lease; 1 declined, 2 expired-reclaimed."""
    last: dict[str, dict] = {}
    for row in csv.DictReader(io.StringIO(text)):
        ip = _leases.ipv4(row.get("address"))
        if not ip:
            continue
        try:
            exp, state = int(row.get("expire") or 0), int(row.get("state") or 0)
        except ValueError:
            continue
        last[ip] = {"ip": ip, "mac": _leases.mac(row.get("hwaddr")),
                    "label": (row.get("hostname") or "").rstrip("."),
                    "detail": "Kea lease", "_live": state == 0 and exp >= now}
    return [{k: v for k, v in r.items() if k != "_live"} for r in last.values() if r["_live"]]


def _utc(s: str, fmt: str) -> float:
    import calendar
    return calendar.timegm(time.strptime(s, fmt))


PARSERS = {"dnsmasq": parse_dnsmasq, "isc": parse_isc, "kea": parse_kea}


def read(cfg: dict, now: float | None = None) -> tuple[str, list[dict]]:
    """(format, rows). Raises ValueError with a message for Settings."""
    path = str(cfg.get("path") or "").strip()
    fmt = str(cfg.get("format") or "auto").strip().lower()
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {', '.join(FORMATS)}")
    if not os.path.isabs(path):
        raise ValueError("the path must be absolute, inside the container")
    try:
        # A regular file, and never more than MAX_BYTES read: a device such as
        # /dev/zero reports size 0 and would otherwise be read forever.
        if os.path.exists(path) and not os.path.isfile(path):
            raise ValueError(f"{path} is not a regular file")
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(MAX_BYTES + 1)
        if len(text) > MAX_BYTES:
            raise ValueError("the file is larger than 20 MB — is this a lease file?")
    except FileNotFoundError:
        raise ValueError(f"no file at {path} — is it mounted into the container?") from None
    except PermissionError:
        raise ValueError(f"cannot read {path} — NetMap runs as uid {os.getuid()}") from None
    if fmt == "auto":
        fmt = detect(text)
    return fmt, PARSERS[fmt](text, time.time() if now is None else now)


def test(cfg: dict) -> dict:
    try:
        fmt, rows = read(cfg)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if not rows:
        return {"ok": False, "error": f"read it as {fmt}, but found no current IPv4 lease"}
    return {"ok": True, "error": None, "format": fmt, "leases": len(rows)}


def scan(cfg: dict) -> dict:
    out = {"source": cfg.get("_id", "leasefile"), "configured": configured(cfg),
           "scanned_at": db.now(), "host": {"path": cfg.get("path", "")},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = "not configured — add the lease file's path in Settings › Sources"
        return out
    try:
        fmt, rows = read(cfg)
    except ValueError as exc:
        out["error"] = str(exc)
        return out
    out["host"]["format"] = fmt
    out["findings"], out["counts"] = _leases.report(cfg, rows, f"the {fmt} lease file")
    return out
