"""A router's ARP table over SNMP as a discovery source - the `leases` role.

Every IPv4 neighbour the router has resolved: which hardware address answers
at which address, whatever handed the address out (DHCP anywhere, or a static
setting on the host). Reads `ipNetToMediaTable` (RFC 1213), or
`ipNetToPhysicalTable` (RFC 4293) where the router only offers that.

SNMP v2c with a community string, spoken by the small client below rather
than a library - the protocol needed here is one request type. Read-only by
construction: the only PDUs this module can build are GetBulkRequest; there
is no SetRequest in it. Give it a read-only community (`rocommunity`) anyway.
SNMPv3 is not supported yet.
"""
import os
import socket

from .. import db
from . import _leases

FIELDS = [
    {"key": "host", "label": "Router address", "type": "text", "required": True,
     "wide": True, "placeholder": "10.0.0.1", "binds": True},
    {"key": "port", "label": "Port", "type": "number", "integer": True, "default": 161},
    {"key": "community", "label": "Community (read-only)", "type": "password",
     "secret": True, "required": True},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 3},
]

ROLES = ("leases",)  # see dynamic.ROLES
ABSENCE = {"ip-moved"}

SYS_DESCR = "1.3.6.1.2.1.1.1"
MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"      # ipNetToMediaPhysAddress.<ifIndex>.<a.b.c.d>
MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"      # 2 = invalid
PHYS_PHYS = "1.3.6.1.2.1.4.35.1.4"       # ipNetToPhysicalPhysAddress.<if>.<type>.<len>.<addr>
PHYS_TYPE = "1.3.6.1.2.1.4.35.1.6"       # 2 = invalid

# ---- a minimal SNMP v2c client (BER) -----------------------------------------------------
GET_BULK, RESPONSE = 0xA5, 0xA2          # the only PDUs: a read, and its answer
END_TAGS = {0x80, 0x81, 0x82}            # noSuchObject, noSuchInstance, endOfMibView


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def _int(v: int) -> bytes:
    return _tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def encode_oid(oid: str) -> bytes:
    p = [int(x) for x in oid.strip(".").split(".")]
    body = bytes([40 * p[0] + p[1]])
    for n in p[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.insert(0, 0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(chunk)
    return _tlv(0x06, body)


def decode_oid(b: bytes) -> str:
    first = b[0]
    out = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    n = 0
    for x in b[1:]:
        n = (n << 7) | (x & 0x7F)
        if not x & 0x80:
            out.append(n)
            n = 0
    return ".".join(map(str, out))


def _read(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """(tag, value, next position) of the TLV at pos."""
    tag, n = data[pos], data[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(data[pos:pos + k], "big")
        pos += k
    if pos + n > len(data):
        raise ValueError("truncated SNMP message")
    return tag, data[pos:pos + n], pos + n


def _items(body: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(body):
        tag, val, pos = _read(body, pos)
        out.append((tag, val))
    return out


def bulk_request(community: str, req_id: int, oid: str, reps: int = 25) -> bytes:
    varbind = _tlv(0x30, encode_oid(oid) + _tlv(0x05, b""))
    pdu = _tlv(GET_BULK, _int(req_id) + _int(0) + _int(reps) + _tlv(0x30, varbind))
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)


def parse_response(data: bytes) -> tuple[int, int, list[tuple[str, int, bytes]]]:
    """(request id, error status, [(oid, value tag, value bytes)])."""
    tag, msg, _ = _read(data, 0)
    parts = _items(msg)
    if tag != 0x30 or len(parts) < 3 or parts[2][0] != RESPONSE:
        raise ValueError("not an SNMP response")
    pdu = _items(parts[2][1])
    req_id = int.from_bytes(pdu[0][1], "big", signed=True)
    status = int.from_bytes(pdu[1][1], "big", signed=True)
    binds = []
    for _, vb in _items(pdu[3][1]):
        (_, oid), (vtag, val) = _items(vb)[:2]
        binds.append((decode_oid(oid), vtag, val))
    return req_id, status, binds


def walk(cfg: dict, base: str, limit: int = 20000) -> list[tuple[str, int, bytes]]:
    """Every (oid, tag, value) under `base`, with GetBulk. Raises OSError on
    no answer - which is also what a wrong v2c community looks like."""
    host, port = str(cfg["host"]).strip(), int(cfg.get("port") or 161)
    addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    out: list = []
    cur = base
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(float(cfg.get("timeout") or 3))
        while len(out) < limit:
            req_id = int.from_bytes(os.urandom(3), "big")
            binds = None
            for _ in range(2):                           # one retry: it is UDP
                s.sendto(bulk_request(cfg["community"], req_id, cur), addr)
                try:
                    while True:
                        data, _ = s.recvfrom(65535)
                        rid, status, got = parse_response(data)
                        if rid == req_id:
                            break
                except socket.timeout:
                    continue
                if status:
                    raise ValueError(f"the agent answered with SNMP error {status}")
                binds = got
                break
            if binds is None:
                raise OSError(f"no answer from {host}:{port} - check the address, "
                              "port and community")
            done = not binds
            for oid, tag, val in binds:
                if tag in END_TAGS or not oid.startswith(base + "."):
                    done = True
                    break
                out.append((oid, tag, val))
                cur = oid
            if done:
                break
    return out


# ---- the ARP table -------------------------------------------------------------------------
def _mac(val: bytes) -> str:
    return ":".join(f"{b:02x}" for b in val) if len(val) == 6 and any(val) else ""


def neighbours(cfg: dict) -> list[dict]:
    rows: dict[str, dict] = {}
    invalid = {oid[len(MEDIA_TYPE) + 1:] for oid, _, v in walk(cfg, MEDIA_TYPE)
               if int.from_bytes(v, "big") == 2}
    for oid, _, val in walk(cfg, MEDIA_PHYS):
        idx = oid[len(MEDIA_PHYS) + 1:]
        ip = _leases.ipv4(".".join(idx.split(".")[1:]))
        if ip and idx not in invalid and _mac(val):
            rows[ip] = {"ip": ip, "mac": _mac(val), "label": "", "detail": "ARP"}
    if rows:
        return list(rows.values())
    invalid = {oid[len(PHYS_TYPE) + 1:] for oid, _, v in walk(cfg, PHYS_TYPE)
               if int.from_bytes(v, "big") == 2}
    for oid, _, val in walk(cfg, PHYS_PHYS):
        idx = oid[len(PHYS_PHYS) + 1:]
        p = idx.split(".")
        if len(p) != 7 or p[1] != "1" or p[2] != "4" or idx in invalid:
            continue                                     # IPv4 only
        ip = _leases.ipv4(".".join(p[3:]))
        if ip and _mac(val):
            rows[ip] = {"ip": ip, "mac": _mac(val), "label": "", "detail": "ARP"}
    return list(rows.values())


def configured(cfg: dict) -> bool:
    return bool(str(cfg.get("host") or "").strip() and cfg.get("community"))


def test(cfg: dict) -> dict:
    try:
        got = walk(cfg, SYS_DESCR, limit=1)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    desc = got[0][2].decode("utf-8", "replace")[:120] if got else ""
    return {"ok": True, "error": None, "system": desc}


def scan(cfg: dict) -> dict:
    out = {"source": cfg.get("_id", "snmparp"), "configured": configured(cfg),
           "scanned_at": db.now(), "host": {"address": cfg.get("host", "")},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = "not configured - add the router address and community in Settings › Sources"
        return out
    try:
        rows = neighbours(cfg)
    except (OSError, ValueError) as exc:
        out["error"] = str(exc)
        return out
    out["findings"], out["counts"] = _leases.report(cfg, rows, "the router's ARP table", "arp")
    return out
