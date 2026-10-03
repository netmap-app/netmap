"""An open-port sweep of the addresses NetMap already tracks.

Every other source reads a system's own records: Docker's container list,
OPNsense's reservations, NPM's proxy hosts. **This one is different in kind —
it generates traffic against machines it does not own**, which is why it is the
only source that is off unless switched on.

It exists because of what the others cannot see. Docker knows the published
ports of its containers and nothing about the NAS, the router, a mini PC's
add-ons or the switches. The status
check TCP-connects to exactly one port per entry, so an entry declaring
"80 (admin), 53 (DNS)" has never had the second claim tested. Between them
those two gaps cover most of the estate.

Two questions, in the shape every other source uses — the inventory states
something and the scan contradicts it:

  is what we claim actually listening?     -> port-closed
  is something listening we never claimed?  -> port-undeclared

**Scanning is per address, not per entry.** Twenty containers can share
one Docker host's address; sweeping it twenty times would be silly, and a port opened by one
of them is not "undeclared" merely because a different entry at that address
does not mention it. So each address is swept once and reconciled against the
union of what every entry there declares.
"""
import errno
import re
import socket
from concurrent.futures import ThreadPoolExecutor

from .. import db, fingerprint

# Phones, tablets and televisions are not infrastructure, and sweeping them is
# the part of this that feels like surveillance rather than inventory — but
# which category holds them is each inventory's own naming, so nothing is
# skipped until a person names it. Also what explain.py treats as "holds no
# data".
DEFAULT_SKIP = ""
# The default before 1.92.1, written into instances that relied on it so an
# upgrade does not start sweeping what was skipped (sources.pin_defaults).
LEGACY_SKIP = "Client / IoT Devices"

FIELDS = [
    # Adding this source is the decision to probe — active probing is a
    # different bargain from reading an API. Pausing it is the general
    # "Enabled" switch every source has (1.93.0); this list once carried its
    # own, which sources.pin_defaults() folds into that one.
    {"key": "timeout", "label": "Per-port timeout (seconds)", "type": "number",
     "default": 0.4, "env": "NETMAP_PORTSCAN_TIMEOUT"},
    {"key": "workers", "label": "Concurrent workers", "type": "number", "integer": True,
     "default": 64, "env": "NETMAP_PORTSCAN_WORKERS"},
    # Never more than this many simultaneous connections to one machine.
    {"key": "per_host", "label": "Max ports per host", "type": "number", "integer": True,
     "default": 12, "env": "NETMAP_PORTSCAN_PER_HOST"},
    {"key": "skip", "label": "Categories never swept (comma separated)", "type": "text",
     "wide": True, "default": DEFAULT_SKIP, "env": "NETMAP_PORTSCAN_SKIP",
     "placeholder": "e.g. Phones, IoT"},
    {"key": "extra_ports", "label": "Extra ports to check (comma separated)",
     "type": "text", "wide": True, "env": "NETMAP_PORTSCAN_PORTS"},
    # Some services break on the very probe this source makes. UniFi's mobile
    # speed-test port (6789) accepts a connection, never notices the probe
    # hang up, and keeps the socket in CLOSE-WAIT; a few dozen of those and it
    # stops accepting at all — which the sweep then reports as "filtered",
    # the damage it caused itself. Listed here, a port is never touched: not
    # by the daily sweep, not by a deep scan.
    {"key": "never_probe", "label": "Never probe (port or address:port, comma separated)",
     "type": "text", "wide": True, "placeholder": "10.0.0.10:6789"},
    # An open port nothing declares is asked what it is: a greeting, or a GET
    # of / (and /manifest.json). See app/fingerprint.py.
    {"key": "fingerprint", "label": "Identify what answers on undeclared ports",
     "type": "checkbox", "default": True},
]

ROLES = ("scanner",)  # see dynamic.ROLES
# Before 1.75 this variable alone switched the sweep on; the one-time seed
# (sources.migrate_legacy) still reads it, now as "add the source".
LEGACY_SWITCH = "NETMAP_PORTSCAN"

# One sweep of the inventory is the whole job; a second would repeat it.
MULTI = False


def never_probe(cfg: dict | None = None) -> tuple[set[int], set[tuple[str, int]]]:
    """(ports never probed anywhere, (address, port) pairs never probed)."""
    anywhere, pairs = set(), set()
    for part in ((cfg or {}).get("never_probe") or "").split(","):
        ip, _, port = part.strip().rpartition(":")
        if not (port.isdigit() and 0 < int(port) < 65536):
            continue                          # not a port: ignored, never guessed at
        if not ip:
            anywhere.add(int(port))
        elif IP_RE.match(ip):
            pairs.add((ip, int(port)))
    return anywhere, pairs


def untouchable(cfg: dict | None, ip: str) -> set[int]:
    """The ports at one address that must not be probed."""
    anywhere, pairs = never_probe(cfg)
    return anywhere | {p for a, p in pairs if a == ip}


def skip_categories(cfg: dict | None = None) -> set[str]:
    raw = str((cfg or {}).get("skip") or DEFAULT_SKIP)
    return {c.strip().lower() for c in raw.split(",") if c.strip()}

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PORT_RE = re.compile(r"\b(\d{2,5})\b")

# Ports worth asking about on a homelab: management interfaces, databases,
# file sharing, and the self-hosted things that turn up on these machines. Not
# a full sweep — 65535 ports per host would take minutes and tell you almost
# nothing you did not already know.
COMMON = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 500, 515, 548, 587, 631, 636, 873, 902, 993, 995, 1080, 1194,
    1400, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2375, 2376,
    2379, 3000, 3001, 3002, 3128, 3260, 3306, 3389, 4357, 5000, 5001, 5006,
    5055, 5060, 5222, 5357, 5432, 5433, 5555, 5900, 5984, 6379, 6443, 6638,
    6789, 7000, 7878, 8000, 8006, 8007, 8008, 8009, 8080, 8081, 8083, 8086,
    8087, 8096, 8112, 8123, 8181, 8191, 8200, 8291, 8443, 8500, 8686, 8765,
    8787, 8888, 8989, 9000, 9090, 9091, 9096, 9117, 9200, 9443, 9696, 9990,
    10000, 11211, 13378, 15672, 19999, 27017, 32400, 32469, 61208,
]

# What a port number usually means, and what actually answers on it, live in
# app/fingerprint.py — shared with the deep scan.
LIKELY = fingerprint.PORT_NAMES

# At most this many unexpected ports are asked what they are per sweep; the
# rest keep the port-number guess. A sweep should stay a few seconds.
FINGERPRINT_MAX = 48


def configured(cfg: dict) -> bool:
    return True                      # nothing to fill in; paused by the source's switch


def _ports(text: str) -> set[int]:
    return {int(m.group(1)) for m in PORT_RE.finditer(text or "")
            if 0 < int(m.group(1)) < 65536}


def _probe(ip: str, port: int, timeout: float) -> str:
    """One of "open", "closed" or "filtered".

    The distinction matters and the first version did not make it. A refusal
    is an answer: something on that host actively said no, so a port the
    inventory claims really is not listening. A timeout says nothing of the
    kind — a firewall dropping the packet and a service that is merely slow
    look identical from here. Collapsing the two into "closed" is how a
    dropped packet becomes a confident false claim that a service is missing.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as exc:
        # Unreachable host or network — no evidence about this port at all.
        return "closed" if exc.errno == errno.ECONNRESET else "filtered"


def _sweep(cfg: dict, ip: str, ports: list[int]) -> dict[int, str]:
    """Every port of one host, at most PER_HOST connections at a time.

    The cap is the point. Sweeping addresses one at a time means the whole
    pool lands on a single machine, and the machines that most need scanning
    here are the ones least able to take it — a fifteen-year-old NAS has a
    small connection table and answers sixty simultaneous SYNs by dropping
    most of them, which the previous version would have read as sixty closed
    ports.
    """
    width = max(1, min(cfg["workers"], cfg["per_host"], len(ports)))
    with ThreadPoolExecutor(max_workers=width) as pool:
        return dict(zip(ports, pool.map(lambda p: _probe(ip, p, cfg["timeout"]), ports)))


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def _evidence(fp: dict) -> str:
    """What the port said, for a finding's detail."""
    bits = [f'title "{fp["title"]}"' if fp.get("title") else "",
            f"server {fp['server']}" if fp.get("server") else "",
            f'greeting "{fp["banner"][:60]}"' if fp.get("banner") else ""]
    bits = [b for b in bits if b]
    return (". It answered with " + ", ".join(bits)) if bits else ""


def _draft(owner: dict, ip: str, port: int, fp: dict) -> dict:
    """A service entry for what answers here — never created by itself."""
    name = fp.get("name") if fp.get("identified") else ""
    return {"name": name or f"{fp.get('name') or 'Service'} on {port}",
            "category": "Uncategorised", "kind": "service", "host": owner["name"],
            "ip": ip, "ports": str(port), "protocol": fingerprint.label(fp) or "",
            "url": fp.get("url") or "",
            "tags": f"icon:{fp['icon']}" if fp.get("icon") else "",
            "notes": f"Found open by the port scan {db.now()[:10]}{_evidence(fp)}.",
            "monitor": True, "verified": False}


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "ports")          # finding-key prefix; see dynamic.py
    out = {"source": cfg.get("_id", "ports"), "configured": configured(cfg), "scanned_at": db.now(),
           "host": {"timeout": cfg.get("timeout"), "workers": cfg.get("workers"),
                    "common_ports": len(COMMON)},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = ("paused — this source probes machines rather than reading "
                        "an API; enable it in Settings › Sources")
        return out
    skip = skip_categories(cfg)

    entries = db.list_entries()
    # address -> the entries that live there, and everything they declare
    at: dict[str, list[dict]] = {}
    for e in entries:
        ip = (e.get("ip") or "").strip()
        if not IP_RE.match(ip):
            continue
        if (e.get("category") or "").strip().lower() in skip:
            continue
        at.setdefault(ip, []).append(e)

    ign = db.ignores()
    findings: list[dict] = []
    seen: list[dict] = []
    scanned = 0
    open_total = 0

    extra = _ports(cfg.get("extra_ports", ""))
    budget = FINGERPRINT_MAX if cfg.get("fingerprint", True) else 0
    identified = 0
    for ip, here in sorted(at.items()):
        # Two different questions, two different sets. A port-forward rule
        # records "6666 (WAN 6881)" — the second number is the port the world
        # knocks on, not something that listens at this address. So a rule's
        # ports still count as *accounted for* (6666 is not a surprise), but
        # they are never a claim that something answers here.
        declared: set[int] = set()
        claimed: set[int] = set()
        for e in here:
            p = _ports(e.get("ports") or "")
            declared |= p
            if e.get("kind") != "rule":
                claimed |= p
        hands_off = untouchable(cfg, ip)
        wanted = sorted((set(COMMON) | declared | extra) - hands_off)
        state = _sweep(cfg, ip, wanted)
        found = {p for p, st in state.items() if st == "open"}
        refused = {p for p, st in state.items() if st == "closed"}
        scanned += 1
        open_total += len(found)

        # A machine that is simply off answers nothing, and reporting every
        # declared port as closed would bury the one host that is genuinely
        # misconfigured. Silence about a silent host is the status check's job.
        if not found:
            continue

        # Only a refusal is evidence. A declared port that timed out is
        # reported separately and at lower confidence: it may be filtered, it
        # may be slow, and the difference is not visible from a TCP connect.
        for port in sorted(claimed & (state.keys() - found - refused)):
            owners = [e for e in here if e.get("kind") != "rule"
                      and port in _ports(e.get("ports") or "")]
            e = owners[0]
            findings.append({
                "type": "port-filtered", "key": f"{P}:filtered:{ip}:{port}",
                "label": f"{e['name']} — {ip}:{port} did not answer",
                "detail": ("the inventory declares this port and the probe "
                           "timed out rather than being refused. Something is "
                           "dropping the packets, or the service is too slow "
                           "to accept — this is not proof that nothing is "
                           "listening."),
                "entry": _ref(e),
            })

        for port in sorted(claimed & refused):
            owners = [e for e in here if e.get("kind") != "rule"
                      and port in _ports(e.get("ports") or "")]
            e = owners[0]
            findings.append({
                "type": "port-closed", "key": f"{P}:closed:{ip}:{port}",
                "label": f"{e['name']} — {ip}:{port} is not listening",
                "detail": ("the inventory declares this port and the host "
                           "actively refused the connection, so nothing is "
                           "listening. Either the service moved or the entry "
                           "is out of date."),
                "entry": _ref(e),
            })

        # Record every state for every port anyone at this address declares,
        # plus every open port. Attribution follows the same rule the findings
        # use: a declared port belongs to whoever declared it, an undeclared
        # open one to the host.
        for e in here:
            for port in _ports(e.get("ports") or ""):
                st = state.get(port) or ("not probed (Never probe)" if port in hands_off else None)
                if st:
                    seen.append({"entry_id": e["id"], "fact": f"port:{port}",
                                 "value": st})

        # On a shared address an undeclared port is the *host's* — a port
        # opened on a Docker host's address belongs to the host, not to whichever
        # container happens to sort first.
        owner = next((e for e in here if e.get("kind") in ("hardware", "vm")),
                     here[0])

        surprise = sorted(found - declared)
        # An ignored port is not asked again: it was already decided about.
        asked = [p for p in surprise if f"{P}:open:{ip}:{p}" not in ign][:budget]
        budget -= len(asked)
        fps = fingerprint.many(ip, asked)
        for port in surprise:
            fp = fps.get(port) or {"name": LIKELY.get(port, ""), "identified": False}
            identified += 1 if fp.get("identified") else 0
            what = fingerprint.label(fp)
            seen.append({"entry_id": owner["id"], "fact": f"port:{port}",
                         "value": f"open — {what}" if fp.get("identified") else "open"})
            findings.append({
                "type": "port-undeclared", "key": f"{P}:open:{ip}:{port}",
                "label": (f"{what} on {ip}:{port} — not in NetMap" if fp.get("identified")
                          else f"{owner['name']} — {ip}:{port} is open"
                          + (f" ({what})" if what else "")),
                "detail": ("something is listening here that no entry at this "
                           "address accounts for"
                           + (f". {len(here)} entries share this address, and "
                              "none of them declares it" if len(here) > 1
                              else "")
                           + _evidence(fp)),
                "entry": _ref(owner),
                "draft": _draft(owner, ip, port, fp),
            })

    # What was seen, not only what disagreed. A port that matches produces no
    # finding, so without this the fact that the scanner confirmed it is
    # thrown away the moment the scan ends.
    db.record_sightings(cfg.get("_id", "ports"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "addresses": scanned, "open": open_total,
        "closed": sum(1 for f in kept if f["type"] == "port-closed"),
        "filtered": sum(1 for f in kept if f["type"] == "port-filtered"),
        "undeclared": sum(1 for f in kept if f["type"] == "port-undeclared"),
        "identified": identified,
        "ignored": len(findings) - len(kept),
    }
    return out
