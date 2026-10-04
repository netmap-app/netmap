"""A full 65535-port sweep of one address, on demand.

This is not the `ports` source with a bigger list. The two differ in kind and
the difference is the design:

| | `sources/portscan` | this |
|---|---|---|
| when | on a schedule, unattended | when a person asks |
| what | 111 common ports, every tracked address | all 65535, one address |
| output | findings - the inventory contradicted | an answer to a question |
| duration | seconds | minutes |

A scheduled job that takes minutes and a person waiting on an answer need
different machinery, so this one is a **job**: it is started, it reports
progress, and its result is fetched. Nothing about it is stored between
restarts and it writes nothing to the inventory - the same rule the discovery
sources hold to. What it produces is evidence for a person to act on.

**It refuses to scan anything that is not a private address.** Port-scanning
the internet from someone's home connection is a different act with different
consequences, and "any IP" is not a capability this should hand out by
accident. RFC1918 and loopback only; everything else is declined with a reason
rather than silently skipped.

**One job at a time.** Two full sweeps at once would double the load on the
network for no benefit, and a second request almost always means the first was
forgotten rather than that two are wanted.
"""
from __future__ import annotations

import errno
import ipaddress
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from . import db, fingerprint

# A deep scan is aimed at one machine, so concurrency here is concurrency
# against that machine. Higher is faster and also looks more like an attack to
# anything watching; 128 open sockets is brisk without being a SYN flood.
WORKERS = 128
TIMEOUT = 0.35
CHUNK = 512                       # ports per progress update

# What a port number usually means - shared with the scheduled sweep, in
# app/fingerprint.py, which also asks each open port what it is.
WELL_KNOWN = fingerprint.PORT_NAMES
FINGERPRINT_MAX = 64

_LOCK = threading.Lock()
_JOB: dict | None = None


def _private(ip: str) -> ipaddress.IPv4Address:
    """Parse and refuse anything that is not this network's business."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise ValueError(f"{ip!r} is not an IP address")
    if addr.version != 4:
        raise ValueError("only IPv4 is supported")
    if not (addr.is_private or addr.is_loopback):
        raise ValueError(
            f"{addr} is a public address. This scans private networks only - "
            "probing the internet from your own connection is a different act "
            "with different consequences.")
    return addr


def _probe(ip: str, port: int) -> str:
    """One of "open", "closed" or "filtered". Same three-state answer the
    scheduled sweep uses: a refusal is evidence, a timeout is not."""
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return "open"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as exc:
        return "closed" if exc.errno == errno.ECONNRESET else "filtered"


def _declared(ip: str) -> tuple[set[int], list[dict]]:
    """Every port the inventory claims at this address, and who claims it.

    Twenty containers can share one address, so the question "is this port
    accounted for" is about the address, not about any one entry.
    """
    import re
    ports: set[int] = set()
    owners = []
    for e in db.list_entries():
        if (e.get("ip") or "").strip() != ip:
            continue
        owners.append({"id": e["id"], "name": e["name"], "kind": e.get("kind"),
                       "ports": e.get("ports") or ""})
        for tok in re.findall(r"\d+(?:\s*-\s*\d+)?", str(e.get("ports") or "")):
            if "-" in tok:
                a, b = (int(x) for x in tok.split("-"))
                if 0 < a <= b < 65536 and b - a <= 1024:
                    ports.update(range(a, b + 1))
            elif 0 < int(tok) < 65536:
                ports.add(int(tok))
    return ports, owners


def _run(job: dict) -> None:
    """Sweep, then reconcile. **Every path must end in a terminal state.**

    The first version guarded only the socket loop, so an exception in the
    reconciliation afterwards escaped and left the job saying "running"
    forever - and a caller polling until it stops running polls until it is
    killed. A job that cannot fail visibly is worse than one that fails.
    """
    ip = job["ip"]
    skip = set(job.get("skipped") or [])
    ports = [p for p in range(job["from"], job["to"] + 1) if p not in skip]
    open_now: list[int] = []
    closed = filtered = 0

    def probe(p: int) -> str:
        # Checked inside the worker as well as between chunks: a cancelled
        # sweep should stop costing the target machine connections now, not at
        # the end of the current block of 512.
        if job["state"] == "cancelled":
            return "skipped"
        return _probe(ip, p)

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for i in range(0, len(ports), CHUNK):
                if job["state"] == "cancelled":
                    break
                block = ports[i:i + CHUNK]
                for port, verdict in zip(block, pool.map(probe, block)):
                    if verdict == "open":
                        open_now.append(port)
                    elif verdict == "closed":
                        closed += 1
                    elif verdict == "filtered":
                        filtered += 1
                job["done"] = min(i + CHUNK, len(ports))
                job["open"] = list(open_now)

        declared, owners = _declared(ip)
        job["open"] = open_now
        job["closed"] = closed
        job["filtered"] = filtered
        job["owners"] = owners
        # Ask each open port what it is - the undeclared ones first, since
        # those are the question this scan was run to answer.
        todo = sorted(open_now, key=lambda p: (p in declared, p))[:FINGERPRINT_MAX]
        fps = {} if job["state"] == "cancelled" else fingerprint.many(ip, todo)
        job["results"] = [
            {"port": p, "service": (fingerprint.label(fps[p]) if p in fps
                                    else WELL_KNOWN.get(p, "")),
             "identified": bool(fps.get(p, {}).get("identified")),
             "url": fps.get(p, {}).get("url", ""),
             "declared": p in declared} for p in open_now]
        job["undeclared"] = [r["port"] for r in job["results"]
                             if not r["declared"]]
        # A host that answered nothing at all is not a host with 65535 closed
        # ports; it is a host that did not answer. Say which.
        job["silent"] = not open_now and closed == 0
        if job["state"] != "cancelled":
            job["state"] = "done"
    except Exception as exc:
        job["state"] = "error"
        job["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if job["state"] == "running":            # belt and braces
            job["state"] = "error"
            job["error"] = job["error"] or "ended without a result"
        job["finished_at"] = db.now()
        job["seconds"] = round(time.time() - job["_t0"], 1)


def start(ip: str, first: int = 1, last: int = 65535) -> dict:
    addr = _private(ip)
    if not (1 <= first <= last <= 65535):
        raise ValueError("port range must be within 1-65535")

    # The Open ports source's "Never probe" list applies here too - a deep scan
    # is the one sweep most likely to hit a port that breaks when probed.
    from .sources import by_role, portscan
    b = next(iter(by_role("scanner", configured_only=False)), None)
    skipped = sorted(p for p in portscan.untouchable(b.cfg if b else None, str(addr))
                     if first <= p <= last)

    global _JOB
    with _LOCK:
        if _JOB and _JOB["state"] == "running":
            raise ValueError(
                f"a scan of {_JOB['ip']} is already running "
                f"({_JOB['done']}/{_JOB['total']} ports). One at a time.")
        _JOB = {
            "id": uuid.uuid4().hex[:12], "ip": str(addr),
            "from": first, "to": last, "total": last - first + 1 - len(skipped),
            "skipped": skipped,
            "done": 0, "open": [], "closed": 0, "filtered": 0,
            "results": [], "undeclared": [], "owners": [], "silent": False,
            "state": "running", "error": None,
            "started_at": db.now(), "finished_at": None, "seconds": None,
            "_t0": time.time(),
        }
        job = _JOB
    threading.Thread(target=_run, args=(job,), daemon=True).start()
    return status()


def status() -> dict | None:
    if not _JOB:
        return None
    j = {k: v for k, v in _JOB.items() if not k.startswith("_")}
    j["percent"] = round(100 * j["done"] / j["total"], 1) if j["total"] else 0
    return j


def cancel() -> bool:
    if _JOB and _JOB["state"] == "running":
        _JOB["state"] = "cancelled"
        return True
    return False


def summarise(job: dict) -> str:
    """The result as a sentence, for an MCP client to read out."""
    if not job:
        return "No scan has been run."
    if job["state"] == "running":
        return (f"Scanning {job['ip']} - {job['done']} of {job['total']} ports "
                f"({job['percent']}%), {len(job['open'])} open so far.")
    if job["state"] == "error":
        return f"Scan of {job['ip']} failed: {job['error']}"
    if job.get("silent"):
        return (f"{job['ip']} answered nothing on any of {job['total']} ports - "
                "no refusals either, so the host is unreachable or dropping "
                "every packet. That is not evidence that its ports are closed.")
    lines = [f"{job['ip']}: {len(job['open'])} open of {job['total']} scanned "
             f"in {job.get('seconds')}s."
             + (f" Not probed (Never probe): {', '.join(map(str, job['skipped']))}."
                if job.get("skipped") else "")]
    for r in job["results"]:
        lines.append(f"  {r['port']:>5}  {r['service'] or '-':<22}"
                     f"{'declared' if r['declared'] else 'NOT DECLARED'}")
    if job["undeclared"]:
        lines.append(f"{len(job['undeclared'])} port(s) nothing in the "
                     "inventory accounts for.")
    return "\n".join(lines)
