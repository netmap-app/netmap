"""Inventory conflict detection.

Finds the mistakes you cannot see by eye across sixty rows: two things
claiming one address, a port booked twice, the same service entered
twice under different names, an entry that says "monitor me" but carries
nothing to probe.

Every rule is deliberately narrow. A detector that cries wolf gets
ignored, and an ignored detector is worse than none — so anything that
is *normally* true of a homelab (a dozen containers sharing the host's
IP, a port-forward pointing at a service that already exists) is not a
conflict here.

Escape hatch: tag either entry `dup-ok` and every pair it belongs to is
suppressed.
"""
import re
from typing import Any

_PORT_RE = re.compile(r"\b(\d{1,5})\b")
SUPPRESS_TAG = "dup-ok"

# Kinds that ARE a machine. Two of these on one address is a real clash;
# twenty services on one address is just a host doing its job.
MACHINE_KINDS = {"hardware", "vm"}


def _ports(entry: dict) -> set[int]:
    """Numeric ports mentioned in the free-text ports field.

    "80, 443, 81 (admin)" -> {80, 443, 81}; "2211 -> 22" -> {2211, 22}.
    Values outside the port range are dropped, so "8123 (HTTP)" does not
    contribute a bogus 0.
    """
    out = set()
    for m in _PORT_RE.finditer(entry.get("ports") or ""):
        p = int(m.group(1))
        if 0 < p < 65536:
            out.add(p)
    return out


def _ip(entry: dict) -> str:
    return (entry.get("ip") or "").strip().lower()


def _is_rule(entry: dict) -> bool:
    """A NAT / firewall rule, which legitimately names an address:port that
    already belongs to a service. Recognised by kind, tag or name, so an
    entry that predates the `kind` field is still excluded."""
    if entry.get("kind") == "rule":
        return True
    if "port-forward" in {t.lower() for t in (entry.get("tags") or [])}:
        return True
    return (entry.get("name") or "").strip().lower().startswith("port forward")


def _suppressed(entry: dict) -> bool:
    return SUPPRESS_TAG in {t.lower() for t in (entry.get("tags") or [])}


def _norm_url(entry: dict) -> str:
    u = (entry.get("url") or "").strip().lower().rstrip("/")
    return re.sub(r"^https?://", "", u)


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "category": e.get("category", ""),
            "ip": e.get("ip", ""), "ports": e.get("ports", ""),
            "kind": e.get("kind", "")}


def find(rows: list[dict]) -> list[dict]:
    """Return conflicts, worst first.

    Each conflict: {type, severity, title, detail, entries:[...]}
    severity is "high" (something is certainly wrong) or "review"
    (probably wrong, but a legitimate arrangement could look like this).
    """
    live = [e for e in rows if not _suppressed(e)]
    out: list[dict] = []

    # ---- 1. one ip:port booked twice -------------------------------------
    # Rules (port forwards) are excluded: a NAT rule exists precisely to
    # point at a service that is already in the inventory.
    booked: dict[tuple[str, int], list[dict]] = {}
    for e in live:
        if _is_rule(e):
            continue
        ip = _ip(e)
        if not ip:
            continue
        for p in _ports(e):
            booked.setdefault((ip, p), []).append(e)
    for (ip, port), group in sorted(booked.items()):
        if len(group) > 1:
            out.append({
                "type": "port-clash",
                "severity": "high",
                "title": f"{ip}:{port} claimed by {len(group)} entries",
                "detail": "Two entries cannot both be listening on the same "
                          "address and port. One of them is wrong, or they are "
                          "the same thing entered twice.",
                "entries": [_ref(e) for e in group],
            })

    # ---- 2. two machines on one address ----------------------------------
    machines: dict[str, list[dict]] = {}
    for e in live:
        if e.get("kind") in MACHINE_KINDS and _ip(e):
            machines.setdefault(_ip(e), []).append(e)
    for ip, group in sorted(machines.items()):
        if len({e["name"].strip().lower() for e in group}) > 1:
            out.append({
                "type": "address-clash",
                "severity": "high",
                "title": f"{ip} assigned to {len(group)} machines",
                "detail": "Two hosts or VMs share one IP. Either the address is "
                          "stale on one of them, or you have a real collision.",
                "entries": [_ref(e) for e in group],
            })

    # ---- 3. the same name twice ------------------------------------------
    names: dict[str, list[dict]] = {}
    for e in live:
        names.setdefault(e["name"].strip().lower(), []).append(e)
    for _, group in sorted(names.items()):
        if len(group) > 1:
            out.append({
                "type": "duplicate-name",
                "severity": "review",
                "title": f"{len(group)} entries named “{group[0]['name']}”",
                "detail": "Same name in more than one place. Fine if they really "
                          "are different things — rename them so you can tell.",
                "entries": [_ref(e) for e in group],
            })

    # ---- 4. the same explicit URL twice ----------------------------------
    urls: dict[str, list[dict]] = {}
    for e in live:
        u = _norm_url(e)
        if u:
            urls.setdefault(u, []).append(e)
    for u, group in sorted(urls.items()):
        if len(group) > 1:
            out.append({
                "type": "duplicate-url",
                "severity": "review",
                "title": f"{len(group)} entries point at {u}",
                "detail": "One URL, several entries. Usually a duplicate.",
                "entries": [_ref(e) for e in group],
            })

    # ---- 5. monitored but unprobeable ------------------------------------
    # These sit permanently grey in the UI and quietly inflate "monitored".
    from . import status
    blind = [e for e in rows if e.get("monitor") and status.target_for(e) is None]
    if blind:
        out.append({
            "type": "unprobeable",
            "severity": "review",
            "title": f"{len(blind)} monitored entr"
                     f"{'y' if len(blind) == 1 else 'ies'} cannot be checked",
            "detail": "Monitoring is on but there is no usable address and port, "
                      "so the status dot stays grey forever. Add an address or "
                      "turn monitoring off.",
            "entries": [_ref(e) for e in blind],
        })

    order = {"high": 0, "review": 1}
    out.sort(key=lambda c: (order.get(c["severity"], 9), c["type"]))
    return out


def summary(rows: list[dict]) -> dict[str, Any]:
    c = find(rows)
    return {"count": len(c),
            "high": sum(1 for x in c if x["severity"] == "high"),
            "conflicts": c}
