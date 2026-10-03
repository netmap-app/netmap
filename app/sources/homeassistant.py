"""Home Assistant as a discovery source.

The other four sources answer "does this exist and where". This one answers a
question none of them can: **is it actually working?**

NetMap's own health check is a TCP connect. That covers most things and misses
the ones that matter most here. Zigbee2MQTT publishes no port at all — its
frontend is mapped to null and reachable only through HA ingress — so a service
that every light switch in the house depends on cannot be probed, and
`critical_down` silently excludes it. Home Assistant already knows the answer:
`binary_sensor.zigbee2mqtt_bridge_connection_state`.

The contract is the same one the Pi-hole source uses for groups. An entry states
its expectation as a tag:

    ha:binary_sensor.zigbee2mqtt_bridge_connection_state     expect "on"
    ha:sensor.some_thing=running                             expect "running"

Without a tag there is nothing to check — Home Assistant's own state cannot be
"wrong", it is simply what is true. The tag is the inventory saying what it
believes, which is the only thing a scan can contradict.

A long-lived access token carries the full privileges of the user who made it;
Home Assistant has no read-only token. As with OPNsense and Pi-hole the
safeguard is that this module issues GETs only, and nothing in it can construct
a write.
"""
import json
import re
import urllib.error
import urllib.request

from .. import db
from . import _http, fields

FIELDS = [
    {"key": "url", "label": "Base URL", "type": "text", "required": True, "wide": True,
     "placeholder": "http://10.0.0.20:8123", "binds": True, "env": "NETMAP_HA_URL"},
    {"key": "token", "label": "Long-lived access token", "type": "password",
     "secret": True, "required": True, "wide": True, "env": "NETMAP_HA_TOKEN"},
    {"key": "verify_ssl", "label": "Verify TLS certificate", "type": "checkbox",
     "default": True, "env": "NETMAP_HA_VERIFY"},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 8,
     "env": "NETMAP_HA_TIMEOUT"},
]

ROLES = ("health",)  # see dynamic.ROLES

# "Not here" findings — dropped when another homeassistant source sees the entry.
ABSENCE = {'ha-missing'}

TAG_RE = re.compile(r"^ha:([a-z_]+\.[a-z0-9_]+)(?:=(.+))?$", re.I)
# What "healthy" means for a domain when the tag does not say. Only these are
# judged; a sensor's value is data, not a verdict, so it is checked for being
# available and nothing more.
EXPECT = {"binary_sensor": "on", "switch": "on", "light": "on",
          "input_boolean": "on", "automation": "on"}
# "unavailable" means the integration behind the entity is not answering.
# "unknown" does not: a button is unknown until pressed, and a sensor is
# unknown until it first reports. Counting them together inflated the number
# to 220 where Home Assistant's own registry said 78 — a figure that disagrees
# with the source system is worse than no figure at all.
DEAD = {"unavailable", "none", ""}


def configured(cfg: dict) -> bool:
    return bool(cfg.get("url") and cfg.get("token"))


def _get(cfg: dict, path: str):
    req = urllib.request.Request(
        cfg["url"] + path, headers={"accept": "application/json",
                                    "authorization": "Bearer " + cfg["token"]})
    with _http.urlopen(req, timeout=cfg["timeout"], context=fields.tls(cfg)) as r:
        return json.loads(r.read())


def test(cfg: dict) -> dict:
    try:
        _get(cfg, "/api/")
        return {"ok": True, "error": None}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"Home Assistant answered HTTP {exc.code}"
                + (" — check the token" if exc.code in (401, 403) else "")}
    except Exception as exc:
        return {"ok": False, "error": f"cannot reach Home Assistant at {cfg['url']}: {exc}"}


def _ref(e: dict) -> dict:
    return {"id": e["id"], "name": e["name"], "ip": e.get("ip", "")}


def _wanted(e: dict) -> list[tuple[str, str | None]]:
    out = []
    for t in (e.get("tags") or []):
        m = TAG_RE.match((t or "").strip())
        if m:
            out.append((m.group(1).lower(), (m.group(2) or "").strip() or None))
    return out


def scan(cfg: dict) -> dict:
    P = cfg.get("_key", "ha")          # finding-key prefix; see dynamic.py
    out = {"source": cfg.get("_id", "homeassistant"), "configured": configured(cfg),
           "scanned_at": db.now(), "host": {"url": cfg.get("url", "")},
           "findings": [], "counts": {}, "error": None}
    if not configured(cfg):
        out["error"] = "not configured — add the URL and token in Settings › Sources"
        return out
    try:
        states = _get(cfg, "/api/states")
    except urllib.error.HTTPError as exc:
        out["error"] = (f"Home Assistant answered HTTP {exc.code}"
                        + (" — check the token; a long-lived access token "
                           "is made under your HA profile"
                           if exc.code in (401, 403) else ""))
        return out
    except Exception as exc:
        out["error"] = f"cannot reach Home Assistant at {cfg['url']}: {exc}"
        return out

    by_id = {s.get("entity_id"): s for s in states if s.get("entity_id")}
    entries = db.list_entries()
    ign = db.ignores()
    findings: list[dict] = []
    checked = 0

    for e in entries:
        for ent, want in _wanted(e):
            checked += 1
            st = by_id.get(ent)
            if st is None:
                findings.append({
                    "type": "ha-missing", "key": f"{P}:missing:{e['id']}:{ent}",
                    "label": f"{e['name']} — {ent} does not exist",
                    "detail": ("the inventory watches this entity and Home "
                               "Assistant has no such entity. Renamed, removed, "
                               "or its integration failed to load — in every "
                               "case nothing is being checked."),
                    "entry": _ref(e),
                })
                continue
            val = str(st.get("state", "")).strip()
            if val.lower() in DEAD:
                findings.append({
                    "type": "ha-unavailable", "key": f"{P}:dead:{e['id']}:{ent}",
                    "label": f"{e['name']} — {ent} is {val or 'empty'}",
                    "detail": ("Home Assistant has the entity but the "
                               "integration behind it is not answering — which "
                               "a TCP check on this entry would not show."),
                    "entry": _ref(e),
                })
                continue
            expect = want or EXPECT.get(ent.split(".", 1)[0])
            if expect and val.lower() != expect.lower():
                findings.append({
                    "type": "ha-state", "key": f"{P}:state:{e['id']}:{ent}",
                    "label": f"{e['name']} — {ent} is \"{val}\"",
                    "detail": f"expected \"{expect}\"" + ("" if want else
                              " (the default for this entity type; add "
                              "=<state> to the tag to expect something else)"),
                    "entry": _ref(e),
                })

    dead_total = sum(1 for s in states
                     if str(s.get("state", "")).lower() == "unavailable")
    # ---- sightings: what Home Assistant currently says -------------------
    seen: list[dict] = []
    for e in entries:
        for ent, _want in _wanted(e):
            st = by_id.get(ent)
            if st is None:
                continue
            val = str(st.get("state", "")).strip() or "empty"
            unit = ((st.get("attributes") or {}).get("unit_of_measurement") or "")
            seen.append({"entry_id": e["id"], "fact": f"ha:{ent}",
                         "value": (val + (f" {unit}" if unit else "")).strip()})
    db.record_sightings(cfg.get("_id", "homeassistant"), seen)

    kept = [f for f in findings if f["key"] not in ign]
    out["findings"] = kept
    out["counts"] = {
        "entities": len(states), "watched": checked,
        # Context, not a finding: NetMap has no opinion about entities nobody
        # asked it to watch, but a jump here is worth a human glance.
        "unavailable_in_ha": dead_total,
        "missing": sum(1 for f in kept if f["type"] == "ha-missing"),
        "unavailable": sum(1 for f in kept if f["type"] == "ha-unavailable"),
        "state": sum(1 for f in kept if f["type"] == "ha-state"),
        "ignored": len(findings) - len(kept),
    }
    return out
