"""GET /metrics - NetMap's state in the Prometheus text format, so Grafana or
Alertmanager can watch it without NetMap growing an alerting engine.

Written by hand: the format is a few lines of text per series and does not
need prometheus_client. Everything here is read from what the status sweep
and the source scans already hold; producing it never probes or scans.
"""
import calendar
import math
import time

from . import db, discovery, status

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _esc(v) -> str:
    """A label value: backslash, double quote and newline escaped, as the
    format requires. Entry names can contain anything."""
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _num(v) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "NaN"
    if isinstance(v, bool):
        return "1" if v else "0"
    return repr(float(v)) if isinstance(v, float) else str(int(v))


def _epoch(ts: str | None):
    if not ts:
        return None
    try:
        return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return None


class _Out:
    def __init__(self):
        self.lines: list[str] = []

    def family(self, name: str, help_: str, rows: list[tuple[dict, object]]) -> None:
        """One metric: HELP and TYPE, then a sample per (labels, value)."""
        self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} gauge"]
        for labels, value in rows:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{lab}}} {_num(value)}" if lab else f"{name} {_num(value)}")


def render(version: str) -> str:
    out = _Out()
    entries = db.list_entries()
    cache = status.CACHE

    def ent(e: dict) -> dict:
        # The id keeps two entries with the same name apart.
        return {"id": e["id"], "entry": e["name"]}

    monitored = [e for e in entries if e.get("monitor")]
    out.family("netmap_entry_up",
               "1 if the entry's health check answered, 0 if not, NaN if not checked.",
               [({**ent(e), "category": e["category"], "criticality": e.get("criticality") or "",
                  "check": (cache.get(e["id"]) or {}).get("check") or ""},
                 (cache.get(e["id"]) or {}).get("up")) for e in monitored])
    out.family("netmap_entry_latency_ms", "How long the last successful check took.",
               [(ent(e), cache[e["id"]]["latency_ms"]) for e in monitored
                if (cache.get(e["id"]) or {}).get("latency_ms") is not None])
    out.family("netmap_cert_expiry_timestamp_seconds",
               "When the certificate an https health check reads expires.",
               [(ent(e), _epoch(cache[e["id"]]["tls"].get("not_after"))) for e in monitored
                if ((cache.get(e["id"]) or {}).get("tls") or {}).get("not_after")])

    health = discovery.health()
    out.family("netmap_source_up",
               "1 if the source's last scan worked, 0 if it failed, NaN before its first.",
               [({"source": h["source"], "type": h["type"]},
                 None if h["pending"] else h["ok"]) for h in health if h["configured"]])
    out.family("netmap_source_last_scan_timestamp_seconds", "When the source was last scanned.",
               [({"source": h["source"]}, _epoch(h["last_try"])) for h in health
                if h["configured"] and h["last_try"]])
    out.family("netmap_source_last_success_timestamp_seconds",
               "When a scan of the source last worked.",
               [({"source": h["source"]}, _epoch(h["last_ok"])) for h in health
                if h["configured"] and h["last_ok"]])
    by_type: dict[tuple, int] = {}
    totals = []
    for h in health:
        r = discovery.cached(h["source"])
        if not h["configured"] or not r or r.get("error"):
            continue
        totals.append(({"source": h["source"]}, len(r.get("findings", []))))
        for f in r.get("findings", []):
            k = (h["source"], f.get("type") or "")
            by_type[k] = by_type.get(k, 0) + 1
    out.family("netmap_findings", "Findings from the source's last scan, by type.",
               [({"source": s, "type": t}, n) for (s, t), n in sorted(by_type.items())])
    out.family("netmap_source_findings",
               "All findings from the source's last scan - 0 is a real answer here.", totals)

    out.family("netmap_build_info", "The running NetMap version.", [({"version": version}, 1)])
    return "\n".join(out.lines) + "\n"
