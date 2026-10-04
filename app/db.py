"""SQLite storage layer for NetMap."""
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any

DB_PATH = os.environ.get("NETMAP_DB", "/data/netmap.db")

_local = threading.local()

FIELDS = [
    "category", "name", "host", "ip", "mac", "ports", "protocol",
    "url", "tags", "notes", "monitor", "verified", "pinned", "kind",
    "criticality", "zone", "secret_ref", "healthcheck",
]

# A device can legitimately have more than one: a laptop's wired and wireless
# NICs, or a phone presenting both a hardware address and an iOS private one.
# Stored as given, matched lowercased and separator-insensitive.
MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")

# How an entry is checked, when a TCP connect to its first port is not enough
# ("port open" is not "service works"). Deliberately small:
#   tcp | tcp:<port>                  a connect, to the first port or this one
#   http | https [:<port>][/<path>][=<code>]
#                                     a GET; without =<code> anything below 500
#                                     is up. https also reads the certificate.
#   ping                              an ICMP echo, for things with no port
#   none                              monitored, but not probed
# Empty is today's behaviour: a TCP connect to the first port.
HEALTHCHECK_RE = re.compile(
    r"(?i)^(?:(tcp)(?::(\d{1,5}))?|(https?)(?::(\d{1,5}))?(/[^\s=]*)?(?:=([1-5]\d\d))?"
    r"|(ping)|(none))$")


def parse_healthcheck(spec: str) -> dict | None:
    """{kind, port, path, expect} for a health check, None for the default
    (empty). Raises ValueError on anything outside the grammar above."""
    spec = (spec or "").strip()
    if not spec:
        return None
    m = HEALTHCHECK_RE.match(spec)
    port = m and (m.group(2) or m.group(4))
    if not m or (port and not 0 < int(port) < 65536):
        raise ValueError(f"health check {spec[:40]!r} is not one of: tcp, tcp:<port>, "
                         "http or https[:<port>][/<path>][=<code>], ping, none")
    kind = (m.group(1) or m.group(3) or m.group(7) or m.group(8)).lower()
    return {"kind": kind, "port": int(port) if port else None,
            "path": m.group(5) or "/", "expect": int(m.group(6)) if m.group(6) else None}


# What a thing *is*, as opposed to what it does (category) or where it runs
# (host). Free text is accepted; these are the values the UI offers.
KINDS = ["hardware", "vm", "container", "service", "rule", "network"]

# How much it matters when this is down. Deliberately four values, not a
# number - anything finer invites debate and gets left at the default.
CRITICALITY = ["critical", "important", "normal", "experimental"]

# How two entries relate. src is the subject: "Plex runs_on NAS".
EDGE_TYPES = ["runs_on", "depends_on", "exposed_by", "connects_to",
              "resolves_to", "backs_up_to"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    category   TEXT    NOT NULL DEFAULT 'Uncategorised',
    name       TEXT    NOT NULL,
    host       TEXT    DEFAULT '',
    ip         TEXT    DEFAULT '',
    mac        TEXT    DEFAULT '',
    ports      TEXT    DEFAULT '',
    protocol   TEXT    DEFAULT '',
    url        TEXT    DEFAULT '',
    tags       TEXT    DEFAULT '',
    notes      TEXT    DEFAULT '',
    monitor    INTEGER NOT NULL DEFAULT 1,
    verified   INTEGER NOT NULL DEFAULT 1,
    pinned     INTEGER NOT NULL DEFAULT 0,
    kind       TEXT    NOT NULL DEFAULT '',
    criticality TEXT   NOT NULL DEFAULT '',
    zone       TEXT    NOT NULL DEFAULT '',
    secret_ref TEXT    NOT NULL DEFAULT '',
    healthcheck TEXT   NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
-- Relationships. The inventory knows what things ARE; edges know how they
-- hang together, which is what makes "why is this down" answerable.
-- derived=1 marks an edge inferred from the entries themselves; those are
-- rebuilt on demand, so a hand-made edge is never overwritten by a guess.
CREATE TABLE IF NOT EXISTS edges (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    src     INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    dst     INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    type    TEXT    NOT NULL,
    note    TEXT    NOT NULL DEFAULT '',
    derived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(src, dst, type)
);
-- Host mapping. `host` is free text ("VM 101", "CT 107", "HA add-on") and
-- rarely equals any entry's name, so fuzzy matching cannot bridge it without
-- inventing edges. This table records the answer once per distinct string -
-- roughly a dozen decisions that then place every entry in the tree.
CREATE TABLE IF NOT EXISTS host_map (
    host_key TEXT PRIMARY KEY,
    raw      TEXT NOT NULL,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    updated_at TEXT NOT NULL
);
-- Discovery exceptions. Findings themselves are recomputed on every scan, so
-- there is no stale inbox to garbage-collect; what has to persist is the
-- decision to stop being told about something.
CREATE TABLE IF NOT EXISTS ignores (
    key        TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
-- How long a problem has been a problem. The queue can say what is wrong and
-- how badly, but "since when" is the thing that separates a blip from a rot,
-- and nothing else in the schema records it: a down entry has a transition in
-- `observations`, but "9 entries not verified" has no event anywhere.
-- Keyed by the item's own key, with the fingerprint beside it - when the
-- situation changes the fingerprint changes and the clock restarts, because
-- "7 mismatches since Tuesday" is a different fact from "5 mismatches since
-- Tuesday, 7 since an hour ago".
CREATE TABLE IF NOT EXISTS attention_age (
    key         TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL
);
-- Status observations. Only transitions are stored, not every sweep: a row
-- here means "this changed at this moment", which is what a timeline needs
-- and keeps the table small enough to ignore.
CREATE TABLE IF NOT EXISTS observations (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    ts       TEXT    NOT NULL,
    up       INTEGER,
    latency_ms INTEGER,
    target   TEXT,
    detail   TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    entry_id INTEGER,
    name     TEXT,
    detail   TEXT
);
-- What each source currently says about an entry, as opposed to where it
-- disagrees. Findings are the disagreements and are recomputed every scan;
-- these are the agreements, and without them a screen cannot answer "who
-- says this port is open" - a port that matches produces no finding at all,
-- so agreement was previously invisible.
--
-- Latest-only by construction: the primary key overwrites, so the table
-- stays at roughly entries x facts x sources. History belongs in `audit`;
-- this answers what is true *now*, and `seen_at` going stale while an entry
-- looks fine is itself worth reporting later.
--
-- Never a write to the inventory. A sighting is what a source saw; the entry
-- changes only when a person accepts a finding.
CREATE TABLE IF NOT EXISTS presence (
    ip      TEXT NOT NULL,
    source  TEXT NOT NULL,
    label   TEXT NOT NULL DEFAULT '',
    mac     TEXT NOT NULL DEFAULT '',
    detail  TEXT NOT NULL DEFAULT '',
    seen_at TEXT NOT NULL,
    PRIMARY KEY (ip, source)
);
CREATE INDEX IF NOT EXISTS idx_presence_ip ON presence(ip);
-- The history `presence` cannot hold, since it is replaced on every scan:
-- when each device was first and last seen. Keyed by MAC when a source knows
-- it, else "ip:<address>". first_seen is written once; the rest follows the
-- latest sighting. Rows unseen for a long time are purged at start-up.
-- baseline=1 marks what a source already saw the first time it reported:
-- there before anyone was keeping track, so never "new".
CREATE TABLE IF NOT EXISTS presence_seen (
    key          TEXT PRIMARY KEY,
    mac          TEXT NOT NULL DEFAULT '',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    first_source TEXT NOT NULL DEFAULT '',
    last_source  TEXT NOT NULL DEFAULT '',
    last_ip      TEXT NOT NULL DEFAULT '',
    label        TEXT NOT NULL DEFAULT '',
    baseline     INTEGER NOT NULL DEFAULT 0
);

-- Devices a person is keeping an eye on without adding them (app/watch.py).
-- `key` is a presence_seen key (the MAC, else "ip:<address>"); `finding` is
-- the new-device finding it was watched from, so Ignore can ignore that.
-- `online` is what the last check saw, so coming back is a transition.
CREATE TABLE IF NOT EXISTS watch (
    key        TEXT PRIMARY KEY,
    finding    TEXT NOT NULL DEFAULT '',
    label      TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    online     INTEGER NOT NULL DEFAULT 0,
    last_seen  TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
-- When something last confirmed an entry exists: a source's sighting, an
-- address a source sees at its MAC or machine, or its health check
-- answering. What app/stale.py reads to say "nothing has seen this for N
-- days" - and only of entries that were confirmed at least once.
CREATE TABLE IF NOT EXISTS entry_seen (
    entry_id  INTEGER PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
    last_seen TEXT NOT NULL,
    how       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sightings (
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    fact     TEXT NOT NULL,
    value    TEXT NOT NULL,
    source   TEXT NOT NULL,
    seen_at  TEXT NOT NULL,
    PRIMARY KEY (entry_id, fact, source)
);
-- Small key/value settings the app itself owns (e.g. the generated key that
-- encrypts source_instances.secrets). Not user-facing config - that is what
-- source_instances and the entries table are for.
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Every source, added from Settings › Sources. `config` is plain JSON (url,
-- flags, anything not secret); `secrets` is JSON of field -> ciphertext,
-- encrypted by app/crypto.py. Neither is read here - this table only stores
-- and retrieves; app/sources/dynamic.py knows what a driver's fields mean.
CREATE TABLE IF NOT EXISTS source_instances (
    id         TEXT PRIMARY KEY,
    type       TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    config     TEXT    NOT NULL DEFAULT '{}',
    secrets    TEXT    NOT NULL DEFAULT '{}',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
-- Where notifications go, added from Settings › Notifications. Stored like a
-- source: `config` plain, `secrets` ciphertext (app/crypto.py), and `events`
-- the JSON list of what this channel is told about. app/notify.py knows what
-- the fields mean; this table only stores them.
CREATE TABLE IF NOT EXISTS notify_channels (
    id         TEXT PRIMARY KEY,
    type       TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    config     TEXT    NOT NULL DEFAULT '{}',
    secrets    TEXT    NOT NULL DEFAULT '{}',
    events     TEXT    NOT NULL DEFAULT '[]',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_cat ON entries(category);
CREATE INDEX IF NOT EXISTS idx_sight_entry ON sightings(entry_id);
CREATE INDEX IF NOT EXISTS idx_sight_fact  ON sightings(fact);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_entry ON audit(entry_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_edges_src   ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst   ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_obs_entry   ON observations(entry_id, id DESC);
"""


def record_sightings(source: str, rows: list[dict]) -> int:
    """Replace everything `source` says. Whole source, not just the entries in
    this batch.

    The first version deleted only the rows of the entries it was about to
    write, reasoning that a half-finished scan should not erase what a source
    said last time - silence is not a retraction. That reasoning was sound and
    the premise was wrong: this is called once, at the end of a scan that
    completed, with the source's full set of observations. A source that fails
    returns before reaching here, so there is no half-finished case to protect
    against.

    What the narrow delete did instead was make every attribution change
    permanent. v1.36.0 credited every container on one Docker host with all
    twenty-odd hostnames at that address; v1.36.1 corrected it to credit only
    the service that owns the name - and because the corrected scan no longer
    mentioned those containers, their rows were never deleted. The Overview
    then read fourteen surviving copies of `hostname:plex.example.org` and
    reported twenty-seven naked hostnames out of sixteen published.

    A record that can only ever grow is not a record of what is true now.
    """
    rows = [r for r in rows if r.get("entry_id") and r.get("fact")]
    ts = now()
    c = conn()
    c.execute("DELETE FROM sightings WHERE source=?", (source,))
    if rows:
        c.executemany(
            "INSERT OR REPLACE INTO sightings "
            "(entry_id, fact, value, source, seen_at) VALUES (?,?,?,?,?)",
            [(int(r["entry_id"]), str(r["fact"]), str(r.get("value") or ""),
              source, ts) for r in rows])
    # A source that says anything about an entry confirms it exists - except
    # a port it found closed or unanswered, which says the opposite, and a
    # planning tool's `intent`, which says only that it should.
    confirm({int(r["entry_id"]) for r in rows if r["fact"] != "intent"
             and not str(r.get("value") or "").startswith(("closed", "filtered", "not probed"))},
            f"seen by {source}")
    _commit()
    return len(rows)


def confirm(entry_ids, how: str) -> None:
    """Record that these entries were just seen to exist - see entry_seen."""
    ids = [int(i) for i in entry_ids]
    if ids:
        conn().executemany(
            "INSERT INTO entry_seen (entry_id, last_seen, how) SELECT ?,?,? "
            "WHERE EXISTS (SELECT 1 FROM entries WHERE id=?) ON CONFLICT(entry_id) "
            "DO UPDATE SET last_seen=excluded.last_seen, how=excluded.how",
            [(i, now(), how, i) for i in ids])
        _commit()


def last_seen(entry_id: int | None = None) -> dict[int, dict]:
    """entry id -> {last_seen, how}; one entry, or all."""
    sql, args = "SELECT * FROM entry_seen", []
    if entry_id is not None:
        sql, args = sql + " WHERE entry_id=?", [entry_id]
    return {r["entry_id"]: dict(r) for r in conn().execute(sql, args)}


def sightings_for(entry_id: int) -> list[dict]:
    return [dict(r) for r in conn().execute(
        "SELECT fact, value, source, seen_at FROM sightings WHERE entry_id=? "
        "ORDER BY fact, source", (entry_id,)).fetchall()]


def sightings_by_fact(fact: str) -> list[dict]:
    """Everyone who says something about one fact - e.g. "port:32400"."""
    return [dict(r) for r in conn().execute(
        "SELECT entry_id, value, source, seen_at FROM sightings WHERE fact=? "
        "ORDER BY source", (fact,)).fetchall()]


def record_presence(source: str, rows: list[dict]) -> int:
    """Who is on the network according to one source, replacing what it said.

    Deliberately *not* entries. The inventory tracks infrastructure, and the
    decision to keep phones and lightbulbs out of it stands - a row nobody
    maintains is worse than no row. But an address map that shows only what
    the inventory knows is wrong in the one moment it is consulted: there are
    a dozen occupied addresses on this LAN that the strip drew as free.

    So presence is a layer over the map, not a set of records. Nothing here
    is authored, nothing needs upkeep, and it is replaced wholesale on every
    scan - see record_sightings for why per-row deletion was the wrong call.
    """
    rows = [r for r in rows if (r.get("ip") or "").strip()]
    ts = now()
    c = conn()
    c.execute("DELETE FROM presence WHERE source=?", (source,))
    # Which sources have reported before, even if they saw nothing: the first
    # report of each is the baseline of the device history.
    reported = set(json.loads(get_setting("presence_reported") or "[]"))
    first_time = source not in reported
    if first_time:
        set_setting("presence_reported", json.dumps(sorted(reported | {source})))
    if rows:
        c.executemany(
            "INSERT OR REPLACE INTO presence (ip, source, label, mac, detail, seen_at) "
            "VALUES (?,?,?,?,?,?)",
            [(str(r["ip"]).strip(), source, str(r.get("label") or ""),
              str(r.get("mac") or "").lower(), str(r.get("detail") or ""), ts)
             for r in rows])
        # An address a source sees confirms the machine that holds it: by
        # MAC, or by address for hardware and VMs (not every service that
        # shares a host's address - the host being up says nothing of them).
        by_mac, by_ip = {}, {}
        for e in list_entries():
            for m in MAC_RE.findall(e.get("mac") or ""):
                by_mac[m.replace("-", ":").lower()] = e["id"]
            if e.get("kind") in ("hardware", "vm") and (e.get("ip") or "").strip():
                by_ip.setdefault(e["ip"].strip(), e["id"])
        confirm({by_mac.get(str(r.get("mac") or "").lower()) or by_ip.get(str(r["ip"]).strip())
                 for r in rows} - {None}, f"address seen by {source}")
        # First seen once, last seen every time - see presence_seen.
        c.executemany(
            "INSERT INTO presence_seen (key, mac, first_seen, last_seen, first_source, "
            "last_source, last_ip, label, baseline) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen, "
            "last_source=excluded.last_source, last_ip=excluded.last_ip, "
            "label=CASE WHEN excluded.label != '' THEN excluded.label ELSE label END",
            [(_seen_key(r), str(r.get("mac") or "").lower(), ts, ts, source, source,
              str(r["ip"]).strip(), str(r.get("label") or ""), 1 if first_time else 0)
             for r in rows])
    _commit()
    return len(rows)


def _seen_key(row: dict) -> str:
    mac = str(row.get("mac") or "").lower()
    return mac if mac else "ip:" + str(row["ip"]).strip()


def presence_history() -> list[dict]:
    """Every device ever seen and not yet purged, newest first."""
    return [dict(r) for r in conn().execute(
        "SELECT * FROM presence_seen ORDER BY first_seen DESC, key")]


def purge_presence_history(days: int) -> int:
    """Forget devices not seen for `days` - a phone that visited once should
    not be remembered for ever."""
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
    cur = conn().execute("DELETE FROM presence_seen WHERE last_seen < ?", (cutoff,))
    _commit()
    return cur.rowcount


def presence(untracked_only: bool = True) -> list[dict]:
    """Addresses a source has seen. By default only those no entry claims -
    the map already draws the tracked ones."""
    rows = [dict(r) for r in conn().execute(
        "SELECT ip, source, label, mac, detail, seen_at FROM presence "
        "ORDER BY ip, source").fetchall()]
    if untracked_only:
        claimed = {(e.get("ip") or "").strip() for e in list_entries()}
        rows = [r for r in rows if r["ip"] not in claimed]
    # One row per address, with every source that saw it.
    merged: dict[str, dict] = {}
    for r in rows:
        m = merged.setdefault(r["ip"], {"ip": r["ip"], "label": "", "mac": "",
                                        "sources": [], "detail": "",
                                        "seen_at": r["seen_at"]})
        m["sources"].append(r["source"])
        # First non-empty wins, so a source with nothing to say does not
        # silence the next one. That is the whole fix: OPNsense's "*"
        # placeholder used to count as an answer and hid UniFi's real name.
        for k in ("label", "mac", "detail"):
            if not m[k] and (r.get(k) or "").strip():
                m[k] = r[k].strip()
    return sorted(merged.values(), key=lambda x: [int(p) for p in x["ip"].split(".")]
                  if x["ip"].count(".") == 3 and all(p.isdigit() for p in x["ip"].split("."))
                  else [0, 0, 0, 0])


def all_sightings() -> list[dict]:
    """Every current sighting. The Overview reads the whole table because the
    question it asks - what is reachable from outside - is not about one
    entry."""
    return [dict(r) for r in conn().execute(
        "SELECT entry_id, fact, value, source, seen_at FROM sightings "
        "ORDER BY source, fact").fetchall()]


def sighting_stats() -> dict:
    r = conn().execute(
        "SELECT COUNT(*) n, COUNT(DISTINCT entry_id) e, COUNT(DISTINCT source) s "
        "FROM sightings").fetchone()
    return {"rows": r["n"], "entries": r["e"], "sources": r["s"]}


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@contextmanager
def transaction():
    """All writes inside commit together at the end, or not at all.

    Every write function here commits as it goes, which is right for one
    change and wrong for many: an import that died after forty of sixty rows
    left forty applied. Inside this block their commits are postponed to its
    end, and any exception rolls the whole block back. Blocks nest - only the
    outermost one commits. Per thread, like the connection it wraps.
    """
    _local.depth = getattr(_local, "depth", 0) + 1
    try:
        yield
    except BaseException:
        _local.depth -= 1
        if _local.depth == 0:
            conn().rollback()
        raise
    _local.depth -= 1
    if _local.depth == 0:
        conn().commit()


def _commit() -> None:
    if getattr(_local, "depth", 0) == 0:
        conn().commit()


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        c = sqlite3.connect(DB_PATH, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        # The background discovery loop and a web request are different
        # threads with different connections, so they can collide on a write.
        # Without this, the loser raises SQLITE_BUSY immediately instead of
        # waiting the moment it takes for the other to finish.
        c.execute("PRAGMA busy_timeout=5000")
        # WAL already makes a torn write impossible; NORMAL trades an fsync
        # per commit for one per checkpoint, which on this workload is the
        # difference between free and not.
        c.execute("PRAGMA synchronous=NORMAL")
        _local.conn = c
    return c


def unwritable_reason() -> str | None:
    """Why the database directory cannot be written, or None if it can.

    Since 1.69.4 the container runs as an ordinary user. A data directory left
    root-owned by an older, root-run container would otherwise fail deep inside
    SQLite with "attempt to write a readonly database" - this says what to do.
    """
    d = os.path.dirname(os.path.abspath(DB_PATH))
    target = DB_PATH if os.path.exists(DB_PATH) else d
    if not os.path.exists(d) or os.access(target, os.W_OK):
        return None
    uid, gid = os.getuid(), os.getgid()
    return (f"cannot write {target} as uid {uid}. Give the data directory to "
            f"that user once, on the Docker host: docker run --rm -v "
            f"<host data dir>:/data --user 0 --entrypoint chown netmap-netmap "
            f"-R {uid}:{gid} /data")


def init() -> None:
    conn().executescript(SCHEMA)
    # Additive migrations for databases created by an earlier version.
    have = {r[1] for r in conn().execute("PRAGMA table_info(entries)").fetchall()}
    for col, ddl in (("pinned", "INTEGER NOT NULL DEFAULT 0"),
                     ("kind", "TEXT NOT NULL DEFAULT ''"),
                     ("criticality", "TEXT NOT NULL DEFAULT ''"),
                     ("zone", "TEXT NOT NULL DEFAULT ''"),
                     ("secret_ref", "TEXT NOT NULL DEFAULT ''"),
                     ("mac", "TEXT NOT NULL DEFAULT ''"),
                     ("healthcheck", "TEXT NOT NULL DEFAULT ''")):
        if col not in have:
            conn().execute(f"ALTER TABLE entries ADD COLUMN {col} {ddl}")
            print(f"[netmap] migrated: added entries.{col}", flush=True)
    # Before 1.92.1 criticality was free text; the spellings that meant one
    # of the four now say so.
    n = conn().execute(
        "UPDATE entries SET criticality=lower(trim(criticality)) "
        "WHERE criticality != lower(trim(criticality)) "
        "AND lower(trim(criticality)) IN (%s)" % ",".join("?" * len(CRITICALITY)),
        CRITICALITY).rowcount
    if n:
        print(f"[netmap] migrated: {n} criticality value(s) normalised", flush=True)
    have = {r[1] for r in conn().execute("PRAGMA table_info(observations)").fetchall()}
    if "detail" not in have:
        conn().execute("ALTER TABLE observations ADD COLUMN detail TEXT")
        print("[netmap] migrated: added observations.detail", flush=True)
    conn().commit()


def log(actor: str, action: str, entry_id: int | None, name: str, detail: Any = None) -> None:
    conn().execute(
        "INSERT INTO audit (ts, actor, action, entry_id, name, detail) VALUES (?,?,?,?,?,?)",
        (now(), actor, action, entry_id, name,
         json.dumps(detail, ensure_ascii=False) if detail is not None else None),
    )
    _commit()


def row_to_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["tags"] = [t.strip() for t in (d.get("tags") or "").split(",") if t.strip()]
    d["monitor"] = bool(d["monitor"])
    d["verified"] = bool(d["verified"])
    d["pinned"] = bool(d.get("pinned", 0))
    return d


def list_entries(query: str = "", category: str = "", tag: str = "",
                 kind: str = "", criticality: str = "", zone: str = "",
                 ip: str = "") -> list[dict]:
    sql = "SELECT * FROM entries WHERE 1=1"
    args: list[Any] = []
    if query:
        # A search for "_" or "%" means that character. Unescaped, LIKE read
        # them as wildcards and a search for "_" matched every entry.
        like = "%" + _like_escape(query.lower()) + "%"
        cols = ("name", "host", "ip", "ports", "notes", "tags", "protocol",
                "category", "mac")
        sql += " AND (" + " OR ".join(f"lower({c}) LIKE ? ESCAPE '\\'" for c in cols) + ")"
        args += [like] * len(cols)
    if category:
        sql += " AND category = ?"
        args.append(category)
    if tag:
        # Narrowed in SQL, decided below: `tags` is one comma-separated
        # string, so LIKE alone matched substrings - "ha" found "alpha".
        sql += " AND lower(tags) LIKE ? ESCAPE '\\'"
        args.append("%" + _like_escape(tag.strip().lower()) + "%")
    if kind:
        sql += " AND kind = ?"
        args.append(kind)
    if criticality:
        sql += " AND criticality = ?"
        args.append(criticality)
    if zone:
        sql += " AND zone = ?"
        args.append(zone)
    if ip:
        # Exact, unlike the search: "10.0.0.1" must not find .15.
        sql += " AND trim(ip) = ?"
        args.append(ip.strip())
    sql += " ORDER BY category, name COLLATE NOCASE"
    rows = [row_to_dict(r) for r in conn().execute(sql, args).fetchall()]
    if tag:
        want = tag.strip().lower()
        rows = [r for r in rows if want in {t.lower() for t in r["tags"]}]
    return rows


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def get_entry(entry_id: int) -> dict | None:
    r = conn().execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    return row_to_dict(r) if r else None


def _norm(data: dict) -> dict:
    out = {}
    for f in FIELDS:
        if f not in data:
            continue
        v = data[f]
        if f == "tags" and isinstance(v, list):
            v = ",".join(str(x).strip() for x in v if str(x).strip())
        if f in ("monitor", "verified", "pinned"):
            v = 1 if v in (True, 1, "1", "true", "True", "yes") else 0
        if f == "mac":
            # Accept whatever the source spells it as - colons, hyphens, upper
            # or lower - and store one canonical form, so a MAC copied from
            # OPNsense matches the same MAC copied from UniFi.
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            found = MAC_RE.findall(str(v or ""))
            v = ", ".join(dict.fromkeys(m.replace("-", ":").lower() for m in found))
        if f == "url" and v:
            # The UI turns this into a link. `javascript:` and `data:` would
            # make it a script instead, and the field is writable by MCP and
            # import as well as by a person, so it is checked here, once.
            v = str(v).strip()
            if not re.match(r"(?i)^https?://[^\s]+$", v):
                raise ValueError(f"url must start with http:// or https:// (got {v[:60]!r})")
        if f == "healthcheck":
            v = str(v or "").strip()
            parse_healthcheck(v)
        if f == "criticality":
            # Alerts and uptime compare it exactly: "Critical" or a typo would
            # quietly make an entry never alert.
            v = str(v or "").strip().lower()
            if v and v not in CRITICALITY:
                raise ValueError(f"criticality must be one of {', '.join(CRITICALITY)} "
                                 f"(got {v[:30]!r})")
        if f == "name" and v is not None and not str(v).strip():
            raise ValueError("name cannot be empty")
        out[f] = "" if v is None else v
    return out


def create_entry(data: dict, actor: str = "web") -> dict:
    d = _norm(data)
    if not d.get("name"):
        raise ValueError("name is required")
    d.setdefault("category", "Uncategorised")
    d.setdefault("monitor", 1)
    d.setdefault("verified", 1)
    d.setdefault("pinned", 0)
    cols = list(d.keys()) + ["created_at", "updated_at"]
    vals = list(d.values()) + [now(), now()]
    cur = conn().execute(
        f"INSERT INTO entries ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
    _commit()
    entry = get_entry(cur.lastrowid)
    log(actor, "create", entry["id"], entry["name"], d)
    return entry


def update_entry(entry_id: int, data: dict, actor: str = "web") -> dict | None:
    before = get_entry(entry_id)
    if not before:
        return None
    d = _norm(data)
    if not d:
        return before
    d["updated_at"] = now()
    conn().execute(
        f"UPDATE entries SET {','.join(f'{k}=?' for k in d)} WHERE id=?",
        list(d.values()) + [entry_id])
    _commit()
    after = get_entry(entry_id)
    changed = {k: [before.get(k), after.get(k)] for k in d
               if k != "updated_at" and before.get(k) != after.get(k)}
    if changed:
        log(actor, "update", entry_id, after["name"], changed)
    return after


def delete_entry(entry_id: int, actor: str = "web") -> bool:
    e = get_entry(entry_id)
    if not e:
        return False
    conn().execute("DELETE FROM entries WHERE id=?", (entry_id,))
    _commit()
    log(actor, "delete", entry_id, e["name"], e)
    return True


# --------------------------------------------------------------------------
# Relationships
# --------------------------------------------------------------------------
def _edge_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["derived"] = bool(d["derived"])
    return d


def edges_for(entry_id: int) -> dict:
    """Both directions, with the other end's name resolved.

    "out" is what this entry depends on / runs on; "in" is what would notice
    if this entry went away.
    """
    out = conn().execute(
        "SELECT e.*, x.name AS other_name, x.kind AS other_kind, "
        "       x.category AS other_category "
        "FROM edges e JOIN entries x ON x.id = e.dst "
        "WHERE e.src = ? ORDER BY e.type, x.name COLLATE NOCASE", (entry_id,)).fetchall()
    inc = conn().execute(
        "SELECT e.*, x.name AS other_name, x.kind AS other_kind, "
        "       x.category AS other_category "
        "FROM edges e JOIN entries x ON x.id = e.src "
        "WHERE e.dst = ? ORDER BY e.type, x.name COLLATE NOCASE", (entry_id,)).fetchall()
    return {"out": [_edge_row(r) for r in out], "in": [_edge_row(r) for r in inc]}


def all_edges() -> list[dict]:
    rows = conn().execute(
        "SELECT e.*, a.name AS src_name, b.name AS dst_name "
        "FROM edges e JOIN entries a ON a.id = e.src JOIN entries b ON b.id = e.dst "
        "ORDER BY e.type, a.name COLLATE NOCASE").fetchall()
    return [_edge_row(r) for r in rows]


def link(src: int, dst: int, type_: str, note: str = "", derived: bool = False,
         actor: str = "web") -> dict:
    if src == dst:
        raise ValueError("an entry cannot link to itself")
    if type_ not in EDGE_TYPES:
        raise ValueError(f"type must be one of {', '.join(EDGE_TYPES)}")
    a, b = get_entry(src), get_entry(dst)
    if not a or not b:
        raise ValueError("both entries must exist")
    conn().execute(
        "INSERT OR IGNORE INTO edges (src, dst, type, note, derived, created_at) "
        "VALUES (?,?,?,?,?,?)", (src, dst, type_, note, 1 if derived else 0, now()))
    _commit()
    if not derived:
        log(actor, "link", src, a["name"], {"type": type_, "to": b["name"], "dst": dst})
    return {"src": src, "dst": dst, "type": type_}


def unlink(src: int, dst: int, type_: str, actor: str = "web") -> bool:
    a, b = get_entry(src), get_entry(dst)
    cur = conn().execute("DELETE FROM edges WHERE src=? AND dst=? AND type=?",
                         (src, dst, type_))
    _commit()
    if cur.rowcount and a:
        log(actor, "unlink", src, a["name"],
            {"type": type_, "to": b["name"] if b else dst})
    return bool(cur.rowcount)


def clear_derived_edges() -> int:
    cur = conn().execute("DELETE FROM edges WHERE derived = 1")
    _commit()
    return cur.rowcount


# --------------------------------------------------------------------------
# Discovery exceptions
# --------------------------------------------------------------------------
def ignores(source: str = "") -> dict[str, dict]:
    sql = "SELECT * FROM ignores"
    args: list = []
    if source:
        sql += " WHERE source = ?"
        args.append(source)
    return {r["key"]: dict(r) for r in conn().execute(sql, args).fetchall()}


def add_ignore(key: str, source: str, label: str = "", reason: str = "",
               actor: str = "web") -> dict:
    if not key.strip():
        raise ValueError("key is required")
    conn().execute(
        "INSERT INTO ignores (key, source, label, reason, created_at) VALUES (?,?,?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET reason=excluded.reason, label=excluded.label",
        (key.strip(), source, label, reason, now()))
    _commit()
    log(actor, "ignore", None, label or key, {"key": key, "source": source})
    return {"key": key, "source": source, "label": label}


def clear_ignore(key: str, actor: str = "web") -> bool:
    cur = conn().execute("DELETE FROM ignores WHERE key=?", (key,))
    _commit()
    if cur.rowcount:
        log(actor, "unignore", None, key, {"key": key})
    return bool(cur.rowcount)


def host_key(text: str) -> str:
    import re as _re
    return _re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def host_map() -> dict[str, dict]:
    rows = conn().execute(
        "SELECT h.*, e.name FROM host_map h JOIN entries e ON e.id = h.entry_id").fetchall()
    return {r["host_key"]: dict(r) for r in rows}


def set_host_map(raw: str, entry_id: int, actor: str = "web") -> dict:
    key = host_key(raw)
    if not key:
        raise ValueError("host cannot be empty")
    e = get_entry(entry_id)
    if not e:
        raise ValueError(f"no entry with id {entry_id}")
    conn().execute(
        "INSERT INTO host_map (host_key, raw, entry_id, updated_at) VALUES (?,?,?,?) "
        "ON CONFLICT(host_key) DO UPDATE SET entry_id=excluded.entry_id, "
        "raw=excluded.raw, updated_at=excluded.updated_at",
        (key, raw.strip(), entry_id, now()))
    _commit()
    log(actor, "map-host", entry_id, e["name"], {"host": raw.strip()})
    return {"host": raw.strip(), "entry_id": entry_id, "name": e["name"]}


def clear_host_map(raw: str, actor: str = "web") -> bool:
    cur = conn().execute("DELETE FROM host_map WHERE host_key=?", (host_key(raw),))
    _commit()
    if cur.rowcount:
        log(actor, "map-host", None, raw.strip(), {"removed": True})
    return bool(cur.rowcount)


def unlinked_count() -> int:
    """Entries with no relationship in either direction - the map's blank spots."""
    return conn().execute(
        "SELECT COUNT(*) FROM entries WHERE id NOT IN "
        "(SELECT src FROM edges UNION SELECT dst FROM edges)").fetchone()[0]


_PORT_RE = re.compile(r"port\s+(\d+)", re.I)


def _via(rel: str, note: str) -> str:
    """One sentence shape for every row of the tree.

    The notes these come from are written by four different hands - the UniFi
    derivation says "UniFi switch port 4", an older hand-mapping says "wired to
    the PoE switch", another says "2.5 GbE uplink into PoE switch port 8", and
    an edge made without a note says nothing at all. All four mean the same
    thing, and reading four phrasings down one column is work the reader should
    not have to do. A cable is reduced to the only part that varies - which
    port - because the other end is the row it is nested under.

    Provenance is not an annotation: "host matched by host map" is how the link
    was derived, and it would put the same sentence on forty rows.
    """
    note = (note or "").strip()
    if rel == "connects_to":
        m = _PORT_RE.search(note)
        return f"port {m.group(1)}" if m else "wired"
    if not note or note.lower().startswith("host matched"):
        return ""
    return note


def topology(mode: str = "tree") -> list[dict]:
    """The forest of what sits under what, physical layer included.

    Two relations, one tree. `connects_to` says what a thing is plugged into;
    `runs_on` says what it runs on. Cabling only parents *hardware*: a switch
    port explains where a NAS or an access point sits, and that is the layer
    the physical tree is drawn in. Everything else - VMs, containers,
    services - hangs off its host, because a `connects_to` edge on a VM means
    something else entirely (a mount, a dependency, a path), and letting that
    outrank `runs_on` would move the VM off the machine it actually runs on.

    Anything with neither is a root, so hardware and stray services both
    surface rather than quietly vanishing.
    """
    rows = {e["id"]: e for e in list_entries()}
    parent: dict[int, int] = {}
    via: dict[int, str] = {}

    def claim(rel: str, hardware_only: bool) -> None:
        for r in conn().execute(
                "SELECT src, dst, type, note FROM edges WHERE type=? "
                "ORDER BY id", (rel,)).fetchall():
            if (r["src"] not in rows or r["dst"] not in rows
                    or r["src"] == r["dst"] or r["src"] in parent):
                continue
            if hardware_only and rows[r["src"]].get("kind") != "hardware":
                continue
            parent[r["src"]] = r["dst"]
            via[r["src"]] = _via(rel, r["note"])

    # Three questions, three trees. "tree" is the whole house - what runs on
    # what, with cabling underneath it. "physical" is the cabling alone, drawn
    # over hardware only, so a switch port is not buried under twenty
    # containers. "deps" abandons hosting entirely and parents each thing by
    # what it needs, which is the shape you want when something is down.
    if mode == "physical":
        rows = {i: e for i, e in rows.items()
                if e.get("kind") in ("hardware", "network")}
        claim("connects_to", False)
    elif mode == "deps":
        claim("depends_on", False)
        claim("exposed_by", False)
    else:
        claim("connects_to", True)
        claim("runs_on", False)

    # A hand-made pair of edges could point at each other; walk up from every
    # node and drop any parent link that closes a loop, so one bad edge cannot
    # make the whole view disappear.
    # Break the cycle, not a bystander. The first version popped
    # `parent[start]` whenever the walk from `start` revisited a node - which
    # orphans anything merely *pointing at* a loop rather than part of one.
    # A small switch sat at the top level for exactly that reason: it hangs
    # off a PoE switch, and the PoE switch and a server are cabled to each
    # other twice (the SFP+ carrying the LAN, and a management RJ45), so the
    # walk 4 → 68 → 71 → 68 found a loop three hops away and dropped 4's link.
    #
    # Two cables between one pair is a real arrangement a tree cannot hold, so
    # one edge has to go. The one dropped is the edge that *closes* the loop -
    # deterministic, and it leaves the rest of the chain standing.
    for start in list(parent):
        seen, prev, cur = {start}, start, parent.get(start)
        while cur is not None:
            if cur in seen:
                parent.pop(prev, None)
                via.pop(prev, None)
                break
            seen.add(cur)
            prev, cur = cur, parent.get(cur)

    kids: dict[int, list[int]] = {}
    for child, par in parent.items():
        kids.setdefault(par, []).append(child)

    def node(i: int, seen: frozenset) -> dict:
        e = rows[i]
        children = [] if i in seen else [
            node(c, seen | {i}) for c in sorted(
                kids.get(i, []), key=lambda x: rows[x]["name"].lower())]
        return {"id": i, "name": e["name"], "kind": e["kind"],
                "category": e["category"], "ip": e["ip"],
                "ports": e["ports"], "criticality": e["criticality"],
                "via": via.get(i, ""), "children": children}

    roots = [i for i in rows if i not in parent]
    if mode == "deps":
        # Nearly nothing declares a dependency, so keeping the unparented
        # childless ones would bury the answer under eighty singletons.
        roots = [i for i in roots if kids.get(i)]
    return [node(i, frozenset()) for i in
            sorted(roots, key=lambda x: rows[x]["name"].lower())]


def _declares(text: str, port: int) -> bool:
    """Does a `ports` field claim this port? Ranges count."""
    for tok in re.findall(r"\d+(?:\s*-\s*\d+)?", str(text or "")):
        if "-" in tok:
            a, b = (int(x) for x in tok.split("-"))
            if a <= port <= b:
                return True
        elif int(tok) == port:
            return True
    return False


def port_dossier(port: int) -> dict:
    """Everything the inventory and the sources say about one port number.

    The Ports table answers "who uses 8080". This answers the question that
    follows it - is it open, is it forwarded, is a name pointed at it, and is
    anything in front of that name - which until now meant opening four
    entries and reading their sightings by eye.
    """
    entries = [e for e in list_entries() if _declares(e.get("ports"), port)]
    ids = {e["id"] for e in entries}
    names = {e["id"]: e["name"] for e in list_entries()}

    rows = [dict(r) for r in conn().execute(
        "SELECT entry_id, fact, value, source, seen_at FROM sightings "
        "WHERE fact LIKE 'port:%' ORDER BY source, entry_id").fetchall()]
    said = [r for r in rows if _declares(r["fact"][5:], port)]
    ids |= {r["entry_id"] for r in said}

    # A name is on this port when the thing it forwards to ends in it.
    routed = [dict(r) for r in conn().execute(
        "SELECT entry_id, fact, value, source, seen_at FROM sightings "
        "WHERE fact LIKE 'proxy:%' OR fact LIKE 'hostname:%' "
        "ORDER BY source, fact").fetchall()]
    routed = [r for r in routed if re.search(rf":{port}\b", r["value"] or "")]
    ids |= {r["entry_id"] for r in routed}

    for r in said + routed:
        r["entry_name"] = names.get(r["entry_id"], "")

    by_id = {e["id"]: e for e in entries}
    for i in ids - set(by_id):
        e = get_entry(i)
        if e:
            by_id[i] = e

    return {
        "port": port,
        "entries": sorted(by_id.values(), key=lambda e: (e["name"] or "").lower()),
        "declared_by": sorted(e["id"] for e in entries),
        "observed": said,
        "routed": routed,
    }


# --------------------------------------------------------------------------
# Status observations - transitions only
# --------------------------------------------------------------------------
OBS_KEEP = 5000


def attention_age(items: list[dict]) -> dict[str, str]:
    """First-seen timestamps for the current queue, recording any new ones.

    Also forgets keys that are no longer in the queue, so a problem that comes
    back is a new problem with a new clock rather than one that claims to have
    been broken for a month while it was fine.
    """
    c = conn()
    have = {r["key"]: dict(r) for r in
            c.execute("SELECT key, fingerprint, first_seen FROM attention_age")}
    ts = now()
    out: dict[str, str] = {}
    for it in items:
        k, fp = it.get("key") or "", str(it.get("fingerprint") or "")
        if not k:
            continue
        row = have.get(k)
        if row and row["fingerprint"] == fp:
            out[k] = row["first_seen"]
        else:
            c.execute("INSERT INTO attention_age (key, fingerprint, first_seen) "
                      "VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET "
                      "fingerprint=excluded.fingerprint, first_seen=excluded.first_seen",
                      (k, fp, ts))
            out[k] = ts
    gone = set(have) - set(out)
    if gone:
        c.executemany("DELETE FROM attention_age WHERE key=?", [(k,) for k in gone])
    _commit()
    return out


def record_observation(entry_id: int, up, latency_ms, target, detail: str = "") -> None:
    conn().execute(
        "INSERT INTO observations (entry_id, ts, up, latency_ms, target, detail) "
        "VALUES (?,?,?,?,?,?)",
        (entry_id, now(), None if up is None else (1 if up else 0), latency_ms, target,
         detail or None))
    _commit()


def last_observation(entry_id: int) -> dict | None:
    r = conn().execute(
        "SELECT * FROM observations WHERE entry_id=? ORDER BY id DESC LIMIT 1",
        (entry_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["up"] = None if d["up"] is None else bool(d["up"])
    return d


def observations(entry_id: int, limit: int = 20) -> list[dict]:
    rows = conn().execute(
        "SELECT * FROM observations WHERE entry_id=? ORDER BY id DESC LIMIT ?",
        (entry_id, limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["up"] = None if d["up"] is None else bool(d["up"])
        out.append(d)
    return out


def recent_observations(limit: int = 40) -> list[dict]:
    rows = conn().execute(
        "SELECT o.*, e.name FROM observations o JOIN entries e ON e.id = o.entry_id "
        "ORDER BY o.id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["up"] = None if d["up"] is None else bool(d["up"])
        out.append(d)
    return out


def prune_observations() -> int:
    cur = conn().execute(
        "DELETE FROM observations WHERE id <= "
        "(SELECT MAX(id) FROM observations) - ?", (OBS_KEEP,))
    _commit()
    return cur.rowcount


def service_context(entry_id: int) -> dict | None:
    """Everything about one entry in a single read - the service card."""
    e = get_entry(entry_id)
    if not e:
        return None
    return {"entry": e, "edges": edges_for(entry_id),
            "observations": observations(entry_id, 12),
            "changes": audit(12, entry_id=entry_id)}


def export_rows() -> list[dict]:
    """Every entry, every stored field - the JSON backup payload."""
    return list_entries()


def _stored(entry: dict, field: str):
    """An existing entry's value in the same shape _norm() produces, so the
    two can be compared without false 'changed' hits (tags are a list on the
    way out and a comma string on the way in; flags are bools vs ints)."""
    v = entry.get(field)
    if field == "tags":
        return ",".join(v or [])
    if field in ("monitor", "verified", "pinned"):
        return 1 if v else 0
    return "" if v is None else v


def _resolve_ref(ref_id, ref_name, existing: dict, by_name: dict) -> int | None:
    """Find an entry from an exported reference: id if it still means the same
    thing, otherwise the name. Ids drift between databases; names usually don't."""
    if isinstance(ref_id, int) and ref_id in existing:
        return ref_id
    cands = by_name.get(str(ref_name or "").strip().lower(), [])
    return cands[0]["id"] if len(cands) == 1 else None


def import_relations(edges: list, hmap: dict, actor: str = "web") -> dict:
    """Restore edges and host mappings after the entries they point at exist."""
    existing = {e["id"]: e for e in list_entries()}
    by_name: dict[str, list[dict]] = {}
    for e in existing.values():
        by_name.setdefault(e["name"].strip().lower(), []).append(e)

    linked = skipped = mapped = 0
    for ed in edges or []:
        src = _resolve_ref(ed.get("src"), ed.get("src_name"), existing, by_name)
        dst = _resolve_ref(ed.get("dst"), ed.get("dst_name"), existing, by_name)
        if src is None or dst is None:
            skipped += 1
            continue
        try:
            link(src, dst, ed.get("type", ""), ed.get("note", ""),
                 derived=bool(ed.get("derived")), actor=actor)
            linked += 1
        except ValueError:
            skipped += 1
    for m in (hmap or {}).values():
        target = _resolve_ref(m.get("entry_id"), m.get("name"), existing, by_name)
        if target is None:
            continue
        try:
            set_host_map(m.get("raw", ""), target, actor=actor)
            mapped += 1
        except ValueError:
            pass
    return {"links": linked, "links_skipped": skipped, "hosts_mapped": mapped}


def import_entries(rows: list, mode: str = "merge", dry_run: bool = True,
                   actor: str = "web") -> dict:
    """Apply a JSON export back to the database.

    Matching: by `id` when that id exists here, otherwise by name
    (case-insensitive). A name that matches several existing entries is
    ambiguous and is reported rather than guessed at.

    mode "merge"   - create what is missing, update what differs, delete nothing.
    mode "replace" - as merge, and delete entries the file does not contain.

    With dry_run the database is untouched and the plan is returned, which is
    what the UI shows before you commit.
    """
    if mode not in ("merge", "replace"):
        raise ValueError("mode must be 'merge' or 'replace'")
    if not isinstance(rows, list):
        raise ValueError("entries must be a list")

    existing = {e["id"]: e for e in list_entries()}
    by_name: dict[str, list[dict]] = {}
    for e in existing.values():
        by_name.setdefault(e["name"].strip().lower(), []).append(e)

    creates: list[dict] = []
    updates: list[tuple[int, dict, dict]] = []   # (id, data, changed-summary)
    problems: list[dict] = []
    matched_ids: set[int] = set()
    unchanged = 0

    for raw in rows:
        if not isinstance(raw, dict) or not str(raw.get("name", "")).strip():
            problems.append({"name": str(raw)[:60], "why": "no name"})
            continue
        name = str(raw["name"]).strip()
        target = None
        rid = raw.get("id")
        if isinstance(rid, int) and rid in existing:
            target = existing[rid]
        else:
            cands = by_name.get(name.lower(), [])
            if len(cands) == 1:
                target = cands[0]
            elif len(cands) > 1:
                problems.append({"name": name,
                                 "why": f"{len(cands)} existing entries share this "
                                        "name - rename them first"})
                continue
        try:
            data = _norm(raw)
        except ValueError as exc:
            problems.append({"name": name, "why": str(exc)})
            continue
        if target:
            matched_ids.add(target["id"])
            changed = {k: [_stored(target, k), v] for k, v in data.items()
                       if _stored(target, k) != v}
            if changed:
                updates.append((target["id"], data,
                                {"id": target["id"], "name": target["name"],
                                 "fields": sorted(changed)}))
            else:
                unchanged += 1
        else:
            creates.append(data)

    deletes = ([existing[i] for i in sorted(set(existing) - matched_ids)]
               if mode == "replace" else [])

    plan = {
        "mode": mode,
        "dry_run": dry_run,
        "create": [c["name"] for c in creates][:200],
        "update": [u[2] for u in updates][:200],
        "delete": [{"id": d["id"], "name": d["name"]} for d in deletes][:200],
        "counts": {"create": len(creates), "update": len(updates),
                   "delete": len(deletes), "unchanged": unchanged,
                   "problems": len(problems)},
        "problems": problems[:50],
    }
    if dry_run:
        return plan

    for d in creates:
        create_entry(d, actor=actor)
    for entry_id, data, _ in updates:
        update_entry(entry_id, data, actor=actor)
    for d in deletes:
        delete_entry(d["id"], actor=actor)
    log(actor, "import", None, f"{mode} import", plan["counts"])
    plan["applied"] = True
    return plan


def audit(limit: int = 100, entry_id: int | None = None,
          include_logins: bool = False) -> list[dict]:
    """Newest first. Sign-ins are recorded here but are not changes to the
    inventory, so they are left out unless asked for."""
    if entry_id is None:
        where = "" if include_logins else "WHERE action != 'login' "
        rows = conn().execute(
            f"SELECT * FROM audit {where}ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    else:
        rows = conn().execute(
            "SELECT * FROM audit WHERE entry_id=? ORDER BY id DESC LIMIT ?",
            (entry_id, limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        if d.get("detail"):
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
        out.append(d)
    return out


def meta() -> dict:
    cats = [r[0] for r in conn().execute(
        "SELECT DISTINCT category FROM entries ORDER BY category").fetchall()]
    tags: set[str] = set()
    for (t,) in conn().execute("SELECT tags FROM entries WHERE tags != ''").fetchall():
        tags.update(x.strip() for x in t.split(",") if x.strip())
    kinds = [r[0] for r in conn().execute(
        "SELECT DISTINCT kind FROM entries WHERE kind != '' ORDER BY kind").fetchall()]
    zones = [r[0] for r in conn().execute(
        "SELECT DISTINCT zone FROM entries WHERE zone != '' ORDER BY zone").fetchall()]
    crits = [r[0] for r in conn().execute(
        "SELECT DISTINCT criticality FROM entries WHERE criticality != ''").fetchall()]
    total = conn().execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    return {"categories": cats, "tags": sorted(tags), "kinds": kinds,
            "all_kinds": KINDS, "zones": zones,
            "criticalities": [c for c in CRITICALITY if c in set(crits)],
            "all_criticalities": CRITICALITY, "edge_types": EDGE_TYPES,
            "total": total}


def count() -> int:
    return conn().execute("SELECT COUNT(*) FROM entries").fetchone()[0]


def seed_if_empty(path: str) -> int:
    """Load app/seed.json on first boot (empty database only)."""
    import json as _json
    if count() > 0 or not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as fh:
        rows = _json.load(fh)
    for r in rows:
        create_entry(r, actor="seed")
    return len(rows)


# --------------------------------------------------------------------------
# App settings (small key/value store - currently just the secret key)
# --------------------------------------------------------------------------
def get_setting(key: str) -> str | None:
    r = conn().execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return r["value"] if r else None


def delete_setting(key: str) -> None:
    conn().execute("DELETE FROM kv WHERE key=?", (key,))
    _commit()


def set_setting(key: str, value: str) -> None:
    conn().execute(
        "INSERT INTO kv (key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    _commit()


# --------------------------------------------------------------------------
# Legacy per-source overrides (≤ 1.74, table `source_settings`). A database
# that has never been upgraded still has them; sources.migrate_legacy() reads
# them once and then drops the table.
# --------------------------------------------------------------------------
LEGACY_SETTINGS_DDL = ("CREATE TABLE IF NOT EXISTS source_settings (source TEXT PRIMARY KEY, "
                       "overrides TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL)")


def get_source_settings(source: str) -> dict:
    try:
        r = conn().execute("SELECT overrides FROM source_settings WHERE source=?",
                           (source,)).fetchone()
    except sqlite3.OperationalError:          # no such table: nothing legacy left
        return {}
    return json.loads(r["overrides"]) if r else {}


def drop_source_settings() -> bool:
    had = conn().execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                         "AND name='source_settings'").fetchone() is not None
    if had:
        conn().execute("DROP TABLE source_settings")
        _commit()
    return had


# --------------------------------------------------------------------------
# Source instances - every source, configured from Settings › Sources.
# --------------------------------------------------------------------------
def list_source_instances(type_: str = "") -> list[dict]:
    sql = "SELECT * FROM source_instances"
    args: list = []
    if type_:
        sql += " WHERE type = ?"
        args.append(type_)
    sql += " ORDER BY created_at"
    out = []
    for r in conn().execute(sql, args).fetchall():
        d = dict(r)
        d["config"] = json.loads(d["config"] or "{}")
        d["secrets"] = json.loads(d["secrets"] or "{}")
        d["enabled"] = bool(d["enabled"])
        out.append(d)
    return out


def get_source_instance(instance_id: str) -> dict | None:
    matches = [i for i in list_source_instances() if i["id"] == instance_id]
    return matches[0] if matches else None


def create_source_instance(type_: str, name: str, config: dict, secrets: dict,
                           enabled: bool = True, actor: str = "web",
                           iid: str | None = None, action: str = "source-add",
                           detail: dict | None = None) -> dict:
    if not type_.strip():
        raise ValueError("type is required")
    if not name.strip():
        raise ValueError("name is required")
    import uuid
    iid = iid or uuid.uuid4().hex[:12]
    ts = now()
    conn().execute(
        "INSERT INTO source_instances "
        "(id, type, name, config, secrets, enabled, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (iid, type_.strip(), name.strip(), json.dumps(config or {}),
         json.dumps(secrets or {}), 1 if enabled else 0, ts, ts))
    _commit()
    log(actor, action, None, name.strip(), {"type": type_, "id": iid, **(detail or {})})
    return get_source_instance(iid)


def rename_source_instance(old_id: str, new_id: str, actor: str = "system") -> None:
    """Give an instance a new id - used once, to make a single-instance
    source's id its type (see sources.migrate_legacy)."""
    conn().execute("UPDATE source_instances SET id=? WHERE id=?", (new_id, old_id))
    _commit()
    log(actor, "source-update", None, new_id, {"id": new_id, "was": old_id})


def update_source_instance(instance_id: str, name: str | None = None,
                           config: dict | None = None, secrets: dict | None = None,
                           enabled: bool | None = None, actor: str = "web",
                           detail: dict | None = None) -> dict | None:
    before = get_source_instance(instance_id)
    if not before:
        return None
    new_name = before["name"] if name is None else name.strip() or before["name"]
    new_config = before["config"] if config is None else config
    # Secrets are merged field-by-field, not replaced wholesale - leaving a
    # field blank in the edit form means "keep what's there", since the
    # actual value is never sent back to the browser to be resubmitted.
    new_secrets = dict(before["secrets"])
    if secrets:
        new_secrets.update(secrets)
    new_enabled = before["enabled"] if enabled is None else enabled
    conn().execute(
        "UPDATE source_instances SET name=?, config=?, secrets=?, enabled=?, "
        "updated_at=? WHERE id=?",
        (new_name, json.dumps(new_config), json.dumps(new_secrets),
         1 if new_enabled else 0, now(), instance_id))
    _commit()
    # Which fields changed, never their values: the audit log is readable
    # over MCP.
    log(actor, "source-update", None, new_name, {"id": instance_id, **(detail or {})})
    return get_source_instance(instance_id)


def delete_source_instance(instance_id: str, actor: str = "web") -> bool:
    inst = get_source_instance(instance_id)
    if not inst:
        return False
    conn().execute("DELETE FROM source_instances WHERE id=?", (instance_id,))
    _commit()
    log(actor, "source-delete", None, inst["name"], {"id": instance_id, "type": inst["type"]})
    return True


# --------------------------------------------------------------------------
# Notification channels - Settings › Notifications. Same shape as a source
# instance, plus the list of events the channel wants.
# --------------------------------------------------------------------------
def list_notify_channels() -> list[dict]:
    out = []
    for r in conn().execute("SELECT * FROM notify_channels ORDER BY created_at, id"):
        d = dict(r)
        for k in ("config", "secrets"):
            d[k] = json.loads(d[k] or "{}")
        d["events"] = json.loads(d["events"] or "[]")
        d["enabled"] = bool(d["enabled"])
        out.append(d)
    return out


def get_notify_channel(channel_id: str) -> dict | None:
    return next((c for c in list_notify_channels() if c["id"] == channel_id), None)


def save_notify_channel(channel_id: str | None, type_: str, name: str, config: dict,
                        secrets: dict, events: list, enabled: bool,
                        actor: str = "web", detail: dict | None = None) -> dict:
    """Create (no id) or replace one channel. `secrets` is the complete
    ciphertext map - merging "blank means keep" is the caller's job."""
    import uuid
    ts = now()
    if not name.strip():
        raise ValueError("name is required")
    row = (type_, name.strip(), json.dumps(config), json.dumps(secrets),
           json.dumps(events), 1 if enabled else 0, ts)
    if channel_id is None:
        channel_id = uuid.uuid4().hex[:12]
        conn().execute(
            "INSERT INTO notify_channels (type, name, config, secrets, events, enabled, "
            "updated_at, id, created_at) VALUES (?,?,?,?,?,?,?,?,?)", row + (channel_id, ts))
        action = "notify-add"
    else:
        conn().execute(
            "UPDATE notify_channels SET type=?, name=?, config=?, secrets=?, events=?, "
            "enabled=?, updated_at=? WHERE id=?", row + (channel_id,))
        action = "notify-update"
    _commit()
    # Field names, never values: the audit log is readable over MCP.
    log(actor, action, None, name.strip(), {"id": channel_id, "type": type_, **(detail or {})})
    return get_notify_channel(channel_id)


def set_notify_secrets(channel_id: str, secrets: dict) -> None:
    """Re-encrypted ciphertext only - used by the key rotation at start-up."""
    conn().execute("UPDATE notify_channels SET secrets=? WHERE id=?",
                   (json.dumps(secrets), channel_id))
    _commit()


def delete_notify_channel(channel_id: str, actor: str = "web") -> bool:
    ch = get_notify_channel(channel_id)
    if not ch:
        return False
    conn().execute("DELETE FROM notify_channels WHERE id=?", (channel_id,))
    _commit()
    log(actor, "notify-delete", None, ch["name"], {"id": channel_id, "type": ch["type"]})
    return True
