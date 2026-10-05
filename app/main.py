"""NetMap - homelab infrastructure / IP / port tracker.

Serves:
  /            responsive web UI
  /api/...     JSON REST API
  /mcp         Model Context Protocol (streamable HTTP) endpoint for Claude -
               off unless NETMAP_MCP_TOKEN is set (README section 10)
"""
import csv
import io
import os
import platform
import time
from contextlib import asynccontextmanager
from typing import Any

import anyio
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import conflicts, db, deepscan, discovery, explain as explain_mod, icons as icons_mod, links, overview as overview_mod, status
from . import accounts, crypto, metrics, newdevices, notify, stale, uptime, watch, web_security
from .sources import dynamic

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
CHANGELOG_PATH = os.path.join(os.path.dirname(HERE), "CHANGELOG.md")
VERSION = "2.6.6"
STARTED = time.time()
notify.VERSION = VERSION

# The MCP endpoint path (README 10). Configurable, but never a credential on
# its own: the endpoint is off until NETMAP_MCP_TOKEN is set.
MCP_PATH = os.environ.get("NETMAP_MCP_PATH", "/mcp")
if not MCP_PATH.startswith("/"):
    MCP_PATH = "/" + MCP_PATH
# The switch and the credential in one: set, the path requires
# "Authorization: Bearer <token>"; empty, the path is refused outright - the
# web UI and API require a login by default, and so does MCP.
MCP_TOKEN = os.environ.get("NETMAP_MCP_TOKEN", "")
MCP_OFF_TEXT = b"MCP is off: set NETMAP_MCP_TOKEN to enable it \xe2\x80\x94 README section 10\n"

# The MCP SDK refuses any Host header it does not recognise (HTTP 421), which
# is DNS-rebinding protection: it stops a malicious web page from making a
# browser POST to this endpoint on your LAN. Localhost is always allowed; list
# every other name this server is reached by - public hostname, LAN IP:port.
# Set to "*" to switch the protection off entirely.
_ALLOWED = os.environ.get("NETMAP_ALLOWED_HOSTS", "").strip()
if _ALLOWED == "*":
    SECURITY = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    ALLOWED_HOSTS = ["(protection disabled)"]
else:
    ALLOWED_HOSTS = [h.strip() for h in _ALLOWED.split(",") if h.strip()]
    ALLOWED_HOSTS += ["localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*"]
    ALLOWED_HOSTS = list(dict.fromkeys(ALLOWED_HOSTS))   # a listed localhost once
    SECURITY = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=ALLOWED_HOSTS,
        # Left empty on purpose: a request carrying ANY Origin header is
        # cross-origin browser traffic, which has no business here.
        allowed_origins=[],
    )

# --------------------------------------------------------------------------
# Shared by the MCP tools and the REST routes, which used to carry their own
# copies of the same enrichment and drift apart one fix at a time.
# --------------------------------------------------------------------------
def service_context(entry_id: int) -> dict | None:
    """One entry with its live status, both edge directions (with the other
    end's status), recent transitions and edits, and every current sighting -
    the agreements, which the findings deliberately never mention."""
    ctx = db.service_context(entry_id)
    if not ctx:
        return None
    ctx["status"] = status.CACHE.get(entry_id, {})
    for e in ctx["edges"]["out"]:
        e["other_status"] = status.CACHE.get(e["dst"], {}).get("up")
    for e in ctx["edges"]["in"]:
        e["other_status"] = status.CACHE.get(e["src"], {}).get("up")
    ctx["sightings"] = db.sightings_for(entry_id)
    ctx["uptime"] = {**uptime.compute(entry_id), "shown": uptime.shown(ctx["entry"])}
    ctx["last_seen"] = db.last_seen(entry_id).get(entry_id)
    return ctx


# --------------------------------------------------------------------------
# MCP server
# --------------------------------------------------------------------------
mcp = FastMCP(
    "netmap",
    instructions=(
        "NetMap is a homelab inventory: infrastructure, services, hosts, "
        "IP addresses and ports. Use list_entries to read the inventory, "
        "create_entry / update_entry / delete_entry to change it, and "
        "check_status for live reachability. Always look up an entry's id with "
        "list_entries before updating or deleting."
    ),
    stateless_http=True,
    json_response=True,
    streamable_http_path=MCP_PATH,
    transport_security=SECURITY,
)


@mcp.tool()
async def list_entries(query: str = "", category: str = "", tag: str = "",
                       kind: str = "", criticality: str = "", zone: str = "",
                       limit: int = 200) -> list[dict]:
    """List or search inventory entries.

    query: free text matched against name, host, ip, ports, protocol, notes, tags.
    category / tag / kind / criticality / zone: exact filters. Omit all to get
    everything. criticality is one of critical, important, normal, experimental.
    kind is what a thing IS - hardware, vm, container, service, rule - as
    opposed to category (what it does) or host (where it runs).
    """
    rows = await anyio.to_thread.run_sync(
        lambda: db.list_entries(query, category, tag, kind, criticality, zone))
    for r in rows:
        r["status"] = status.CACHE.get(r["id"], {}).get("up")
    return rows[:max(1, min(limit, 1000))]


@mcp.tool()
async def get_entry(entry_id: int) -> dict:
    """Get a single inventory entry by its numeric id."""
    e = await anyio.to_thread.run_sync(lambda: db.get_entry(entry_id))
    if not e:
        raise ValueError(f"no entry with id {entry_id}")
    e["status"] = status.CACHE.get(entry_id, {})
    return e


@mcp.tool()
async def create_entry(name: str, category: str = "Uncategorised", host: str = "",
                       ip: str = "", mac: str = "", ports: str = "", protocol: str = "",
                       url: str = "", tags: str = "", notes: str = "",
                       monitor: bool = True, verified: bool = True,
                       pinned: bool = False, kind: str = "",
                       criticality: str = "", zone: str = "",
                       secret_ref: str = "", healthcheck: str = "") -> dict:
    """Create a new inventory entry. name is required; tags is comma separated.

    pinned: show this entry in the dashboard's Quick links row.
    criticality: critical | important | normal | experimental.
    zone: network zone, e.g. LAN, IoT, DMZ, Management.
    secret_ref: a POINTER to credentials elsewhere (e.g. "op://Vault/Item"),
    never a credential itself.
    mac: one or more MAC addresses, comma separated. Normalised on write, so
    any spelling is accepted. This is what lets Pi-hole and UniFi match a
    device that has no address to match on.
    healthcheck: how a monitored entry is checked. Empty = a TCP connect to
    its first port. Otherwise one of: tcp, tcp:<port>,
    http or https[:<port>][/<path>][=<code>] (e.g. "https:8443/health=200";
    without =<code> any status below 500 is up; https also reads the
    certificate's expiry), ping, none.
    """
    data = dict(name=name, category=category, host=host, ip=ip, mac=mac,
                ports=ports,
                protocol=protocol, url=url, tags=tags, notes=notes,
                monitor=monitor, verified=verified, pinned=pinned, kind=kind,
                criticality=criticality, zone=zone, secret_ref=secret_ref,
                healthcheck=healthcheck)
    return await anyio.to_thread.run_sync(lambda: db.create_entry(data, actor="claude"))


@mcp.tool()
async def update_entry(entry_id: int, name: str | None = None, category: str | None = None,
                       host: str | None = None, ip: str | None = None,
                       mac: str | None = None,
                       ports: str | None = None, protocol: str | None = None,
                       url: str | None = None, tags: str | None = None,
                       notes: str | None = None, monitor: bool | None = None,
                       verified: bool | None = None, pinned: bool | None = None,
                       kind: str | None = None, criticality: str | None = None,
                       zone: str | None = None, secret_ref: str | None = None,
                       healthcheck: str | None = None) -> dict:
    """Update fields of an existing entry. Only the fields you pass are changed.

    pinned: show this entry in the dashboard's Quick links row.
    mac: one or more MAC addresses, comma separated; normalised on write.
    healthcheck: "" (TCP to the first port), tcp, tcp:<port>,
    http or https[:<port>][/<path>][=<code>], ping or none - see create_entry.
    """
    data = {k: v for k, v in dict(
        name=name, category=category, host=host, ip=ip, mac=mac,
        ports=ports, protocol=protocol,
        url=url, tags=tags, notes=notes, monitor=monitor, verified=verified,
        pinned=pinned, kind=kind, criticality=criticality, zone=zone,
        secret_ref=secret_ref, healthcheck=healthcheck).items()
        if v is not None}
    out = await anyio.to_thread.run_sync(lambda: db.update_entry(entry_id, data, actor="claude"))
    if out is None:
        raise ValueError(f"no entry with id {entry_id}")
    return out


@mcp.tool()
async def delete_entry(entry_id: int) -> dict:
    """Delete an inventory entry by id. The deletion is recorded in the change log."""
    ok = await anyio.to_thread.run_sync(lambda: db.delete_entry(entry_id, actor="claude"))
    if not ok:
        raise ValueError(f"no entry with id {entry_id}")
    return {"deleted": entry_id}


@mcp.tool()
async def list_categories() -> dict:
    """List all categories and tags currently in use, with the total entry count."""
    return await anyio.to_thread.run_sync(db.meta)


@mcp.tool()
async def check_status(entry_id: int | None = None) -> Any:
    """Run the reachability check now - for one entry, or all of them. Each
    entry is checked as its healthcheck field says (a TCP connect by default,
    or HTTP(S), ping); `summary` says what was checked and what answered."""
    if entry_id is not None:
        e = await anyio.to_thread.run_sync(lambda: db.get_entry(entry_id))
        if not e:
            raise ValueError(f"no entry with id {entry_id}")
        return await status.check_entry(e)
    await status.sweep()
    rows = await anyio.to_thread.run_sync(db.list_entries)
    return [{"id": r["id"], "name": r["name"], **status.CACHE.get(r["id"], {})} for r in rows]


@mcp.tool()
async def get_service_context(entry_id: int) -> dict:
    """Everything known about one entry in a single call: its fields, live
    status, what it depends on and what depends on it, its recent up/down
    transitions and its recent edits. Use this before answering "why is X
    down" or "what would break if I stop Y"."""
    ctx = await anyio.to_thread.run_sync(lambda: service_context(entry_id))
    if not ctx:
        raise ValueError(f"no entry with id {entry_id}")
    return ctx


@mcp.tool()
async def whats_wrong() -> dict:
    """The control room: what needs a person right now, worst first.

    One ranked queue rather than one list per subsystem - a source that has
    stopped answering, a critical service that is down, a public hostname with
    nothing in front of it and a mismatch between NetMap and a system it reads
    all compete on what it costs to ignore them. A dead source ranks above
    everything it would have reported, because "0 mismatches" from a source
    that never answered is not good news.

    Returns a one-sentence verdict, the ranked items, the current exposure
    surface, and source health. Use this to answer "is anything wrong?"."""
    d = await anyio.to_thread.run_sync(
        lambda: overview_mod.snapshot(status.CACHE))
    return d


@mcp.tool()
async def deep_scan(ip: str, wait_seconds: int = 90) -> dict:
    """Sweep all 65535 TCP ports of one private address and say what answers.

    Different in kind from `scan_ports`, which checks 111 common ports on every
    tracked address on a schedule. This is one address, every port, when a
    person asks - it takes minutes, so it runs as a job: this call starts it
    and waits up to `wait_seconds`, returning either the finished result or a
    progress snapshot to poll with `deep_scan_status`.

    Private addresses only (RFC1918 and loopback). Scanning the public
    internet from someone's home connection is a different act with different
    consequences, and it is refused rather than silently skipped.

    Each open port is marked `declared` or not, against the union of what every
    inventory entry at that address claims - twenty containers share one IP, so
    the question is about the address, not any one entry. Writes nothing."""
    await anyio.to_thread.run_sync(lambda: deepscan.start(ip))
    deadline = time.time() + max(0, min(int(wait_seconds), 600))
    while time.time() < deadline:
        j = deepscan.status()
        if not j or j["state"] != "running":
            break
        await anyio.sleep(2)
    j = deepscan.status()
    j["summary"] = deepscan.summarise(j)
    return j


@mcp.tool()
async def deep_scan_status() -> dict:
    """Progress or result of the current/last deep scan. Empty if none ran."""
    j = deepscan.status()
    if not j:
        return {"state": "none", "summary": "No scan has been run."}
    j["summary"] = deepscan.summarise(j)
    return j


@mcp.tool()
async def explain_service(entry_id: int) -> dict:
    """Say in plain sentences what is known about one entry: what it is, where
    it runs, what answers where, who can reach it from outside, what it
    touches, and - the part that matters - what no source can see about it.

    Everything is derived from the inventory, the edges and the sightings the
    discovery sources left behind. Nothing here is guessed; "nothing
    observed" is a real answer and appears often."""
    d = await anyio.to_thread.run_sync(
        lambda: explain_mod.explain(entry_id, status.CACHE.get(entry_id, {})))
    if not d:
        raise ValueError(f"no entry with id {entry_id}")
    d["text"] = explain_mod.as_text(d)
    return d


@mcp.tool()
async def link_entries(src_id: int, dst_id: int, type: str, note: str = "") -> dict:
    """Record a relationship: "src runs_on dst", "src depends_on dst", and so on.

    type is one of runs_on, depends_on, exposed_by, connects_to, resolves_to,
    backs_up_to. src is the subject - a service runs_on its host, not the
    reverse.
    """
    return await anyio.to_thread.run_sync(
        lambda: db.link(src_id, dst_id, type, note, actor="claude"))


@mcp.tool()
async def unlink_entries(src_id: int, dst_id: int, type: str) -> dict:
    """Remove a relationship."""
    ok = await anyio.to_thread.run_sync(
        lambda: db.unlink(src_id, dst_id, type, actor="claude"))
    return {"removed": ok}


@mcp.tool()
async def derive_links(dry_run: bool = True) -> dict:
    """Infer relationships from the entries themselves - `host` becomes
    runs_on, a hostname the public edge publishes becomes exposed_by the
    tunnel, a
    port-forward becomes exposed_by that rule. Ambiguous matches are reported
    under "unresolved" rather than guessed at. Hand-made links are never
    touched; only previously derived ones are rebuilt. Dry run by default."""
    if dry_run:
        return await anyio.to_thread.run_sync(links.plan)
    return await anyio.to_thread.run_sync(lambda: links.apply(actor="claude"))


@mcp.tool()
async def map_host(host: str, entry_id: int) -> dict:
    """Teach NetMap which entry a free-text `host` value means - "VM 101" is
    one Proxmox VM, "CT 107" one LXC container. One mapping per distinct
    string places every entry that uses it. Run derive_links afterwards.
    Call derive_links(dry_run=True) first: its "unmapped" list is exactly the
    set of strings still needing an answer."""
    return await anyio.to_thread.run_sync(
        lambda: db.set_host_map(host, entry_id, actor="claude"))


@mcp.tool()
async def scan_docker() -> dict:
    """Compare the Docker host's running containers with the inventory.

    Read-only in both directions: it writes nothing, and reaches Docker
    through a socket proxy that refuses every write verb. Returns findings -
    "new" (a container with no entry, with a ready-made draft), "gone" (an
    entry on that host with no container), "ports" (published ports differ
    from what is recorded) and "stopped". Use create_entry with the draft to
    accept a "new", update_entry to accept a "ports" change, and
    ignore_finding to stop being told about one."""
    return await anyio.to_thread.run_sync(discovery.scan_docker)


@mcp.tool()
async def scan_opnsense() -> dict:
    """Compare OPNsense with the inventory. Read-only: this issues GETs only.

    Reads three things the firewall knows and NetMap only believes - the DHCP
    lease table (what holds an address now), the reservations (what is meant
    to), and the inbound NAT rules (what is exposed). Findings:

      nat-unknown        a live port forward with no entry, with a draft
      nat-stale          an entry describing a forward the firewall no longer has
      nat-drift          entry and rule disagree about ports
      mac-unrecorded     a reservation carrying a hardware address the entry
                         does not - the field UniFi and Pi-hole match on
      addr-unreserved    NetMap records a fixed address that is a dynamic lease,
                         so it can move on the next renewal
      reservation-mismatch a reservation naming a hardware address the machine
                         at that address does not use, so it can never match -
                         the address only looks reserved
      reservation-orphan a reservation with nothing in NetMap at that address
      lease-unknown      something on the network NetMap has never heard of
                         (off unless the source's report-unknown setting is on -
                         otherwise every phone and lightbulb is a finding)

    Accept one with create_entry (using its draft) or update_entry; silence one
    with ignore_finding. Fixing a nat-* or addr-* finding on the firewall side
    is a change to OPNsense, which NetMap deliberately cannot make."""
    return await anyio.to_thread.run_sync(lambda: discovery.scan_type("opnsense"))


@mcp.tool()
async def scan_pihole() -> dict:
    """Compare Pi-hole with the inventory. Read-only apart from logging in.

    Reads the local DNS records and the client/group assignments. Findings:

      dns-drift        a local A record and the inventory disagree about an
                       address - usually a pointer left behind by a renumbering
      dns-orphan       a local record for an address NetMap does not track
      group-missing    an entry tagged `pihole:<Group>` that Pi-hole has no
                       client for at all, so that group is not being applied
      group-drift      the client exists but is not in the tagged group
      group-unknown    the tag names a group Pi-hole does not have
      client-untracked a Pi-hole client with group assignments and no entry

    The group findings only exist for entries tagged `pihole:<Group>` - that
    tag is how the inventory states what it expects, and without it there is
    nothing to check against. Add the tag to anything whose filtering matters."""
    return await anyio.to_thread.run_sync(lambda: discovery.scan_type("pihole"))


@mcp.tool()
async def scan_unifi() -> dict:
    """Compare the UniFi controller with the inventory. Read-only apart from
    logging in - and unlike the other sources this one can be given a genuinely
    read-only credential, because UniFi has roles.

    UniFi is the only source that knows the *physical* layer. Findings:

      device-untracked  an adopted UniFi device with no entry (with a draft)
      device-drift      the controller's address differs from the inventory's -
                        what a device that fell back to DHCP looks like
      device-down       adopted but offline, or not adopted
      link-missing      the controller reports an uplink NetMap has no
                        `connects_to` edge for
      client-unplaced   a wired client the physical map does not show
                        correctly: either no edge at all, or a hand-made edge
                        with no port, which permanently blocks the derived one
                        that has it (db.link is INSERT OR IGNORE)
      weak-signal       a wireless client below the weak-signal setting (off by
                        default; signal is weather, not inventory)

    `link-missing` is reported, never written: run derive_links to record the
    physical edges, which also picks up wired clients' switch ports."""
    return await anyio.to_thread.run_sync(lambda: discovery.scan_type("unifi"))


@mcp.tool()
async def scan_home_assistant() -> dict:
    """Compare Home Assistant's view of reality with the inventory. GET only.

    The other sources answer "does this exist, and where". This one answers
    "is it actually working" - which matters for things NetMap cannot probe.
    Zigbee2MQTT publishes no port, so a TCP check is impossible and
    critical_down silently excludes it; Home Assistant knows the answer.

    Only entries carrying an `ha:<entity_id>` tag are checked - that tag is the
    inventory stating what it believes, and it is the only thing a scan can
    contradict. Add `=<state>` to expect something other than the default
    ("on" for binary_sensor, switch, light, automation; availability only for
    a sensor). Findings:

      ha-missing      the tagged entity does not exist - renamed, removed, or
                      its integration failed to load, so nothing is checked
      ha-unavailable  the entity exists but has no value, which usually means
                      the integration behind it is down
      ha-state        the entity has a value and it is not the expected one"""
    return await anyio.to_thread.run_sync(lambda: discovery.scan_type("homeassistant"))


@mcp.tool()
async def scan_cloudflare() -> dict:
    """Compare the Cloudflare Tunnel's ingress with the inventory. GET only,
    with a scoped API token that cannot write whatever this code does.

    This is the only source that looks at the *edge* - which public hostnames
    reach into the network, where each lands, and whether Access stands in
    front of them. Findings:

      tunnel-down       the tunnel is down, degraded or has never connected
      ingress-orphan    a published hostname no inventory entry accounts for
      origin-untracked  an ingress rule pointing at an address nothing holds -
                        a renumbering nobody finished: the name breaks while
                        the service itself is healthy
      route-missing     an entry publishing a public URL that neither the
                        tunnel nor Pi-hole's local records serve - the same
                        failure seen from the inventory's side. A name Pi-hole
                        answers for is LAN-only by design and is not reported
      access-open       a hostname published with no Access application in
                        front of it

    Locally-managed tunnels keep their ingress in cloudflared's own config
    file rather than the API; for those the scan reports that and stops."""
    return await anyio.to_thread.run_sync(lambda: discovery.scan_type("cloudflare"))


@mcp.tool()
async def scan_npm() -> dict:
    """Compare Nginx Proxy Manager with the inventory. Read-only apart from
    logging in - and this credential can be genuinely read-only, because NPM
    has per-resource permissions and a non-admin user set to View Only on
    proxy hosts is enforced by NPM itself.

    NPM is the leg between the edge and the service: it decides which name
    reaches which port. Findings:

      proxy-drift      NPM forwards a name to an ip:port the entry does not
                       record. Meaningful here and nowhere else - NPM forwards
                       to the service itself, not to another proxy
      proxy-orphan     forwards to an address no entry holds - a renumbering
                       nobody finished, the inside twin of origin-untracked
      proxy-untracked  a name NPM serves that no entry claims (with a draft)
      proxy-disabled   an entry publishes a URL whose proxy host is switched
                       off, so the name resolves and then answers nothing
      cert-expiring    a certificate within the source's warning window of expiry"""
    return await anyio.to_thread.run_sync(lambda: discovery.scan_type("npm"))


@mcp.tool()
async def scan_ports() -> dict:
    """Sweep the addresses the inventory tracks and compare what answers with
    what it claims. Only once the Open ports source is added.

    This is the only source that probes machines rather than reading a
    system's records, and it exists for what the others cannot see: Docker
    knows nineteen containers on one host, and the status check tests exactly
    one port per entry. Findings:

      port-closed      an entry declares a port nothing answers on, though the
                       host itself does answer elsewhere
      port-undeclared  something is listening that no entry at that address
                       accounts for

    Sweeps per address rather than per entry, since many containers can share
    one host's address, and reconciles against the union of what every entry
    there declares. Categories listed in the source's "never swept" setting
    are skipped."""
    return await anyio.to_thread.run_sync(lambda: discovery.scan_type("ports"))


@mcp.tool()
async def scan_all_sources() -> dict:
    """Every added discovery source at once - whichever of Docker, OPNsense,
    Pi-hole, AdGuard Home, a DHCP lease file, router ARP over SNMP, UniFi,
    Home Assistant, NPM, Traefik, Cloudflare, Open ports, Proxmox VE and
    NetBox have been added.

    Findings stay grouped by source: the same service reported by two sources
    is usually corroboration, not duplication, and merging the lists would hide
    that. A type can have several sources (two Docker hosts, two Pi-holes):
    each has its own `source` id - "docker", "docker-2" - and its finding keys
    start with that id ("ha" for the first Home Assistant). Use this to answer
    "does the inventory still match reality?" in one call; use the per-type
    tools when acting on one system's findings - with several sources of a
    type they return each one under `sources`."""
    return await anyio.to_thread.run_sync(discovery.scan_all)


@mcp.tool()
async def list_sources() -> list[dict]:
    """Every source that has been added, without scanning anything: its id
    (what scan_source and finding keys use - "docker", "docker-2",
    "adguard"…), name, type, roles (containers, hypervisor, firewall, dns,
    proxy, edge, leases, layer2, health, intent, scanner), and whether it is
    set up and answering, with its last error. No credentials, not even
    masked."""
    return await anyio.to_thread.run_sync(discovery.health)


@mcp.tool()
async def scan_source(source: str) -> dict:
    """Scan one source by its id and return its findings - any type,
    including those without a scan_<type> tool of their own (AdGuard Home,
    Traefik, Proxmox VE, NetBox, a DHCP lease file, router ARP over SNMP) and
    the second or third source of a type
    ("pihole-2"). Get the ids from list_sources. A type name that has not
    been added answers "not added"; an unknown id is an error naming the
    ones that exist."""
    try:
        return await anyio.to_thread.run_sync(lambda: discovery.scan(source))
    except KeyError:
        raise ValueError(f"no source '{source}' - have {', '.join(discovery.names()) or 'none'}")


@mcp.tool()
async def ignore_finding(key: str, reason: str = "", label: str = "") -> dict:
    """Permanently stop a discovery finding from being reported. `key` comes
    from a scan result - for example "docker:new:watchtower". Use this for
    things that are deliberately not in the inventory; use list_ignored to see
    what is currently suppressed. Un-ignoring is done from the Network view."""
    return await anyio.to_thread.run_sync(
        lambda: db.add_ignore(key, key.split(":")[0], label, reason, actor="claude"))


@mcp.tool()
async def list_ignored() -> dict:
    """Discovery findings that are currently suppressed, and why."""
    return await anyio.to_thread.run_sync(lambda: db.ignores())


@mcp.tool()
async def get_topology() -> list[dict]:
    """The runs_on tree: what runs on what, nested from the machines down."""
    return await anyio.to_thread.run_sync(db.topology)


@mcp.tool()
async def find_conflicts() -> dict:
    """Find contradictions in the inventory: one ip:port claimed twice, two
    machines on one IP, duplicated names or URLs, and monitored entries that
    carry nothing probeable. Returns worst first; "high" means something is
    certainly wrong. Tag an entry `dup-ok` to suppress a deliberate pair."""
    rows = await anyio.to_thread.run_sync(db.list_entries)
    return await anyio.to_thread.run_sync(lambda: conflicts.summary(rows))


@mcp.tool()
async def recent_changes(limit: int = 25, include_logins: bool = False) -> list[dict]:
    """Show the most recent changes made to the inventory (who, what, when).
    Sign-ins to the web UI are left out unless include_logins is set."""
    return await anyio.to_thread.run_sync(lambda: db.audit(limit, include_logins=include_logins))


def mcp_startup_line() -> str:
    """What start-up says about the MCP endpoint. Without NETMAP_MCP_TOKEN it
    is off - not a problem, just a state."""
    if not MCP_TOKEN:
        return "[netmap] MCP endpoint off - NETMAP_MCP_TOKEN not set"
    return f"[netmap] MCP endpoint mounted at {MCP_PATH} (bearer token required)"


# --------------------------------------------------------------------------
# FastAPI app
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    why = db.unwritable_reason()
    if why:
        print(f"[netmap] FATAL: {why}", flush=True)
        raise SystemExit(1)
    db.init()
    discovery.migrate_legacy()
    paused = discovery.fold_scan_switch()
    if paused:
        print(f"[netmap] {', '.join(paused)}: paused with its own switch before 1.93.0 - "
              "now paused with the source's Enabled switch", flush=True)
    pinned = discovery.pin_defaults()
    if pinned:
        print(f"[netmap] kept the old \"Categories never swept\" default on "
              f"{', '.join(pinned)} - it is now blank for new sources", flush=True)
    rot = discovery.rotate_secrets()
    notify.upgrade_events()
    back = stale.backfill()
    if back:
        print(f"[netmap] {back} entr{'y' if back == 1 else 'ies'} last confirmed when "
              "their health check stopped answering", flush=True)
    gap = uptime.note_start(status.INTERVAL)
    if gap:
        print(f"[netmap] not running {gap['from']} – {gap['to']}: that time counts as "
              "unknown in uptime, not as up", flush=True)
    # Before the history purge: a watched device's last sighting is its own.
    drop = watch.check()["dropped"]
    if drop:
        print(f"[netmap] stopped watching {len(drop)} device(s) not seen for "
              f"{watch.DROP_DAYS} days", flush=True)
    gone = newdevices.purge()
    if gone:
        print(f"[netmap] forgot {gone} device(s) not seen for "
              f"{newdevices.settings()['keep_days']} days", flush=True)
    print(f"[netmap] secret key: {crypto.key_location()}"
          + (f"; re-encrypted {rot['rotated']} secret(s)" if rot["rotated"] else "")
          + ("; database copy of the key removed" if rot["stored_key_removed"] else ""),
          flush=True)
    if rot["undecryptable"]:
        print(f"[netmap] ERROR: {len(rot['undecryptable'])} stored secret(s) cannot be "
              f"decrypted with any known key: {', '.join(rot['undecryptable'])}. "
              "NETMAP_SECRET_KEY does not match the key they were saved with.", flush=True)
    generated = accounts.bootstrap()
    if generated:
        # Once, on the very first start - the only time it is ever shown.
        print("[netmap] ------------------------------------------------------\n"
              f"[netmap] local login created: user 'admin', password: {generated}\n"
              "[netmap] sign in at /login and change it under Settings > Profile.\n"
              "[netmap] lost it? docker exec -it netmap python -m app.accounts reset\n"
              "[netmap] ------------------------------------------------------",
              flush=True)
    # A new install starts empty. NETMAP_SEED_FILE loads a JSON export into an
    # empty database once - how to start from an inventory kept elsewhere.
    seed = os.environ.get("NETMAP_SEED_FILE", "").strip()
    n = db.seed_if_empty(seed) if seed else 0
    if n:
        print(f"[netmap] seeded {n} entries from {seed}", flush=True)
    print(mcp_startup_line(), flush=True)
    if MCP_TOKEN:
        print(f"[netmap] MCP accepts Host: {', '.join(ALLOWED_HOSTS)}", flush=True)
    for line in web_security.startup_lines():
        print(line, flush=True)
    # Service marks, on a thread, best effort. Nothing waits for it: until it
    # finishes every entry shows its category glyph, which is a finished
    # interface rather than a loading state.
    icons_mod.warm_in_background()
    async with mcp.session_manager.run():
        async with anyio.create_task_group() as tg:
            tg.start_soon(status.loop)
            tg.start_soon(discovery.loop)
            tg.start_soon(notify.loop)
            yield
            tg.cancel_scope.cancel()


app = FastAPI(title="NetMap", version=VERSION, lifespan=lifespan)

# Outermost last. Host first: DNS rebinding - a page on another site that
# re-points its own name at this LAN address - arrives with that site's name in
# Host, and is refused before anything else looks at it. The MCP path never
# reaches these; _MCPDispatcher routes it first and it has its own Host check.
app.add_middleware(web_security.SecurityHeaders)
app.add_middleware(web_security.RequireIdentity)
app.add_middleware(
    web_security.HostCheck,
    # Compared without the port, so "localhost:*" is "localhost" here.
    allowed_hosts=["*"] if _ALLOWED == "*" else sorted(
        {h.split(":")[0] for h in ALLOWED_HOSTS}))


def actor(request: Request) -> str:
    """Who made a change: the identity web_security verified for this request
    - the Cloudflare Access e-mail, or "api-token". Never a header the client
    chose, which is what this used to read."""
    return getattr(request.state, "actor", None) or "web"


@app.get("/api/entries")
def api_list(q: str = "", category: str = "", tag: str = "", kind: str = "",
             criticality: str = "", zone: str = "", ip: str = ""):
    rows = db.list_entries(q, category, tag, kind, criticality, zone, ip)
    for r in rows:
        r["status"] = status.CACHE.get(r["id"], {})
    # The 30-day figure for the entries the uptime rule shows it on.
    rl = uptime.rule()
    ids = [r["id"] for r in rows if uptime.shown(r, rl)]
    ups = uptime.compute_all(ids) if ids else {}
    for r in rows:
        r["uptime"] = ups[r["id"]]["percent"] if r["id"] in ups else None
    return rows


@app.post("/api/entries", status_code=201)
def api_create(request: Request, payload: dict = Body(...)):
    try:
        return db.create_entry(payload, actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.patch("/api/entries/{entry_id}")
def api_update(entry_id: int, request: Request, payload: dict = Body(...)):
    try:
        out = db.update_entry(entry_id, payload, actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if out is None:
        raise HTTPException(404, "not found")
    return out


@app.delete("/api/entries/{entry_id}")
def api_delete(entry_id: int, request: Request):
    if not db.delete_entry(entry_id, actor=actor(request)):
        raise HTTPException(404, "not found")
    return {"deleted": entry_id}


@app.get("/api/meta")
def api_meta():
    return {**db.meta(), "version": VERSION,
            "check_interval": status.INTERVAL}


@app.get("/api/status")
def api_status():
    return {str(k): v for k, v in status.CACHE.items()}


@app.post("/api/status/refresh")
async def api_status_refresh(entry_id: int | None = Query(None)):
    if entry_id is not None:
        e = db.get_entry(entry_id)
        if not e:
            raise HTTPException(404, "not found")
        return await status.check_entry(e)
    await status.sweep()
    return {str(k): v for k, v in status.CACHE.items()}


@app.get("/api/summary")
def api_summary():
    """Compact counters - designed for a dashboard widget (e.g. Homepage's customapi)."""
    rows = db.list_entries()
    up = sum(1 for r in rows if status.CACHE.get(r["id"], {}).get("up") is True)
    down = sum(1 for r in rows if status.CACHE.get(r["id"], {}).get("up") is False)
    return {
        "total": len(rows),
        "up": up,
        "down": down,
        "monitored": sum(1 for r in rows if r["monitor"]),
        "unverified": sum(1 for r in rows if not r["verified"]),
        "categories": len({r["category"] for r in rows}),
        "pinned": sum(1 for r in rows if r["pinned"]),
        "by_kind": {k: sum(1 for r in rows if r["kind"] == k)
                    for k in sorted({r["kind"] for r in rows if r["kind"]})},
        "unclassified": sum(1 for r in rows if not r["kind"]),
        "conflicts": len(conflicts.find(rows)),
        "findings": discovery.summary()["total"],
        "critical_down": sum(
            1 for r in rows if r["criticality"] == "critical"
            and status.CACHE.get(r["id"], {}).get("up") is False),
    }


@app.get("/api/about")
def api_about():
    """Everything the Settings > About panel shows. Never leaks the MCP path."""
    rows = db.list_entries()
    try:
        db_bytes = os.path.getsize(db.DB_PATH)
    except OSError:
        db_bytes = None
    return {
        "version": VERSION,
        "entries": len(rows),
        "categories": len({r["category"] for r in rows}),
        "monitored": sum(1 for r in rows if r["monitor"]),
        "pinned": sum(1 for r in rows if r["pinned"]),
        "unverified": sum(1 for r in rows if not r["verified"]),
        "unclassified": sum(1 for r in rows if not r["kind"]),
        "conflicts": len(conflicts.find(rows)),
        "findings": discovery.summary()["total"],
        "links": len(db.all_edges()),
        "discovery_sources": [
            {"name": h["source"], "label": h["label"], "configured": h["configured"]}
            for h in discovery.health()],
        "ignored_findings": len(db.ignores()),
        "unlinked": db.unlinked_count(),
        "uptime_seconds": int(time.time() - STARTED),
        "last_sweep": status.LAST_SWEEP,
        "check_interval": status.INTERVAL,
        "check_timeout": status.TIMEOUT,
        "mcp_enabled": bool(MCP_TOKEN),
        "mcp_path_is_default": MCP_PATH == "/mcp",
        "mcp_allowed_hosts": ALLOWED_HOSTS,
        "auth": web_security.describe(),
        "secret_key": crypto.key_location(),
        "secrets_undecryptable": len(crypto.UNDECRYPTABLE),
        "db_path": db.DB_PATH,
        "db_bytes": db_bytes,
        "python": platform.python_version(),
    }


@app.get("/api/changelog")
def api_changelog():
    """Parsed CHANGELOG.md - a '## <version> - <date>' heading per release,
    followed by '- ' bullet lines. Missing file just means an empty list."""
    try:
        with open(CHANGELOG_PATH, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        text = ""
    entries = []
    for block in text.split("\n## ")[1:]:
        head, _, body = block.partition("\n")
        version, _, date = head.partition(" - ")
        entries.append({
            "version": version.strip(),
            "date": date.strip(),
            "notes": [ln[2:].strip() for ln in body.splitlines() if ln.startswith("- ")],
        })
    return {"version": VERSION, "entries": entries}


@app.get("/api/entries/{entry_id}/context")
def api_context(entry_id: int):
    """The service card: fields, status, both edge directions, transitions, edits."""
    ctx = service_context(entry_id)
    if not ctx:
        raise HTTPException(404, "not found")
    return ctx


@app.post("/api/scan/deep", status_code=201)
def api_deep_start(payload: dict = Body(...)):
    """Start a full-port sweep of one private address - see app/deepscan.py."""
    try:
        return deepscan.start(str(payload.get("ip", "")),
                              int(payload.get("from", 1)),
                              int(payload.get("to", 65535)))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/scan/deep")
def api_deep_status():
    return deepscan.status() or {"state": "none"}


@app.delete("/api/scan/deep")
def api_deep_cancel():
    return {"cancelled": deepscan.cancel()}


# ---- service marks --------------------------------------------------------
# Addressed by entry rather than by slug, so the browser never has to know how
# a name becomes a mark - it asks for "the icon for entry 24" and either gets
# one or doesn't. A 404 here is the normal, expected answer for most entries.
ICON_HEADERS = {"Cache-Control": "private, max-age=604800",
                "Content-Security-Policy": web_security.ICON_CSP}


@app.get("/api/icon/{slug}.svg")
def api_icon(slug: str, t: str = "dark"):
    """A mark by name, for the parts of the interface that are not an entry -
    the discovery sources, which are products with their own marks."""
    got = icons_mod.read(slug, "light" if t == "light" else "dark")
    if not got:
        raise HTTPException(404, "no mark by that name")
    data, media = got
    return Response(data, media_type=media, headers=ICON_HEADERS)


@app.get("/api/entries/{entry_id}/icon.svg")
def api_entry_icon(entry_id: int, t: str = "dark"):
    e = db.get_entry(entry_id)
    if not e:
        raise HTTPException(404, "no such entry")
    got = icons_mod.read(icons_mod.slug_for(e), "light" if t == "light" else "dark")
    if not got:
        raise HTTPException(404, "no mark for this entry")
    data, media = got
    return Response(data, media_type=media, headers=ICON_HEADERS)


@app.get("/api/icons")
def api_icons():
    """Which entries have a mark on disk right now. The browser asks this so
    it never requests one that does not exist - the fallback glyph is then the
    normal state for an unknown product rather than a failed image."""
    return {"icons": icons_mod.list_cached()}


@app.post("/api/icons/warm")
def api_icons_warm():
    """Fetch every mark the inventory wants, now, so nobody's first page load
    pays for it. Safe to run repeatedly; cached marks are not re-fetched."""
    return icons_mod.warm()


@app.get("/api/presence")
def api_presence(all: bool = False):
    """Addresses a source has seen. Default: only those no entry claims - the
    address map already draws the tracked ones. See db.record_presence."""
    return {"presence": newdevices.enrich(db.presence(untracked_only=not all))}


@app.get("/api/overview")
def api_overview():
    """The control-room snapshot - see app/overview.py."""
    return overview_mod.snapshot(status.CACHE)


@app.post("/api/overview/dismiss", status_code=201)
def api_dismiss(payload: dict = Body(...)):
    """Set one attention item aside. See app/overview.py - a dismissal is not
    a mute: it records what was seen, and the item returns when that changes."""
    key = str(payload.get("key", "")).strip()
    if not key:
        raise HTTPException(400, "key is required")
    return overview_mod.dismiss(key, str(payload.get("title", "")),
                                str(payload.get("fingerprint", "")))


@app.delete("/api/overview/dismiss")
def api_undismiss(key: str):
    return {"restored": overview_mod.undismiss(key)}


@app.get("/api/entries/{entry_id}/explain")
def api_explain(entry_id: int):
    """The service card in sentences - see app/explain.py."""
    d = explain_mod.explain(entry_id, status.CACHE.get(entry_id, {}))
    if not d:
        raise HTTPException(404, "not found")
    return d


@app.get("/api/sightings/{fact}")
def api_sightings(fact: str):
    """Every source that says something about one fact, e.g. "port:32400"."""
    rows = db.sightings_by_fact(fact)
    names = {e["id"]: e["name"] for e in db.list_entries()}
    for r in rows:
        r["entry_name"] = names.get(r["entry_id"], "")
    return {"fact": fact, "sightings": rows}


@app.get("/api/graph")
def api_graph():
    """What the topology graph draws besides the entries: every link, and
    which entries the internet reaches (overview.reached_from_internet)."""
    return {"edges": db.all_edges(), "internet": overview_mod.reached_from_internet()}


@app.get("/api/edges")
def api_edges():
    return db.all_edges()


@app.post("/api/edges", status_code=201)
def api_link(request: Request, payload: dict = Body(...)):
    try:
        return db.link(int(payload["src"]), int(payload["dst"]),
                       str(payload["type"]), str(payload.get("note", "")),
                       actor=actor(request))
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, str(exc))


@app.delete("/api/edges")
def api_unlink(request: Request, src: int, dst: int, type: str):
    if not db.unlink(src, dst, type, actor=actor(request)):
        raise HTTPException(404, "no such link")
    return {"removed": True}


@app.post("/api/edges/derive")
def api_derive(request: Request, dry_run: bool = Query(True)):
    return links.plan() if dry_run else links.apply(actor=actor(request))


@app.get("/api/hostmap")
def api_hostmap():
    return db.host_map()


@app.put("/api/hostmap")
def api_hostmap_set(request: Request, payload: dict = Body(...)):
    try:
        return db.set_host_map(str(payload["host"]), int(payload["entry_id"]),
                               actor=actor(request))
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, str(exc))


@app.delete("/api/hostmap")
def api_hostmap_del(request: Request, host: str):
    if not db.clear_host_map(host, actor=actor(request)):
        raise HTTPException(404, "not mapped")
    return {"removed": True}


@app.get("/api/topology")
def api_topology(mode: str = "tree"):
    if mode not in ("tree", "physical", "deps"):
        raise HTTPException(400, "mode must be tree, physical or deps")
    return db.topology(mode)


@app.get("/api/ports/{port}")
def api_port(port: int):
    """One port number, and everything the sources say about it."""
    if not 0 < port < 65536:
        raise HTTPException(400, "not a port number")
    d = db.port_dossier(port)
    # What each witness *is*, so the page can say "forwarded" or "published"
    # without knowing which firewall or tunnel said it.
    for r in d["observed"] + d["routed"]:
        r["roles"] = list(dynamic.roles_of(dynamic.type_of(r["source"])))
    for e in d["entries"]:
        e["status"] = status.CACHE.get(e["id"], {}).get("up")
    return d


@app.get("/api/observations")
def api_observations(limit: int = 40, entry_id: int | None = None):
    return (db.observations(entry_id, limit) if entry_id is not None
            else db.recent_observations(limit))


@app.get("/api/discovery/ignores")
def api_ignores():
    return db.ignores()


@app.post("/api/discovery/ignores", status_code=201)
def api_ignore(request: Request, payload: dict = Body(...)):
    """One key, or `keys` for a whole source at once - a first scan against a
    drifted inventory can produce thirty findings that are all the same
    decision, and clicking Ignore thirty times is how people stop scanning."""
    who = actor(request)
    keys = payload.get("keys")
    if keys is not None:
        if not isinstance(keys, list) or not keys:
            raise HTTPException(400, "keys must be a non-empty list")
        labels = payload.get("labels") or {}
        done = [db.add_ignore(str(k), str(k).split(":")[0],
                              str(labels.get(k, "")), str(payload.get("reason", "")),
                              actor=who) for k in keys]
        return {"ignored": len(done)}
    try:
        key = str(payload["key"])
        return db.add_ignore(key, key.split(":")[0], str(payload.get("label", "")),
                             str(payload.get("reason", "")), actor=who)
    except (KeyError, ValueError) as exc:
        raise HTTPException(400, str(exc))


@app.delete("/api/discovery/ignores")
def api_unignore(request: Request, key: str):
    if not db.clear_ignore(key, actor=actor(request)):
        raise HTTPException(404, "not ignored")
    return {"removed": True}


@app.get("/api/watch")
def api_watch():
    """Devices being watched: on the network or not, and what is known."""
    return {"watching": watch.listing(), "drop_days": watch.DROP_DAYS}


@app.post("/api/watch", status_code=201)
def api_watch_add(request: Request, payload: dict = Body(...)):
    """`key`: a new-device finding's key, or a device's MAC / "ip:<address>"."""
    try:
        return watch.add(str(payload.get("key") or ""), payload.get("note", ""),
                         actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.patch("/api/watch")
def api_watch_note(request: Request, payload: dict = Body(...)):
    try:
        out = watch.update(str(payload.get("key") or ""), payload.get("note", ""),
                           actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if out is None:
        raise HTTPException(404, "not watched")
    return out


@app.delete("/api/watch")
def api_watch_stop(request: Request, key: str, ignore: bool = False):
    """Stop watching; `ignore=true` also ignores its new-device finding."""
    who = actor(request)
    if not (watch.ignore(key, who) if ignore else watch.remove(key, who)):
        raise HTTPException(404, "not watched")
    return {"removed": True, "ignored": ignore}


@app.get("/api/discovery/summary")
def api_discovery_summary():
    """Finding counts from the last background scan. Free - never scans, so
    the nav badge can poll it without touching the firewall. `icons` names
    the source marks on disk, by source type."""
    return {**discovery.summary(), "icons": icons_mod.source_marks()}


@app.get("/api/discovery/findings")
def api_discovery_findings(limit: int = 0):
    """The cached findings themselves, flattened and newest-source-first, for
    the Overview. Also free."""
    out = []
    for name in discovery.names():
        r = discovery.cached(name)
        if r and not r.get("error"):
            out.extend(r.get("findings", []))
    return {"findings": out[:limit] if limit else out, "total": len(out)}


@app.get("/api/discovery")
def api_discovery_all():
    """Every configured source. Unconfigured ones come back marked `skipped`
    rather than omitted, so the UI can say what is available but switched off."""
    return discovery.scan_all()


@app.get("/api/discovery/{source}")
def api_discovery_one(source: str, max_age: float = 0):
    """Scan one source. `max_age` seconds: a result that recent is returned
    instead of scanning again - what the Network view sends when it is only
    being opened; its "scan again" sends 0."""
    try:
        return discovery.scan(source, max(0.0, min(max_age, 300.0)))
    except KeyError:
        raise HTTPException(404, f"unknown source '{source}' - "
                                 f"have {', '.join(discovery.names())}")


@app.get("/api/settings/scan")
def api_scan_schedule():
    """How often every source is scanned automatically, and when next."""
    return discovery.schedule()


@app.put("/api/settings/scan")
def api_scan_schedule_set(request: Request, payload: dict = Body(...)):
    """`interval` seconds and/or `stale_hours`; either may be left out."""
    if payload.get("interval") is None and payload.get("stale_hours") is None:
        raise HTTPException(400, "send interval (seconds) or stale_hours")
    for key, what, setter in (("interval", "interval must be a number of seconds",
                               discovery.set_interval),
                              ("stale_hours", "stale_hours must be a whole number",
                               discovery.set_stale_hours)):
        if payload.get(key) is None:
            continue
        try:
            n = int(payload[key])
        except (TypeError, ValueError):
            raise HTTPException(400, what)
        try:
            setter(n, actor=actor(request))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    return discovery.schedule()


@app.get("/api/overview/hardware")
def api_overview_hardware():
    """Per physical host: what runs on it and how much of that is watched;
    plus the network gear."""
    return overview_mod.hardware(status.CACHE)


@app.get("/api/settings/overview")
def api_overview_layout():
    """The Overview's cards in order, each with whether it is shown."""
    return {"cards": overview_mod.layout()}


@app.put("/api/settings/overview")
def api_overview_layout_set(request: Request, payload: dict = Body(...)):
    """`cards`: [{id, show}] in display order, or `reset`: true for the default."""
    try:
        if payload.get("reset"):
            return {"cards": overview_mod.reset_layout(actor(request))}
        return {"cards": overview_mod.set_layout(payload.get("cards"), actor(request))}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/settings/timezone")
def api_timezone():
    """The local time zone summary notifications are scheduled in."""
    from . import digest
    return {"timezone": digest.timezone()}


@app.put("/api/settings/timezone")
def api_timezone_set(request: Request, payload: dict = Body(...)):
    from . import digest
    try:
        digest.set_timezone(payload.get("timezone"), actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return api_timezone()


@app.get("/api/settings/stale")
def api_stale_settings():
    """After how many days unseen an entry is flagged - see app/stale.py."""
    return {"days": stale.days(), "default": stale.DAYS_DEFAULT}


@app.put("/api/settings/stale")
def api_stale_settings_set(request: Request, payload: dict = Body(...)):
    try:
        n = int(payload.get("days"))
    except (TypeError, ValueError):
        raise HTTPException(400, "days must be a whole number")
    try:
        stale.set_days(n, actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return api_stale_settings()


@app.get("/api/settings/uptime")
def api_uptime_rule():
    """Which entries show their 30-day uptime: by kind, category or
    criticality. A tag uptime:on / uptime:off on an entry overrides it."""
    return uptime.rule()


@app.put("/api/settings/uptime")
def api_uptime_rule_set(request: Request, payload: dict = Body(...)):
    if not all(isinstance(payload.get(k, []), list) for k in uptime.DEFAULT_RULE):
        raise HTTPException(400, "kinds, categories and criticalities must be lists")
    return uptime.save_rule(payload, actor=actor(request))


@app.get("/api/settings/newdevices")
def api_newdevices_settings():
    """What counts as new on the network, and how long device history is kept."""
    return newdevices.settings()


@app.put("/api/settings/newdevices")
def api_newdevices_settings_set(request: Request, payload: dict = Body(...)):
    try:
        return newdevices.save_settings(
            days=payload.get("days"), keep_days=payload.get("keep_days"),
            include_random=(None if payload.get("include_random") is None
                            else bool(payload.get("include_random"))),
            actor=actor(request))
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, str(exc) if "between" in str(exc) or "within" in str(exc)
                            else "days and keep_days must be whole numbers")


@app.get("/api/settings/checks")
def api_checks_settings():
    """How many days before expiry a checked certificate is worth a warning."""
    return {"tls_warn_days": status.tls_warn_days(), "default": status.TLS_WARN_DEFAULT}


@app.put("/api/settings/checks")
def api_checks_settings_set(request: Request, payload: dict = Body(...)):
    try:
        days = int(payload.get("tls_warn_days"))
    except (TypeError, ValueError):
        raise HTTPException(400, "tls_warn_days must be a whole number of days")
    try:
        status.set_tls_warn_days(days, actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return api_checks_settings()


@app.get("/api/sources/drivers")
def api_sources_drivers():
    """Every source type Settings › Sources can add, with the form fields each
    one needs, its roles, and whether another one can be added."""
    return {"drivers": discovery.drivers(), "roles": discovery.roles()}


@app.get("/api/sources/instances")
def api_sources_instances():
    """Every source. Secrets never come back as plaintext - only whether one
    is set, and a last-four-characters preview."""
    return discovery.list_instances()


@app.post("/api/sources/instances", status_code=201)
def api_sources_instance_create(request: Request, payload: dict = Body(...)):
    try:
        type_ = str(payload["type"])
        name = str(payload.get("name") or "")
    except KeyError as exc:
        raise HTTPException(400, f"missing {exc}")
    try:
        return discovery.create_instance(
            type_, name, payload.get("fields") or {},
            enabled=bool(payload.get("enabled", True)), actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.put("/api/sources/instances/{instance_id}")
def api_sources_instance_update(instance_id: str, request: Request,
                                payload: dict = Body(...)):
    try:
        out = discovery.update_instance(
            instance_id, name=payload.get("name"), fields_in=payload.get("fields"),
            enabled=payload.get("enabled"), actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not out:
        raise HTTPException(404, "no such source")
    return out


@app.delete("/api/sources/instances/{instance_id}")
def api_sources_instance_delete(instance_id: str, request: Request):
    if not discovery.delete_instance(instance_id, actor=actor(request)):
        raise HTTPException(404, "no such source")
    return {"removed": True}


@app.post("/api/sources/instances/{instance_id}/test")
def api_sources_instance_test(instance_id: str):
    try:
        return discovery.test_instance(instance_id)
    except KeyError:
        raise HTTPException(404, "no such source")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/sources/test")
def api_sources_test(payload: dict = Body(...)):
    """Test connection details before they are saved - the Add-source form
    has no instance id yet to test against."""
    try:
        return discovery.test_fields(str(payload["type"]), payload.get("fields") or {})
    except KeyError as exc:
        raise HTTPException(400, f"missing {exc}")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/notify/types")
def api_notify_types():
    """Every channel type Settings › Notifications can add, its form, and the
    events a channel can be told about."""
    return notify.types()


@app.get("/api/notify/channels")
def api_notify_channels():
    """Every channel. Secrets never come back - only whether one is set and a
    last-four-characters preview - plus how the last delivery went."""
    return notify.list_channels()


@app.post("/api/notify/channels", status_code=201)
def api_notify_create(request: Request, payload: dict = Body(...)):
    try:
        return notify.create(str(payload.get("type") or ""), str(payload.get("name") or ""),
                             payload.get("fields") or {}, payload.get("events"),
                             bool(payload.get("enabled", True)), actor=actor(request),
                             delivery=payload.get("delivery"))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.put("/api/notify/channels/{channel_id}")
def api_notify_update(channel_id: str, request: Request, payload: dict = Body(...)):
    try:
        out = notify.update(channel_id, name=payload.get("name"),
                            fields_in=payload.get("fields"), events=payload.get("events"),
                            enabled=payload.get("enabled"), actor=actor(request),
                            delivery=payload.get("delivery"))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not out:
        raise HTTPException(404, "no such channel")
    return out


@app.delete("/api/notify/channels/{channel_id}")
def api_notify_delete(channel_id: str, request: Request):
    if not notify.delete(channel_id, actor=actor(request)):
        raise HTTPException(404, "no such channel")
    return {"removed": True}


@app.post("/api/notify/channels/{channel_id}/test")
def api_notify_test(channel_id: str):
    try:
        return notify.test(channel_id)
    except KeyError:
        raise HTTPException(404, "no such channel")


@app.post("/api/notify/test")
def api_notify_test_fields(payload: dict = Body(...)):
    """Send a test with details not saved yet - the Add form has no id."""
    try:
        return notify.test_fields(str(payload.get("type") or ""), payload.get("fields") or {})
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/conflicts")
def api_conflicts():
    return conflicts.summary(db.list_entries())


@app.get("/api/export.json")
def api_export_json():
    """Full backup: every entry, every field. Restore it through /api/import."""
    payload = {
        "netmap": 1,
        "version": VERSION,
        "exported_at": db.now(),
        "entries": db.export_rows(),
        "edges": db.all_edges(),
        "host_map": db.host_map(),
    }
    return JSONResponse(
        payload,
        headers={"Content-Disposition":
                 'attachment; filename="netmap-export.json"'})


@app.post("/api/import")
def api_import(request: Request, payload: dict = Body(...),
               mode: str = Query("merge", pattern="^(merge|replace)$"),
               dry_run: bool = Query(True)):
    """Import a JSON export. Defaults to a dry run - pass dry_run=false to commit.

    Accepts either a whole export document or a bare {"entries": [...]}.
    """
    rows = payload.get("entries")
    if not isinstance(rows, list):
        raise HTTPException(400, "expected an export document with an 'entries' list")
    edges, hmap = payload.get("edges") or [], payload.get("host_map") or {}
    who = actor(request)
    if dry_run:
        try:
            plan = db.import_entries(rows, mode=mode, dry_run=True, actor=who)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        plan["relations"] = {"links": len(edges), "hosts_mapped": len(hmap)}
        return plan
    # One transaction: entries, then the relationships that need both ends to
    # exist, then the audit rows - all of it lands, or none of it does.
    try:
        with db.transaction():
            plan = db.import_entries(rows, mode=mode, dry_run=False, actor=who)
            if edges or hmap:
                plan["relations"] = db.import_relations(edges, hmap, actor=who)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        # Rolled back. Record that it was tried, outside the rolled-back block.
        db.log(who, "import-failed", None, f"{mode} import",
               {"error": f"{type(exc).__name__}: {exc}"[:300]})
        raise HTTPException(500, f"import failed and was rolled back - nothing "
                                 f"changed: {type(exc).__name__}: {exc}")
    return plan


@app.get("/api/audit")
def api_audit(limit: int = 100, logins: bool = False):
    return db.audit(limit, include_logins=logins)


@app.get("/api/export.csv")
def api_export():
    rows = db.list_entries()
    buf = io.StringIO()
    cols = ["id", "category", "name", "host", "ip", "mac", "ports", "protocol",
            "url", "tags", "notes", "monitor", "verified", "updated_at"]
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        r = dict(r)
        r["tags"] = ",".join(r["tags"])
        w.writerow([r.get(c, "") for c in cols])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.read()]), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="netmap-export.csv"'})


# ---- the local account -------------------------------------------------------
# See app/accounts.py: a password login that works when Cloudflare Access
# does not. The session is a signed cookie; these three routes are the only
# account endpoints reachable without one.
def _client(request: Request) -> str:
    return (request.headers.get("cf-connecting-ip")
            or (request.client.host if request.client else "") or "?")


def _set_session(resp: Response, request: Request) -> None:
    resp.set_cookie(accounts.COOKIE, accounts.issue(),
                    max_age=accounts.SESSION_DAYS * 86400, path="/", httponly=True,
                    samesite="strict", secure=request.url.scheme == "https")


@app.get("/login")
def login_page():
    with open(os.path.join(STATIC, "login.html"), encoding="utf-8") as fh:
        html = fh.read().replace("__V__", VERSION)
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


@app.post("/api/auth/login")
async def api_login(request: Request, payload: dict = Body(...)):
    if web_security._foreign_origin(dict(request.scope["headers"])):
        raise HTTPException(403, "cross-site request refused")
    who = _client(request)
    wait = accounts.throttled(who)
    if wait:
        raise HTTPException(429, f"too many failed attempts - try again in {wait // 60 + 1} min")
    user, pw = str(payload.get("username", "")), str(payload.get("password", ""))
    ok = await anyio.to_thread.run_sync(lambda: accounts.verify(user, pw))
    if not ok:
        accounts.failed(who)
        await anyio.sleep(0.5)
        raise HTTPException(401, "wrong username or password")
    accounts.succeeded(who)
    db.log(user, "login", None, user, {"client": who})
    resp = JSONResponse({"ok": True, "must_change": accounts.profile()["must_change"]})
    _set_session(resp, request)
    return resp


@app.post("/api/auth/logout")
def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(accounts.COOKIE, path="/")
    return resp


@app.get("/api/profile")
def api_profile(request: Request):
    return {**accounts.profile(), "signed_in_as": actor(request),
            "via": getattr(request.state, "auth", "off")}


@app.put("/api/profile")
def api_profile_update(request: Request, payload: dict = Body(...)):
    try:
        out = accounts.rename(str(payload.get("username", "")), actor=actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    resp = JSONResponse(out)
    # The session names the user; renaming would otherwise sign this one out.
    if getattr(request.state, "auth", "") == "password":
        _set_session(resp, request)
    return resp


@app.post("/api/profile/password")
async def api_password(request: Request, payload: dict = Body(...)):
    who = _client(request)
    wait = accounts.throttled(who)
    if wait:
        raise HTTPException(429, f"too many failed attempts - try again in {wait // 60 + 1} min")
    try:
        await anyio.to_thread.run_sync(lambda: accounts.change_password(
            str(payload.get("current", "")), str(payload.get("new", "")), actor(request)))
    except PermissionError as exc:
        accounts.failed(who)
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    # Changing the password ends every session, this one included - issue
    # this browser a fresh one so the person who just changed it stays in.
    resp = JSONResponse({"ok": True, **accounts.profile()})
    if getattr(request.state, "auth", "") == "password":
        _set_session(resp, request)
    return resp


@app.get("/metrics")
def prometheus_metrics():
    """Prometheus text format. Behind the same authentication as the API; a
    scraper can use NETMAP_METRICS_TOKEN, which opens this and nothing else."""
    return Response(metrics.render(VERSION), media_type=metrics.CONTENT_TYPE)


@app.get("/healthz")
def healthz():
    return {"ok": True, "entries": db.count(), "version": VERSION}


@app.get("/")
def index():
    """Serve the shell with version-stamped asset URLs.

    Without the stamp a proxy or browser happily pairs a new index.html with
    cached old scripts or style.css, which renders as a broken page.
    """
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as fh:
        html = fh.read().replace("__V__", VERSION)
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.exception_handler(404)
def nf(_r, _e):
    return JSONResponse({"error": "not found"}, status_code=404)


class _MCPDispatcher:
    """Send exactly one path to the MCP app; everything else to FastAPI.

    This used to be `app.mount("/", mcp.streamable_http_app())`, which made the
    MCP app the handler for every unmatched path - including Cloudflare's
    /cdn-cgi/access/* callbacks, which broke Access login with a bare
    "Not Found". Matching one exact path keeps the rest of the URL space ours.
    """

    def __init__(self, primary, mcp_app, path: str):
        self.primary = primary
        self.mcp_app = mcp_app
        self.path = "/" + path.strip("/")

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and \
                "/" + scope.get("path", "").strip("/") == self.path:
            # Normalise so the MCP app always sees its own configured path,
            # with or without a trailing slash, and never issues a redirect.
            if not MCP_TOKEN:
                # Off: nothing reaches the MCP app. A path alone is no
                # credential - it travels in URLs, logs and screenshots.
                return await self._off(send)
            if not web_security.bearer_ok(dict(scope.get("headers") or []), MCP_TOKEN):
                return await self._deny(send)
            scope = dict(scope)
            scope["path"] = self.path
            return await self.mcp_app(scope, receive, send)
        return await self.primary(scope, receive, send)

    @staticmethod
    async def _deny(send):
        # Say which scheme is expected: a client that gets a bare 401 cannot
        # tell "wrong token" from "wrong path" from "server broken".
        await send({"type": "http.response.start", "status": 401,
                    "headers": [(b"content-type", b"application/json"),
                                (b"www-authenticate", b'Bearer realm="netmap-mcp"')]})
        await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})

    @staticmethod
    async def _off(send):
        await send({"type": "http.response.start", "status": 503,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
        await send({"type": "http.response.body", "body": MCP_OFF_TEXT})


# ASGI entrypoint - uvicorn serves `application`, not `app`.
application = _MCPDispatcher(app, mcp.streamable_http_app(), MCP_PATH)
