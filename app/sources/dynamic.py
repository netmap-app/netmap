"""Driver registry: every kind of source NetMap can read.

A driver is a module with:

    FIELDS               the Settings form - see app/sources/fields.py for the
                         shape of one field
    configured(cfg) -> bool
    scan(cfg) -> dict    the finding shape the rest of the package uses,
                         minus label/hint, which the instance wrapper in
                         app/sources/__init__.py adds
    test(cfg) -> dict    optional; {"ok": bool, "error": str} for the
                         Settings "Test connection" button. Falls back to
                         treating a scan with no `error` as a pass.

    ABSENCE              optional; finding types that say "this entry is not
                         here". With two instances of a type, one instance
                         saying an entry is missing is dropped when another
                         instance sees it - see sources._shadow().
    MULTI                optional, default True; False for a type that can
                         be added only once (see below)
    ROLES                what the source *is* to the rest of NetMap - see
                         ROLES below. Shared code (Overview, explain, links,
                         other drivers) asks for a role, never for a product,
                         so a new DNS server or reverse proxy only has to
                         keep its role's contract to be understood.

`cfg` is the instance's stored config plus its decrypted secrets, typed by
fields.coerce(), plus:

    _state   a dict that lives as long as the instance does and is dropped
             whenever Settings changes it. Login sessions go there, never in
             a module global.
    _id      the instance id: the type for the first instance ("pihole"),
             "<type>-<n>" for more ("pihole-2"). Sightings, presence and the
             scan result's `source` carry it.
    _key     the prefix of every finding key, and so of every ignore. The
             first instance keeps the prefix it has always had ("pihole",
             "ha" for Home Assistant); another instance uses its id.

Adding a driver type is a code change - write the module, add one line below.
Every *instance* of a type (which firewall, which token) is added, edited and
removed from Settings › Sources, with no deploy. Order here is the order
sources are listed and scanned in.
"""
from . import (adguard, cloudflare, docker, homeassistant, leasefile, netbox, npm,
               opnsense, pihole, portscan, proxmox, snmparp, traefik, unifi)

DRIVERS = {
    "docker": {"label": "Docker", "mod": docker,
               "hint": "containers on one Docker or Podman host - through a socket proxy "
                       "(recommended), the TLS port with a client certificate, or a "
                       "mounted socket"},
    "opnsense": {"label": "OPNsense", "mod": opnsense,
                 "hint": "leases, reservations and port forwards"},
    "pihole": {"label": "Pi-hole", "mod": pihole,
               "hint": "local DNS records and client groups"},
    "adguard": {"label": "AdGuard Home", "mod": adguard,
                "hint": "DNS rewrites and persistent clients"},
    "leasefile": {"label": "DHCP lease file", "mod": leasefile,
                  "hint": "who holds which address - dnsmasq, ISC dhcpd or Kea"},
    "snmparp": {"label": "Router ARP (SNMP)", "mod": snmparp,
                "hint": "who answers at which address - any router with SNMP v2c"},
    "unifi": {"label": "UniFi", "mod": unifi,
              "hint": "the physical layer - devices, uplinks and switch ports"},
    "homeassistant": {"label": "Home Assistant", "mod": homeassistant,
                      "hint": "whether watched things are actually working"},
    "npm": {"label": "NPM", "mod": npm,
            "hint": "the reverse proxy - which name reaches which service"},
    "traefik": {"label": "Traefik", "mod": traefik,
                "hint": "routers and services - which name reaches which service"},
    "cloudflare": {"label": "Cloudflare", "mod": cloudflare,
                   "hint": "the edge - which public hostnames reach in, and where"},
    "proxmox": {"label": "Proxmox VE", "mod": proxmox,
                "hint": "VMs and LXC containers on a Proxmox node or cluster"},
    "ports": {"label": "Open ports", "mod": portscan,
              "hint": "what is listening, against what the inventory claims"},
    "netbox": {"label": "NetBox", "mod": netbox,
               "hint": "the source of truth - devices, VMs and addresses it says exist"},
}


# Roles, and the contract a driver keeps by declaring one. A role with no
# function to implement is a promise about the sightings it records.
ROLES = {
    "containers": ("Containers", "sightings `container`, `port:<n>` = published"),
    "hypervisor": ("Virtualisation", "VMs and containers a hypervisor runs"),
    "firewall": ("Firewall & DHCP",
                 "sightings `port:<n>` = forwarded from the WAN; `dhcp`, `mac`"),
    "dns": ("DNS", "dns_names(cfg) -> set[str]: names with a local record"),
    "proxy": ("Reverse proxy", "domains(cfg) -> set[str]: names it serves; "
              "sightings `proxy:<name>` = where a name is forwarded"),
    "edge": ("Public edge", "sightings `hostname:<name>` = published to the "
             "internet, value containing \"no Access\" when nothing is in "
             "front; finding key `<prefix>:access:<name>` for that; optional "
             "gateway(cfg, entries) -> the entry that is the edge's connector"),
    "leases": ("Leases & ARP", "record_presence rows {ip, mac, label}: who holds "
               "which address. A source whose whole job this is maps its data "
               "onto rows and calls _leases.report() for mac-mismatch, "
               "ip-moved and the `lease`/`arp` sightings"),
    "layer2": ("Switches & Wi-Fi", "topology(cfg) -> {devices, clients}, "
               "keyed by MAC - what is plugged into what"),
    "health": ("Health", "whether watched things are actually working"),
    "intent": ("Source of truth", "what a planning tool says should exist; sightings "
               "`intent` on the entries it matches"),
    "scanner": ("Port scan", "sightings `port:<n>` = open / closed / filtered; "
                "skip_categories(cfg) -> set[str]: categories never probed"),
}


def roles_of(type_: str) -> tuple[str, ...]:
    d = DRIVERS.get(type_)
    return tuple(getattr(d["mod"], "ROLES", ())) if d else ()


def types_with(role: str) -> list[str]:
    return [t for t in DRIVERS if role in roles_of(t)]


# Key prefixes that are not the type's own name, from before instances.
LEGACY_PREFIX = {"homeassistant": "ha"}


def type_of(source: str) -> str:
    """The driver type behind an instance id or a finding-key prefix:
    "pihole-2" → "pihole", "ha" → "homeassistant"."""
    base = (source or "").split("-", 1)[0]
    return next((t for t, p in LEGACY_PREFIX.items() if p == base), base)


def has_role(source: str, role: str) -> bool:
    """Whether an instance id or finding-key prefix belongs to a source with
    that role - "cloudflare-2" and "edge", "ha" and "health"."""
    return role in roles_of(type_of(source))


def multi(type_: str) -> bool:
    d = DRIVERS.get(type_)
    return bool(d) and getattr(d["mod"], "MULTI", True)


def fields(type_: str) -> list[dict]:
    d = DRIVERS.get(type_)
    return d["mod"].FIELDS if d else []
