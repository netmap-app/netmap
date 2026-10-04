# Changelog

Notable changes to NetMap, newest first. One line per change, no commentary -
each bullet stays on a single line, since `/api/changelog` parses this
file with a simple line-based reader (see `app/main.py`).

## 2.1.1 - 2026-10-04

- CI: the Dockhand address for the optional deploy is now the repository secret `DOCKHAND_URL` instead of a variable, so public CI logs no longer print it. If you deploy through Dockhand, add the secret and delete the variable.

## 2.1.0 - 2026-10-04

- Network › Reconciliation shows each source as its product's mark with a status bar under it (green, amber, red, grey while scanning); the name and last answer are in the tooltip, and a source with no mark gets a drawn glyph.
- Open ports now comes after Proxmox VE in the source order.
- Plain dashes instead of em dashes everywhere: interface text, empty-value placeholders, docs and changelog headings (now `## <version> - <date>`).

## 2.0.2 - 2026-10-03

- The MCP endpoint is off unless `NETMAP_MCP_TOKEN` is set: without it the MCP path answers 503 and nothing reaches the MCP server, instead of serving its tools to anyone who knows the path. If you use MCP without a token, set one (README section 10).
- Start-up says "MCP endpoint off - NETMAP_MCP_TOKEN not set"; the Overview no longer warns about it, and Settings › About shows MCP as on or off.
- CONTRIBUTING.md now carries all of the project's ground rules.

## 2.0.1 - 2026-10-03

- Updated the MCP library to 1.28.1.

## 2.0.0 - 2026-10-03

- First public release.
- Inventory of hosts, VMs, containers, services, ports and addresses, edited from a desktop or a phone, with live reachability checks, 30-day uptime, relationships and a topology graph.
- Reconciliation against read-only sources: Docker (socket proxy, TLS or socket), Proxmox VE, OPNsense, Pi-hole, AdGuard Home, UniFi, Home Assistant, Nginx Proxy Manager, Traefik, Cloudflare, NetBox, a DHCP lease file, router ARP over SNMP and an open-port sweep - several instances of each.
- New devices on the network, with Watch for the ones nobody can name yet; notifications through ntfy, Gotify, Telegram or a webhook, at once or as a summary.
- MCP server for AI assistants, Prometheus metrics, JSON backup and restore.
- Images for amd64 and arm64; the app runs as an ordinary user, every source secret is encrypted at rest, and login is required by default.
- A request to a host name that is not in `NETMAP_ALLOWED_HOSTS` now says which name and what to set, instead of a bare "Invalid host header".
