# Changelog

Notable changes to NetMap, newest first. One line per change, no commentary
— each bullet stays on a single line, since `/api/changelog` parses this
file with a simple line-based reader (see `app/main.py`).

## 2.0.1 — 2026-10-03

- Updated the MCP library to 1.28.1.

## 2.0.0 — 2026-10-03

- First public release.
- Inventory of hosts, VMs, containers, services, ports and addresses, edited from a desktop or a phone, with live reachability checks, 30-day uptime, relationships and a topology graph.
- Reconciliation against read-only sources: Docker (socket proxy, TLS or socket), Proxmox VE, OPNsense, Pi-hole, AdGuard Home, UniFi, Home Assistant, Nginx Proxy Manager, Traefik, Cloudflare, NetBox, a DHCP lease file, router ARP over SNMP and an open-port sweep — several instances of each.
- New devices on the network, with Watch for the ones nobody can name yet; notifications through ntfy, Gotify, Telegram or a webhook, at once or as a summary.
- MCP server for AI assistants, Prometheus metrics, JSON backup and restore.
- Images for amd64 and arm64; the app runs as an ordinary user, every source secret is encrypted at rest, and login is required by default.
- A request to a host name that is not in `NETMAP_ALLOWED_HOSTS` now says which name and what to set, instead of a bare "Invalid host header".
