# Changelog

Notable changes to NetMap, newest first. One line per change, no commentary -
each bullet stays on a single line, since `/api/changelog` parses this
file with a simple line-based reader (see `app/main.py`).

## 2.6.2 - 2026-10-04

- The Address space legend shows reserved addresses the way the grid draws them: "reserved, in use" (a framed filled cell) and "reserved, unused" (an outline), after the four fills (used, shared, seen, free).

## 2.6.1 - 2026-10-04

- Address space starts at .1 and ends at .254: the network and broadcast addresses (.0, .255) are no longer drawn.
- A reserved address that is also used, shared or seen is drawn as a framed cell (a thin ring in the background colour inside the fill) instead of with a light ring that looked like a glow in dark mode.

## 2.6.0 - 2026-10-04

- Address space on the Overview is a 32 x 8 grid per /24, one cell per address: used, shared, seen (by a source, not in the inventory), reserved (outlined) or free, with a legend, the subnet's zone and its summary. Every cell names its address and state on hover.
- Clicking an address with entries opens Inventory filtered to exactly that address, shown as an "IP" chip that removes the filter. API: `/api/entries?ip=` matches the address exactly.

## 2.5.2 - 2026-10-04

- Every Overview card now uses the card shell from Quick launch: Reachable from outside, Hardware & blast radius, Inventory by category, Changes and Address space have their title inside a panel, their content on the darker shade, and no panel inside the panel. The status strip takes the same corners and padding with its own tint.

## 2.5.1 - 2026-10-04

- Quick launch is drawn as a card: a panel with its title and "N pinned · by name" inside, rows a shade darker than the panel, larger names. New Overview cards use the same shell (CONTRIBUTING.md says how).

## 2.5.0 - 2026-10-04

- Quick links is now Quick launch: pinned services by name in two columns, each a link showing the URL's host name (ip:port when there is no URL, and on hover) and a status dot. Pinned entries with nothing to open open their card.
- Quick launch suggests up to two critical entries with a URL that are not pinned, with a Pin button each.
- Recent changes is now Changes: the change log and status changes (up/down) together, grouped by day ("Today", "Yesterday · Sat, Oct 3"), with a run of changes by one actor to one entry or to entries on one address within two hours folded into one row that opens. Filters: All, Discovered, Edits, State. Six groups, then All changes; if the log or the status changes cannot load, the card says which.

## 2.4.0 - 2026-10-04

- New Overview card, Hardware & blast radius: one tile per physical host that something runs on, with how many entries depend on it (through VMs and containers), how many of those a health check watches, and amber notes when two of the firewall, DNS, proxy and edge sources point at the same host, when three or more critical entries depend on it, or when it is tagged `backup:none`. A Network gear tile shows the Core Network hardware, up out of monitored. API: `GET /api/overview/hardware`.
- Inventory by category shows each category's monitored share: a solid fill for monitored inside a faint fill for the total, and "monitored/total" on each row.
- The default card order is now Reachable from outside, Hardware, Categories, Quick links, Recent changes, Address space. A saved layout keeps its order and gets the new card after Reachable from outside.

## 2.3.0 - 2026-10-04

- The Overview opens with a status strip instead of the big banner: "All clear - nothing needs you" as one row with the numbers when nothing does, otherwise "N things need you" with the queue folded in, tinted by the worst level (red critical, amber to look at, neutral for later).
- Each queue row shows its rank, a type pill (source, down, certificate, exposure, mismatch, conflict, coverage, verify), when it started, an action (Retry scan, Open entry, Accept, Review) and Snooze. The order is the server's, unchanged: a dead source still ranks above what it would have reported.
- Accept marks a hostname with no Access application as open on purpose (it ignores that edge finding, after a confirmation).
- "Set aside" is now Snooze, and snoozed items sit behind an "N snoozed" link in the strip rather than in a card of their own.
- New numbers: "unmonitored" counts entries a health check could probe (hardware, VM, container, service) that have none and no `ha:` expectation; "seen" is now "sightings". `/api/overview` items carry `type` (and `accept` for exposure), and `counts` carries `unmonitored`.

## 2.2.0 - 2026-10-04

- Customize overview: show, hide and reorder the Overview's cards (button at the bottom of the page). The layout is stored on the server, one for the instance; the status and Needs you always show first. API: `GET`/`PUT /api/settings/overview`.
- The header says when the sources were last scanned and when the next automatic scan is due ("Scanned 12:15 · next in 40 min"); `/api/discovery/summary` and `/api/overview` carry `next_scan`.
- The header's Export CSV button is gone (export stays in Settings › Data), and the page name is no longer shown next to the search box: the side rail or the tabs already say which page this is.
- The search placeholder shows the quick-search shortcut for this keyboard (⌘K or Ctrl+K); the rescan button has a spoken name.
- Closing a dialog returns focus to the button that opened it even when the page redrew that button meanwhile.

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
