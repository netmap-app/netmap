"""Real marks for real services, fetched once and then owned.

A dashboard that says "Plex" in text and one that shows the Plex mark are not
the same page: the second is scannable. Marks come from two places, because
neither alone covers a homelab:

- **dashboard-icons** (homarr-labs) - the self-hosted-application vocabulary:
  Plex, Sonarr, Pi-hole, Proxmox, UniFi. Full colour, already the set Homepage
  and Homarr use, so the marks are the ones a homelab expects.
- **simple-icons** - the *brand* vocabulary: Ubuntu, Intel, LG, Philips,
  Western Digital. Single-colour glyphs, which is why they are recoloured on
  the way out to whichever theme asked.

Plus one local mark: NetMap's own, which is in this repo and needs no network.

Three rules, and the design is all three together:

1. **Fetched by the server, not by the browser.** A browser hitting a CDN per
   tile makes every reader's page depend on someone else's uptime and hands
   that someone a log of what this person runs. One process fetches, once.
2. **Cached on disk beside the database**, so the second load - and every load
   after the network goes away - is local.
3. **A miss is not an error.** No mark published, a wrong guess, no internet:
   the interface keeps the drawn glyph it already had. `list_cached()` is what
   the browser asks, and it only ever names marks that are already on disk, so
   the common case is not even a 404 - it is a question never asked.

Matching is by substring on the entry's name, which is unglamorous and right:
the names are written by one person and they contain the product. An entry can
override with a tag - `icon:jellyseerr`, `icon:si:ubuntu`, or `icon:none`.
"""
from __future__ import annotations

import os
import re
import threading
import time

from . import db

DASH = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/{ext}/{slug}.{ext}"
SIMPLE = "https://cdn.jsdelivr.net/npm/simple-icons@16.32.0/icons/{slug}.svg"
LOCAL = os.path.join(os.path.dirname(__file__), "static", "brand")

SLUG_RE = re.compile(r"^(si:|local:)?[a-z0-9][a-z0-9._-]{0,48}$")
# Bumped whenever RULES or the fetching changes: a mark cached under the old
# rules - or a ".miss" written when the old rules asked for the wrong name -
# would otherwise outlive the fix and make it look like nothing happened.
CACHE_GEN = "v2"
CACHE = os.path.join(os.path.dirname(db.DB_PATH) or ".", "icons-" + CACHE_GEN)
MISS_TTL = 6 * 3600         # retry a name that came up empty, but not per load
TIMEOUT = 6.0
MAX_BYTES = 512 * 1024
# Single-colour marks are painted in the interface's own ink, so they need to
# know which one. These are --fg from style.css, dark and light.
INK = {"dark": "#e6e9ef", "light": "#1a1d23"}

# The index calls these PNG-first: their SVG either does not exist or is not
# the drawing people recognise, so they are fetched as PNG and not argued with.
PNG_FIRST = {"homepage", "kometa", "cloudflare-zero-trust", "smlight"}

# Marks the interface needs that no entry asks for: the discovery sources are
# products too, and the strip that names them reads far faster with their own
# marks than with eight identical dots.
SOURCE_SLUGS = {
    "docker": "docker", "opnsense": "opnsense", "pihole": "pi-hole",
    "unifi": "unifi", "homeassistant": "home-assistant",
    "npm": "nginx-proxy-manager", "cloudflare": "cloudflare",
    "adguard": "adguard-home", "traefik": "traefik", "proxmox": "proxmox",
    "netbox": "netbox",
}

# Ordered, most specific first: "cockpit unifi" must not become the UniFi mark,
# and "home assistant mcp" must not become the MCP one. Every dashboard-icons
# slug here was checked against the index; the `si:` ones are brand names that
# dashboard-icons does not carry and simple-icons does.
RULES: list[tuple[str, str]] = [
    ("cloudflare access", "cloudflare-zero-trust"),
    ("cloudflare tunnel", "cloudflare"), ("cloudflared", "cloudflare"),
    ("cockpit", "si:ubuntu"),
    ("netmap", "local:netmap"),
    ("dockhand", "dockhand"), ("docker proxy", "docker"),
    ("openclaw", "openclaw"),
    ("audiobookshelf", "audiobookshelf"),
    ("filebrowser", "filebrowser"),
    ("flaresolverr", "flaresolverr"),
    ("glances", "glances"),
    ("ha mcp", "home-assistant"), ("home assistant", "home-assistant"),
    ("file editor", "home-assistant"), ("terminal ssh", "home-assistant"),
    ("piper", "home-assistant"), ("whisper", "home-assistant"),
    ("openthread", "home-assistant"),
    ("homepage", "homepage"),
    ("intel nuc", "si:intel"),
    ("kometa", "kometa"),
    ("matter", "matter"),
    ("metube", "metube"),
    ("mosquitto", "mosquitto"),
    ("nginx proxy manager", "nginx-proxy-manager"), ("npm", "nginx-proxy-manager"),
    ("nzbget", "nzbget"),
    ("opnsense", "opnsense"),
    ("pbs", "proxmox"), ("pegaprox", "proxmox"), ("proxmox", "proxmox"),
    ("pi hole", "pi-hole"), ("pihole", "pi-hole"),
    ("plex", "plex"),
    ("prowlarr", "prowlarr"),
    ("qbittorrent", "qbittorrent"),
    ("radarr", "radarr"),
    ("seerr", "seerr"),
    ("shelly", "shelly"),
    ("slzb", "smlight"), ("thread border router", "smlight"),
    ("sonarr", "sonarr"),
    ("stirling", "stirling-pdf"),
    ("synology", "synology-dsm"),
    ("uptime kuma", "uptime-kuma"),
    ("unifi", "unifi"), ("u7 pro", "unifi"), ("usw flex", "unifi"),
    ("ubuntu", "si:ubuntu"),
    ("wd mycloud", "wd-mycloud"),
    ("windows 11", "windows-11"),
    ("wireguard", "wireguard"),
    ("wiz bulb", "wiz"),
    ("zigbee2mqtt", "zigbee2mqtt"),
    ("philips", "si:philips|si:philipshue"),
    ("lg ", "si:lg"),
    ("ipad", "si:apple"), ("iphone", "si:apple"),
]


def _norm(s: str) -> str:
    """Lowercase, punctuation to spaces: "NPM (Nginx Proxy Manager)" and
    "Pi-hole" both have to land on something a substring can find."""
    return " " + re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip() + " "


def slug_for(entry: dict) -> str:
    for t in (entry.get("tags") or []):
        t = str(t).strip().lower()
        if t.startswith("icon:"):
            v = t.split(":", 1)[1].strip()
            return "" if v in ("none", "-") else (v if SLUG_RE.match(v) else "")
    n = _norm(entry.get("name"))
    for sub, slug in RULES:
        if sub in n:
            return slug
    return ""


def _cands(slug: str) -> list[str]:
    """A rule may name more than one candidate, first preferred: some brands
    are filed under a name this cannot check from here, and trying two is
    cheaper than being wrong. `read` walks the same list, so whichever one
    landed on disk is the one that gets served."""
    return [c for c in (slug or "").split("|") if c]


def _file(slug: str, suffix: str) -> str:
    return os.path.join(CACHE, slug.replace(":", "-") + suffix)


def _http(url: str) -> bytes | None:
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "NetMap"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(MAX_BYTES + 1)
        return body if 0 < len(body) <= MAX_BYTES else None
    except Exception:
        return None                      # offline is a miss, not a failure


def _ink(svg: bytes, theme: str) -> bytes:
    """Paint a single-colour mark in the interface's ink.

    Two shapes need it and for the same underlying reason - an <img> is its own
    document and inherits nothing from the page. simple-icons ship one path
    with no fill, which renders black; NetMap's own glyph asks for
    `currentColor`, which in an <img> *is* black. Both are invisible on a dark
    panel, so the colour is written into the bytes on the way out."""
    ink = INK.get(theme, INK["dark"]).encode()
    svg = svg.replace(b"currentColor", ink)
    if b"fill=" not in svg[:400]:
        svg = re.sub(rb"<svg\b", b'<svg fill="' + ink + b'"', svg, count=1)
    return svg


def fetch(slug: str) -> bool:
    """Put this mark on disk if it is not there. True if it is there after."""
    cands = _cands(slug)
    if len(cands) > 1:
        for c in cands:
            if fetch(c):
                return True
        return False
    slug = cands[0] if cands else ""
    if not SLUG_RE.match(slug or ""):
        return False
    if slug.startswith("local:"):
        return os.path.exists(os.path.join(LOCAL, slug[6:] + "-glyph-adaptive.svg"))
    for ext in (".svg", ".png"):
        if os.path.exists(_file(slug, ext)):
            return True
    miss = _file(slug, ".miss")
    try:
        if time.time() - os.path.getmtime(miss) < MISS_TTL:
            return False
    except OSError:
        pass

    got: list[tuple[str, bytes]] = []
    if slug.startswith("si:"):
        body = _http(SIMPLE.format(slug=slug[3:]))
        if body and b"<svg" in body[:2048].lower():
            got.append((".svg", body))
    else:
        # The index calls some marks PNG-first, and asking for the SVG of one
        # of those is a 404 - so try both rather than assume.
        exts = ("png", "svg") if slug in PNG_FIRST else ("svg", "png")
        for ext in exts:
            body = _http(DASH.format(ext=ext, slug=slug))
            if body and (ext == "png" or b"<svg" in body[:2048].lower()):
                got.append(("." + ext, body))
                break
        # Several marks ship a variant drawn for dark backgrounds. Take it if
        # it exists; the base one stays the answer for light.
        dark = _http(DASH.format(ext="svg", slug=slug + "-dark"))
        if dark and b"<svg" in dark[:2048].lower():
            got.append((".dark.svg", dark))

    os.makedirs(CACHE, exist_ok=True)
    if not any(s in (".svg", ".png") for s, _ in got):
        try:
            open(miss, "wb").close()
        except OSError:
            pass
        return False
    for suffix, body in got:
        tmp = _file(slug, suffix + ".tmp")
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, _file(slug, suffix))
    return True


def read(slug: str, theme: str = "dark") -> tuple[bytes, str] | None:
    """The bytes to serve, and their media type. Disk only - never fetches, so
    a page load can never wait on a CDN."""
    cands = _cands(slug)
    if len(cands) > 1:
        for c in cands:
            got = read(c, theme)
            if got:
                return got
        return None
    slug = cands[0] if cands else ""
    if not SLUG_RE.match(slug or ""):
        return None
    if slug.startswith("local:"):
        try:
            with open(os.path.join(LOCAL, slug[6:] + "-glyph-adaptive.svg"), "rb") as f:
                return _ink(f.read(), theme), "image/svg+xml"
        except OSError:
            return None
    order = [".dark.svg", ".svg", ".png"] if theme == "dark" else [".svg", ".png"]
    for suffix in order:
        try:
            with open(_file(slug, suffix), "rb") as f:
                body = f.read()
        except OSError:
            continue
        if suffix == ".png":
            return body, "image/png"
        if slug.startswith("si:"):
            body = _ink(body, theme)
        return body, "image/svg+xml"
    return None


def wanted() -> dict[str, str]:
    """entry id -> slug, for every entry that names something with a mark."""
    out = {}
    for e in db.list_entries():
        s = slug_for(e)
        if s:
            out[str(e["id"])] = s
    return out


def list_cached() -> dict[str, str]:
    """What the browser may ask for: entries whose mark is already on disk."""
    return {i: s for i, s in wanted().items() if read(s) is not None}


def source_marks() -> dict[str, str]:
    """Source type -> slug, for the marks already on disk. The browser draws a
    glyph for any type missing here and never asks for it."""
    return {t: s for t, s in SOURCE_SLUGS.items() if read(s) is not None}


def warm() -> dict:
    """Fetch every mark the inventory wants. Cached ones are not re-fetched."""
    want = set(wanted().values()) | set(SOURCE_SLUGS.values())
    got = [s for s in sorted(want) if fetch(s)]
    return {"wanted": len(want), "cached": len(got),
            "missing": sorted(want - set(got))}


def warm_in_background() -> None:
    """Called at startup. Marks appear on their own a few seconds in; until
    then every entry shows its category glyph, which is a complete interface,
    not a loading state."""
    threading.Thread(target=lambda: warm(), daemon=True).start()
