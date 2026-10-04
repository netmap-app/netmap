"""The Network page draws each source as its product's mark. The summary names
the marks already on disk, by source type, so the browser never asks for one
that is not there; and Open ports sits after Proxmox VE in the line."""
import os

TOKEN = {"authorization": "Bearer full-token"}


def test_summary_names_only_the_source_marks_on_disk(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    from app import icons
    assert c.get("/api/discovery/summary", headers=TOKEN).json()["icons"] == {}
    os.makedirs(icons.CACHE, exist_ok=True)
    with open(icons._file("proxmox", ".svg"), "wb") as f:
        f.write(b'<svg xmlns="http://www.w3.org/2000/svg"/>')
    assert c.get("/api/discovery/summary", headers=TOKEN).json()["icons"] == {"proxmox": "proxmox"}


def test_every_source_type_with_a_product_mark_names_one(make_app):
    make_app()
    from app import icons
    from app.sources import dynamic
    drawn = {"ports", "leasefile", "snmparp"}      # no product: the UI draws a glyph
    assert set(icons.SOURCE_SLUGS) == set(dynamic.DRIVERS) - drawn
    assert all(icons.SLUG_RE.match(s) for s in icons.SOURCE_SLUGS.values())


def test_open_ports_comes_after_proxmox(make_app):
    make_app()
    from app.sources import dynamic
    order = list(dynamic.DRIVERS)
    assert order.index("ports") == order.index("proxmox") + 1
