"""What a person sees: the Overview's states, Settings › Sources, an entry
from the Add button to the list, the port page, and a phone-width screen.
See conftest.py for how the server and browser are set up."""
import json
import re

from playwright.sync_api import expect


def open_settings(page, tab: str):
    page.click("#railSet")
    page.click(f'[data-settab="{tab}"]')


def toast(page):
    return page.locator("#toast")


# ---- Overview ---------------------------------------------------------------------------------
def _overview_with(page, server, **changes):
    """Serve the real /api/overview with some fields replaced - the states the
    test data does not produce by itself."""
    real = server.api("GET", "/api/overview")
    page.route("**/api/overview", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps({**real, **changes})))
    page.reload()
    page.wait_for_selector("#overview .verdict")


def test_overview_all_clear(page, server):
    _overview_with(page, server, level="ok", attention=[], verdict="Nothing needs you.")
    expect(page.locator("#overview .verdict")).to_have_class(re.compile(r"\bok\b"))
    expect(page.locator("#overview .vhead")).to_have_text("All clear - nothing needs you")
    expect(page.locator("#overview .attn")).to_have_count(0)


def test_overview_queue_worst_first(page, server):
    items = [
        {"key": "source:npm", "level": "critical", "order": 0, "title": "NPM is not answering",
         "detail": "login refused"},
        {"key": "open:x", "level": "warn", "order": 3, "title": "x.example.org has no Access application"},
    ]
    _overview_with(page, server, level="critical", attention=items,
                   verdict="NPM is not answering.")
    expect(page.locator("#overview .verdict")).to_have_class(re.compile(r"\bcritical\b"))
    expect(page.locator("#overview .vhead")).to_have_text("2 things need you")
    expect(page.locator("#overview .vhead")).to_have_attribute("title", "NPM is not answering.")
    rows = page.locator("#overview .attn .at")
    expect(rows).to_have_count(2)
    expect(rows.nth(0)).to_have_class(re.compile(r"\bcritical\b"))
    expect(rows.locator(".atrank")).to_have_text(["1", "2"])
    expect(rows.nth(0).locator(".atn")).to_have_text("NPM is not answering")
    expect(rows.nth(1).locator(".atn")).to_have_text("x.example.org has no Access application")


# ---- Settings › Sources -----------------------------------------------------------------------
def test_fresh_install_has_no_sources(page):
    open_settings(page, "sources")
    expect(page.locator("#srcList")).to_contain_text("No sources yet")


def test_add_sources_by_role_with_validation(page):
    open_settings(page, "sources")
    page.click("#srcAddBtn")
    dns = page.locator(".pickgroup", has=page.locator(".pickhead", has_text="DNS"))
    expect(dns.locator(".picklabel")).to_have_text(["Pi-hole", "AdGuard Home"])

    # A required field left empty is refused before anything is stored.
    page.click('[data-src-pick="docker"]')
    page.click("#srcSaveBtn")
    expect(toast(page)).to_contain_text("Docker API URL, Host IP are required")

    page.fill("#srcf_url", "http://127.0.0.1:9")
    page.fill("#srcf_host_ip", "127.0.0.1")
    page.click("#srcSaveBtn")
    expect(page.locator("#srcList .srcname")).to_have_text(["Docker"])

    # A second one of a type that allows several is numbered.
    page.click("#srcAddBtn")
    page.click('[data-src-pick="docker"]')
    page.fill("#srcf_url", "http://127.0.0.2:9")
    page.fill("#srcf_host_ip", "127.0.0.2")
    page.click("#srcSaveBtn")
    expect(page.locator("#srcList .srcname").nth(1)).to_contain_text("Docker 2")

    # A type that allows one is shown as added, and cannot be picked again.
    page.click("#srcAddBtn")
    page.click('[data-src-pick="proxmox"]')
    page.fill("#srcf_url", "https://127.0.0.1:9")
    page.fill("#srcf_token_id", "a@pve!ro")
    page.fill("#srcf_token_secret", "s")
    page.click("#srcSaveBtn")
    expect(page.locator("#srcList .srcname")).to_have_count(3)
    page.click("#srcAddBtn")
    expect(page.locator('[data-src-pick="proxmox"]')).to_be_disabled()
    expect(page.locator('[data-src-pick="proxmox"]')).to_contain_text("already added")
    expect(page.locator('[data-src-pick="docker"]')).to_be_enabled()


def test_sources_are_named_by_their_own_names(page, server):
    for ip in ("127.0.0.1", "127.0.0.2"):
        server.api("POST", "/api/sources/instances",
                   {"type": "docker", "fields": {"url": f"http://{ip}:9", "host_ip": ip}})
    e = server.api("POST", "/api/entries", {"name": "Wiki", "ip": "127.0.0.2"})
    server.sightings("docker-2", [{"entry_id": e["id"], "fact": "container",
                                   "value": "wiki running"}])
    page.goto(f"{server.url}/#/entry/{e['id']}")
    page.reload()
    expect(page.locator("#cardBody .ssrc")).to_contain_text(["Docker 2"])


# ---- Inventory --------------------------------------------------------------------------------
def test_add_an_entry_and_find_it(page, server):
    page.click("#addBtn")
    page.fill("#f_name", "Grafana")
    page.fill("#f_ip", "10.9.8.7")
    page.fill("#f_ports", "3000")
    page.click("#saveBtn")
    expect(page.locator("#editModal")).to_be_hidden()
    assert any(x["name"] == "Grafana" for x in server.api("GET", "/api/entries"))

    page.click('#railnav [data-view="inventory"]')
    page.fill("#search", "grafana")
    expect(page.locator("#listbody")).to_contain_text("Grafana")
    page.fill("#search", "nothing-like-this")
    expect(page.locator("#listbody")).not_to_contain_text("Grafana")


def test_saving_without_a_name_is_refused(page):
    page.click("#addBtn")
    page.click("#saveBtn")
    expect(toast(page)).to_contain_text("Name is required")
    expect(page.locator("#editModal")).to_be_visible()


# ---- the port page, by role -------------------------------------------------------------------
def test_port_page_tells_published_from_forwarded(page, server):
    plex = server.api("POST", "/api/entries", {"name": "Plex", "ip": "10.0.0.7", "ports": "32400"})
    server.sightings("opnsense", [{"entry_id": plex["id"], "fact": "port:32400",
                                   "value": "forwarded from WAN 32400 (TCP)"}])
    page.evaluate("showPort(32400)")
    expect(page.locator("#portBody")).to_contain_text("forwarded from the WAN by 1 rule")

    # Any edge source - here a second Cloudflare - makes it published.
    server.sightings("cloudflare-2", [{"entry_id": plex["id"], "fact": "hostname:plex.example.org",
                                       "value": "→ http://10.0.0.7:32400"}])
    page.evaluate("showPort(32400)")
    expect(page.locator("#portBody")).to_contain_text("reachable from the internet through 1 hostname")


# ---- phone width ------------------------------------------------------------------------------
def test_phone_width_never_scrolls_sideways(page, server):
    server.api("POST", "/api/entries", {"name": "A rather long service name for a phone screen",
                                        "ip": "10.0.0.9", "url": "https://a-very-long-hostname.example.org"})
    page.set_viewport_size({"width": 375, "height": 812})
    for view in ("overview", "inventory", "network"):
        page.evaluate(f'document.querySelector(\'#viewtabs [data-view="{view}"]\').click()')
        page.wait_for_timeout(300)
        width = page.evaluate("document.documentElement.scrollWidth")
        assert width <= 375, f"{view} is {width}px wide at 375px"


# ---- every view opens -------------------------------------------------------------------------
def test_every_view_tab_and_dialog_opens(page, server):
    """A smoke pass over everything a person can open. Any uncaught error on
    the way fails the test (see the page fixture) - which is how a script
    loaded in the wrong order, or a render exception, shows up."""
    e = server.api("POST", "/api/entries", {"name": "Router", "ip": "10.0.0.1", "ports": "443"})
    page.reload()
    page.wait_for_selector("#overview .verdict")
    for view, marker in (("inventory", "#listbody"), ("network", "#network .ovsec"),
                         ("changes", "#changes"), ("overview", "#overview .verdict")):
        page.click(f'#railnav [data-view="{view}"]')
        expect(page.locator(marker).first).to_be_visible()
    for tab in ("about", "sources", "data", "profile"):
        open_settings(page, tab)
        expect(page.locator(f'.setpanel[data-panel="{tab}"]')).to_be_visible()
    expect(page.locator("#aboutBody")).to_contain_text(re.compile(r"Version\s*\d+\.\d+\.\d+"))  # version line rendered
    page.keyboard.press("Control+k")
    expect(page.locator("#palModal")).to_be_visible()
    page.fill("#palInput", "rout")
    expect(page.locator("#palResults")).to_contain_text("Router")
    page.keyboard.press("Escape")
    page.evaluate(f"showCard({e['id']})")
    expect(page.locator("#cardModal")).to_be_visible()


# ---- long pages: what opens is where you can see it -------------------------------------------
def test_editing_a_source_brings_the_form_into_view(page, server):
    for i in range(9):                                   # a list taller than the screen
        server.api("POST", "/api/sources/instances", {"type": "docker", "fields": {
            "url": f"http://127.0.0.{i + 1}:9", "host_ip": f"127.0.0.{i + 1}"}})
    page.set_viewport_size({"width": 1280, "height": 600})
    open_settings(page, "sources")
    page.locator('[data-src-edit="docker"]').click()
    form = page.locator("#srcForm .srcform")
    expect(form).to_be_in_viewport()
    expect(page.locator("#srcf_url")).to_be_focused()     # the first setting, not the name
    page.click("#srcCancelBtn")
    expect(form).to_have_count(0)
    expect(page.locator('[data-src-edit="docker"]')).to_be_focused()

    page.click("#srcAddBtn")
    expect(page.locator("#srcForm .srcform")).to_be_in_viewport()
    expect(page.locator(".pickrow:not([disabled])").first).to_be_focused()


def test_long_sheets_close_from_the_top(page):
    for opener, modal in (("showChangelog()", "#changelogModal"),
                          ("$('#histModal').hidden = false", "#histModal")):
        page.evaluate(opener)
        expect(page.locator(modal)).to_be_visible()
        x = page.locator(f"{modal} .sheetx")
        expect(x).to_be_in_viewport()
        # Still there at the bottom of a long list - the reason it exists.
        page.locator(f"{modal} .sheet").evaluate("s => s.scrollTop = s.scrollHeight")
        expect(x).to_be_in_viewport()
        x.click()
        expect(page.locator(modal)).to_be_hidden()


# ---- reconciliation, one source at a time ------------------------------------------------------
def test_each_source_turns_green_or_red_as_its_own_scan_lands(page, server):
    for i in (1, 2, 3):
        server.api("POST", "/api/sources/instances", {"type": "docker", "fields": {
            "url": f"http://127.0.0.{i}:9", "host_ip": f"127.0.0.{i}"}})
    held = []
    ok = {"source": "docker-2", "label": "Docker 2", "configured": True, "error": None,
          "findings": [], "counts": {}, "scanned_at": "2026-01-01T00:00:00Z", "host": {}}

    def answer(route):
        if "/api/discovery/docker-3" in route.request.url:
            held.append(route)                            # keep this one waiting
        elif "/api/discovery/docker-2" in route.request.url:
            route.fulfill(status=200, content_type="application/json", body=json.dumps(ok))
        else:
            route.continue_()                             # docker: nothing listens, so it fails
    page.route("**/api/discovery/docker*", answer)
    page.click('#railnav [data-view="network"]')

    chip = lambda i: page.locator(f'#network [data-srcchip="{i}"]')
    expect(chip("docker-2")).to_have_class(re.compile(r"\bgood\b"))
    expect(chip("docker")).to_have_class(re.compile(r"\bbad\b"))
    expect(chip("docker-3")).to_have_class(re.compile(r"\bwait\b"))    # still scanning
    expect(page.locator("#reconHint")).to_have_text("scanning… 2/3")

    page.wait_for_timeout(200)
    held[0].fulfill(status=200, content_type="application/json",
                    body=json.dumps({**ok, "source": "docker-3", "label": "Docker 3"}))
    expect(page.locator("#reconHint")).not_to_contain_text("scanning")
    expect(page.locator("#network [data-srcchip].wait")).to_have_count(0)


def test_the_refresh_button_greys_the_sources_at_once(page, server):
    """Pressing refresh turns every source gray straight away - not after the
    reachability sweep, which runs alongside and is held back here."""
    for port in (9, 10):                  # refused at once, so each fails fast
        server.api("POST", "/api/sources/instances", {"type": "docker", "fields": {
            "url": f"http://127.0.0.1:{port}", "host_ip": "127.0.0.1"}})
    page.click('#railnav [data-view="network"]')
    expect(page.locator("#reconHint")).not_to_contain_text("scanning")
    held = []
    page.route("**/api/status/refresh", lambda r: held.append(r))
    page.route("**/api/discovery/docker-2*", lambda r: held.append(r))
    page.click("#refreshBtn")
    expect(page.locator('#network [data-srcchip="docker-2"]')).to_have_class(re.compile(r"\bwait\b"))
    expect(page.locator('#network [data-srcchip="docker"]')).to_have_class(re.compile(r"\bbad\b"))
    for r in held:
        r.continue_()
    expect(page.locator("#reconHint")).not_to_contain_text("scanning")


# ---- a tab that outlived a deploy --------------------------------------------------------------
def test_a_newer_server_version_offers_a_reload(page, server):
    page.evaluate("checkVersion()")
    expect(page.locator("#updBanner")).to_be_hidden()          # same version: nothing to say

    real = server.api("GET", "/healthz")
    page.route("**/healthz", lambda r: r.fulfill(status=200, content_type="application/json",
                                                 body=json.dumps({**real, "version": "99.0.0"})))
    page.evaluate("checkVersion()")
    banner = page.locator("#updBanner")
    expect(banner).to_have_text("NetMap was updated to 99.0.0 - reload to use it.")
    page.unroute("**/healthz")
    with page.expect_navigation():
        banner.click()                                          # reloads the page
    expect(page.locator("#updBanner")).to_be_hidden()


# ---- confirmation, and What's new --------------------------------------------------------------
def test_removing_a_source_asks_in_app_and_cancel_keeps_it(page, server):
    server.api("POST", "/api/sources/instances", {"type": "docker", "fields": {
        "url": "http://127.0.0.1:9", "host_ip": "127.0.0.1"}})
    page.on("dialog", lambda d: (_ for _ in ()).throw(AssertionError("native dialog shown")))
    open_settings(page, "sources")
    remove = page.locator('[data-src-del="docker"]')

    remove.click()
    dialog = page.locator("#confirmModal")
    expect(dialog).to_be_visible()
    expect(page.locator("#confirmTitle")).to_have_text('Remove "Docker"?')
    expect(page.locator("#confirmCancel")).to_be_focused()        # the safe answer by default
    page.keyboard.press("Escape")
    expect(dialog).to_be_hidden()
    expect(remove).to_be_focused()                                # focus back where it was
    assert [s["id"] for s in server.api("GET", "/api/sources/instances")] == ["docker"]

    remove.click()
    page.click("#confirmOk")
    expect(page.locator("#srcList")).to_contain_text("No sources yet")


def test_escape_in_the_confirm_does_not_close_the_form_that_asked(page, server):
    e = server.api("POST", "/api/entries", {"name": "Old box"})
    page.evaluate("e => openEdit(e)", e)
    expect(page.locator("#editModal")).to_be_visible()
    page.click("#delBtn")
    expect(page.locator("#confirmModal")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.locator("#confirmModal")).to_be_hidden()
    expect(page.locator("#editModal")).to_be_visible()            # still editing
    page.click("#delBtn")
    page.click("#confirmOk")
    expect(page.locator("#editModal")).to_be_hidden()
    assert not [x for x in server.api("GET", "/api/entries") if x["id"] == e["id"]]


def test_whats_new_shows_code_as_code(page):
    page.evaluate("showChangelog()")
    body = page.locator("#changelogBody")
    expect(body.locator("code").first).to_be_visible()
    assert "`" not in body.inner_text()


# ---- automatic scan interval ---------------------------------------------------------------------
def test_scan_interval_in_hours_and_minutes(page, server):
    import time
    for _ in range(100):                  # the first automatic pass, 5s after start-up
        if server.api("GET", "/api/settings/scan")["next_scan"]:
            break
        time.sleep(0.1)
    open_settings(page, "sources")
    expect(page.locator("#scanH")).to_have_value("24")          # the default: daily
    expect(page.locator("#scanM")).to_have_value("0")

    page.fill("#scanH", "0")
    page.fill("#scanM", "2")
    page.click("#scanSave")
    expect(page.locator("#toast")).to_contain_text("between 5 minutes and 7 days")

    page.fill("#scanH", "1")
    page.fill("#scanM", "30")
    page.click("#scanSave")
    expect(page.locator("#toast")).to_contain_text("every 1 h 30 min")
    assert server.api("GET", "/api/settings/scan")["interval"] == 5400
    expect(page.locator("#scanNext")).to_contain_text("Next automatic scan")

    page.reload()
    open_settings(page, "sources")
    expect(page.locator("#scanH")).to_have_value("1")
    expect(page.locator("#scanM")).to_have_value("30")


# ---- notifications ---------------------------------------------------------------------------------
def _telegram_stub():
    """A local stand-in for the Telegram Bot API that records each sendMessage."""
    import http.server
    import threading
    got = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("content-length") or 0)
            got.append({"path": self.path, "body": json.loads(self.rfile.read(n))})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", got


def test_add_a_telegram_channel_and_send_a_test(page, server):
    bot = "987654:UI-test-token-qrst"
    srv, url, got = _telegram_stub()
    try:
        open_settings(page, "notify")
        expect(page.locator("#notifyList")).to_contain_text("No channels yet")
        page.click("#notifyAddBtn")
        page.click('[data-n-pick="telegram"]')
        expect(page.locator("#ntff__name")).to_be_focused()
        page.fill("#ntff_token", bot)
        page.fill("#ntff_chat_id", "42")
        page.fill("#ntff_api_url", url)
        page.uncheck('[data-n-event="finding"]')

        page.click("#notifyTestBtn")                     # before saving: the typed details
        expect(page.locator("#notifyTestOut")).to_contain_text("Sent")
        assert got[-1]["path"] == f"/bot{bot}/sendMessage"
        assert got[-1]["body"]["chat_id"] == "42"

        page.click("#notifySaveBtn")
        expect(toast(page)).to_contain_text("Channel added")
        row = page.locator("#notifyList .srcrow")
        expect(row).to_contain_text("Telegram")
        expect(row).to_contain_text("chat 42")
        expect(row).not_to_contain_text("new findings")  # the event left unchecked
        assert bot not in page.content()                 # the token never comes back

        row.locator("[data-n-test]").click()
        expect(toast(page)).to_contain_text("Test sent to Telegram")
        assert len(got) == 2
        expect(row.locator(".dot")).to_have_class(re.compile(r"\bup\b"))

        row.locator("[data-n-edit]").click()
        expect(page.locator("#ntff_token")).to_have_value("")
        expect(page.locator("#notifyForm")).to_contain_text("currently set")
        expect(page.locator("#notifyForm")).to_contain_text("qrst")
        assert not page.is_checked('[data-n-event="finding"]')
        assert page.is_checked('[data-n-event="entry"]')

        page.set_viewport_size({"width": 375, "height": 812})
        page.wait_for_timeout(200)
        width = page.evaluate("document.documentElement.scrollWidth")
        assert width <= 375, f"Settings › Notifications is {width}px wide at 375px"
    finally:
        srv.shutdown()


def test_a_failed_delivery_shows_on_the_channel(page, server):
    server.api("POST", "/api/notify/channels", {
        "type": "webhook", "name": "hook", "fields": {"url": "http://127.0.0.1:9/in"}})
    open_settings(page, "notify")
    page.click("[data-n-test]")
    row = page.locator("#notifyList .srcrow")
    expect(row.locator(".srcerr")).to_contain_text("cannot reach it")
    expect(row.locator(".dot")).to_have_class(re.compile(r"\bdown\b"))


def test_each_event_checkbox_sits_beside_its_sentence(page, server):
    """The event list once inherited the text-field layout: checkboxes
    stretched to full width, their sentences pushed to the far right in
    capitals."""
    open_settings(page, "notify")
    page.click("#notifyAddBtn")
    page.click('[data-n-pick="ntfy"]')
    n = len(server.api("GET", "/api/notify/types")["events"])
    expect(page.locator(".nevents .ckf")).to_have_count(n)
    # Measured in one step: the form scrolls into view, so two separate
    # reads can land on different frames of the scroll.
    rows = page.evaluate("""() => [...document.querySelectorAll('.nevents .ckf')].map(l => {
        const b = l.querySelector('input').getBoundingClientRect();
        const t = l.querySelector('span').getBoundingClientRect();
        return {bw: b.width, gap: t.left - b.right, dy: Math.abs((b.top + b.height / 2)
                - (t.top + t.height / 2)), tt: getComputedStyle(l).textTransform};
    })""")
    for r in rows:
        assert r["bw"] < 30, "the checkbox is stretched"
        assert 0 <= r["gap"] < 20, "the sentence is not beside its box"
        assert r["dy"] < 12 and r["tt"] == "none"


# ---- health checks -------------------------------------------------------------------------------
def test_a_health_check_is_set_in_the_form_and_bad_ones_are_refused(page, server):
    page.click("#addBtn")
    page.fill("#f_name", "API")
    page.fill("#f_ip", "10.0.0.5")
    expect(page.locator("#hcHelp")).to_contain_text("https:8443/health=200")
    page.fill("#f_healthcheck", "ftp")
    page.click("#saveBtn")
    expect(toast(page)).to_contain_text("health check")
    expect(page.locator("#editModal")).to_be_visible()          # nothing lost
    page.fill("#f_healthcheck", "https/health=200")
    page.click("#saveBtn")
    expect(page.locator("#editModal")).to_be_hidden()
    e = [x for x in server.api("GET", "/api/entries") if x["name"] == "API"][0]
    assert e["healthcheck"] == "https/health=200"
    page.evaluate("e => openEdit(e)", e)                        # and it reads back
    expect(page.locator("#f_healthcheck")).to_have_value("https/health=200")


def test_the_card_names_the_check_and_the_certificate(page, server, tmp_path):
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
    from test_checks import Web, self_signed
    web = Web(*self_signed(tmp_path, 5))
    try:
        web.status = 200
        e = server.api("POST", "/api/entries", {"name": "Vault", "ip": "127.0.0.1",
                                                "healthcheck": f"https:{web.port}/health=200"})
        server.api("POST", f"/api/status/refresh?entry_id={e['id']}")
        page.reload()
        page.evaluate(f"showCard({e['id']})")
        head = page.locator("#cardBody .ch2")
        expect(head).to_contain_text(f"HTTPS 127.0.0.1:{web.port}/health → 200")
        cert = page.locator("#cardBody .cscert")
        expect(cert).to_contain_text("certificate valid until")
        expect(cert).to_contain_text("not trusted")                # self-signed
        expect(cert).to_have_class(re.compile(r"\bwarn\b"))          # 5 days < 21
        dot_title = page.locator("#cardBody .ch1 .dot").get_attribute("title")
        assert dot_title.startswith(f"HTTPS 127.0.0.1:{web.port}/health → 200")

        page.set_viewport_size({"width": 375, "height": 812})
        page.wait_for_timeout(200)
        box = page.locator("#cardBody").bounding_box()
        assert box["x"] >= 0 and box["x"] + box["width"] <= 375
        assert page.evaluate("document.documentElement.scrollWidth") <= 375
    finally:
        web.close()


def test_the_certificate_warning_window_is_saved(page, server):
    open_settings(page, "sources")
    expect(page.locator("#certDays")).to_have_value("21")
    page.fill("#certDays", "30")
    page.click("#certSave")
    expect(toast(page)).to_contain_text("30 days before")
    assert server.api("GET", "/api/settings/checks")["tls_warn_days"] == 30


# ---- leases & ARP --------------------------------------------------------------------------------
def test_a_lease_file_source_is_added_tested_and_its_finding_shown(page, server, tmp_path):
    leases = tmp_path / "dnsmasq.leases"
    leases.write_text("4102444800 aa:bb:cc:00:00:99 192.168.10.11 impostor *\n"
                      "4102444800 aa:bb:cc:00:00:07 192.168.10.60 guest *\n")
    server.api("POST", "/api/entries", {"name": "Camera", "ip": "192.168.10.11",
                                        "mac": "aa:bb:cc:00:00:02"})
    open_settings(page, "sources")
    page.click("#srcAddBtn")
    group = page.locator(".pickgroup", has=page.locator(".pickhead", has_text="Leases & ARP"))
    expect(group.locator(".picklabel")).to_have_text(["DHCP lease file", "Router ARP (SNMP)"])
    page.click('[data-src-pick="leasefile"]')
    page.fill("#srcf_path", str(tmp_path / "nothing.leases"))
    page.click("#srcTestBtn")
    expect(page.locator("#srcTestOut")).to_contain_text("is it mounted into the container")
    page.fill("#srcf_path", str(leases))
    page.click("#srcTestBtn")
    expect(page.locator("#srcTestOut")).to_contain_text("Reachable")
    page.click("#srcSaveBtn")
    expect(page.locator("#srcList .srcname")).to_have_text(["DHCP lease file"])

    page.click('#railnav [data-view="network"]')
    net = page.locator("#network")
    expect(net).to_contain_text("Camera - 192.168.10.11 is held by aa:bb:cc:00:00:99")
    expect(net.locator(".cf .sev", has_text="other MAC")).to_have_count(1)
    expect(net).to_contain_text("2 addresses")


# ---- new on the network ----------------------------------------------------------------------------
def test_the_map_says_who_made_a_device_and_since_when(page, server):
    import sqlite3
    server.api("POST", "/api/entries", {"name": "Router", "ip": "10.0.0.1"})
    c = sqlite3.connect(server.db)
    c.execute("INSERT INTO presence (ip, source, label, mac, detail, seen_at) VALUES "
              "('10.0.0.5', 'opnsense', 'nas01', '00:11:32:00:00:01', 'DHCP lease', "
              "'2026-09-27T10:00:00Z')")
    c.execute("INSERT INTO presence_seen (key, mac, first_seen, last_seen, first_source, "
              "last_source, last_ip, label) VALUES ('00:11:32:00:00:01', '00:11:32:00:00:01', "
              "'2026-09-01T08:00:00Z', '2026-09-27T10:00:00Z', 'opnsense', 'opnsense', "
              "'10.0.0.5', 'nas01')")
    c.commit()
    c.close()
    page.reload()
    page.click('#railnav [data-view="network"]')
    page.wait_for_function("() => SEEN['10.0.0.5']")
    page.hover('.snbar[data-net="10.0.0.0/24"] i[data-a="5"]')
    read = page.locator('.snread[data-read="10.0.0.0/24"]')
    expect(read).to_contain_text("Synology Incorporated")
    expect(read).to_contain_text(re.compile(r"first seen (1 September|September 1,) 2026"))
    page.click('.snbar[data-net="10.0.0.0/24"] i[data-a="5"]')
    expect(page.locator("#addrpop .apwhen")).to_contain_text(
        re.compile(r"first seen (1 September|September 1,) 2026, last"))


def test_what_counts_as_new_is_saved(page, server):
    open_settings(page, "sources")
    expect(page.locator("#ndDays")).to_have_value("7")
    expect(page.locator("#ndKeep")).to_have_value("90")
    assert not page.is_checked("#ndRandom")
    page.fill("#ndDays", "14")
    page.check("#ndRandom")
    page.click("#ndSave")
    expect(toast(page)).to_contain_text("New for 14 days")
    r = server.api("GET", "/api/settings/newdevices")
    assert r["days"] == 14 and r["include_random"] is True

    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(200)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375


# ---- topology graph ------------------------------------------------------------------------------
def _graph_fixture(server, extra_containers=0):
    mk = lambda **e: server.api("POST", "/api/entries", e)                      # noqa: E731
    sw = mk(name="Switch", kind="hardware", ip="10.0.0.2")
    host = mk(name="Host", kind="hardware", ip="10.0.0.3")
    vm = mk(name="Docker VM", kind="vm", ip="10.0.0.15")
    app = mk(name="Wiki", kind="container", ip="10.0.0.15", ports="8080")
    mk(name="Loner", kind="service")                                           # no links
    link = lambda s, d, t: server.api("POST", "/api/edges", {"src": s["id"], "dst": d["id"], "type": t})  # noqa: E731
    link(host, sw, "connects_to")
    link(vm, host, "runs_on")
    link(app, vm, "runs_on")
    for i in range(extra_containers):
        c = mk(name=f"svc-{i:02d}", kind="container", ip="10.0.0.15")
        link(c, vm, "runs_on")
    server.sightings("cloudflare", [{"entry_id": app["id"], "fact": "hostname:wiki.example.org",
                                     "value": "tunnel; no Access"}])
    return {"sw": sw, "host": host, "vm": vm, "app": app}


def _boxes_overlap(page):
    boxes = page.eval_on_selector_all("#graphSvg .gn", "els => els.map(e => { const r = e.getBoundingClientRect(); return [r.left, r.top, r.right, r.bottom]; })")
    for i, a in enumerate(boxes):
        for b in boxes[i + 1:]:
            if a[0] < b[2] - 0.5 and b[0] < a[2] - 0.5 and a[1] < b[3] - 0.5 and b[1] < a[3] - 0.5:
                return (a, b)
    return None


def test_the_graph_draws_entries_links_and_the_way_in(page, server):
    f = _graph_fixture(server, extra_containers=30)
    page.evaluate("() => localStorage.removeItem('netmap.graph')")
    page.reload()
    page.click('#railnav [data-view="network"]')
    page.click('[data-topo="graph"]')
    svg = page.locator("#graphSvg")
    expect(svg).to_be_visible()
    expect(svg.locator(".gn[data-gid]")).to_have_count(34)                   # Loner is not drawn
    expect(svg.locator(".gn-internet")).to_have_count(1)
    expect(svg.locator(".ge")).to_have_count(33 + 1)                         # links + the way in
    expect(page.locator("#gCount")).to_contain_text("1 without links not drawn")
    assert _boxes_overlap(page) is None, "two nodes overlap"
    width = page.evaluate("document.querySelector('#graphBox').clientWidth")
    assert page.evaluate("document.querySelector('#graphSvg').getBoundingClientRect().width") <= width
    # Hosts above what runs on them.
    y = lambda i: page.locator(f'#graphSvg [data-gid="{i}"]').bounding_box()["y"]  # noqa: E731
    assert y(f["sw"]["id"]) < y(f["vm"]["id"]) < y(f["app"]["id"])

    page.check("#gUnlinked")
    expect(svg.locator(".gn[data-gid]")).to_have_count(35)
    page.uncheck("#gUnlinked")
    page.check("#gExposed")                                                  # Wiki and its host
    expect(page.locator("#graphSvg .gn[data-gid]")).to_have_count(2)
    page.reload()                                                             # filters remembered
    page.click('#railnav [data-view="network"]')
    expect(page.locator("#gExposed")).to_be_checked()
    page.click(f'#graphSvg [data-gid="{f["app"]["id"]}"]')
    expect(page.locator("#cardModal")).to_be_visible()
    expect(page.locator("#cardBody h2")).to_have_text("Wiki")


def test_on_a_phone_the_graph_tab_shows_the_tree(page, server):
    _graph_fixture(server)
    page.set_viewport_size({"width": 375, "height": 812})
    page.reload()
    page.evaluate('document.querySelector(\'#viewtabs [data-view="network"]\').click()')
    page.click('[data-topo="graph"]')
    expect(page.locator(".gnarrow")).to_contain_text("wider screen")
    expect(page.locator("#network .tree")).to_contain_text("Docker VM")
    expect(page.locator("#graphSvg")).to_have_count(0)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375


# ---- what answers on a port ------------------------------------------------------------------------
def test_the_deep_scan_links_what_it_identified_and_marks_guesses(page, server):
    job = {"state": "done", "ip": "10.0.0.5", "total": 2, "done": 2, "percent": 100,
           "open": [3000, 5432], "closed": 0, "filtered": 0, "skipped": [], "owners": [],
           "undeclared": [3000, 5432], "silent": False, "seconds": 1.0, "error": None,
           "results": [
               {"port": 3000, "service": "Grafana (HTTP)", "identified": True,
                "url": "http://10.0.0.5:3000/", "declared": False},
               {"port": 5432, "service": "PostgreSQL", "identified": False, "url": "",
                "declared": False}]}
    page.route("**/api/scan/deep", lambda r: r.fulfill(
        status=200, content_type="application/json", body=json.dumps(job)))
    page.click('#railnav [data-view="network"]')
    rows = page.locator(".dsres .prow")
    expect(rows).to_have_count(2)
    link = rows.nth(0).locator("a")
    expect(link).to_have_text("Grafana (HTTP)")
    assert link.get_attribute("href") == "http://10.0.0.5:3000/"
    expect(rows.nth(0)).not_to_contain_text("(guess)")
    expect(rows.nth(1)).to_contain_text("PostgreSQL (guess)")


# ---- NetBox ----------------------------------------------------------------------------------------
def test_netbox_is_offered_as_a_source_of_truth(page):
    open_settings(page, "sources")
    page.click("#srcAddBtn")
    group = page.locator(".pickgroup", has=page.locator(".pickhead", has_text="Source of truth"))
    expect(group.locator(".picklabel")).to_have_text(["NetBox"])
    page.click('[data-src-pick="netbox"]')
    expect(page.locator("#srcf_token")).to_have_attribute("type", "password")
    page.fill("#srcf_url", "http://127.0.0.1:9")
    page.click("#srcSaveBtn")
    expect(toast(page)).to_contain_text("API token (read-only) is required")


# ---- no accidental zoom on a phone --------------------------------------------------------------
def test_a_phone_does_not_zoom_into_fields_or_on_double_tap(browser, server):
    ctx = browser.new_context(viewport={"width": 390, "height": 844}, has_touch=True,
                              is_mobile=True, device_scale_factor=3)
    pg = ctx.new_page()
    try:
        pg.goto(server.url + "/")
        pg.wait_for_selector("#overview .verdict")
        assert pg.evaluate("matchMedia('(pointer: coarse)').matches")
        assert pg.evaluate("getComputedStyle(document.documentElement).touchAction") == "manipulation"
        # Every field, not a sample: a field's own, more specific rule used to
        # override the touch-screen one (IP, ports, the Settings number boxes).
        small = """() => [...document.querySelectorAll('input:not([type=checkbox]):not([type=hidden]), select, textarea')]
            .filter(e => e.offsetParent && parseFloat(getComputedStyle(e).fontSize) < 16)
            .map(e => e.id || e.outerHTML.slice(0, 50))"""
        pg.evaluate("openEdit(null)")
        assert pg.evaluate(small) == [], "iOS would zoom into these"
        pg.keyboard.press("Escape")
        for tab in ("sources", "notify", "profile"):
            pg.evaluate("document.querySelector('#setBtn').click()")
            pg.evaluate(f"document.querySelector('[data-settab={tab}]').click()")
            pg.wait_for_timeout(300)
            assert pg.evaluate(small) == [], f"Settings › {tab}: iOS would zoom into these"
        assert pg.evaluate("document.documentElement.scrollWidth") <= 390
        pg.goto(server.url + "/login")
        assert pg.evaluate("parseFloat(getComputedStyle(document.querySelector('#lUser')).fontSize)") >= 16
    finally:
        ctx.close()


# ---- uptime --------------------------------------------------------------------------------------
def test_uptime_on_the_card_where_the_rule_says(page, server):
    import sqlite3
    import time as _t
    iso = lambda t: _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(t))                # noqa: E731
    crit = server.api("POST", "/api/entries", {"name": "Router", "ip": "10.0.0.1", "ports": "1",
                                               "criticality": "critical"})
    toy = server.api("POST", "/api/entries", {"name": "Toy", "ip": "10.0.0.2", "ports": "1"})
    now = _t.time()
    c = sqlite3.connect(server.db)
    for eid in (crit["id"], toy["id"]):
        c.executemany("INSERT INTO observations (entry_id, ts, up) VALUES (?,?,?)", [
            (eid, iso(now - 40 * 86400), 1), (eid, iso(now - 3 * 86400), 0),
            (eid, iso(now - 3 * 86400 + 3 * 3600), 1)])
    c.commit()
    c.close()
    page.reload()
    page.evaluate(f"showCard({crit['id']})")
    cup = page.locator("#cardBody .cup")
    expect(cup).to_contain_text("99.58% up over 30 days")
    expect(cup).to_contain_text("down 3h")
    expect(cup.locator(".us.down")).to_have_count(1)
    title = page.locator("#cardBody .ch1 .dot").get_attribute("title")
    assert "99.58% up over 30 days" in title
    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(150)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375
    page.set_viewport_size({"width": 1280, "height": 900})
    page.keyboard.press("Escape")

    page.evaluate(f"showCard({toy['id']})")
    expect(page.locator("#cardBody h2")).to_have_text("Toy")
    expect(page.locator("#cardBody .cup")).to_have_count(0)                 # normal: not shown
    page.keyboard.press("Escape")

    open_settings(page, "sources")
    expect(page.locator('[data-up="criticalities"][value="critical"]')).to_be_checked()
    page.check('[data-up="criticalities"][value="normal"]')
    page.click("#uptimeSave")
    expect(toast(page)).to_contain_text("Uptime rule saved")
    assert "normal" in server.api("GET", "/api/settings/uptime")["criticalities"]


# ---- stale entries -------------------------------------------------------------------------------
def test_stale_entries_are_one_overview_note_with_chips(page, server):
    import sqlite3
    import time as _t
    iso = lambda t: _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(t))                # noqa: E731
    old = server.api("POST", "/api/entries", {"name": "Old NAS"})
    c = sqlite3.connect(server.db)
    c.execute("INSERT INTO entry_seen VALUES (?,?,?)", (old["id"], iso(_t.time() - 30 * 86400),
                                                         "seen by docker"))
    c.commit()
    c.close()
    page.reload()
    page.wait_for_selector("#overview .verdict")
    note = page.locator("#overview .at", has_text="nothing has seen for 14 days")
    expect(note).to_have_count(1)
    chip = note.locator(".atents .lchip")
    expect(chip).to_contain_text("Old NAS")
    chip.click()
    expect(page.locator("#cardModal")).to_be_visible()
    expect(page.locator("#cardBody")).to_contain_text("seen by docker")
    page.keyboard.press("Escape")

    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(150)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375
    page.set_viewport_size({"width": 1280, "height": 900})

    open_settings(page, "sources")
    expect(page.locator("#staleDays")).to_have_value("14")
    page.fill("#staleDays", "60")
    page.click("#staleSave")
    expect(toast(page)).to_contain_text("unseen for 60 days")
    assert server.api("GET", "/api/settings/stale")["days"] == 60


# ---- summary notifications -----------------------------------------------------------------------
def test_a_channel_can_switch_to_a_daily_summary(page, server):
    server.api("PUT", "/api/settings/timezone", {"timezone": "UTC"})
    server.api("POST", "/api/notify/channels", {
        "type": "webhook", "name": "hook", "fields": {"url": "http://127.0.0.1:9/in"}})
    open_settings(page, "notify")
    expect(page.locator("#tzName")).to_have_value("UTC")
    row = page.locator("#notifyList .srcrow")
    expect(row).not_to_contain_text("summary")                           # off by default
    row.locator("[data-n-edit]").click()
    expect(page.locator("#ntff__mode")).to_have_value("off")
    expect(page.locator("#ntff__hour")).to_be_hidden()
    expect(page.locator(".nurgent")).to_be_hidden()

    page.select_option("#ntff__mode", "weekly")
    expect(page.locator("#ntff__day")).to_be_visible()
    page.select_option("#ntff__mode", "daily")
    expect(page.locator("#ntff__day")).to_be_hidden()
    expect(page.locator(".nurgent")).to_be_visible()
    page.select_option("#ntff__hour", "7")
    page.uncheck('[data-n-urgent="cert"]')

    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(150)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375
    page.set_viewport_size({"width": 1280, "height": 900})

    page.click("#notifySaveBtn")
    expect(toast(page)).to_contain_text("Channel updated")
    expect(row).to_contain_text("daily summary at 07:00")
    d = server.api("GET", "/api/notify/channels")[0]["delivery"]
    assert d["mode"] == "daily" and d["hour"] == 7 and "cert" not in d["urgent"]

    page.fill("#tzName", "Nowhere/Land")
    page.click("#tzSave")
    expect(toast(page)).to_contain_text("not a time zone")
    page.fill("#tzName", "Europe/Berlin")
    page.click("#tzSave")
    expect(toast(page)).to_contain_text("Europe/Berlin")
    assert server.api("GET", "/api/settings/timezone")["timezone"] == "Europe/Berlin"


# ---- an MCP endpoint that is off (no NETMAP_MCP_TOKEN) ------------------------------------------
def test_mcp_off_is_in_about_and_not_a_warning(page, server):
    # The test server sets no NETMAP_MCP_TOKEN, so the endpoint is off.
    page.wait_for_selector("#overview .verdict")
    expect(page.locator("#overview .at", has_text="MCP")).to_have_count(0)
    open_settings(page, "about")
    body = page.locator("#aboutBody")
    expect(body).to_contain_text("off - set NETMAP_MCP_TOKEN to enable it")
    expect(body).not_to_contain_text("MCP accepts Host")
    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(150)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375
    r = page.request.post(server.url + "/mcp", data="{}",
                          headers={"content-type": "application/json"})
    assert r.status == 503 and "NETMAP_MCP_TOKEN" in r.text()


# ---- the UI audit (1.92.2) -------------------------------------------------------------------------
CONTRAST = """sel => { const el = document.querySelector(sel);
  const rgb = c => c.match(/\\d+(\\.\\d+)?/g).slice(0, 3).map(Number);
  const lum = c => { const v = rgb(c).map(x => { x /= 255; return x <= .03928 ? x / 12.92 : ((x + .055) / 1.055) ** 2.4; });
                     return .2126 * v[0] + .7152 * v[1] + .0722 * v[2]; };
  const s = getComputedStyle(el); const a = lum(s.color), b = lum(s.backgroundColor);
  return (Math.max(a, b) + .05) / (Math.min(a, b) + .05); }"""


def test_text_on_the_accent_is_readable_in_both_themes(browser, server):
    for scheme in ("dark", "light"):
        ctx = browser.new_context(viewport={"width": 1280, "height": 900}, color_scheme=scheme)
        pg = ctx.new_page()
        pg.goto(server.url + "/")
        pg.wait_for_selector("#overview .verdict")
        for sel in ("#addBtn", ".rnav.on"):
            ratio = pg.evaluate(CONTRAST, sel)
            assert ratio >= 4.5, f"{scheme} {sel}: {ratio:.2f}:1"
        ctx.close()


def test_every_entry_field_has_its_label_and_dialogs_return_focus(page, server):
    page.evaluate("document.querySelector('[data-view=inventory]').click()")
    page.focus("#addBtn")
    page.keyboard.press("Enter")
    expect(page.locator("#editModal")).to_be_visible()
    assert page.get_attribute("#editModal", "role") == "dialog"
    missing = page.evaluate("""[...document.querySelectorAll('#editModal input, #editModal select, #editModal textarea')]
        .filter(el => el.type !== 'checkbox' && !(el.labels && el.labels.length)).map(el => el.id)""")
    assert missing == []
    page.click("label[for=f_ip]")
    assert page.evaluate("document.activeElement.id") == "f_ip"
    page.keyboard.press("Escape")
    expect(page.locator("#editModal")).to_be_hidden()
    assert page.evaluate("document.activeElement.id") == "addBtn"


def test_a_failed_first_load_says_so_and_can_retry(browser, server):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    fail = {"on": True}
    pg.route("**/api/entries*", lambda r: r.fulfill(status=500, body="boom") if fail["on"] else r.continue_())
    pg.goto(server.url + "/")
    expect(pg.locator("#overview .loadfail")).to_contain_text("could not load")
    assert errors == []
    fail["on"] = False
    pg.click("#overview [data-retry-load]")
    pg.wait_for_selector("#overview .verdict")
    ctx.close()


def test_long_unbroken_text_never_pushes_the_page_sideways(page, server):
    long = "x" * 120
    e = server.api("POST", "/api/entries", {"name": "N" * 80, "notes": long, "host": "h" * 60})
    page.reload()
    page.wait_for_selector("#overview .verdict")
    page.evaluate("document.querySelector('[data-view=inventory]').click()")
    page.wait_for_timeout(300)
    assert page.evaluate("document.documentElement.scrollWidth") <= 1280
    page.evaluate(f"showCard({e['id']})")
    expect(page.locator("#cardBody h2")).to_be_visible()
    over = page.evaluate("""() => { const s = document.querySelector('#cardBody').getBoundingClientRect();
        return [...document.querySelectorAll('#cardBody *')].filter(x => x.getBoundingClientRect().right > s.right + 1).length }""")
    assert over == 0
    # The status dot stays beside the title, and an unmonitored entry shows no uptime strip.
    dot, h2 = page.locator("#cardBody .ch1 .dot").bounding_box(), page.locator("#cardBody h2").bounding_box()
    assert dot["y"] >= h2["y"] - 4 and dot["y"] <= h2["y"] + h2["height"]
    server.api("PATCH", f"/api/entries/{e['id']}", {"monitor": False, "criticality": "critical"})
    page.evaluate(f"showCard({e['id']})")
    page.wait_for_timeout(300)
    expect(page.locator("#cardBody .cup")).to_have_count(0)


def test_the_palette_on_a_phone_keeps_one_shape_and_no_key_hints(browser, server):
    server.api("POST", "/api/entries", {"name": "Pl", "ip": "10.0.0.1", "ports": "80", "category": "A long category"})
    server.api("POST", "/api/entries", {"name": "Plex media server with a long name", "ip": "10.0.0.2", "ports": "32400"})
    ctx = browser.new_context(viewport={"width": 375, "height": 812}, is_mobile=True, has_touch=True)
    pg = ctx.new_page()
    pg.goto(server.url + "/")
    pg.wait_for_selector("#overview .verdict")
    pg.evaluate("palOpen()")
    pg.keyboard.type("pl")
    pg.wait_for_timeout(300)
    heights = pg.evaluate("[...document.querySelectorAll('.palrow')].map(r => Math.round(r.getBoundingClientRect().height))")
    assert len(heights) >= 2 and max(heights) - min(heights) <= 2, heights
    expect(pg.locator(".palfoot")).to_be_hidden()
    assert pg.evaluate("document.documentElement.scrollWidth") <= 375
    ctx.close()


def test_entries_down_at_one_address_are_one_row_with_chips(page, server):
    a = server.api("POST", "/api/entries", {"name": "Alpha", "ip": "10.0.0.5"})
    b = server.api("POST", "/api/entries", {"name": "Beta", "ip": "10.0.0.5"})
    ov = page.evaluate("fetch('/api/overview').then(r => r.json())")
    ov["attention"] = [{"level": "warn", "order": 2, "key": "down:@10.0.0.5",
                        "title": "2 entries at 10.0.0.5 are not answering",
                        "detail": "Several at one address usually means the machine itself is down.",
                        "entries": [{"id": a["id"], "name": "Alpha", "how": "10.0.0.5:80"},
                                    {"id": b["id"], "name": "Beta", "how": "10.0.0.5:80"}],
                        "fingerprint": "x", "since": None}] + ov["attention"]
    page.route("**/api/overview", lambda r: r.fulfill(json=ov))
    page.reload()
    page.wait_for_selector("#overview .verdict")
    row = page.locator("#overview .at", has_text="2 entries at 10.0.0.5")
    expect(row.locator(".lchip")).to_have_count(2)
    row.locator(".lchip", has_text="Beta").click()
    expect(page.locator("#cardBody h2")).to_have_text("Beta")


# ---- 1.93.0: explanations behind "i", Enabled first, a tab that knows it is old ---------------------
def test_explanations_sit_behind_an_i_that_hovers_taps_and_closes(browser, server):
    for w in (1280, 375):
        ctx = browser.new_context(viewport={"width": w, "height": 860}, is_mobile=w < 500, has_touch=w < 500)
        pg = ctx.new_page()
        pg.goto(server.url + "/")
        pg.wait_for_selector("#overview .verdict")
        # No explanation is left as visible text in a section heading.
        loose = pg.evaluate("""[...document.querySelectorAll('.ovhead > .hint')]
            .filter(h => h.offsetParent && /worst first|what the edge|pinned services/i.test(h.textContent)).length""")
        assert loose == 0
        tip = pg.locator("#overview .itip").first
        box_id = tip.get_attribute("aria-describedby")
        box = pg.locator(f"#{box_id}")
        expect(box).to_be_hidden()
        if w > 500:
            tip.hover()
            expect(box).to_be_visible()
            pg.mouse.move(5, 500)
            expect(box).to_be_hidden()
        tip.click()                                         # a tap or click pins it
        expect(box).to_be_visible()
        r = box.bounding_box()
        assert r["x"] >= 0 and r["x"] + r["width"] <= w
        pg.mouse.click(5, 700) if w > 500 else pg.tap("#overview .verdict")
        expect(box).to_be_hidden()
        ctx.close()


def test_esc_closes_an_explanation_before_the_dialog_under_it(page, server):
    page.evaluate("document.querySelector('[data-view=inventory]').click()")
    page.click("#addBtn")
    expect(page.locator("#editModal")).to_be_visible()
    page.locator("#editModal .itip").first.click()
    expect(page.locator("#editModal .tipbox").first).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.locator("#editModal .tipbox").first).to_be_hidden()
    expect(page.locator("#editModal")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.locator("#editModal")).to_be_hidden()


def test_enabled_comes_first_and_pauses_a_source(page, server):
    open_settings(page, "sources")
    page.click("#srcAddBtn")
    page.click('[data-src-pick="ports"]')
    first = page.evaluate("document.querySelector('#srcForm .srcform input').id")
    assert first == "srcEnabled"
    page.uncheck("#srcEnabled")
    page.click("#srcSaveBtn")
    expect(toast(page)).to_contain_text("Source added")
    expect(page.locator("#srcList")).to_contain_text("disabled")
    assert server.api("GET", "/api/sources/instances")[0]["enabled"] is False
    open_settings(page, "notify")
    page.click("#notifyAddBtn")
    page.click('[data-n-pick="webhook"]')
    first = page.evaluate("document.querySelector('#notifyForm .srcform input').id")
    assert first == "ntffEnabled"


def test_a_tab_that_has_not_refreshed_greys_its_colours_and_says_since_when(page, server):
    page.evaluate("LAST_REFRESH = Date.now() - 10 * 3600 * 1000; pageFreshness()")
    expect(page.locator("#staleBanner")).to_be_visible()
    expect(page.locator("#staleBanner")).to_contain_text("Not refreshed since")
    assert page.evaluate("document.body.classList.contains('pagestale')")
    page.click("#staleBanner")
    expect(page.locator("#staleBanner")).to_be_hidden()
    assert not page.evaluate("document.body.classList.contains('pagestale')")


def test_source_colours_follow_the_clock_without_new_data(page, server):
    now = page.evaluate("Date.now()")
    iso = lambda ms: page.evaluate(f"new Date({ms}).toISOString()")              # noqa: E731
    page.evaluate(f"""SRC_HEALTH = {{interval: 3600, health: [{{source: 'x', label: 'X', configured: true,
        ok: true, last_ok: '{iso(now - 30 * 60 * 1000)}'}}]}};
        document.querySelector('#overview').insertAdjacentHTML('afterbegin', srcHtml(SRC_HEALTH));""")
    expect(page.locator('[data-srcchip="x"]')).to_have_class(re.compile(r"\bgood\b"))
    # Time passes: the last answer is now older than the window (5 h floor).
    page.evaluate(f"SRC_HEALTH.health[0].last_ok = '{iso(now - 6 * 3600 * 1000)}'; repaintSrcChips()")
    expect(page.locator('[data-srcchip="x"]')).to_have_class(re.compile(r"\bstale\b"))


def test_the_i_sits_on_the_line_of_the_text_it_explains(page, server):
    # The heading rows align by text baseline; an icon has none, so it used to
    # sit its bottom edge on the baseline and ride high.
    offsets = page.evaluate("""[...document.querySelectorAll('#overview .ovhead .tipwrap')].map(w => {
        const a = w.querySelector('svg').getBoundingClientRect();
        const r = w.parentElement.querySelector('h2').getBoundingClientRect();
        return Math.abs((a.top + a.bottom) / 2 - (r.top + r.bottom) / 2) })""")
    assert offsets and max(offsets) <= 2, offsets


def test_the_docker_form_offers_every_way_in(page, server):
    open_settings(page, "sources")
    page.click("#srcAddBtn")
    page.click('[data-src-pick="docker"]')
    form = page.locator("#srcForm")
    for label in ("Docker API URL", "CA certificate", "Client certificate", "Client key"):
        expect(form).to_contain_text(label)
    assert page.get_attribute("#srcf_client_key", "type") == "password"
    assert "unix://" in page.get_attribute("#srcf_url", "placeholder")
    assert "VM 101" not in form.inner_text() and "192.168.1" not in page.content().split('id="srcForm"')[1][:4000]
    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(150)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375


# ---- watching an unidentified device ---------------------------------------------------------------
WATCHED = {"drop_days": 90, "watching": [
    {"key": "00:11:32:00:00:01", "name": "nas01", "mac": "00:11:32:00:00:01",
     "vendor": "Synology Incorporated", "randomised": False, "online": True,
     "ips": ["10.0.0.5"], "sources": ["unifi"], "first_seen": "2026-09-30T08:00:00Z",
     "last_seen": "2026-10-03T08:00:00Z", "note": "in the cupboard?",
     "since": "2026-10-01T08:00:00Z", "finding": "unifi:new:00:11:32:00:00:01",
     "drop_on": "2027-01-01"},
    {"key": "ip:10.0.0.77", "name": "10.0.0.77", "mac": "", "vendor": "", "randomised": False,
     "online": False, "ips": ["10.0.0.77"], "sources": [], "first_seen": "2026-09-01T08:00:00Z",
     "last_seen": "2026-09-02T08:00:00Z", "note": "", "since": "2026-09-03T08:00:00Z",
     "finding": "pihole:new:ip:10.0.0.77", "drop_on": "2026-12-01"}]}


def _watching(page, phone=False):
    calls = []

    def answer(route):
        req = route.request
        if req.method == "GET":
            route.fulfill(status=200, content_type="application/json", body=json.dumps(WATCHED))
        else:
            calls.append((req.method, req.url, req.post_data))
            route.fulfill(status=200, content_type="application/json", body="{}")
    page.route("**/api/watch*", answer)
    if phone:
        page.reload()
        page.evaluate('document.querySelector(\'#viewtabs [data-view="network"]\').click()')
    else:
        page.click('#railnav [data-view="network"]')
    return calls


def test_watching_shows_what_is_known_and_keeps_a_note(page, server):
    calls = _watching(page)
    cards = page.locator("#watchSec .wcard")
    expect(cards).to_have_count(2)
    expect(page.locator("#watchSec .ovhead")).to_contain_text("2 devices · 1 on the network now")
    first, second = cards.nth(0), cards.nth(1)
    expect(first.locator(".sev")).to_have_text("online")
    expect(first).to_contain_text("00:11:32:00:00:01 · Synology Incorporated · at 10.0.0.5 · seen by unifi")
    expect(first).to_contain_text("last seen now")
    expect(second.locator(".sev")).to_have_text("away")
    expect(second).to_contain_text("dropped on 01.12.2026 if not seen again")
    expect(first.locator(".wnoteIn")).to_have_value("in the cupboard?")
    first.locator(".wnoteIn").fill("printer, probably")
    first.locator("[data-wsave]").click()
    expect(toast(page)).to_contain_text("Note saved")
    method, _, body = calls[-1]
    assert method == "PATCH" and json.loads(body) == {"key": "00:11:32:00:00:01",
                                                      "note": "printer, probably"}
    second.locator("[data-wstop]").click()
    expect(toast(page)).to_contain_text("No longer watched")
    assert calls[-1][0] == "DELETE" and "key=ip%3A10.0.0.77" in calls[-1][1] \
        and "ignore" not in calls[-1][1]


def test_watching_create_entry_is_prefilled_and_ignore_ignores(page, server):
    calls = _watching(page)
    card = page.locator("#watchSec .wcard").nth(0)
    card.locator("[data-wcreate]").click()
    expect(page.locator("#editModal")).to_be_visible()
    expect(page.locator("#f_name")).to_have_value("nas01")
    expect(page.locator("#f_mac")).to_have_value("00:11:32:00:00:01")
    expect(page.locator("#f_ip")).to_have_value("10.0.0.5")
    expect(page.locator("#f_notes")).to_have_value(
        "First seen 2026-09-30; Synology Incorporated; in the cupboard?.")
    expect(page.locator("#f_verified")).not_to_be_checked()
    page.keyboard.press("Escape")
    expect(page.locator("#editModal")).to_be_hidden()
    card.locator("[data-wignore]").click()
    expect(toast(page)).to_contain_text("Ignored")
    assert calls[-1][0] == "DELETE" and "ignore=true" in calls[-1][1]
    # an address-only device has nothing to port-scan only if it has no address
    expect(page.locator("#watchSec [data-wscan]")).to_have_count(2)


def test_watching_fits_a_phone(page, server):
    page.set_viewport_size({"width": 375, "height": 812})
    _watching(page, phone=True)
    expect(page.locator("#watchSec .wcard")).to_have_count(2)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    expect(page.locator("#watchSec .wnoteIn").first).to_be_visible()
    assert page.evaluate("""[...document.querySelectorAll('#watchSec .wcard *')]
        .every(el => el.getBoundingClientRect().right <= window.innerWidth + 0.5)""")


def test_a_new_device_finding_offers_watch(page):
    html = page.evaluate("""findingHtml({type: "new-device", key: "unifi:new:aa:bb:cc:dd:ee:ff",
        label: "x - new on the network at 10.0.0.9", detail: "",
        draft: {name: "x"}})""")
    assert 'data-fwatch="unifi:new:aa:bb:cc:dd:ee:ff"' in html
    assert "data-fwatch" not in page.evaluate(
        """findingHtml({type: "lease-unknown", key: "k", label: "l", detail: ""})""")


# ---- when a source is stale ----------------------------------------------------------------------
def test_a_source_is_stale_after_the_hours_set(page, server):
    six_h_ago = "new Date(Date.now() - 6 * 3600e3).toISOString()"
    st = lambda hours: page.evaluate(
        f"srcState({{ok: true, last_ok: {six_h_ago}}}, srcStaleMs({{stale_hours: {hours}}}))")
    assert st(5) == "stale" and st(12) == "good"
    assert page.evaluate(f"srcState({{ok: true, last_ok: {six_h_ago}}}, srcStaleMs({{}}))") == "stale"
    open_settings(page, "sources")
    expect(page.locator("#srcStaleH")).to_have_value("5")
    page.fill("#srcStaleH", "12")
    page.click("#scanSave")
    expect(toast(page)).to_contain_text("stale after 12 h")
    assert server.api("GET", "/api/discovery/summary")["stale_hours"] == 12


# ---- the banner and "not verified" -------------------------------------------------------------
def test_the_status_strip_is_one_row_of_numbers_when_clear(page, server):
    _overview_with(page, server, level="ok", attention=[],
                   counts={"entries": 9, "monitored": 4, "up": 3, "down": 1, "critical_down": 0,
                           "unverified": 0, "unmonitored": 2})
    strip = page.locator("#overview .verdict")
    expect(strip).to_have_class(re.compile(r"\bok\b"))
    expect(strip.locator(".vhead")).to_have_text("All clear - nothing needs you")
    facts = strip.locator(".vfact")
    expect(facts).to_have_count(4)
    expect(facts.nth(0)).to_have_text(re.compile(r"3/4\s*monitored up"))
    expect(facts.nth(0)).to_have_class(re.compile(r"\bwarn\b"))        # not at 100%
    assert facts.nth(0).get_attribute("title") == "3 of 4 monitored entries answering"
    expect(facts.nth(2)).to_have_text(re.compile(r"9\s*entries ·\s*2\s*unmonitored"))
    expect(facts.nth(3)).to_contain_text("sightings")
    page.set_viewport_size({"width": 375, "height": 812})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_not_verified_lists_the_entries_and_marks_them_verified(page, server):
    for name in ("DNS on 53", "Body scale"):
        server.api("POST", "/api/entries", {"name": name, "category": "Network", "verified": False})
    page.reload()
    row = page.locator("#overview .at", has_text="2 entries not verified")
    expect(row.locator(".lchip")).to_have_text(["Body scale", "DNS on 53"])
    row.locator("[data-verify]").click()
    page.click("#confirmOk")
    expect(toast(page)).to_contain_text("2 entries marked verified")
    expect(page.locator("#overview .at", has_text="not verified")).to_have_count(0)
    assert all(e["verified"] for e in server.api("GET", "/api/entries"))


def test_sources_show_as_marks_with_a_status_bar(page, server):
    """Each source is its product's mark with a bar under it in the status
    colour; the name is in the tooltip. A type with no mark, or a mark that
    fails to load, falls back to a drawn glyph. Fits a phone screen."""
    now = page.evaluate("new Date().toISOString()")
    old = page.evaluate("new Date(Date.now() - 10 * 3600 * 1000).toISOString()")
    real = server.api("GET", "/api/discovery/summary")
    health = [
        {"source": "docker", "label": "Docker", "type": "docker", "configured": True,
         "pending": False, "ok": True, "last_ok": now, "error": None},
        {"source": "proxmox", "label": "Proxmox VE", "type": "proxmox", "configured": True,
         "pending": False, "ok": True, "last_ok": old, "error": None},
        {"source": "ports", "label": "Open ports", "type": "ports", "configured": True,
         "pending": False, "ok": False, "last_ok": None, "error": "timed out"},
    ]
    summary = {**real, "health": health, "icons": {"docker": "docker", "proxmox": "proxmox"}}
    svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#08f"/></svg>'

    def scan(route):
        sid = route.request.url.split("/api/discovery/")[1].split("?")[0]
        body = {"source": sid, "label": sid, "configured": True, "findings": [], "counts": {},
                "error": "timed out" if sid == "ports" else None,
                "scanned_at": "2026-01-01T00:00:00Z", "host": {}}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))
    page.route("**/api/discovery/*", scan)
    page.route("**/api/discovery/summary", lambda r: r.fulfill(
        status=200, content_type="application/json", body=json.dumps(summary)))
    page.route("**/api/icon/docker.svg*", lambda r: r.fulfill(
        status=200, content_type="image/svg+xml", body=svg))
    page.route("**/api/icon/proxmox.svg*", lambda r: r.fulfill(status=404, body=""))
    page.click('#railnav [data-view="network"]')
    expect(page.locator("#reconHint")).not_to_contain_text("scanning")

    chips = page.locator("#network [data-srcchip]")
    assert chips.evaluate_all("els => els.map(e => e.dataset.srcchip)") == ["docker", "proxmox", "ports"]
    expect(page.locator("#network .srcline")).to_have_text("")              # marks, not names
    chip = lambda i: page.locator(f'#network [data-srcchip="{i}"]')         # noqa: E731
    expect(chip("docker")).to_have_attribute("title", re.compile(r"^Docker: last answered"))
    expect(chip("ports")).to_have_attribute("title", "Open ports: timed out")
    expect(chip("docker").locator("img.svc")).to_be_visible()
    expect(chip("docker").locator("svg.ico")).to_be_hidden()
    expect(chip("ports").locator("img")).to_have_count(0)
    expect(chip("ports").locator("svg.ico")).to_be_visible()
    expect(chip("proxmox").locator(".sm")).to_have_class(re.compile(r"\bnoicon\b"))   # 404: glyph
    expect(chip("proxmox").locator("svg.ico")).to_be_visible()

    bar = """([el, v]) => {
      const probe = document.createElement('b'); probe.style.color = `var(${v})`;
      document.body.append(probe); const want = getComputedStyle(probe).color; probe.remove();
      return getComputedStyle(el, '::after').backgroundColor === want; }"""
    for sid, var in (("docker", "--up"), ("proxmox", "--warn"), ("ports", "--down")):
        assert chip(sid).evaluate(f"el => ({bar})([el, '{var}'])"), sid

    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(100)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375


# ---- Customize overview / header ---------------------------------------------------------------
def _ov_cards(page):
    return page.locator("#overview [data-ovcard]").evaluate_all("els => els.map(e => e.dataset.ovcard)")


def test_overview_cards_can_be_hidden_reordered_and_reset(page, server):
    assert _ov_cards(page) == ["exposure", "hardware", "categories", "quicklinks", "changes", "addresses"]
    page.click("#ovCustomize")
    dlg = page.locator("#layoutModal")
    expect(dlg).to_be_visible()
    expect(dlg.locator("#lyStatus")).to_be_disabled()             # the status strip always shows
    dlg.get_by_label("Address space", exact=True).uncheck()
    expect(page.locator('#overview [data-ovcard="addresses"]')).to_have_count(0)
    for _ in range(3):
        dlg.get_by_role("button", name="Move Quick links up").click()
    expect(page.locator("#overview [data-ovcard]").first).to_have_attribute("data-ovcard", "quicklinks")
    # Focus stays on the control that moved, so the keyboard can keep going.
    expect(dlg.get_by_role("button", name="Move Quick links down")).to_be_focused()
    page.keyboard.press("Escape")
    expect(dlg).to_be_hidden()
    expect(page.locator("#ovCustomize")).to_be_focused()

    page.reload()                                                   # saved on the server
    page.wait_for_selector("#overview .verdict")
    assert _ov_cards(page) == ["quicklinks", "exposure", "hardware", "categories", "changes"]
    page.click("#ovCustomize")
    page.click("#layoutReset")
    expect(page.locator('#overview [data-ovcard="addresses"]')).to_have_count(1)
    assert _ov_cards(page) == ["exposure", "hardware", "categories", "quicklinks", "changes", "addresses"]


def test_every_card_hidden_leaves_the_status_and_the_way_back(page, server):
    server.api("PUT", "/api/settings/overview", {"cards": [
        {"id": i, "show": False} for i in ("exposure", "hardware", "quicklinks", "changes", "categories",
                                           "addresses")]})
    page.reload()
    page.wait_for_selector("#overview .verdict")
    expect(page.locator("#overview [data-ovcard]")).to_have_count(0)
    expect(page.locator("#overview .verdict")).to_be_visible()
    expect(page.locator("#ovCustomize")).to_be_visible()


def test_header_shows_freshness_and_drops_the_csv_button(page, server):
    real = server.api("GET", "/api/discovery/summary")
    scanned = page.evaluate("new Date(Date.now() - 5 * 60 * 1000).toISOString()")
    nxt = page.evaluate("new Date(Date.now() + 40 * 60 * 1000 + 20000).toISOString()")
    health = [{"source": "docker", "label": "Docker", "type": "docker", "configured": True,
               "pending": False, "ok": True, "last_ok": scanned, "error": None}]
    page.route("**/api/discovery/summary", lambda r: r.fulfill(
        status=200, content_type="application/json",
        body=json.dumps({**real, "health": health, "scanned_at": scanned, "next_scan": nxt})))
    page.reload()
    page.wait_for_selector("#overview .verdict")
    hm = page.evaluate(f"(() => {{ const d = new Date('{scanned}'); return String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0'); }})()")
    expect(page.locator("#freshness")).to_have_text(f"Scanned {hm} · next in 40 min")

    # No scheduled scan: only the "Scanned" part.
    page.evaluate("SRC_HEALTH.next_scan = null; paintFreshness()")
    expect(page.locator("#freshness")).to_have_text(f"Scanned {hm}")

    expect(page.locator('header a[href="/api/export.csv"]')).to_have_count(0)
    expect(page.locator('#refreshBtn')).to_have_attribute("aria-label", "Rescan all sources")
    expect(page.get_by_label("Search the inventory")).to_have_attribute(
        "placeholder", re.compile(r"^Search name, IP, port, tag….*(Ctrl\+K|⌘K)$"))
    # The page name is still there for screen readers, just not on screen.
    expect(page.locator("#ptName")).to_have_text("Overview")
    box = page.locator(".pagetitle").bounding_box()
    assert box["width"] <= 1 and box["height"] <= 1

    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(100)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375
    page.click("#ovCustomize")
    page.wait_for_timeout(100)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375


# ---- status strip, degraded ----------------------------------------------------------------------
def test_status_strip_ranks_and_acts_on_what_needs_you(page, server):
    """Rows keep the server's order (a dead source first), each with a rank,
    a type pill, an action and Snooze; snoozed ones sit behind a link."""
    e = server.api("POST", "/api/entries", {"name": "Wiki"})["id"]
    items = [
        {"key": "source:npm", "type": "source", "level": "critical", "order": 0,
         "title": "NPM is not answering", "detail": "login refused"},
        {"key": "open:wiki.example.org", "type": "exposure", "level": "warn", "order": 3,
         "accept": "cloudflare:access:wiki.example.org", "entry_id": e,
         "title": "wiki.example.org has no Access application"},
        {"key": "findings", "type": "mismatch", "level": "warn", "order": 4, "goto": "network",
         "title": "3 mismatches between NetMap and the systems it reads"},
    ]
    hidden = [{"key": "conflicts", "type": "conflict", "level": "note",
               "title": "1 conflict in the inventory", "dismissed_at": "2026-10-01T10:00:00"}]
    _overview_with(page, server, level="critical", attention=items, dismissed=hidden)
    strip = page.locator("#overview .verdict")
    expect(strip).to_have_class(re.compile(r"\bcritical\b"))
    expect(strip.locator(".vhead")).to_have_text("3 things need you")
    rows = strip.locator(".attn > .at")
    expect(rows.locator(".atpill")).to_have_text(["source", "exposure", "mismatch"])
    expect(rows.nth(0).get_by_role("button", name="Retry scan")).to_be_visible()
    expect(rows.nth(1).get_by_role("button", name="Accept")).to_be_visible()
    expect(rows.nth(2).get_by_role("button", name="Review")).to_be_visible()
    expect(rows.get_by_role("button", name="Snooze")).to_have_count(3)

    # Retry scan asks that one source again.
    page.route("**/api/discovery/npm*", lambda r: r.fulfill(
        status=200, content_type="application/json",
        body='{"source":"npm","findings":[],"error":null}'))
    with page.expect_request("**/api/discovery/npm*"):
        rows.nth(0).get_by_role("button", name="Retry scan").click()

    # Accept ignores the edge finding, after a confirmation.
    rows.nth(1).get_by_role("button", name="Accept").click()
    expect(page.locator("#confirmTitle")).to_have_text("Accept wiki.example.org as open on purpose?")
    page.click("#confirmOk")
    expect(toast(page)).to_contain_text("wiki.example.org accepted as open on purpose")
    assert "cloudflare:access:wiki.example.org" in server.api("GET", "/api/discovery/ignores")

    # Snoozed items: a count, then the list, each one can come back.
    link = strip.get_by_role("button", name="1 snoozed")
    expect(link).to_have_attribute("aria-expanded", "false")
    link.click()
    expect(strip.locator(".attn.dis .at")).to_have_text(re.compile("1 conflict in the inventory"))
    expect(strip.get_by_role("button", name="Bring back")).to_be_visible()

    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(100)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375


def test_only_for_later_items_tint_the_strip_neutral(page, server):
    later = [{"key": "unverified", "type": "verify", "level": "note", "order": 7,
              "title": "2 entries not verified"}]
    _overview_with(page, server, level="note", attention=later)
    expect(page.locator("#overview .verdict")).to_have_class(re.compile(r"\bnote\b"))
    expect(page.locator("#overview .vhead")).to_have_text("1 thing needs you")


# ---- hardware & categories ---------------------------------------------------------------------
def test_hardware_card_shows_dependents_coverage_and_risks(page, server):
    box = server.api("POST", "/api/entries", {"name": "Box", "kind": "hardware", "ip": "10.0.0.2"})["id"]
    hw = {"hosts": [{"id": box, "name": "Box", "ip": "10.0.0.2", "up": True, "dependents": 12,
                     "checkable": 10, "monitored": 2,
                     "notes": [{"text": "OPNsense and Pi-hole share this host", "risk": True},
                               {"text": "1 critical entry depends on it", "risk": False}]}],
          "gear": {"total": 3, "monitored": 2, "up": 2,
                   "items": [{"id": box, "name": "Switch", "ip": "", "monitor": True, "up": True}]}}
    page.route("**/api/overview/hardware", lambda r: r.fulfill(
        status=200, content_type="application/json", body=json.dumps(hw)))
    page.reload()
    card = page.locator('#overview [data-ovcard="hardware"]')
    tile = card.locator("button.hwcard").first
    expect(tile).to_contain_text("12")
    expect(tile).to_contain_text("entries depend on it")
    expect(tile.locator(".hwcov small")).to_have_text("2 of 10 monitored")
    expect(tile.locator(".hwcov small")).to_have_class(re.compile(r"\bwarnc\b"))
    expect(tile.locator(".hwnote.warnc")).to_have_text("OPNsense and Pi-hole share this host")
    expect(tile.locator(".dot")).to_have_attribute("title", "up")
    gear = card.locator(".hwgear")
    expect(gear).to_contain_text("2/2")
    expect(gear).to_contain_text("1 of 3 not monitored")
    tile.click()
    expect(page.locator("#cardModal")).to_be_visible()
    page.keyboard.press("Escape")
    page.set_viewport_size({"width": 375, "height": 812})
    page.wait_for_timeout(100)
    assert page.evaluate("document.documentElement.scrollWidth") <= 375


def test_hardware_card_says_when_it_cannot_load(page, server):
    page.route("**/api/overview/hardware", lambda r: r.fulfill(status=500, body="no"))
    page.reload()
    expect(page.locator("#ovHw")).to_contain_text("could not load")


def test_categories_show_the_monitored_share(page, server):
    for name, mon in (("A", True), ("B", False), ("C", True)):
        server.api("POST", "/api/entries", {"name": name, "category": "Media", "monitor": mon})
    server.api("POST", "/api/entries", {"name": "D", "category": "Tools", "monitor": False})
    page.reload()
    rows = page.locator('#overview [data-ovcard="categories"] .catrow')
    expect(rows.locator(".cc")).to_have_text(["2/3", "0/1"])
    expect(rows.first).to_have_attribute("title", "Show only Media: 2 of 3 monitored")
    expect(page.locator('#overview [data-ovcard="categories"] .ovhead')).to_contain_text("solid = monitored")
    rows.first.click()
    expect(page.locator("#list")).to_be_visible()
