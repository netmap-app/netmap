/* NetMap front end - boot.js: wiring that spans views, keyboard access, and start-up - last.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

$("#iconWarm").onclick = async (ev) => {
  const b = ev.currentTarget, out = $("#iconWarmOut");
  b.disabled = true; out.textContent = "Fetching…";
  try {
    const r = await api("/api/icons/warm", { method: "POST" });
    out.textContent = `${r.cached} of ${r.wanted} marks cached` + (r.missing.length
      ? ` - no mark published for: ${r.missing.join(", ")}` : ".");
    ICONS = {}; await load();
  } catch { out.textContent = "Could not reach the icon source."; }
  b.disabled = false;
};
const openSettings = () => { view = "settings"; applyView(); };
$("#setBtn").onclick = openSettings;
$("#railSet").onclick = openSettings;
$("#themeSeg").addEventListener("click", ev => {
  const b = ev.target.closest("[data-theme-set]"); if (!b) return;
  applyTheme(b.dataset.themeSet);
});

$("#addBtn").onclick = () => openEdit(null);
$("#cancelBtn").onclick = closeEdit;
$("#saveBtn").onclick = save;
$("#delBtn").onclick = del;
$("#histBtn").onclick = () => { view = "changes"; applyView(); };
$("#histClose").onclick = () => ($("#histModal").hidden = true);
/* One button, both kinds of "go and look". The reachability sweep is local
   and quick; a discovery scan reaches four external systems and is slower, so
   the sweep lands first and the sources follow - the page updates twice
   rather than making you wait for the slowest thing to say anything. */
async function recheckAll() {
  const btn = $("#refreshBtn");
  if (btn) btn.classList.add("spin");
  try {
    // Both at once: the sources' names go gray the moment the button is
    // pressed and resolve one by one, instead of waiting out the reachability
    // sweep first with nothing on screen changing.
    toast("Re-checking reachability and every source…");
    const scans = scanAll(true);
    await api("/api/status/refresh", { method: "POST" }).catch(() => {});
    await load();
    await scans;
    await load();
    if (view === "network") renderNetwork();
    const n = FINDINGS.total;
    toast(n ? `${n} finding${n === 1 ? "" : "s"}` : "Everything agrees");
  } finally {
    if (btn) btn.classList.remove("spin");
  }
}
$("#refreshBtn").onclick = recheckAll;
$("#refreshBtn").setAttribute("aria-label", "Rescan all sources");
// The shortcut in the placeholder is the one this keyboard has.
$("#search").placeholder = "Search name, IP, port, tag…   "
  + (/Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent) ? "⌘K" : "Ctrl+K");

for (const m of ["editModal", "histModal", "palModal", "cardModal", "portModal", "changelogModal", "layoutModal"])
  $("#" + m).addEventListener("click", ev => {
    if (ev.target.id !== m) return;
    if (m === "cardModal") closeCard(); else $("#" + m).hidden = true;
  });
// iOS Safari lets a drag that starts on the backdrop scroll the page behind
// a fixed-position modal instead of the modal's own content, which is what
// "scrolling is stuck" turns out to be - the touch went to the wrong
// element. Locking body scroll for as long as any modal is open removes the
// element it could go to instead.
new MutationObserver(() => {
  const open = [...document.querySelectorAll(".modal")].some(m => !m.hidden);
  document.body.classList.toggle("modalopen", open);
}).observe(document.body, { attributes: true, attributeFilter: ["hidden"], subtree: true });
/* A dialog that closes gives focus back to whatever opened it - without this
   a keyboard or screen-reader user is dropped at the top of the page. Each
   dialog remembers the element that had focus when it opened. */
const MODAL_OPENER = new Map();
// The two most recent focus targets: a dialog that moves focus into itself
// while opening has already taken it by the time the observer runs.
let FOCUS_NOW = null, FOCUS_BEFORE = null;
document.addEventListener("focusin", ev => { FOCUS_BEFORE = FOCUS_NOW; FOCUS_NOW = ev.target; });
new MutationObserver(muts => {
  for (const m of muts) {
    const el = m.target;
    if (!el.classList || !el.classList.contains("modal") || el.id === "confirmModal") continue;
    if (!el.hidden) {
      let a = document.activeElement;
      if (a && el.contains(a)) a = FOCUS_BEFORE;
      if (a && a !== document.body && !el.contains(a)) MODAL_OPENER.set(el.id, a);
    } else {
      let back = MODAL_OPENER.get(el.id);
      MODAL_OPENER.delete(el.id);
      // The opener may have been re-rendered while the dialog was open (the
      // Overview redraws as its layout changes); its replacement has its id.
      if (back && !document.contains(back) && back.id) back = document.getElementById(back.id);
      const lost = !document.activeElement || document.activeElement === document.body
        || el.contains(document.activeElement);
      if (back && document.contains(back) && lost) back.focus({ preventScroll: true });
    }
  }
}).observe(document.body, { attributes: true, attributeFilter: ["hidden"], subtree: true });
document.addEventListener("keydown", ev => {
  if ((ev.metaKey || ev.ctrlKey) && (ev.key === "k" || ev.key === "K")) {
    ev.preventDefault();
    $("#palModal").hidden ? palOpen() : palClose();
    return;
  }
  if (ev.key === "Escape") {
    palClose(); closeEdit(); $("#histModal").hidden = true;
    closeCard();
    $("#portModal").hidden = true; $("#changelogModal").hidden = true;
    $("#layoutModal").hidden = true;
  }
  if (ev.key === "/" && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) {
    ev.preventDefault(); $("#search").focus();
  }
  if ((ev.metaKey || ev.ctrlKey) && ev.key === "Enter" && !$("#editModal").hidden) save();
});

/* ---- Network: jump to a section ------------------------------------------------
   Five sections stacked into ~3,400px. The bar lists whichever ones the view
   rendered - rebuilt from its headings each time it re-renders - and scrolls
   to them. It sits just under the header and stays there. */
function buildNetJump() {
  const heads = [...document.querySelectorAll("#network .ovsec > .ovhead > h2")];
  $("#netJump").innerHTML = heads.map((h, i) => {
    const sec = h.closest(".ovsec");
    sec.id = sec.id || "netsec-" + i;
    return `<button type="button" data-jump="${sec.id}">${esc(h.textContent.trim())}</button>`;
  }).join("");
}
new MutationObserver(buildNetJump).observe($("#network"), { childList: true });
$("#netJump").addEventListener("click", ev => {
  const b = ev.target.closest("[data-jump]"); if (!b) return;
  const target = document.getElementById(b.dataset.jump);
  const offset = $("header").getBoundingClientRect().bottom + $("#netJump").offsetHeight + 8;
  window.scrollTo({ top: target.getBoundingClientRect().top + scrollY - offset,
                    behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
});

/* ---- phone header: out of the way while reading --------------------------------
   On a narrow screen the sticky header (tabs, search, five buttons, the filter
   strip) covered a quarter to a third of the screen. It now slides away while
   scrolling down and returns on the first scroll up, or at the top. It stays
   while the search box has focus or the filter panel is open. */
(() => {
  let lastY = scrollY;
  const narrow = matchMedia("(max-width: 979px)");
  addEventListener("scroll", () => {
    const y = scrollY, h = $("header");
    const busy = document.activeElement === $("#search") || !$("#filterPop").hidden;
    if (!narrow.matches || busy || y < h.offsetHeight) h.classList.remove("hidehdr");
    else if (y > lastY + 6) h.classList.add("hidehdr");
    else if (y < lastY - 6) h.classList.remove("hidehdr");
    lastY = y;
  }, { passive: true });
  // Keep the jump bar right under the header, whatever height it has now.
  new ResizeObserver(() => document.documentElement.style.setProperty(
    "--hdrh", $("header").offsetHeight + "px")).observe($("header"));
})();

/* ---- keyboard access ---------------------------------------------------------
   Much of the interface is clickable elements that are not buttons - filter
   chips, table rows and cards, tree nodes, tags, "more" links - handled by
   delegated click listeners. A mouse reaches them; a keyboard could not. Rather
   than rewrite every template, this makes each one focusable, announces it as a
   button where that is what it is, and lets Enter and Space activate it. It runs
   on whatever the page renders, so newly drawn rows are covered too.
   Table rows keep their row role (a row that opens is still a row). */
const KBD_CLICK = [
  "[data-card]:not(a):not(button)", "tr[data-id]", ".card[data-id]", ".chip",
  "[data-tag]", "[data-cat]", "[data-group]:not(button)", "[data-goto]:not(a):not(button)",
  "[data-port]:not(button)", "[data-unlink]:not(button)", "[data-rescan]:not(button)",
  "[data-fopen]:not(button)", "[data-fignoreall]:not(button)",
  ".tn", "#ovHist", "span.more", "[data-theme-set]:not(button)",
].join(",");
function kbdify(root) {
  root.querySelectorAll?.(KBD_CLICK).forEach(el => {
    if (el.hasAttribute("tabindex")) return;
    el.tabIndex = 0;
    // A row or card that holds its own links and buttons stays focusable and
    // Enter-able, but is not announced as a button: a button may not contain
    // other controls.
    if (el.tagName !== "TR" && !el.getAttribute("role")
        && !el.querySelector("a[href], button, input, select, textarea"))
      el.setAttribute("role", "button");
  });
}
new MutationObserver(muts => {
  for (const m of muts) for (const n of m.addedNodes) if (n.nodeType === 1) {
    if (n.matches(KBD_CLICK)) kbdify(n.parentNode || n); else kbdify(n);
    tipify(n);
  }
}).observe(document.body, { childList: true, subtree: true });
kbdify(document);
tipify(document);
/* While a dialog is open, Tab and Shift+Tab cycle through its controls
   instead of escaping to the page underneath. */
document.addEventListener("keydown", ev => {
  if (ev.key !== "Tab") return;
  const open = [...document.querySelectorAll(".modal:not([hidden])")].pop();
  if (!open) return;
  const f = [...open.querySelectorAll('a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])')]
    .filter(e => e.offsetParent && !e.disabled);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (!open.contains(document.activeElement)) { ev.preventDefault(); first.focus(); }
  else if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
  else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
});

document.addEventListener("keydown", ev => {
  if (ev.key !== "Enter" && ev.key !== " ") return;
  const el = ev.target;
  if (!(el instanceof HTMLElement) || !el.matches(KBD_CLICK)) return;
  if (/^(INPUT|TEXTAREA|SELECT|BUTTON|A)$/.test(el.tagName)) return;
  ev.preventDefault();            // Space would scroll the page
  el.click();
});

/* The first load failing (the server restarting, a proxy error) used to
   leave a blank page and a toast gone in two seconds. Say so where the
   content would be, with a way to try again. */
function loadFailed() {
  if (ENTRIES.length) return;                     // an earlier load's data is still on screen
  const msg = `<div class="loadfail" role="alert"><b>NetMap could not load its data.</b>
    <span class="hint">The server did not answer as expected - it may be restarting.</span>
    <button class="btn" data-retry-load>Try again</button></div>`;
  for (const id of ["#overview", "#listbody", "#network", "#changes"]) $(id).innerHTML = msg;
}
document.addEventListener("click", ev => {
  if (!ev.target.closest("[data-retry-load]")) return;
  for (const id of ["#overview", "#listbody", "#network", "#changes"]) $(id).innerHTML = "";
  load().then(routeFromHash).catch(loadFailed);
});
load().then(routeFromHash).catch(loadFailed);
// After signing in with the starting password, /login lands on #settings.
// Here in boot.js rather than beside loadProfile() in profile.js: applyView()
// reads `shownView`, which card.js declares, and at boot this must run last.
if (location.hash === "#settings") {
  history.replaceState(null, "", location.pathname);
  view = "settings"; applySetTab("profile"); applyView();
}
api("/api/profile").then(showPwBanner).catch(() => {});
// A tab keeps running the code it loaded. After a deploy that is the previous
// version, and a change looks like it did nothing - so compare with what the
// server runs now and offer the reload. /healthz is open and costs nothing;
// while a deploy restarts the server it simply does not answer.
const PAGE_VERSION = (document.querySelector('meta[name="netmap-version"]') || {}).content || "";
async function checkVersion() {
  try {
    const r = await fetch("/healthz", { cache: "no-store" });
    const v = (await r.json()).version;
    if (v && PAGE_VERSION && v !== PAGE_VERSION) {
      const b = $("#updBanner");
      b.textContent = `NetMap was updated to ${v} - reload to use it.`;
      b.hidden = false;
    }
  } catch { /* server restarting, or offline: ask again next time */ }
}
$("#updBanner").onclick = () => location.reload();

/* Every 15 s: is what the page shows still fresh? A tab that slept - or a
   server that stopped answering - is greyed and says so; it also asks for
   fresh data at once rather than waiting out the minute. With a dialog open
   it waits: the page under it is not being read, and reloading it would
   change what the dialog was opened from. */
let REFRESHING = false, LAST_TRY = 0;
function freshnessTick() {
  if (document.hidden) return;
  repaintSrcChips();
  const anyOpen = [...document.querySelectorAll(".modal")].some(m => !m.hidden);
  // A server that is down is asked once a minute, not every tick - each
  // failed try is a toast.
  if (anyOpen || !pageFreshness() || REFRESHING || Date.now() - LAST_TRY < 60000) return;
  REFRESHING = true; LAST_TRY = Date.now();
  load({ quiet: true }).catch(() => {}).finally(() => { REFRESHING = false; });
}
setInterval(freshnessTick, 15000);
$("#staleBanner").onclick = () => {
  REFRESHING = true;
  load().catch(() => toast("NetMap is not answering yet")).finally(() => { REFRESHING = false; });
};
setInterval(() => {
  if (document.hidden) return;                    // no point polling a background tab
  checkVersion();
  if ($("#editModal").hidden && $("#histModal").hidden &&
      $("#palModal").hidden && $("#cardModal").hidden &&
      $("#portModal").hidden && $("#changelogModal").hidden &&
      $("#layoutModal").hidden) load({ quiet: true }).catch(() => {});
}, 60000);
// Coming back to the tab is the moment stale data is most likely and most
// noticed, so refresh then rather than waiting out the interval.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) { freshnessTick(); load({ quiet: true }).catch(() => {}); checkVersion(); }
});
