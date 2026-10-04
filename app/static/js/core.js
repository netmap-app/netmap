/* NetMap front end - core.js: shared state and helpers: $, esc, api(), toast, formatting, theme.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ICON = {
  edit: '<svg viewBox="0 0 24 24" width="15" height="15" class="ico"><path d="M4 20h4l10-10-4-4L4 16v4z"/><path d="M13.5 6.5l4 4"/></svg>',
  recheck: '<svg viewBox="0 0 24 24" width="15" height="15" class="ico"><path d="M20 11a8 8 0 1 0-2.3 5.6"/><path d="M20 5v6h-6"/></svg>',
  ext: '<svg viewBox="0 0 24 24" width="15" height="15" class="ico"><path d="M14 5h5v5"/><path d="M19 5l-8 8"/><path d="M18 14v5H5V6h5"/></svg>',
  pin: '<svg viewBox="0 0 24 24" width="15" height="15" class="ico"><path d="M12 3l2.4 5.2 5.6.7-4.1 3.9 1.1 5.6L12 15.8 6.9 18.4 8 12.8 4 8.9l5.6-.7z"/></svg>',
};

/* Category glyphs. Drawn here rather than fetched: NetMap is one container
   with no outbound dependency, and a dashboard that goes grey when a CDN is
   unreachable is worse than one with plainer marks. Same 24-grid stroke style
   as the rest of the chrome, so they sit with the toolbar icons.
   The key is the category's own name - an unknown category gets the dot. */
const CAT = {
  "Core Network":              ["core",  '<path d="M4 13h16v6H4z"/><path d="M8 16h.01M11 16h.01"/><path d="M12 10V6"/><path d="M8.5 7.5L12 4l3.5 3.5"/>'],
  "Infrastructure & Management":["infra", '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><path d="M7.5 7.5h.01M7.5 17h.01"/>'],
  "Media":                     ["media", '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M10 9.5l5 2.5-5 2.5z"/>'],
  "Smart Home":                ["smart", '<path d="M4 11l8-6 8 6"/><path d="M6 10v9h12v-9"/><path d="M10 19v-5h4v5"/>'],
  "Hosts & VMs":               ["hosts", '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>'],
  "Client / IoT Devices":      ["client",'<rect x="3" y="5" width="13" height="9" rx="1.5"/><path d="M2 18h13"/><rect x="17" y="10" width="5" height="9" rx="1.5"/>'],
  "Remote Access":             ["remote",'<circle cx="12" cy="12" r="8"/><path d="M4 12h16"/><path d="M12 4c2.5 2.6 2.5 12.4 0 16-2.5-3.6-2.5-13.4 0-16z"/>'],
  "Storage / NAS":             ["store", '<ellipse cx="12" cy="6.5" rx="7.5" ry="3"/><path d="M4.5 6.5v11c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-11"/><path d="M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3"/>'],
  "Tools & Utilities":         ["tools", '<path d="M15 3a5 5 0 0 0-4.6 7L3 17.4 6.6 21l7.4-7.4A5 5 0 1 0 15 3z"/>'],
};
const catKey = (c) => (CAT[c] || ["misc"])[0];
/* Which entries have a real mark, by id. Asked for once: without it the
   inventory would fire seventy requests for marks that do not exist, and a
   404 per row is a worse cost than one small map. */
let ICONS = {};
/* Single-colour brand marks are painted in the interface's ink, so the server
   has to know which one - an <img> cannot inherit `currentColor`. Some marks
   also ship a variant drawn for dark backgrounds. Both need the theme, and it
   goes in the URL so the browser caches one file per theme rather than
   serving the wrong one from cache after a switch. */
const inkNow = () => {
  const t = document.documentElement.getAttribute("data-theme");
  if (t) return t;
  return matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
};
const iconSrc = (e) => (ICONS[e.id] ? `/api/entries/${e.id}/icon.svg?t=${inkNow()}` : "");
/* The mark and the glyph occupy the same square, never both: the glyph is
   hidden while an <img> is present and comes back if that image fails, which
   is how a wrong guess or a missing network turns back into a drawn icon
   without any code noticing. */
const svcImg = (e) => {
  const src = iconSrc(e);
  return src ? `<img class="svc" src="${esc(src)}" alt="">` : "";
};
// A mark that fails to load falls back to its category glyph. One listener
// rather than an onerror="" per <img>: the Content-Security-Policy allows no
// inline script, and an inline event handler is inline script. `error` does
// not bubble, so this listens in the capture phase.
document.addEventListener("error", ev => {
  const img = ev.target;
  if (img instanceof HTMLImageElement && img.classList.contains("svc")) {
    const box = img.closest(".cg, .sm");
    if (box) box.classList.add("noicon");
  }
}, true);
const catBody = (c) => (CAT[c] || ["misc", '<circle cx="12" cy="12" r="6"/>'])[1];
const catGlyph = (c) => `<span class="cg ${catKey(c)}"><svg viewBox="0 0 24 24" class="ico">${
  catBody(c)}</svg></span>`;
/* An entry's mark: the product's own if there is one, its category's glyph
   otherwise. */
const entGlyph = (e) => {
  const img = svcImg(e);
  return `<span class="cg ${catKey(e.category)}${img ? " svcbox" : ""}"><svg viewBox="0 0 24 24" class="ico">${
    catBody(e.category)}</svg>${img}</span>`;
};

let ENTRIES = [], META = { categories: [], tags: [] };
let ALL = [];                       // the whole inventory, ignoring filters
let CONFLICTS = { count: 0, conflicts: [] };
let FINDINGS = { total: 0, findings: [] };   // from the cached scan, never live
let filter = { q: "", category: "", tag: "", kind: "", criticality: "", zone: "" };
let editingId = null;
/* Inventory grouping: category is what a thing does, host is where it runs,
   kind is what it is. Same rows, three ways of looking at them. */
const GROUPS = { category: "Uncategorised", host: "No host set", kind: "No kind set" };
let groupBy = GROUPS[localStorage.getItem("netmap.groupby")] ? localStorage.getItem("netmap.groupby") : "category";
const VIEWS = ["overview", "inventory", "network", "changes", "settings"];
// Always Overview on load - it is the one page that answers "is anything
// wrong", which is the only question worth asking before you've looked at
// anything else. Remembering the last tab meant a Network visit yesterday
// silently became tomorrow's startup page.
let view = "overview";

/* ---- confirm: the app's own dialog -------------------------------------------
   For anything that deletes or cannot be undone. The browser's confirm() box
   looked like another program and could not say which button was the
   dangerous one. Resolves true or false. Cancel has focus, so Enter on a
   reflex does not delete anything; Esc and a click outside also cancel, and
   focus goes back to whatever asked. */
function confirmDialog({ title, body = "", ok = "Delete", danger = true }) {
  return new Promise(resolve => {
    const m = $("#confirmModal"), yes = $("#confirmOk"), no = $("#confirmCancel");
    $("#confirmTitle").textContent = title;
    $("#confirmBody").textContent = body;
    yes.textContent = ok;
    yes.className = "btn " + (danger ? "danger" : "primary");
    const back = document.activeElement;
    const done = answer => {
      m.hidden = true;
      m.onkeydown = m.onclick = yes.onclick = no.onclick = null;
      if (back && document.contains(back)) back.focus();
      resolve(answer);
    };
    yes.onclick = () => done(true);
    no.onclick = () => done(false);
    m.onclick = ev => { if (ev.target === m) done(false); };
    // Esc answers this dialog only - not the global handler, which would
    // also close the dialog underneath that asked the question.
    m.onkeydown = ev => { if (ev.key === "Escape") { ev.stopPropagation(); done(false); } };
    m.hidden = false;
    no.focus();
  });
}

/* ---- "i" tooltips ------------------------------------------------------------
   An explanation of how something works sits behind an "i" next to what it
   explains, instead of as a line of text on the page. What the page *reports*
   (a count, a state, an error) stays visible. Markup: any element carrying
   `data-tip` is the explanation; tipify() - run on everything the page draws,
   by boot.js - puts the "i" button before it and hides it. The button shows
   it on mouse hover and on keyboard focus, and a tap or click pins it open
   until a tap elsewhere or Esc. A screen reader gets it as the button's
   description. */
let TIP_N = 0;
const TIP_ICON = '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true">'
  + '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/>'
  + '<path d="M12 11v6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>'
  + '<circle cx="12" cy="7.6" r="1.2" fill="currentColor"/></svg>';

function tipify(root) {
  if (!root || !root.querySelectorAll) return;
  const boxes = [...root.querySelectorAll("[data-tip]:not([data-tipped])")];
  if (root.matches && root.matches("[data-tip]:not([data-tipped])")) boxes.unshift(root);
  for (const box of boxes) {
    box.setAttribute("data-tipped", "");
    if (!box.id) box.id = "tip" + (++TIP_N);
    box.classList.add("tipbox");
    box.setAttribute("role", "tooltip");
    box.hidden = true;
    const b = document.createElement("button");
    b.type = "button";
    b.className = "itip";
    b.setAttribute("aria-label", box.dataset.tip || "More about this");
    b.setAttribute("aria-describedby", box.id);
    b.setAttribute("aria-expanded", "false");
    b.innerHTML = TIP_ICON;
    const w = document.createElement("span");
    w.className = "tipwrap";
    box.replaceWith(w);
    w.append(b, box);
  }
}

function tipShow(w, pinned) {
  const b = w.querySelector(".itip"), box = w.querySelector(".tipbox");
  if (!b || !box) return;
  document.querySelectorAll(".tipwrap.open").forEach(o => { if (o !== w) tipHide(o, true); });
  w.classList.add("open");
  if (pinned) w.classList.add("pinned");
  b.setAttribute("aria-expanded", "true");
  box.hidden = false;
  // Fixed, so no scrolling container or card edge can cut it off; kept
  // inside the window, below the icon unless there is no room there.
  const r = b.getBoundingClientRect();
  box.style.maxWidth = Math.min(340, innerWidth - 16) + "px";
  const bw = box.offsetWidth, bh = box.offsetHeight;
  box.style.left = Math.max(8, Math.min(r.left - 10, innerWidth - bw - 8)) + "px";
  box.style.top = (r.bottom + 6 + bh > innerHeight && r.top - 6 - bh > 0
    ? r.top - 6 - bh : r.bottom + 6) + "px";
}

function tipHide(w, force) {
  if (!force && w.classList.contains("pinned")) return;
  w.classList.remove("open", "pinned");
  const b = w.querySelector(".itip"), box = w.querySelector(".tipbox");
  if (b) b.setAttribute("aria-expanded", "false");
  if (box) box.hidden = true;
}

const tipHideAll = () => document.querySelectorAll(".tipwrap.open").forEach(w => tipHide(w, true));
document.addEventListener("pointerover", ev => {
  if (ev.pointerType !== "mouse") return;
  const w = ev.target.closest && ev.target.closest(".tipwrap");
  if (w && !w.classList.contains("open")) tipShow(w, false);
});
document.addEventListener("pointerout", ev => {
  if (ev.pointerType !== "mouse") return;
  const w = ev.target.closest && ev.target.closest(".tipwrap");
  if (w && !(ev.relatedTarget && w.contains(ev.relatedTarget))) tipHide(w, false);
});
document.addEventListener("focusin", ev => {
  if (ev.target.classList && ev.target.classList.contains("itip")) tipShow(ev.target.parentNode, false);
});
document.addEventListener("focusout", ev => {
  if (ev.target.classList && ev.target.classList.contains("itip")) tipHide(ev.target.parentNode, false);
});
document.addEventListener("click", ev => {
  const b = ev.target.closest && ev.target.closest(".itip");
  if (b) {
    ev.preventDefault(); ev.stopPropagation();
    const w = b.parentNode;
    if (w.classList.contains("pinned")) tipHide(w, true); else tipShow(w, true);
    return;
  }
  if (!(ev.target.closest && ev.target.closest(".tipbox"))) tipHideAll();
}, true);
// Esc closes an open explanation first - not the dialog it sits in.
document.addEventListener("keydown", ev => {
  if (ev.key === "Escape" && document.querySelector(".tipwrap.open")) {
    tipHideAll(); ev.stopPropagation();
  }
}, true);
addEventListener("scroll", tipHideAll, { passive: true, capture: true });
addEventListener("resize", tipHideAll);

/* ---- how old is what this tab shows ------------------------------------------
   A laptop that slept, or a server that stopped answering, leaves the page
   showing what was true when it last loaded - with every colour still green.
   LAST_REFRESH is when data last arrived; past STALE_PAGE_MS the status
   colours go grey and a line says since when, until a refresh succeeds. */
let LAST_REFRESH = Date.now();
const STALE_PAGE_MS = 2 * 60 * 1000;

function pageFreshness() {
  const old = Date.now() - LAST_REFRESH > STALE_PAGE_MS;
  document.body.classList.toggle("pagestale", old);
  const b = document.getElementById("staleBanner");
  if (!b) return old;
  b.hidden = !old;
  if (old) {
    const d = new Date(LAST_REFRESH);
    const today = d.toDateString() === new Date().toDateString();
    const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
    b.textContent = `Not refreshed since ${today ? t : d.toLocaleDateString() + " " + t} - `
      + "what this page shows may be out of date. Refresh now";
  }
  return old;
}
