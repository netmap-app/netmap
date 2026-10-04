/* NetMap front end - overview.js: the Overview: verdict, the attention queue, exposure, tiles.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

/* ================= overview ================= */
// The control room. What this page owes the reader is one sentence - is
// anything wrong - and then the queue, worst first. The counts that used to
// lead it (entries tracked, a bar chart of categories) answered "how much is
// there", which never changes and never asks anything of you; they live on
// Inventory now, where you go when you actually want to look something up.
//
// The server decides the verdict and the ranking (app/overview.py), so that
// this page and the MCP client cannot disagree about whether the house is on
// fire.
let OV = null;
let OVSHOW = false;                     // is the "set aside" list expanded

/* The status strip. One row when nothing needs you; otherwise a ranked list
   of what does, in the order the server ranked it (app/overview.py, the same
   ranking MCP answers with) - never re-sorted here. A dead source ranks above
   what it would have reported, because the server says so. Colour is never
   the only signal: every stat is a number and every row names its type. */
const svgi = (paths, cls) => `<svg viewBox="0 0 24 24" class="ico ${cls}" aria-hidden="true">${paths}</svg>`;
const LEVEL_WORD = { critical: "critical", warn: "to look at", note: "for later" };

// One stat: the number first, then what it counts. `tone` is "warn" when it
// is not at 100% - the number already says so, the colour only repeats it.
const stat = (value, label, tone = "", tip = "") => `
  <span class="vfact ${tone}" title="${esc(tip || label)}">
    <b class="num mono">${value}</b><small>${label}</small></span>`;

function statsHtml(c) {
  const s = OV.sources;
  const unmon = c.unmonitored || 0;
  return `<div class="vfacts">
    ${stat(`${c.up}/${c.monitored}`, "monitored up", c.up < c.monitored ? "warn" : "",
           `${c.up} of ${c.monitored} monitored entries answering`)}
    ${s.total ? stat(`${s.ok}/${s.total}`, "sources fresh", s.ok < s.total ? "warn" : "",
                     `${s.ok} of ${s.total} sources reporting`)
              : `<span class="vfact" title="No discovery source is added"><small>no sources added</small></span>`}
    <span class="vfact" title="${esc(`${c.entries} entries; ${unmon} that could have a health check have none`)}">
      <b class="num mono">${c.entries}</b><small>entries${unmon ? " ·" : ""}</small>${
      unmon ? `<b class="num mono warnc">${unmon}</b><small class="warnc">unmonitored</small>` : ""}</span>
    ${stat(OV.sightings.rows, "sightings", "", `${OV.sightings.rows} observations from the sources`)}
  </div>`;
}

/* How long, in one token. A queue row has room for "9m" and not for
   "9 minutes ago", and at a glance the unit is the part that matters. */
function ago(ts) {
  if (!ts) return "";
  const t = new Date(String(ts).endsWith("Z") ? ts : ts + "Z");
  if (isNaN(t)) return "";
  const s = Math.max(0, (Date.now() - t.getTime()) / 1000);
  if (s < 90) return "now";
  if (s < 5400) return Math.round(s / 60) + "m";
  if (s < 172800) return Math.round(s / 3600) + "h";
  if (s < 1209600) return Math.round(s / 86400) + "d";
  return Math.round(s / 604800) + "w";
}

// The one thing to do about a row, as a real button. Rows without an
// obvious action (a count of entries nothing has seen) get none.
function attnAction(it) {
  const k = it.key || "";
  if (k.startsWith("source:") || k.startsWith("source-pending:")) {
    const src = k.slice(k.indexOf(":") + 1);
    return `<button class="btn sm" data-rescan="${esc(src)}">${k.startsWith("source:") ? "Retry scan" : "Scan now"}</button>`;
  }
  if (k === "secrets-undecryptable") return `<button class="btn sm" data-goto-sources>Open Sources</button>`;
  if (it.accept) return `<button class="btn sm" data-accept="${esc(it.accept)}" data-label="${esc(it.accept.split(":access:").pop())}">Accept</button>`;
  if (it.entry_id) return `<button class="btn sm" data-card="${it.entry_id}">Open entry</button>`;
  if (it.goto) return `<button class="btn sm" data-goto="${esc(it.goto)}">Review</button>`;
  return "";
}

function attnRow(it, i) {
  const age = it.since ? `<span class="atage" title="${esc(it.since_exact
      ? "since " + when(it.since)
      : "first seen by NetMap " + when(it.since) + " - nothing records when this actually began")}">${
      it.since_exact || ago(it.since) === "now" ? "" : "~"}${ago(it.since)}</span>` : "";
  return `
    <li class="at ${esc(it.level)}"${it.entry_id ? ` data-card="${it.entry_id}"` : ""}${
      it.goto ? ` data-goto="${esc(it.goto)}"` : ""}>
      <span class="atrank mono" aria-label="rank ${i + 1}">${i + 1}</span>
      <span class="atpill ${esc(it.level)}" title="${esc(LEVEL_WORD[it.level] || it.level)}">${esc(it.type || "other")}</span>
      <div class="att">
        <span class="atn">${esc(it.title)}${
          it.changed_since_dismissed
            ? `<span class="again" title="You snoozed this; it has changed since">changed</span>` : ""}${
          it.was_snoozed
            ? `<span class="again" title="Snoozed earlier; still here a day later">still here</span>` : ""}</span>
        ${it.detail ? `<span class="atd">${esc(it.detail)}</span>` : ""}
        ${it.entries ? `<span class="atents">${it.entries.map(x =>
          `<span class="lchip" data-card="${x.id}" title="${esc(x.how || "")}">${esc(x.name)}${
            x.last_seen ? `<i>${esc(dayLabel(x.last_seen))}</i>` : ""}</span>`).join("")}${
          it.more ? `<span class="pmore">+${it.more}</span>` : ""}</span>` : ""}
        ${it.verify ? `<span class="atact"><button class="btn sm" data-verify="${esc(it.verify.join(","))}">Mark ${
          it.verify.length === 1 ? "" : "all "}verified</button></span>` : ""}
      </div>
      ${age}
      <span class="atbtns">${attnAction(it)}
        <button class="btn sm" data-dismiss="${esc(it.key)}" data-fp="${esc(it.fingerprint || "")}"
          data-title="${esc(it.title)}" title="${esc(it.level === "critical"
            ? "Snooze for a day" : "Snooze until this changes")}">Snooze</button></span>
    </li>`;
}

// Snoozed items stay one click away. A dismissal that cannot be seen or
// undone is indistinguishable from a bug.
function snoozedHtml(hidden) {
  if (!hidden || !hidden.length) return "";
  return `
    <div class="stsnz">
      <button class="linkbtn" id="ovShowDis" aria-expanded="${OVSHOW}">${hidden.length} snoozed</button>
      ${OVSHOW ? `<ul class="attn dis">${hidden.map(it => `
        <li class="at ${esc(it.level)}">
          <span class="atpill ${esc(it.level)}">${esc(it.type || "other")}</span>
          <div class="att">
            <span class="atn">${esc(it.title)}</span>
            <span class="atd">snoozed ${esc(when(it.dismissed_at || ""))} - returns if it changes</span>
          </div>
          <span class="atbtns"><button class="btn sm" data-undismiss="${esc(it.key)}">Bring back</button></span>
        </li>`).join("")}</ul>` : ""}
    </div>`;
}

function statusHtml(c) {
  const items = OV.attention || [];
  const ok = !items.length;
  const tone = ok ? "ok" : OV.level === "critical" ? "critical" : OV.level === "warn" ? "warn" : "note";
  const head = ok ? "All clear - nothing needs you"
    : `${items.length} thing${items.length === 1 ? " needs" : "s need"} you`;
  return `
    <section class="verdict ${tone}" aria-labelledby="stHead">
      <div class="sthead">
        <div class="vstate"><span class="stdot" aria-hidden="true"></span>
          <h2 class="vhead" id="stHead" title="${esc(OV.verdict)}">${esc(head)}</h2></div>
        ${statsHtml(c)}
      </div>
      ${ok ? "" : `<ol class="attn">${items.map(attnRow).join("")}</ol>`}
      ${snoozedHtml(OV.dismissed)}
    </section>`;
}

/* Open hostnames split two ways: ones nobody has looked at (red - a real
   question) and ones ignored with a reason (neutral - a decision on record,
   the reason on hover). */
function exOpenCaption(naked) {
  const open = naked.filter(n => !n.accepted).length;
  const ok = naked.length - open;
  if (!open) return `<div class="excap">no Access application - open on purpose</div>`;
  return `<div class="excap bad">no Access application${ok ? ` · ${ok} open on purpose` : ""}</div>`;
}

function exposureHtml(x) {
  const naked = x.no_access || [];
  const fwd = x.wan_forwards || [];
  if (!x.published && !fwd.length)
    return `<div class="exline dimline">No source reports anything reachable
      from outside this network.</div>`;
  // Two statements of fact, side by side, each led by its number. The chips
  // under each one are the exceptions worth naming: hostnames with nothing in
  // front of them, and the ports that bypass the tunnel altogether.
  return `
    <div class="exgrid">
      <div class="excell">
        <div class="exnum"><b>${x.published}</b>
          <span>hostname${x.published === 1 ? "" : "s"} through the tunnel</span></div>
        ${naked.length ? `<div class="exchips">${naked.map(n =>
          `<span class="lchip ${n.accepted ? "" : "bad "}mono"${n.entry_id ? ` data-card="${n.entry_id}"` : ""}${
            n.accepted ? ` title="${esc("Open on purpose" + (n.reason ? ": " + n.reason : ""))}"` : ""}>${esc(n.host)}</span>`).join("")}</div>
          ${exOpenCaption(naked)}`
        : `<div class="excap">all behind Access</div>`}
      </div>
      <div class="excell">
        <div class="exnum"><b>${fwd.length}</b>
          <span>port${fwd.length === 1 ? "" : "s"} forwarded from the WAN</span></div>
        ${fwd.length ? `<div class="exchips">${fwd.map(f =>
          `<span class="lchip mono"${f.entry_id ? ` data-card="${f.entry_id}"` : ""}><b>${esc(f.port)}</b> ${esc(f.entry)}</span>`).join("")}</div>`
        : `<div class="excap">nothing bypasses the tunnel</div>`}
      </div>
    </div>`;
}

async function renderOverview(all) {
  const box = $("#overview");
  if (!box.firstChild) box.innerHTML = `<div class="empty-hint">Loading…</div>`;
  try { OV = await api("/api/overview"); }
  catch {
    box.innerHTML = `<div class="loadfail" role="alert"><b>The Overview could not load.</b>
      <span class="hint">The server did not answer as expected - it may be restarting.</span>
      <button class="btn" data-retry-load>Try again</button></div>`;
    return;
  }

  // The address card calls an address free only if nothing is living on it,
  // which needs the presence layer - normally loaded by the Network view. On
  // a first visit to the Overview it has never run, so fetch it once.
  if (!Object.keys(SEEN).length) {
    try {
      const pr = await api("/api/presence");
      for (const x of (pr.presence || [])) SEEN[x.ip] = x;
    } catch { /* the card degrades to "free" meaning "unclaimed" */ }
  }
  if (!RESV.size) {
    try {
      const d = await api("/api/sightings/dhcp");
      for (const r of (d.sightings || [])) {
        const m = String(r.value || "").match(/^reserved\s+(\d+\.\d+\.\d+\.\d+)/);
        if (m) RESV.add(m[1]);
      }
    } catch { /* no reservation label, everything else still true */ }
  }

  if (!OV_LAYOUT) await loadOvLayout();

  const pinned = all.filter(e => e.pinned);
  const c = OV.counts;
  const ok = OV.level === "ok";

  // Everything below is one template literal, and an exception anywhere in it
  // leaves the "Loading…" placeholder standing - a fault that looks exactly
  // like a slow network and hides its own stack. Build it, then swap it in:
  // if it throws, the page says so instead of spinning forever.
  let html;
  try {
    html = overviewHtml(all, pinned, c, ok);
  } catch (err) {
    console.error("overview render failed", err);
    box.innerHTML = `<div class="empty-hint">The overview failed to render:
      <code>${esc(String(err && err.message || err))}</code></div>`;
    return;
  }
  box.innerHTML = html;
  wireOverview(box, all);
}

/* The cards below the status strip, by id. Which ones show, and in what
   order, is the layout in Settings (one for the whole instance, see
   overview.py); the status strip above them is not in it and always shows. */
const OV_CARDS = {
  exposure: () => `
    <section class="ovsec ovcard wide2" data-ovcard="exposure" aria-labelledby="exHead">
      <div class="ovhead"><h2 id="exHead">Reachable from outside</h2>
        <span class="hint" data-tip>What the edge actually says - the firewall, proxy and
          tunnel sources, not the inventory.</span></div>
      ${exposureHtml(OV.exposure)}
    </section>`,
  quicklinks: (all, pinned) => `
    <section class="ovsec ovcard" data-ovcard="quicklinks" aria-labelledby="qlHead">
      <div class="ovhead"><h2 id="qlHead">Quick launch</h2>
        <span class="cardnote">${pinned.length ? `${pinned.length} pinned · by name` : "pin any entry from its card"}</span></div>
      ${pinned.length ? `<div class="qlgrid">${[...pinned]
          .sort((a, b) => a.name.localeCompare(b.name)).map(qlRow).join("")}</div>`
      : `<div class="empty-hint">Nothing pinned yet - open any entry and tick
           <strong>Pin to Quick links</strong> to put it here.</div>`}
      ${qlSuggest(all)}
    </section>`,
  changes: () => `
    <section class="ovsec ovcard" data-ovcard="changes" aria-labelledby="chHead">
      <div class="ovhead"><h2 id="chHead">Changes</h2>
        <span class="chfilters" role="group" aria-label="Show">${CHG_FILTERS.map(([k, label]) =>
          `<button class="chip chf${CHG_FILTER === k ? " on" : ""}" data-chf="${k}" aria-pressed="${
            CHG_FILTER === k}">${label}</button>`).join("")}</span></div>
      <div class="feed" id="ovFeed"><div class="empty-hint">Loading…</div></div>
      <button class="linkbtn chall" id="ovHist">All changes</button>
    </section>`,
  hardware: () => `
    <section class="ovsec ovcard" data-ovcard="hardware" aria-labelledby="hwHead">
      <div class="ovhead"><h2 id="hwHead">Hardware &amp; blast radius</h2>
        <span class="hint" data-tip>What runs on each physical box, directly or through
          a VM or container, and how much of it a health check watches.</span>
        <button class="more linkbtn" data-goto="network">Open topology</button></div>
      <div id="ovHw"><div class="empty-hint">Loading…</div></div>
    </section>`,
  categories: (all) => `
    <section class="ovsec ovcard" data-ovcard="categories" aria-labelledby="catHead">
      <div class="ovhead"><h2 id="catHead">Inventory by category</h2>
        <span class="cardnote">${all.length} tracked · solid = monitored</span></div>
      ${catCardHtml(all)}
    </section>`,
  addresses: (all) => `
    <section class="ovsec ovcard wide2" data-ovcard="addresses" aria-labelledby="adHead">
      <div class="ovhead"><h2 id="adHead">Address space</h2>
        <span class="hint" data-tip>Every /24 in the inventory, one cell per address.</span>
        <button class="more linkbtn" data-goto="network">Open addresses</button></div>
      ${addrCardHtml(all)}
    </section>`,
};
// Until the saved layout arrives (or if it cannot), every card in this order.
let OV_LAYOUT = null;
const ovLayout = () => OV_LAYOUT || Object.keys(OV_CARDS).map(id => ({ id, show: true }));

function overviewHtml(all, pinned, c, ok) {
  const cards = ovLayout().filter(x => x.show && OV_CARDS[x.id]);
  return `
    ${statusHtml(c)}

    ${cards.length ? `<div class="ovgrid">${cards.map(x => OV_CARDS[x.id](all, pinned)).join("")}</div>` : ""}

    <div class="ovfoot"><button class="btn" id="ovCustomize" aria-haspopup="dialog">
      <svg viewBox="0 0 24 24" class="ico" aria-hidden="true"><path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/></svg>
      Customize overview</button></div>`;
}

/* ---- Customize: show, hide and reorder the cards ---- */
async function loadOvLayout() {
  try { OV_LAYOUT = (await api("/api/settings/overview")).cards; }
  catch { /* the default order stands */ }
}

function layoutListHtml() {
  const rows = ovLayout();
  const label = (x) => x.label || x.id;
  const arrow = (d) => `<svg viewBox="0 0 24 24" class="ico" aria-hidden="true"><path d="${
    d === "up" ? "M6 15l6-6 6 6" : "M6 9l6 6 6-6"}"/></svg>`;
  return `
    <li class="lrow fixed"><span class="lchk"><input type="checkbox" checked disabled
      id="lyStatus"><label for="lyStatus">Status</label></span>
      <span class="hint">always shown, always first</span></li>
    ${rows.map((x, i) => `
    <li class="lrow" data-lid="${esc(x.id)}">
      <span class="lchk"><input type="checkbox" id="ly-${esc(x.id)}" data-lshow="${esc(x.id)}"${
        x.show ? " checked" : ""}><label for="ly-${esc(x.id)}">${esc(label(x))}</label></span>
      <span class="lmove">
        <button class="btn icon-only" data-lmove="-1" data-lid="${esc(x.id)}"${i ? "" : " disabled"}
          aria-label="Move ${esc(label(x))} up">${arrow("up")}</button>
        <button class="btn icon-only" data-lmove="1" data-lid="${esc(x.id)}"${i < rows.length - 1 ? "" : " disabled"}
          aria-label="Move ${esc(label(x))} down">${arrow("down")}</button>
      </span>
    </li>`).join("")}`;
}

async function saveOvLayout(body, focusSel) {
  try {
    OV_LAYOUT = (await api("/api/settings/overview", {
      method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify(body) })).cards;
  } catch { /* api() said why; the list redraws from what is stored */ }
  $("#layoutList").innerHTML = layoutListHtml();
  const f = focusSel && $(focusSel);
  if (f && !f.disabled) f.focus();
  else if (f) $("#layoutList").querySelector(`[data-lid="${CSS.escape(f.dataset.lid)}"] [data-lmove]:not([disabled])`)?.focus();
  renderOverview(ALL.length ? ALL : ENTRIES);
}

async function openLayout() {
  await loadOvLayout();
  $("#layoutList").innerHTML = layoutListHtml();
  $("#layoutModal").hidden = false;
  $("#layoutList").querySelector("[data-lshow]")?.focus();
}

$("#layoutList").addEventListener("change", ev => {
  const cb = ev.target.closest("[data-lshow]"); if (!cb) return;
  const cards = ovLayout().map(x => ({ id: x.id, show: x.id === cb.dataset.lshow ? cb.checked : x.show }));
  saveOvLayout({ cards }, `[data-lshow="${CSS.escape(cb.dataset.lshow)}"]`);
});
$("#layoutList").addEventListener("click", ev => {
  const b = ev.target.closest("[data-lmove]"); if (!b) return;
  const cards = ovLayout().map(x => ({ id: x.id, show: x.show }));
  const i = cards.findIndex(x => x.id === b.dataset.lid), j = i + Number(b.dataset.lmove);
  if (i < 0 || j < 0 || j >= cards.length) return;
  [cards[i], cards[j]] = [cards[j], cards[i]];
  saveOvLayout({ cards }, `[data-lid="${CSS.escape(b.dataset.lid)}"][data-lmove="${b.dataset.lmove}"]`);
});
$("#layoutReset").onclick = () => saveOvLayout({ reset: true });
// The rail's own way in: from any page, it goes to the Overview first so the
// change is seen as it is made.
$("#railCustomize").onclick = () => {
  if (view !== "overview") { view = "overview"; applyView(); }
  openLayout();
};
$("#layoutClose").onclick = () => ($("#layoutModal").hidden = true);

function wireOverview(box, all) {
  // When the house was last looked at is a fact about the whole app, not
  // about this page, so it lives with the version in the rail rather than in
  // a line the Overview owns and the other views lose.
  const rc = $("#railCheck");
  if (rc) rc.textContent = OV.sources.scanned_at
    ? "checked " + whenScan(OV.sources.scanned_at) : "";

  box.querySelectorAll("[data-dismiss]").forEach(b => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      await api("/api/overview/dismiss", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ key: b.dataset.dismiss, title: b.dataset.title,
                               fingerprint: b.dataset.fp }),
      });
      renderOverview(ALL.length ? ALL : ENTRIES);
    };
  });
  // "Not verified": the person has checked them - say so for all at once.
  box.querySelectorAll("[data-verify]").forEach(b => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      const ids = b.dataset.verify.split(",").filter(Boolean);
      if (ids.length > 1 && !(await confirmDialog({
        title: `Mark ${ids.length} entries verified?`,
        body: "Only if their values are checked - each change is in the history.",
        ok: "Mark verified", danger: false }))) return;
      try {
        for (const id of ids) await api("/api/entries/" + id, {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ verified: true }),
        });
      } catch { return; }          // api() already said why
      toast(ids.length === 1 ? "Marked verified" : `${ids.length} entries marked verified`);
      await load();
    };
  });
  box.querySelectorAll("[data-undismiss]").forEach(b => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      await api("/api/overview/dismiss?key=" +
                encodeURIComponent(b.dataset.undismiss), { method: "DELETE" });
      renderOverview(ALL.length ? ALL : ENTRIES);
    };
  });
  box.querySelectorAll("[data-rescan]").forEach(b => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      b.disabled = true; b.textContent = "Scanning…";
      await scanOne(b.dataset.rescan);
      await load();
    };
  });
  box.querySelectorAll("[data-accept]").forEach(b => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      const host = b.dataset.label;
      if (!(await confirmDialog({
        title: `Accept ${host} as open on purpose?`,
        body: "It stays listed under Reachable from outside, marked open on purpose, "
            + "and leaves this list. Undo it from the source's ignored findings on Network.",
        ok: "Accept", danger: false }))) return;
      try {
        await api("/api/discovery/ignores", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ key: b.dataset.accept, label: host, reason: "accepted on the Overview" }),
        });
      } catch { return; }
      toast(`${host} accepted as open on purpose`);
      renderOverview(ALL.length ? ALL : ENTRIES);
    };
  });
  const sd = $("#ovShowDis");
  if (sd) sd.onclick = () => { OVSHOW = !OVSHOW; renderOverview(ALL.length ? ALL : ENTRIES); };

  const cz = $("#ovCustomize");
  if (cz) cz.onclick = openLayout;

  box.querySelectorAll("[data-goto]").forEach(el => {
    el.onclick = (ev) => {
      if (ev.target.closest("[data-card]")) return;
      ev.stopPropagation();
      view = el.dataset.goto; applyView(); renderNetwork();
    };
  });

  box.querySelectorAll(".agrid [data-ip]").forEach(b => {
    b.onclick = () => {
      for (const k of ["category", "tag", "kind", "criticality", "zone"]) filter[k] = "";
      filter.ip = b.dataset.ip;
      view = "inventory"; applyView(); load();
    };
  });
  const hw = $("#ovHw");
  if (hw) api("/api/overview/hardware").then(h => { hw.innerHTML = hwHtml(h); })
    .catch(() => { hw.innerHTML = `<div class="empty-hint">The hardware view could not load.</div>`; });

  const feed = $("#ovFeed");
  if (feed) loadChanges().then(ok => {
    const f = $("#ovFeed");
    if (f) f.innerHTML = ok ? chgHtml() : `<div class="empty-hint">The change log could not load.</div>`;
  });
  box.querySelectorAll("[data-chf]").forEach(b => {
    b.onclick = () => {
      CHG_FILTER = b.dataset.chf; CHG_OPEN.clear();
      box.querySelectorAll("[data-chf]").forEach(x => {
        x.classList.toggle("on", x === b); x.setAttribute("aria-pressed", String(x === b)); });
      $("#ovFeed").innerHTML = chgHtml();
    };
  });
  const fd = $("#ovFeed");
  if (fd) fd.addEventListener("click", ev => {
    const m = ev.target.closest("[data-chopen]"); if (!m) return;
    const i = Number(m.dataset.chopen);
    CHG_OPEN.has(i) ? CHG_OPEN.delete(i) : CHG_OPEN.add(i);
    fd.innerHTML = chgHtml();
    fd.querySelector(`[data-chopen="${i}"]`)?.focus();
  });
  box.querySelectorAll("[data-pin]").forEach(b => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      try {
        await api("/api/entries/" + b.dataset.pin, {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ pinned: true }) });
      } catch { return; }
      toast("Pinned");
      await load();
    };
  });
}

/* What the inventory is made of. The bar is proportional to the largest
   category, not to the total - with nine categories a share-of-total bar is
   nine slivers, and the question this answers is "which of these is big",
   not "what fraction of everything is it". */
/* One tile per physical host that something runs on, biggest first, then
   the network gear as one line. The dot and the coverage both say their
   state in words as well (title, "N of M monitored"). */
const UPWORD = (u) => u === true ? "up" : u === false ? "down" : "not checked";
const upTone = (u) => u === true ? "up" : u === false ? "down" : "na";

function hwHtml(h) {
  const hosts = h.hosts || [], g = h.gear || { total: 0 };
  if (!hosts.length && !g.total)
    return `<div class="empty-hint">Nothing records what runs on which machine yet - set
      <strong>Runs on</strong> on an entry, or let a source derive it.</div>`;
  const pc = (a, b) => b ? Math.round(100 * a / b) : 0;
  return `<div class="hwgrid">${hosts.map(x => `
    <button class="hwcard" data-card="${x.id}">
      <span class="hwtop"><i class="dot ${upTone(x.up)}" title="${UPWORD(x.up)}"></i>
        <b class="hwn">${esc(x.name)}</b><span class="mono hwip">${esc(x.ip)}</span></span>
      <span class="hwbig"><b class="num mono">${x.dependents}</b>
        <small>entr${x.dependents === 1 ? "y depends" : "ies depend"} on it</small></span>
      ${x.checkable ? `<span class="hwcov" title="${x.monitored} of ${x.checkable} that a check could probe">
        <span class="hwbar"><i style="width:${pc(x.monitored, x.checkable)}%"></i></span>
        <small class="${x.monitored < x.checkable ? "warnc" : ""}">${x.monitored} of ${x.checkable} monitored</small></span>` : ""}
      ${(x.notes || []).map(n => `<small class="hwnote${n.risk ? " warnc" : ""}">${esc(n.text)}</small>`).join("")}
    </button>`).join("")}
    ${g.total ? `
    <div class="hwcard hwgear">
      <span class="hwtop"><b class="hwn">Network gear</b></span>
      <span class="hwbig"><b class="num mono">${g.up}/${g.monitored}</b><small>up</small></span>
      ${g.total > g.monitored ? `<small class="warnc">${g.total - g.monitored} of ${g.total} not monitored</small>` : ""}
      <span class="hwitems">${g.items.map(i => `<span class="lchip" data-card="${i.id}" title="${
        esc(i.monitor ? UPWORD(i.up) : "not monitored")}"><i class="dot ${i.monitor ? upTone(i.up) : "na"}"></i>${
        esc(i.name)}</span>`).join("")}</span>
    </div>` : ""}</div>`;
}

function catCardHtml(all) {
  const n = {}, m = {};
  for (const e of all) {
    const c = (e.category || "").trim() || "Uncategorised";
    n[c] = (n[c] || 0) + 1;
    if (e.monitor) m[c] = (m[c] || 0) + 1;
  }
  const rows = Object.entries(n).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (!rows.length) return `<div class="empty-hint">Nothing tracked yet.</div>`;
  const max = rows[0][1];
  // The track is as long as the category is big; inside it, the faint fill is
  // every entry and the solid fill the monitored ones.
  return `<div class="cats">${rows.map(([cat, k]) => {
    const mon = m[cat] || 0;
    return `
    <button class="catrow" data-cat="${esc(cat)}" title="Show only ${esc(cat)}: ${mon} of ${k} monitored">
      ${catGlyph(cat)}
      <span class="cn">${esc(cat)}</span>
      <span class="catbar"><span class="cattrack ${catKey(cat)}" style="width:${Math.round(100 * k / max)}%">
        <i style="width:${Math.round(100 * mon / k)}%"></i></span></span>
      <span class="cc num mono">${mon}/${k}</span>
    </button>`;
  }).join("")}</div>`;
}

/* Address space, in proportion. The Network view draws all 254 addresses one
   cell each, which is the right tool for "is .41 free"; this one answers the
   only question the front page should ask, which is whether a subnet is
   filling up. Seen-but-untracked is drawn as its own band because those
   addresses are occupied - counting them as free is the error this layer was
   built to stop. */
/* Which addresses the firewall holds a reservation for. A reserved address is
   not the same as a used one: it is spoken for whether or not anything is
   answering on it today, which is exactly what you need to know before
   handing it to something else. OPNsense says so in its `dhcp` sightings. */
let RESV = new Set();

/* One block per /24: its 254 usable addresses, .1 to .254, 32 to a row, each cell coloured by
   what holds it - used, shared (two or more entries), seen (a source sees
   something there that the inventory does not have), reserved (a DHCP
   reservation) or free. Every cell names its address and state on hover;
   the ones with entries are buttons that open Inventory on exactly that
   address. .0 and .255 (network, broadcast) are never assignable, so not drawn. */
// Fill says what holds an address; a frame says it is reserved, so the
// legend shows both reserved forms rather than one that matches few cells.
const ADDR_STATES = [["used", "used"], ["dup", "shared"], ["seen", "seen"], ["free", "free"]];
const ADDR_RESV = [["used resv", "reserved, in use"], ["resv", "reserved, unused"]];

function addrCell(base, i, here) {
  const ip = base + i;
  const resv = RESV.has(ip);
  if (here.length) {
    const st = here.length > 1 ? "dup" : "used";
    const names = here.slice(0, 3).map(e => e.name).join(", ") + (here.length > 3 ? ` +${here.length - 3}` : "");
    const tip = `${ip} · ${here.length} entr${here.length === 1 ? "y" : "ies"}: ${names}${resv ? " · reserved" : ""}`;
    return `<button class="acell ${st}${resv ? " resv" : ""}" data-ip="${esc(ip)}" title="${esc(tip)}"
      aria-label="${esc(tip)}"></button>`;
  }
  if (SEEN[ip]) return `<i class="acell seen${resv ? " resv" : ""}" title="${esc(`${ip} · seen by a source, not in the inventory${resv ? " · reserved" : ""}`)}"></i>`;
  if (resv) return `<i class="acell resv" title="${esc(`${ip} · reserved, nothing recorded`)}"></i>`;
  return `<i class="acell free" title="${esc(`${ip} · free`)}"></i>`;
}

function addrCardHtml(all) {
  const nets = subnets(all);
  if (!nets.length) return `<div class="empty-hint">No addresses recorded yet.</div>`;
  const sw = ([k, label]) => `<span><i class="acell ${k}" aria-hidden="true"></i>${label}</span>`;
  const legend = `<div class="alegend">${ADDR_STATES.map(sw).join("")}<span class="asep" aria-hidden="true"></span>${
    ADDR_RESV.map(sw).join("")}</div>`;
  return legend + `<div class="ablocks">${nets.map(n => {
    const free = Math.max(0, n.free - n.seen);
    const base = n.net.replace(/0\/24$/, "");
    let res = 0;
    for (let i = 1; i <= 254; i++) if (RESV.has(base + i)) res++;
    // The zone most of its entries say they are in.
    const zc = {};
    for (const e of Object.values(n.addrs).flat()) if (e.zone) zc[e.zone] = (zc[e.zone] || 0) + 1;
    const zone = Object.entries(zc).sort((a, b) => b[1] - a[1])[0]?.[0] || "";
    const cells = [];
    for (let i = 1; i <= 254; i++) cells.push(addrCell(base, i, n.addrs[i] || []));
    return `
    <div class="ablock">
      <div class="ahead"><b class="mono">${esc(n.net)}</b>${zone ? `<span class="azone">${esc(zone)}</span>` : ""}
        <span class="hint ac">${n.used} used · ${free} free${
          res ? ` · <span class="resw">${res} reserved</span>` : ""}${
          n.seen ? ` · <span class="seenw">${n.seen} seen</span>` : ""}${
          n.dup ? ` · <span class="dupw">${n.dup} shared</span>` : ""}</span></div>
      <div class="agrid" role="group" aria-label="${esc(n.net)} addresses">${cells.join("")}</div>
    </div>`;
  }).join("")}</div>`;
}

/* ---- Quick launch ---- */
// The address a person recognises: the URL's host name, else ip:port.
function qlAddr(e) {
  const port = (e.ports || "").match(/\b\d{1,5}\b/);
  const ipport = [e.ip, port ? port[0] : ""].filter(Boolean).join(":");
  let host = "";
  try { host = e.url ? new URL(e.url).host : ""; } catch { /* not a URL */ }
  return { main: host || ipport, ipport };
}

function qlRow(e) {
  const href = linkFor(e);
  const a = qlAddr(e);
  const st = e.status || {};
  const tone = st.up === true ? "up" : st.up === false ? "down" : "na";
  const inner = `${entGlyph(e)}
    <span class="t"><span class="n">${esc(e.name)}</span><span class="a mono">${esc(a.main || "-")}</span></span>
    <i class="dot ${tone}" title="${esc(statusWhy(st))}"></i>`;
  const tip = esc([a.ipport, statusWhy(st)].filter(Boolean).join(" · "));
  return href
    ? `<a class="qlrow" href="${esc(href)}" target="_blank" rel="noopener" title="${tip}">${inner}</a>`
    : `<button class="qlrow" data-card="${e.id}" title="${tip}">${inner}</button>`;
}

// Critical, has a URL, not pinned yet: worth one click. At most two.
function qlSuggest(all) {
  const s = all.filter(e => e.criticality === "critical" && e.url && !e.pinned)
    .sort((a, b) => a.name.localeCompare(b.name)).slice(0, 2);
  if (!s.length) return "";
  return `<div class="qlsug"><span title="Critical entries with a URL that are not pinned">Suggested to pin:</span>${s.map(e => `
    <span class="qlsugi">${esc(e.name)}<button class="btn sm" data-pin="${e.id}"
      aria-label="Pin ${esc(e.name)}">Pin</button></span>`).join("")}</div>`;
}

/* ---- Changes ---- */
// The change log and the status transitions as one readable feed: grouped by
// day, and a run of changes by one actor to one entry (or to entries on one
// address) within two hours folded into a row that opens.
const CHG_FILTERS = [["all", "All"], ["discovered", "Discovered"], ["edit", "Edits"], ["state", "State"]];
let CHG_FILTER = "all";
let CHG_EVENTS = null, CHG_NOTE = "";
const CHG_OPEN = new Set();
const CHG_GAP = 2 * 3600 * 1000, CHG_MAX = 6;
const chgDate = (ts) => new Date(String(ts).endsWith("Z") ? ts : ts + "Z");
const chgTime = (d) => `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;

function chgKind(ev) {
  if (ev.obs || ev.actor === "system" || /^(source|notify)-/.test(ev.action)) return "state";
  if (ev.action === "create" && ev.detail && typeof ev.detail === "object"
      && (ev.detail.verified === false || ev.detail.verified === 0
          || /^Discovered\b/.test(ev.detail.notes || ""))) return "discovered";
  return "edit";
}

function chgSummary(ev) {
  const n = ev.name || "";
  switch (ev.action) {
    case "create": return (ev.kind === "discovered" ? "Discovered " : "Added ") + n;
    case "update": {
      const d = ev.detail && typeof ev.detail === "object" ? ev.detail : {};
      if (d.name) return `Renamed ${d.name[0] || "?"} to ${d.name[1] || "?"}`;
      return `Edited ${n}`;
    }
    case "delete": return `Deleted ${n}`;
    case "link": return `Linked ${n}`;
    case "unlink": return `Unlinked ${n}`;
    case "ignore": return `Ignored ${n}`;
    case "unignore": return `Brought back ${n}`;
    case "setting": return `Setting: ${n}`;
    case "up": return `${n} answers again`;
    case "down": return `${n} stopped answering`;
    default: return `${ev.action} ${n}`.trim();
  }
}

function chgDetail(ev) {
  if (ev.obs) return ev.detail || "";
  const d = ev.detail;
  if (ev.action === "update" && d && typeof d === "object")
    return Object.keys(d).join(", ");
  if (ev.action === "create" && d && typeof d === "object") return d.ip || "";
  return "";
}

function chgGroups(events) {
  const ipOf = {};
  for (const e of (ALL.length ? ALL : ENTRIES)) if (e.ip) ipOf[e.id] = e.ip.trim();
  const same = (a, b) => a.entry_id && b.entry_id && (a.entry_id === b.entry_id
    || (ipOf[a.entry_id] && ipOf[a.entry_id] === ipOf[b.entry_id]));
  // Consecutive for that actor: another actor's event in between (a status
  // flap while someone edits) does not split the run.
  const groups = [];
  for (const ev of events) {                         // newest first
    const g = groups.find(x => {
      const last = x.items[x.items.length - 1];
      return last.actor === ev.actor && same(last, ev)
        && last.d.toDateString() === ev.d.toDateString() && last.d - ev.d <= CHG_GAP;
    });
    if (g) g.items.push(ev); else groups.push({ items: [ev] });
  }
  return groups;
}

function dayHead(d) {
  const today = new Date(), y = new Date(Date.now() - 86400000);
  const dd = d.toLocaleDateString([], { weekday: "short", day: "numeric", month: "short" });
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === y.toDateString()) return `Yesterday · ${dd}`;
  return dd;
}

function chgGroupHtml(g, i) {
  const first = g.items[0], n = g.items.length;      // first = newest
  if (n === 1) {
    const det = chgDetail(first);
    return `<div class="chrow"${first.entry_id ? ` data-card="${first.entry_id}"` : ""}>
      <span class="cht mono">${chgTime(first.d)}</span>
      <span class="chs"><span class="chm">${esc(chgSummary(first))}</span>
        <span class="chsub">${esc(first.actor)}${det ? " · " + esc(det) : ""}</span></span></div>`;
  }
  // Oldest to newest reads as a story: "Added X, then renamed to Y".
  const story = [...g.items].reverse();
  const head = story.length > 2
    ? `${chgSummary(story[0])}, then ${chgSummary(story[story.length - 1]).replace(/^./, c => c.toLowerCase())}`
    : story.map((e, k) => k ? chgSummary(e).replace(/^./, c => c.toLowerCase()) : chgSummary(e)).join(", then ");
  const open = CHG_OPEN.has(i);
  return `<div class="chgrp">
    <button class="chrow chmerged" data-chopen="${i}" aria-expanded="${open}">
      <span class="cht mono">${chgTime(first.d)}</span>
      <span class="chs"><span class="chm">${esc(head)}</span>
        <span class="chsub">${esc(first.actor)} · ${n} changes collapsed · ${chgTime(story[0].d)}-${chgTime(first.d)}</span></span>
    </button>
    ${open ? `<div class="chsubs">${g.items.map(e => `
      <div class="chrow"${e.entry_id ? ` data-card="${e.entry_id}"` : ""}>
        <span class="cht mono">${chgTime(e.d)}</span>
        <span class="chs"><span class="chm">${esc(chgSummary(e))}</span>
          ${chgDetail(e) ? `<span class="chsub">${esc(chgDetail(e))}</span>` : ""}</span></div>`).join("")}</div>` : ""}
  </div>`;
}

function chgHtml() {
  if (!CHG_EVENTS) return `<div class="empty-hint">Loading…</div>`;
  const evs = CHG_EVENTS.filter(e => CHG_FILTER === "all" || e.kind === CHG_FILTER);
  if (!evs.length) return `<div class="empty-hint">Nothing ${CHG_FILTER === "all" ? "recorded" : "of this kind"} yet.</div>${
    CHG_NOTE ? `<div class="hint">${esc(CHG_NOTE)}</div>` : ""}`;
  const groups = chgGroups(evs).slice(0, CHG_MAX);
  let day = "";
  return groups.map((g, i) => {
    const h = dayHead(g.items[0].d);
    const head = h === day ? "" : `<div class="dayhead">${esc(h)}</div>`;
    day = h;
    return head + chgGroupHtml(g, i);
  }).join("") + (CHG_NOTE ? `<div class="hint">${esc(CHG_NOTE)}</div>` : "");
}

async function loadChanges() {
  const [audit, obs] = await Promise.all([
    api("/api/audit?limit=200").catch(() => null),
    api("/api/observations?limit=100").catch(() => null),
  ]);
  if (!audit && !obs) { CHG_EVENTS = null; return false; }
  CHG_NOTE = !audit ? "The change log could not load." : !obs ? "Status changes could not load." : "";
  const evs = (audit || []).map(h => ({ ...h }))
    .concat((obs || []).filter(o => o.up !== null).map(o => ({
      ts: o.ts, actor: "system", action: o.up ? "up" : "down", entry_id: o.entry_id,
      name: o.name, detail: o.target || "", obs: true })));
  for (const e of evs) { e.d = chgDate(e.ts); e.kind = chgKind(e); }
  CHG_EVENTS = evs.filter(e => !isNaN(e.d)).sort((a, b) => b.d - a.d);
  return true;
}

