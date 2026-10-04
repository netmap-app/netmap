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
    <div class="ovsec wide2" data-ovcard="exposure">
      <div class="ovhead"><h2>Reachable from outside</h2>
        <span class="hint" data-tip>What the edge actually says - the firewall, proxy and
          tunnel sources, not the inventory.</span></div>
      ${exposureHtml(OV.exposure)}
    </div>`,
  quicklinks: (all, pinned) => `
    <div class="ovsec wide2" data-ovcard="quicklinks">
      <div class="ovhead"><h2>Quick links</h2><span class="hint" data-tip>Pinned services.</span></div>
      ${pinned.length ? `<div class="qgrid">${pinned.map(qlink).join("")}</div>`
      : `<div class="empty-hint">Nothing pinned yet - open any entry and tick
           <strong>Pin to Quick links</strong> to put it here.</div>`}
    </div>`,
  changes: () => `
    <div class="ovsec" data-ovcard="changes">
      <div class="ovhead"><h2>Recent changes</h2><span class="more" id="ovHist">View all</span></div>
      <div class="card2"><div class="feed" id="ovFeed"><div class="empty-hint">Loading…</div></div></div>
    </div>`,
  hardware: () => `
    <div class="ovsec" data-ovcard="hardware">
      <div class="ovhead"><h2>Hardware &amp; blast radius</h2>
        <span class="hint" data-tip>What runs on each physical box, directly or through
          a VM or container, and how much of it a health check watches.</span>
        <button class="more linkbtn" data-goto="network">Open topology</button></div>
      <div id="ovHw"><div class="empty-hint">Loading…</div></div>
    </div>`,
  categories: (all) => `
    <div class="ovsec" data-ovcard="categories">
      <div class="ovhead"><h2>Inventory by category</h2>
        <span class="hint">${all.length} tracked · solid = monitored</span></div>
      <div class="card2">${catCardHtml(all)}</div>
    </div>`,
  addresses: (all) => `
    <div class="ovsec wide2" data-ovcard="addresses">
      <div class="ovhead"><h2>Address space</h2>
        <span class="hint" data-tip>Every /24 in the inventory.</span></div>
      <div class="card2">${addrCardHtml(all)}</div>
    </div>`,
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

  const hw = $("#ovHw");
  if (hw) api("/api/overview/hardware").then(h => { hw.innerHTML = hwHtml(h); })
    .catch(() => { hw.innerHTML = `<div class="empty-hint">The hardware view could not load.</div>`; });

  api("/api/audit?limit=6").then(rows => {
    const f = $("#ovFeed");
    if (!f) return;
    f.innerHTML = rows.length ? rows.map(h => `
      <div class="feeditem ${h.action === "delete" ? "del" : ""}"${
        h.action !== "delete" && h.entry_id ? ` data-card="${h.entry_id}"` : ""}>
        <span class="fd"></span>
        <div class="ft">
          <span class="fa"><b>${esc(h.action)}</b> ${esc(h.name || "")}</span>
          <span class="fw">${esc(h.actor)} · ${esc(when(h.ts))}</span>
        </div>
      </div>`).join("") : `<div class="empty-hint">No changes recorded yet.</div>`;
  }).catch(() => {});
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

function addrCardHtml(all) {
  const nets = subnets(all);
  if (!nets.length) return `<div class="empty-hint">No addresses recorded yet.</div>`;
  return `<div class="addrs">${nets.map(n => {
    const free = Math.max(0, n.free - n.seen);
    const pc = (v) => (100 * v / 254).toFixed(1) + "%";
    const base = n.net.replace(/0\/24$/, "");
    let res = 0;
    for (const k of Object.keys(n.addrs)) if (RESV.has(base + k)) res++;
    // Shared addresses get their own band in the bar rather than only a
    // number at the end of a sentence: two things on one address is the kind
    // of fact that should be visible in the shape, not just readable in the
    // caption.
    // The track is fixed rather than fluid. A 1600px bar holding one blue
    // pixel does not read as "one address in use", it reads as an empty
    // section - the proportion is the information, and the proportion is the
    // same at 200px.
    return `
    <div class="addr" data-goto="network">
      <b class="mono an">${esc(n.net)}</b>
      <span class="abar">
        <i class="on" style="width:${pc(Math.max(0, n.used - n.dup))}"></i>
        <i class="dup" style="width:${pc(n.dup)}"></i>
        <i class="seen" style="width:${pc(n.seen)}"></i>
      </span>
      <span class="hint ac">${n.used} used · ${free} free${
        res ? ` · <span class="resw">${res} reserved</span>` : ""}${
        n.seen ? ` · <span class="seenw">${n.seen} seen</span>` : ""}${
        n.dup ? ` · <span class="dupw">${n.dup} shared</span>` : ""}</span>
    </div>`;
  }).join("")}</div>`;
}

function qlink(e) {
  const href = linkFor(e);
  const port = (e.ports || "").match(/\b\d{1,5}\b/);
  const addr = [e.ip, port ? port[0] : ""].filter(Boolean).join(":");
  // Status is a short rule standing beside the name rather than a dot or a
  // full-height cell border: findable in peripheral vision and in greyscale,
  // and set in from the edge so it reads as part of the entry rather than as
  // part of the grid.
  const st = e.status || {};
  const tone = st.up === true ? "up" : st.up === false ? "down" : "na";
  const why = statusWhy(st);
  return `<a class="qlink" title="${esc(why)}" ${href ? `href="${esc(href)}" target="_blank" rel="noopener"` : ""}>
    <i class="qbar ${tone}"></i>
    ${entGlyph(e)}
    <span class="t"><span class="n">${esc(e.name)}</span><span class="a mono">${esc(addr || "-")}</span></span>
  </a>`;
}
