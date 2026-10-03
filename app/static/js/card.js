/* NetMap front end — card.js: the service card, and the port page.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines — tests/test_frontend.py checks. */

/* ================= service card ================= */
const EDGE_LABEL = {
  runs_on: "runs on", depends_on: "depends on", exposed_by: "exposed by",
  connects_to: "connects to", resolves_to: "resolves to", backs_up_to: "backs up to",
};
const EDGE_BACK = {
  runs_on: "hosts", depends_on: "needed by", exposed_by: "exposes",
  connects_to: "connected from", resolves_to: "resolved from", backs_up_to: "backup of",
};
let cardId = null;
let portsAll = false;
// Tree, physical, dependencies. Three questions about the same graph; the
// old single view answered the first and buried the other two.
let topoMode = (() => {
  try { return localStorage.getItem("netmap.topo") || "tree"; } catch { return "tree"; }
})();
const TOPO_HINT = {
  tree: "what runs on what",
  physical: "what is plugged into what",
  deps: "what needs what",
  graph: "every link at once, and the ways in from the internet",
};
let shownView = null;

/* The last 30 days as a strip: green up, red down, grey unknown — the
   gaps where nothing was checked are shown, not smoothed over. */
function uptimeHtml(u) {
  if (!u || !u.shown) return "";
  const t = s => Date.parse(s);
  const segs = u.segments || [];
  const t0 = segs.length ? t(segs[0][0]) : 0, t1 = segs.length ? t(segs[segs.length - 1][1]) : 1;
  const span = Math.max(1, t1 - t0);
  const rects = segs.map(([a, b, s]) => {
    const x = (t(a) - t0) / span * 300, w = Math.max(s === "down" ? 1.5 : 0, (t(b) - t(a)) / span * 300);
    return `<rect class="us ${s}" x="${x.toFixed(2)}" y="0" width="${w.toFixed(2)}" height="8">
      <title>${esc(s)}: ${esc(when(a))} – ${esc(when(b))}</title></rect>`;
  }).join("");
  const pct = u.percent == null ? "not enough data yet" : `<b>${u.percent}%</b> up`;
  const down = u.down_s >= 60 ? ` · down ${fmtDur(u.down_s)} in all` : "";
  return `<div class="cup"><span class="cuph">${pct} over ${u.window_days} days${
      u.since ? ` (since ${esc(dayLabel(u.since))})` : ""}${down}</span>
    <svg class="ustrip" viewBox="0 0 300 8" preserveAspectRatio="none" role="img"
      aria-label="Up and down over the last ${u.window_days} days">${rects}</svg></div>`;
}

function statusLine(st) {
  if (!st || st.up === undefined || st.up === null)
    return `<span class="cs na">${st && st.check === "none" ? "not probed" : "not monitored"}</span>`;
  const why = st.summary || `${st.target || ""}${st.up ? ` · ${st.latency_ms}ms` : ""}`;
  return (st.up ? `<span class="cs up">up</span>` : `<span class="cs down">no answer</span>`)
    + `<span class="csx">${esc(why)}</span>` + certLine(st.tls);
}

// What an https check read from the certificate.
function certLine(tls) {
  if (!tls || !tls.not_after) return "";
  const d = tls.days_left, until = tls.not_after.slice(0, 10);
  const cls = d < 0 ? "down" : tls.soon ? "warn" : "";
  const text = d < 0 ? `certificate expired ${until}`
    : `certificate valid until ${until} (${d} day${d === 1 ? "" : "s"})`;
  return `<span class="cscert ${cls}">${esc(text)}${tls.valid === false
    ? ` · not trusted: ${esc(tls.error || "")}` : ""}</span>`;
}

function edgeList(edges, dir) {
  if (!edges.length) return `<div class="empty-hint">Nothing recorded.</div>`;
  return `<div class="edges">${edges.map(e => {
    const other = dir === "out" ? e.dst : e.src;
    const label = dir === "out" ? EDGE_LABEL[e.type] : EDGE_BACK[e.type];
    const bad = e.other_status === false;
    return `<div class="edge${bad ? " bad" : ""}">
      <span class="et">${esc(label || e.type)}</span>
      <span class="en" data-card="${other}">${esc(e.other_name)}</span>
      ${bad ? `<span class="cs down">down</span>` : ""}
      ${e.derived ? `<span class="derived" title="${esc(e.note || "derived")}">auto</span>` : ""}
      <button class="iconbtn xbtn" title="Remove link"
        data-unlink="${e.src}:${e.dst}:${esc(e.type)}">✕</button>
    </div>`;
  }).join("")}</div>`;
}

// What the sources currently *say*, as opposed to where they disagree. A
// finding is an argument; a sighting is a witness statement, and most of the
// time the interesting thing is that five of them agree.
// A source's own name ("Docker 2") from the last health read, falling back to
// its id — ids are what sightings carry.
const srcLabel = id => ((SRC_HEALTH.health || []).find(h => h.source === id) || {}).label || id;

function sightRows(list, { withEntry = false } = {}) {
  if (!list || !list.length)
    return `<div class="empty-hint">No source says anything about this yet.</div>`;
  // Group by fact so the agreements line up: one row per fact, one badge per
  // source that speaks to it.
  const byFact = new Map();
  for (const r of list) (byFact.get(r.fact) || byFact.set(r.fact, []).get(r.fact)).push(r);
  return `<div class="sights">${[...byFact.entries()].map(([fact, rows]) => `
    <div class="sight">
      <span class="sf mono">${esc(fact)}</span>
      <span class="sv">${rows.map(r => `
        <span class="sitem"${r.seen_at ? ` title="seen ${esc(when(r.seen_at))}"` : ""}>
          <span class="ssrc s-${esc(srcType(r.source))}">${esc(srcLabel(r.source))}</span>
          ${withEntry && r.entry_name
            ? `<span class="sen" data-card="${r.entry_id}">${esc(r.entry_name)}</span>` : ""}
          <span class="stx">${esc(r.value)}</span>
        </span>`).join("")}</span>
    </div>`).join("")}</div>`;
}

// The card in sentences. It is the first thing on the page because it is the
// only part that answers a question rather than presenting a field.
function explainHtml(x) {
  if (!x || !x.sections || !x.sections.length) return "";
  return `<div class="explain">
    ${x.sections.map(s => `
      <div class="exs ${esc(s.level)}">
        <div class="exh">${esc(s.title)}</div>
        <div class="ext">${esc(s.text)}</div>
        ${(s.items || []).length ? `<ul class="exl">${s.items.map(i =>
          `<li>${esc(i)}</li>`).join("")}</ul>` : ""}
      </div>`).join("")}
    <div class="exfoot">${x.sighting_count
      ? `${x.sighting_count} observation${x.sighting_count === 1 ? "" : "s"} from ${
          x.sources.map(t => esc(srcLabel(t))).join(", ")}`
      : "No source has confirmed this entry exists."}</div>
  </div>`;
}

/* ================= one port, everything about it ================= */
async function showPort(port) {
  $("#portModal").hidden = false;
  $("#portBody").innerHTML = SHEETX + `<div class="empty-hint">Loading…</div>`;
  let d;
  try { d = await api(`/api/ports/${port}`); }
  catch { $("#portBody").innerHTML = SHEETX + `<div class="empty-hint">Could not load.</div>`; return; }

  // By role, not product: any scanner, any firewall, any public edge.
  const has = (r, role) => (r.roles || []).includes(role);
  const open = d.observed.filter(r => has(r, "scanner") && /open/.test(r.value));
  const fwd = d.observed.filter(r => has(r, "firewall"));
  const pub = d.routed.filter(r => has(r, "edge"));
  // The one sentence a port page exists to produce.
  const verdict = pub.length
    ? `reachable from the internet through ${pub.length} hostname${pub.length === 1 ? "" : "s"}`
    : fwd.length ? `forwarded from the WAN by ${fwd.length} rule${fwd.length === 1 ? "" : "s"}`
    : open.length ? `listening on ${open.length} address${open.length === 1 ? "" : "es"}, LAN only`
    : "nothing observed listening";
  const bad = pub.some(r => /no Access/.test(r.value));

  $("#portBody").innerHTML = SHEETX + `
    <div class="cardhead">
      <div class="ch1"><h2 class="mono">Port ${d.port}</h2>
        <span class="kind service">${d.entries.length} entr${d.entries.length === 1 ? "y" : "ies"}</span></div>
      <div class="ch2"><span class="cs ${bad ? "down" : pub.length || fwd.length ? "na" : "up"}">${esc(verdict)}</span>
        ${bad ? `<span class="csx">one hostname has no Access application in front of it</span>` : ""}</div>
    </div>

    <div class="setsec"><h3>Entries <i>who claims this port</i></h3>
      ${d.entries.length ? `<div class="edges">${d.entries.map(e => `
        <div class="edge">
          <span class="et mono">${esc(e.ip || "—")}</span>
          <span class="en" data-card="${e.id}">${esc(e.name)}</span>
          ${e.kind ? `<span class="kind ${esc(e.kind)}">${esc(e.kind)}</span>` : ""}
          ${d.declared_by.includes(e.id) ? "" : `<span class="derived" title="not in this entry's ports field">observed</span>`}
        </div>`).join("")}</div>`
        : `<div class="empty-hint">Nothing in the inventory claims this port.</div>`}
    </div>

    <div class="setsec"><h3>Observed <i>what the scanners see</i></h3>
      ${sightRows(d.observed, { withEntry: true })}</div>

    <div class="setsec"><h3>Names pointed at it <i>proxy and tunnel</i></h3>
      ${sightRows(d.routed, { withEntry: true })}</div>

    <div class="sheetfoot">
      <span class="spacer"></span>
      <button class="btn primary" id="portClose">Close</button>
    </div>`;
  $("#portClose").onclick = () => ($("#portModal").hidden = true);
}

let cardReturnFocus = null;         // where keyboard focus goes back to on close

async function showCard(id, push = true) {
  cardId = +id;
  if ($("#cardModal").hidden) cardReturnFocus = document.activeElement;
  $("#cardModal").hidden = false;
  // An asset is a place, so it gets an address. Sharing "the Plex page" and
  // pressing Back both work; closing the card returns the URL to the list.
  if (push && location.hash !== "#/entry/" + cardId)
    history.pushState({ entry: cardId }, "", "#/entry/" + cardId);
  $("#cardBody").innerHTML = SHEETX + `<div class="empty-hint">Loading…</div>`;
  let c, x = null;
  try {
    [c, x] = await Promise.all([
      api(`/api/entries/${id}/context`),
      // The explanation is a convenience, not the card: if it fails the rest
      // of the page still has to render.
      api(`/api/entries/${id}/explain`).catch(() => null),
    ]);
  }
  catch { $("#cardBody").innerHTML = SHEETX + `<div class="empty-hint">Could not load.</div>`; return; }

  const e = c.entry;
  const link = linkFor(e);
  const facts = [
    ["Host", e.host], ["Address", e.ip], ["MAC", e.mac], ["Ports", e.ports],
    ["Access", e.protocol], ["Zone", e.zone], ["Category", e.category],
    ["Credentials", e.secret_ref],
    // When something last confirmed it exists — see app/stale.py.
    ["Last seen", c.last_seen ? `${when(c.last_seen.last_seen)} — ${c.last_seen.how}` : ""],
  ].filter(([, v]) => v);

  const obs = c.observations.length ? `<div class="obs">${c.observations.map(o => `
      <div class="ob"><span class="dot ${o.up === true ? "up" : o.up === false ? "down" : "na"}"></span>
        <span>${o.up === true ? "came up" : o.up === false ? "stopped answering" : "stopped being monitored"}</span>
        <span class="ow">${esc(when(o.ts))}</span></div>`).join("")}</div>`
    : `<div class="empty-hint">No changes of state recorded yet.</div>`;

  const changes = c.changes.length ? `<div class="obs">${c.changes.map(h => `
      <div class="ob"><span class="fd"></span><span><b>${esc(h.action)}</b>
        ${h.action === "update" && h.detail && typeof h.detail === "object"
          ? esc(Object.keys(h.detail).join(", ")) : ""}</span>
        <span class="ow">${esc(h.actor)} · ${esc(when(h.ts))}</span></div>`).join("")}</div>`
    : `<div class="empty-hint">No edits recorded.</div>`;

  $("#cardBody").innerHTML = SHEETX + `
    <div class="cardhead">
      <div class="ch1">${dot({ ...e, status: c.status,
          uptime: c.uptime && c.uptime.shown ? c.uptime.percent : null })}<h2>${esc(e.name)}</h2>
        ${e.kind ? `<span class="kind ${esc(e.kind)}">${esc(e.kind)}</span>` : ""}
        ${critBadge(e)}
        ${e.verified ? "" : `<span class="unver">verify</span>`}</div>
      <div class="ch2">${statusLine(c.status)}</div>
      ${uptimeHtml(c.uptime)}
      ${e.notes ? `<div class="cnotes">${esc(e.notes)}</div>` : ""}
    </div>

    ${explainHtml(x)}

    <dl class="about cardfacts">${facts.map(([k, v]) =>
      `<dt>${esc(k)}</dt><dd class="${k === "Address" || k === "Ports" || k === "Credentials" ? "mono" : ""}">${esc(v)}</dd>`).join("")}</dl>
    ${e.tags.length ? `<div class="cardtags">${tagHtml(e.tags)}</div>` : ""}
    ${link ? `<div class="setrow"><a class="btn" href="${esc(link)}" target="_blank" rel="noopener">Open ${ICON.ext}</a></div>` : ""}

    <div class="setsec"><h3>Upstream <i>what this needs</i></h3>${edgeList(c.edges.out, "out")}</div>
    <div class="setsec"><h3>Downstream <i>what needs this</i></h3>${edgeList(c.edges.in, "in")}</div>

    <div class="setsec"><h3>Add a link</h3>
      <div class="setrow linkform">
        <select id="lkType" aria-label="Relationship">${(META.edge_types || Object.keys(EDGE_LABEL)).map(t =>
          `<option value="${esc(t)}">${esc(EDGE_LABEL[t] || t)}</option>`).join("")}</select>
        <input id="lkTarget" list="entrylist" placeholder="entry name…" aria-label="Other entry">
        <button class="btn" id="lkAdd">Add</button>
      </div>
      <datalist id="entrylist">${(ALL.length ? ALL : ENTRIES)
        .filter(x => x.id !== e.id)
        .map(x => `<option value="${esc(x.name)}">`).join("")}</datalist>
    </div>

    <div class="setsec"><h3>What the sources see <i>agreements, not findings</i></h3>
      ${sightRows(c.sightings)}</div>

    <div class="setsec"><h3>Status history</h3>${obs}</div>
    <div class="setsec"><h3>Recent changes</h3>${changes}</div>

    <div class="sheetfoot">
      <button class="btn" id="cardRecheck">Re-check</button>
      <span class="spacer"></span>
      <button class="btn" id="cardEdit">Edit</button>
      <button class="btn primary" id="cardClose">Close</button>
    </div>`;

  $("#cardClose").onclick = () => closeCard();
  // Keyboard focus moves into the card, so Tab walks its contents rather than
  // the page behind it.
  $("#cardBody .sheetx")?.focus({ preventScroll: true });
  $("#cardEdit").onclick = () => {
    closeCard();
    const full = entryById(e.id) || e;
    openEdit(full);
  };
  $("#cardRecheck").onclick = async () => {
    await api("/api/status/refresh?entry_id=" + e.id, { method: "POST" });
    showCard(e.id);
  };
  $("#lkAdd").onclick = async () => {
    const name = $("#lkTarget").value.trim().toLowerCase();
    const target = (ALL.length ? ALL : ENTRIES).find(x => x.name.toLowerCase() === name);
    if (!target) { toast("Pick an entry from the list"); return; }
    try {
      await api("/api/edges", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ src: e.id, dst: target.id, type: $("#lkType").value }),
      });
      toast("Linked"); showCard(e.id);
    } catch { /* api() already reported it */ }
  };
}

/* A close button at the top of the long sheets. "Close" also sits at the
   bottom of the card, which on a long card meant scrolling to leave it. */
const SHEETX = `<button class="sheetx" data-sheetclose aria-label="Close" title="Close (Esc)">
  <svg viewBox="0 0 24 24" class="ico" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg></button>`;
document.addEventListener("click", ev => {
  const x = ev.target.closest("[data-sheetclose]");
  if (x) {
    // The card has its own close (history, focus); any other sheet just hides.
    if (x.closest("#cardModal")) closeCard(); else x.closest(".modal").hidden = true;
    return;
  }
  const go = ev.target.closest("[data-goto-sources]");
  if (go) { ev.preventDefault(); view = "settings"; applySetTab("sources"); applyView(); }
});

function closeCard() {
  $("#cardModal").hidden = true;
  cardId = null;
  // ...and returns to what opened the card, typically the row.
  if (cardReturnFocus?.isConnected) cardReturnFocus.focus({ preventScroll: true });
  cardReturnFocus = null;
  if (location.hash.startsWith("#/entry/")) history.pushState({}, "", location.pathname);
}

function routeFromHash() {
  const m = location.hash.match(/^#\/entry\/(\d+)$/);
  if (m) { showCard(+m[1], false); return; }
  $("#cardModal").hidden = true;
  cardId = null;
}
window.addEventListener("popstate", routeFromHash);
