/* NetMap front end — inventory.js: the Inventory: load(), filters, grouping, the list.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines — tests/test_frontend.py checks. */

/* ================= inventory ================= */
function groupOf(e) { return String(e[groupBy] || "").trim() || GROUPS[groupBy]; }
/* Repeating the grouping field in every row is wasted width, so the second
   column shows the other axis: group by host and you get Category there. */
const secondCol = () => (groupBy === "host" ? "category" : "host");

/* Which categories the reader has folded away, per browser. Same bargain as
   the topology tree: an arrangement you have to redo on every visit is one
   nobody makes. Keyed by grouping mode, because the buckets are different
   things when you group by host or by kind. */
const GFOLD = new Set((() => {
  try { return JSON.parse(localStorage.getItem("netmap.groups") || "[]"); }
  catch { return []; }
})());

function gkey(cat) { return groupBy + ":" + cat; }

function gsave() {
  try { localStorage.setItem("netmap.groups", JSON.stringify([...GFOLD])); }
  catch { /* private mode */ }
}

/* Categories in order of what is at stake in them: the most critical entry
   each holds decides, then the name. Alphabetical put "Client / IoT Devices"
   first and "Core Network" second; the phones and bulbs now sink to the end.
   Ranked over every entry, not the filtered ones, so the order holds still
   while you search. */
const CRIT_RANK = { critical: 0, important: 1, normal: 2, experimental: 3 };
function categoryOrder(cats) {
  const best = {};
  for (const e of (ALL.length ? ALL : ENTRIES))
    best[e.category] = Math.min(best[e.category] ?? 9, CRIT_RANK[e.criticality] ?? 4);
  return [...cats].sort((a, b) => (best[a] ?? 9) - (best[b] ?? 9)
    || a.localeCompare(b, undefined, { sensitivity: "base" }));
}

function renderList() {
  const groups = {};
  for (const e of ENTRIES) (groups[groupOf(e)] ||= []).push(e);
  // the "nothing set" bucket always sinks to the bottom
  const empty = GROUPS[groupBy];
  const cats = (groupBy === "category" ? categoryOrder(Object.keys(groups))
                : Object.keys(groups).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" })))
    .sort((a, b) => (a === empty) - (b === empty));

  if (!ENTRIES.length) { $("#listbody").innerHTML = `<div class="empty">Nothing matches.</div>`; return; }

  $("#listbody").innerHTML = cats.map(cat => {
    const rows = groups[cat];
    const up = rows.filter(r => r.status && r.status.up === true).length;
    const down = rows.filter(r => r.status && r.status.up === false).length;
    const open = !GFOLD.has(gkey(cat));
    return `
    <div class="groupname" data-open="${open}">
      <button class="gcar" data-gtog="${esc(cat)}" aria-expanded="${open}"
              aria-label="${open ? "Collapse" : "Expand"} ${esc(cat)}"></button>
      <span class="gt">${esc(cat)}</span>
      <span class="rule"></span>
      <span class="gs">
        <span>${rows.length} entr${rows.length === 1 ? "y" : "ies"}</span>
        ${up ? `<span class="gu"><i></i>${up} up</span>` : ""}
        ${down ? `<span class="gd"><i></i>${down} down</span>` : ""}
      </span>
    </div>
    <div class="gbody"${open ? "" : " hidden"}>
    <table>
      <colgroup><col style="width:30px"><col style="width:22%"><col style="width:11%">
        <col style="width:12%"><col style="width:11%"><col style="width:12%"><col><col style="width:76px"></colgroup>
      <thead><tr><th><span class="vh">Status</span></th><th>Service</th><th>${secondCol() === "host" ? "Host" : "Category"}</th><th>Address</th>
        <th>Ports</th><th>Access</th><th>Notes</th><th><span class="vh">Actions</span></th></tr></thead>
      <tbody>${rows.map(rowHtml).join("")}</tbody>
    </table>
    <div class="cards">${rows.map(cardHtml).join("")}</div>
    </div>`;
  }).join("");
}

/* Three deliberate lines: what it is called, what it is, what it is labelled.
   Previously all of it ran together on one line and wrapped wherever it
   happened to fit, so two rows with the same badges could break differently
   and the column read as noise. */
function nameCell(e, link) {
  const badges = [
    e.kind ? `<span class="kind ${esc(e.kind)}">${esc(e.kind)}</span>` : "",
    critBadge(e),
    e.verified ? "" : `<span class="unver">verify</span>`,
  ].filter(Boolean).join("");
  return `<div class="name">${entGlyph(e)}${
      link ? `<a href="${esc(link)}" target="_blank" rel="noopener">${esc(e.name)}</a>`
           : esc(e.name)}${
      e.pinned ? `<span class="pin" title="Pinned to Quick links">${ICON.pin}</span>` : ""}</div>
    ${badges ? `<div class="badgerow">${badges}</div>` : ""}
    ${e.tags.length ? `<div class="tagrow">${tagHtml(e.tags)}</div>` : ""}`;
}

/* Ports, for scanning rather than for reading.
   The field is free text and people write what a port is for — "5000/5001
   (DSM), 80/443 (DSM redirect), 22 (SSH)…" — which is worth having and is
   the wrong thing in a table cell: on the NAS rows it wrapped into twenty
   lines and pushed every other column off the screen. The numbers are what
   you scan a table for; the prose is what you open the entry for. So the cell
   shows the numbers in the order they were written, caps the list, and keeps
   the original text on hover.
   "5000/5001" is two ports, and a bare "2211 → 22" is two as well, so digits
   are taken in order and de-duplicated rather than split on commas. */
const PORT_CAP = 6;
function portsCell(e) {
  const raw = (e.ports || "").trim();
  if (!raw) return nil();
  const nums = [...new Set((raw.match(/\d{1,5}/g) || [])
    .map(Number).filter(n => n > 0 && n < 65536))];
  if (!nums.length) return `<span class="notes">${esc(raw)}</span>`;
  const show = nums.slice(0, PORT_CAP), rest = nums.length - show.length;
  return `<span class="ports" title="${esc(raw)}">${
    show.map(n => `<span class="pnum">${n}</span>`).join("")}${
    rest ? `<span class="pmore" title="${esc(raw)}">+${rest}</span>` : ""}</span>`;
}

/* An empty cell should say "nothing here", not look like a rendering fault. */
const nil = () => `<span class="nil" title="not recorded">—</span>`;

function rowHtml(e) {
  const link = linkFor(e);
  const lat = e.status && e.status.up ? `<span class="lat">${e.status.latency_ms}ms</span>` : "";
  return `<tr data-id="${e.id}">
    <td>${dot(e)}</td>
    <td>${nameCell(e, link)}</td>
    <td class="notes">${e[secondCol()] ? esc(e[secondCol()]) : nil()}</td>
    <td class="mono">${e.ip ? esc(e.ip) : nil()}</td>
    <td>${portsCell(e)}${lat}</td>
    <td class="notes">${e.protocol ? esc(e.protocol) : nil()}</td>
    <td class="notes"><div class="notecell">${e.notes ? esc(e.notes) : nil()}</div></td>
    <td><div class="acts">
      <button class="iconbtn" data-edit="${e.id}" title="Edit" aria-label="Edit ${esc(e.name)}">${ICON.edit}</button>
      <button class="iconbtn" data-recheck="${e.id}" title="Re-check" aria-label="Re-check ${esc(e.name)}">${ICON.recheck}</button>
    </div></td>
  </tr>`;
}

/* On a phone the classification badges had never been rendered at all — the
   three-line treatment above is a table layout, and the card is a different
   component. Here they share one wrapping row with the tags at the foot of the
   card, because vertical space is the scarce thing on a phone and horizontal
   space is not. */
function metaRow(e) {
  const bits = [
    e.kind ? `<span class="kind ${esc(e.kind)}">${esc(e.kind)}</span>` : "",
    critBadge(e),
    e.verified ? "" : `<span class="unver">verify</span>`,
    tagHtml(e.tags),
  ].filter(Boolean).join("");
  return bits ? `<div class="kv metarow">${bits}</div>` : "";
}

function cardHtml(e) {
  const link = linkFor(e);
  return `<div class="card" data-id="${e.id}">
    <div class="row1">${dot(e)}
      <div class="name">${link ? `<a href="${esc(link)}" target="_blank" rel="noopener">${esc(e.name)}</a>` : esc(e.name)}</div>
      <button class="iconbtn" data-edit="${e.id}" aria-label="Edit ${esc(e.name)}" title="Edit">${ICON.edit}</button>
    </div>
    <div class="kv mono">${e.ip ? esc(e.ip) : nil()}${e.ports ? ` <span class="sep">:</span> ` + portsCell(e) : ""}</div>
    <div class="kv">${[e.host || "no host", e.protocol].filter(Boolean).map(esc).join(" · ")}</div>
    ${e.notes ? `<div class="kv notecell">${esc(e.notes)}</div>` : ""}
    ${metaRow(e)}
  </div>`;
}

// [filter key, label, values, chip data attribute, prefix]
const FILTER_GROUPS = [
  ["kind", "Kind", () => META.kinds, "kindchip", ""],
  ["criticality", "Criticality", () => META.criticalities, "critchip", ""],
  ["zone", "Zone", () => META.zones, "zonechip", ""],
  ["tag", "Tag", () => META.tags, "tagchip", "#"],
];

function renderChips() {
  document.querySelectorAll("[data-group]").forEach(b =>
    b.classList.toggle("on", b.dataset.group === groupBy));
  if (view !== "inventory") { $("#chips").innerHTML = ""; return; }
  const anyFilter = filter.category || filter.tag || filter.kind || filter.criticality || filter.zone;
  // The strip carries the categories — the one filter everything has. Kind,
  // criticality, zone and tags (thirty-odd more chips, two-thirds of them
  // scrolled out of sight) moved behind "Filters"; whichever of those is
  // active shows here as a chip that removes it.
  const sec = FILTER_GROUPS.find(([k]) => filter[k]);
  $("#chips").innerHTML = [`<span class="chip ${anyFilter ? "" : "on"}" data-cat="">All</span>`]
    .concat(sec ? [`<span class="chip on" data-${sec[3]}="${esc(filter[sec[0]])}"
        title="Remove this filter">${esc(sec[1])}: ${esc(filter[sec[0]])} ✕</span>`] : [])
    .concat(categoryOrder(META.categories).map(x =>
      `<span class="chip ${filter.category === x ? "on" : ""}" data-cat="${esc(x)}">${esc(x)}</span>`)).join("");
  $("#filterBtn").classList.toggle("on", !!sec);
  $("#filterPop").innerHTML = FILTER_GROUPS.map(([k, label, list, attr, pre]) => {
    const vals = (typeof list === "function" ? list() : list) || [];
    return vals.length ? `<div class="fgroup"><div class="fglabel">${esc(label)}</div>
      <div class="fgchips">${vals.map(x =>
        `<span class="chip ${k === "criticality" ? "crit-" + esc(x) : ""} ${filter[k] === x ? "on" : ""}" data-${attr}="${esc(x)}">${pre}${esc(x)}</span>`).join("")}</div></div>` : "";
  }).join("") || `<div class="hint">Nothing else to filter by.</div>`;
  $("#catlist").innerHTML = META.categories.map(x => `<option value="${esc(x)}">`).join("");
  $("#zonelist").innerHTML = (META.zones || []).map(x => `<option value="${esc(x)}">`).join("");
}

function applyView() {
  // A new view starts at its top. It used to keep the previous view's scroll
  // position, so Inventory opened halfway down after a long Overview.
  if (shownView !== null && shownView !== view) window.scrollTo(0, 0);
  $("#overview").hidden = view !== "overview";
  $("#list").hidden = view !== "inventory";
  $("#network").hidden = view !== "network";
  $("#netJump").hidden = view !== "network";
  $("#changes").hidden = view !== "changes";
  $("#settingsPage").hidden = view !== "settings";
  if (view === "changes" && shownView !== "changes") renderChanges().catch(() => {});
  // Rebuilding this on every applyView made the poll repaint the whole tree
  // once a minute. Build it on entry; load() rebuilds it when data moves.
  if (view === "network" && shownView !== "network") renderNetwork().catch(() => {});
  if (view === "settings" && shownView !== "settings") renderSettingsPage().catch(() => {});
  shownView = view;
  // The name alone. The subtitle under it explained the page to a reader who
  // has already chosen it from a list of four.
  const PT = { overview: "Overview", inventory: "Inventory",
               network: "Network", changes: "Changes", settings: "Settings" };
  $("#ptName").textContent = PT[view] || "";
  document.querySelectorAll(".vtab,.rnav[data-view]").forEach(
    b => b.classList.toggle("on", b.dataset.view === view));
  $("#chipsrow").hidden = view !== "inventory";

  renderChips();
}

/* A count on a view tab. Findings are news from a system NetMap does not
   control, so they have to be visible from whichever tab you are on — the
   Network view is no use as a notification if you have to go there to be
   notified. */
function badge(viewName, n) {
  // Two nav surfaces now — the rail on a wide screen, the tab group on a
  // narrow one. Only one of them is visible at a time, and which one is a
  // question for CSS, so both are kept current.
  document.querySelectorAll(
    `.vtab[data-view="${viewName}"],.rnav[data-view="${viewName}"]`).forEach(tab => {
    let b = tab.querySelector(".vbadge");
    if (!n) { if (b) b.remove(); return; }
    if (!b) { b = document.createElement("span"); b.className = "vbadge"; tab.appendChild(b); }
    b.hidden = false;
    b.textContent = n > 99 ? "99+" : n;
    b.title = `${n} reconciliation finding${n === 1 ? "" : "s"}`;
  });
}

/* What the page actually displays, as one short string. If this has not moved
   there is nothing to repaint — which is the difference between a poll you
   never notice and a page that visibly blinks every minute. */
function signature(rows, cf) {
  // Data only. View and grouping changes are rendered by the handlers that
  // make them, so including them here would just force one extra repaint.
  return rows.map(e => `${e.id}.${e.updated_at}.${e.status && e.status.up}`).join("|")
    + "#" + (cf ? cf.count : 0)
    + "#" + (FINDINGS.findings || []).map(f => f.key).join(",")
    // Source health too: a rescan or a source failing changes the colours and
    // the "checked" times even when the inventory itself did not move.
    + "#" + ((SRC_HEALTH && SRC_HEALTH.health) || [])
      .map(h => `${h.source}.${h.ok}.${h.last_ok}.${h.error}`).join(",");
}
let lastSig = "";

async function load(opts = {}) {
  // Before the first paint, not after: a row that renders without its mark
  // and grows one a moment later is a visible flinch on every cold load.
  if (!Object.keys(ICONS).length)
    try { ICONS = (await api("/api/icons")).icons || {}; } catch { /* glyphs */ }
  const qs = new URLSearchParams();
  if (filter.q) qs.set("q", filter.q);
  if (filter.category) qs.set("category", filter.category);
  if (filter.tag) qs.set("tag", filter.tag);
  if (filter.kind) qs.set("kind", filter.kind);
  if (filter.criticality) qs.set("criticality", filter.criticality);
  if (filter.zone) qs.set("zone", filter.zone);
  const [rows, meta, cf, fnd] = await Promise.all([
    api("/api/entries?" + qs), api("/api/meta"),
    api("/api/conflicts").catch(() => ({ count: 0, conflicts: [] })),
    // Free: the server answers from its last background scan, so polling this
    // never reaches out to Docker or the firewall.
    api("/api/discovery/findings").catch(() => ({ total: 0, findings: [] })),
    // Also free; carries each source's name, which an entry's "what the
    // sources say" needs on any page, not only on Network.
    api("/api/discovery/summary").then(x => { SRC_HEALTH = x; }).catch(() => {}),
  ]);
  FINDINGS = fnd;
  LAST_REFRESH = Date.now();
  pageFreshness();
  const sig = signature(rows, cf);
  if (opts.quiet && sig === lastSig) return;      // nothing moved; leave the DOM alone
  lastSig = sig;

  ENTRIES = rows; META = meta; CONFLICTS = cf;
  badge("network", FINDINGS.total);
  // the overview always describes the whole inventory, never the current filter
  const filtered = filter.q || filter.category || filter.tag || filter.kind
    || filter.criticality || filter.zone;
  // Before renderList: the category order is ranked over the whole inventory.
  ALL = filtered ? await api("/api/entries") : rows;
  renderList();
  // Filtered, the count has to say what it is showing AND out of what — a bare
  // "12 entries" on a filtered table looks like the inventory shrank.
  $("#count").innerHTML = filtered
    ? `<b>${ENTRIES.length}</b> of ${ALL.length} entries`
    : `<b>${ENTRIES.length}</b> entries`;
  renderOverview(ALL);
  applyView();
  if (view === "network" && opts.quiet) renderNetwork().catch(() => {});
}
