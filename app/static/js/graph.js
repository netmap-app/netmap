/* NetMap front end — graph.js: Network › Topology › Graph, the drawn map.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines — tests/test_frontend.py checks. */

/* ================= topology graph ================= */
/* The tree answers "what runs on what" one parent at a time; this draws every
   link at once — cabling, hosting, dependencies, and the paths in from the
   internet. Hand-written SVG, no library: layers by kind (the internet, then
   hardware, VMs, containers, services, rules), each ordered by the average
   position of its neighbours so links cross as little as a few passes can
   manage. A homelab has tens to a few hundred entries; that is enough. */
const GRAPH_LAYER = { network: 1, hardware: 1, vm: 2, container: 3, service: 4 };
const GRAPH_W = 136, GRAPH_H = 34, GRAPH_GX = 14, GRAPH_GY = 70, GRAPH_ROW = 22;
const GRAPH_EDGE = {
  connects_to: "cabled to", runs_on: "runs on", depends_on: "depends on",
  exposed_by: "exposed by", resolves_to: "resolves to", backs_up_to: "backs up to",
};
let GRAPH_DATA = null;
let GRAPH_F = (() => {
  try { return JSON.parse(localStorage.getItem("netmap.graph") || "{}") || {}; }
  catch { return {}; }
})();

function graphSave() {
  try { localStorage.setItem("netmap.graph", JSON.stringify(GRAPH_F)); } catch { /* private */ }
}

/* Which nodes and links to draw, after the filters. */
function graphPick(entries, data, f) {
  let nodes = entries.filter(e => (!f.cat || e.category === f.cat) && (!f.zone || e.zone === f.zone));
  let ids = new Set(nodes.map(e => e.id));
  let links = (data.edges || []).filter(l => ids.has(l.src) && ids.has(l.dst) && l.src !== l.dst);
  const inet = new Map((data.internet || []).filter(x => ids.has(x.entry_id))
    .map(x => [x.entry_id, x.via]));
  if (f.exposed) {
    // The exposed entries and what they touch: the path in, one hop deep.
    const keep = new Set(inet.keys());
    for (const l of links)
      if (inet.has(l.src) || inet.has(l.dst)) { keep.add(l.src); keep.add(l.dst); }
    nodes = nodes.filter(e => keep.has(e.id));
    ids = keep;
    links = links.filter(l => keep.has(l.src) && keep.has(l.dst));
  }
  const linked = new Set(inet.keys());
  for (const l of links) { linked.add(l.src); linked.add(l.dst); }
  const hidden = f.unlinked ? 0 : nodes.filter(e => !linked.has(e.id)).length;
  if (!f.unlinked) nodes = nodes.filter(e => linked.has(e.id));
  return { nodes, links, inet, hidden };
}

/* x/y for every node. Pure: the same input always draws the same picture. */
function graphLayout(nodes, links, inet, width) {
  const kindOf = e => e.id === "internet" ? 0 : (GRAPH_LAYER[e.kind] || 5);
  const all = inet.size ? [{ id: "internet", name: "Internet", kind: "" }, ...nodes] : nodes;
  // Within one kind, what a node hangs off sits a row above it: the switch
  // above what is cabled to it, Home Assistant above its add-ons, the proxy
  // above what it exposes. (A link's src is the child: "Wiki runs_on VM".)
  const byId = new Map(all.map(e => [e.id, e]));
  const up = new Map(all.map(e => [e.id, []]));
  for (const l of links)
    if (kindOf(byId.get(l.src)) === kindOf(byId.get(l.dst))) up.get(l.src).push(l.dst);
  const depth = new Map();
  const depthOf = (id, seen = new Set()) => {
    if (depth.has(id)) return depth.get(id);
    if (seen.has(id)) return 0;                            // a loop: stop here
    seen.add(id);
    const d = Math.min(3, Math.max(0, ...up.get(id).map(p => depthOf(p, seen) + 1)));
    seen.delete(id);
    depth.set(id, d);
    return d;
  };
  const layerOf = e => kindOf(e) + depthOf(e.id) / 4;
  const nbr = new Map(all.map(e => [e.id, []]));
  for (const l of links) { nbr.get(l.src).push(l.dst); nbr.get(l.dst).push(l.src); }
  for (const id of inet.keys()) { nbr.get("internet").push(id); nbr.get(id).push("internet"); }

  const layers = new Map();
  for (const e of all) {
    const k = layerOf(e);
    if (!layers.has(k)) layers.set(k, []);
    layers.get(k).push(e);
  }
  const keys = [...layers.keys()].sort((a, b) => a - b);
  for (const k of keys)
    layers.get(k).sort((a, b) => (a.category || "").localeCompare(b.category || "")
                               || a.name.localeCompare(b.name));
  // Barycentre passes: each node moves toward the mean position of its
  // neighbours, alternating downward and upward sweeps.
  const pos = new Map();
  const place = () => keys.forEach(k => layers.get(k).forEach((e, i, a) =>
    pos.set(e.id, a.length > 1 ? i / (a.length - 1) : 0.5)));
  place();
  for (let pass = 0; pass < 6; pass++) {
    const order = pass % 2 ? [...keys].reverse() : keys;
    for (const k of order) {
      const row = layers.get(k);
      const at = new Map(row.map(e => {
        const ns = nbr.get(e.id).filter(n => pos.has(n));
        return [e.id, ns.length ? ns.reduce((s, n) => s + pos.get(n), 0) / ns.length : pos.get(e.id)];
      }));
      row.sort((a, b) => at.get(a.id) - at.get(b.id) || a.name.localeCompare(b.name));
      row.forEach((e, i) => pos.set(e.id, row.length > 1 ? i / (row.length - 1) : 0.5));
    }
  }
  // Long layers wrap into rows the width of the view, never wider.
  const cols = Math.max(1, Math.floor((width - 16 + GRAPH_GX) / (GRAPH_W + GRAPH_GX)));
  const xy = new Map();
  let y = 12;
  for (const k of keys) {
    const row = layers.get(k);
    for (let r = 0; r < row.length; r += cols) {
      const chunk = row.slice(r, r + cols);
      const w = chunk.length * (GRAPH_W + GRAPH_GX) - GRAPH_GX;
      const x0 = Math.max(8, (width - w) / 2);
      chunk.forEach((e, i) => xy.set(e.id, { x: x0 + i * (GRAPH_W + GRAPH_GX), y, node: e }));
      y += GRAPH_H + GRAPH_ROW;
    }
    y += GRAPH_GY - GRAPH_ROW;
  }
  return { xy, height: y - GRAPH_GY + GRAPH_ROW + 12 };
}

function graphPath(a, b) {
  const ax = a.x + GRAPH_W / 2, bx = b.x + GRAPH_W / 2;
  if (Math.abs(a.y - b.y) < 1) {                      // same row: arc over the top
    const lift = Math.min(60, 18 + Math.abs(ax - bx) / 6);
    return `M${ax},${a.y} C${ax},${a.y - lift} ${bx},${b.y - lift} ${bx},${b.y}`;
  }
  const [t, u] = a.y < b.y ? [a, b] : [b, a];
  const tx = t.x + GRAPH_W / 2, ux = u.x + GRAPH_W / 2;
  const y1 = t.y + GRAPH_H, y2 = u.y, m = (y1 + y2) / 2;
  return `M${tx},${y1} C${tx},${m} ${ux},${m} ${ux},${y2}`;
}

function graphSvg(pick, width) {
  const { xy, height } = graphLayout(pick.nodes, pick.links, pick.inet, width);
  const edges = pick.links.map(l => {
    const a = xy.get(l.src), b = xy.get(l.dst);
    const tip = `${a.node.name} ${GRAPH_EDGE[l.type] || l.type} ${b.node.name}${l.note ? " — " + l.note : ""}`;
    return `<path class="ge ge-${esc(l.type)}${l.derived ? " derived" : ""}" d="${graphPath(a, b)}"
      data-src="${l.src}" data-dst="${l.dst}"><title>${esc(tip)}</title></path>`;
  });
  for (const [id, via] of pick.inet) {
    const a = xy.get("internet"), b = xy.get(id);
    edges.push(`<path class="ge ge-internet" d="${graphPath(a, b)}" data-src="internet" data-dst="${id}">
      <title>${esc(`Internet → ${b.node.name}: ${via.join(", ")}`)}</title></path>`);
  }
  const nodes = [...xy.values()].map(({ x, y, node: e }) => {
    if (e.id === "internet") {
      return `<g class="gn gn-internet" transform="translate(${x},${y})">
        <rect width="${GRAPH_W}" height="${GRAPH_H}" rx="17"></rect>
        <text x="${GRAPH_W / 2}" y="${GRAPH_H / 2 + 4}" text-anchor="middle">Internet</text></g>`;
    }
    const st = (e.status || {}).up;
    const cls = st === true ? "up" : st === false ? "down" : "na";
    const name = e.name.length > 17 ? e.name.slice(0, 16) + "…" : e.name;
    const tip = [e.name, e.kind, e.ip, statusWhy(e.status || {})].filter(Boolean).join(" · ");
    return `<g class="gn${e.criticality === "critical" ? " gcrit" : ""}" data-card="${e.id}"
        data-gid="${e.id}" transform="translate(${x},${y})" aria-label="${esc(e.name)}">
      <title>${esc(tip)}</title>
      <rect width="${GRAPH_W}" height="${GRAPH_H}" rx="6"></rect>
      <circle class="gd ${cls}" cx="13" cy="${GRAPH_H / 2}" r="4"></circle>
      <text x="24" y="${GRAPH_H / 2 + 4}">${esc(name)}</text></g>`;
  });
  return `<svg class="gsvg" id="graphSvg" viewBox="0 0 ${width} ${height}" width="${width}"
      height="${height}" role="img" aria-label="Topology graph: ${pick.nodes.length} entries, ${
      pick.links.length} links">
    <g class="gedges">${edges.join("")}</g><g class="gnodes">${nodes.join("")}</g></svg>`;
}

/* The whole section body: filters, the drawing, a legend. Built as one string
   and swapped in, so a failure shows an error instead of half a picture. */
function graphHtml(entries, data, width) {
  const f = GRAPH_F;
  const pick = graphPick(entries, data, f);
  const cats = [...new Set(entries.map(e => e.category).filter(Boolean))].sort();
  const zones = [...new Set(entries.map(e => e.zone).filter(Boolean))].sort();
  const opt = (vals, cur) => vals.map(v =>
    `<option value="${esc(v)}"${v === cur ? " selected" : ""}>${esc(v)}</option>`).join("");
  const bar = `<div class="gbar">
      <select id="gCat" aria-label="Category"><option value="">All categories</option>${opt(cats, f.cat)}</select>
      <select id="gZone" aria-label="Zone"><option value="">All zones</option>${opt(zones, f.zone)}</select>
      <label class="ckf"><input type="checkbox" id="gExposed"${f.exposed ? " checked" : ""}> Only what the internet reaches</label>
      <label class="ckf"><input type="checkbox" id="gUnlinked"${f.unlinked ? " checked" : ""}> Unlinked entries too</label>
      <span class="hint" id="gCount">${pick.nodes.length} entries · ${pick.links.length} links${
        pick.hidden ? ` · ${pick.hidden} without links not drawn` : ""}</span>
    </div>`;
  const legend = `<div class="glegend">${["connects_to", "runs_on", "depends_on", "exposed_by"]
    .map(t => `<span><i class="gl ge-${t}"></i>${GRAPH_EDGE[t]}</span>`).join("")}
    <span><i class="gl ge-internet"></i>from the internet</span></div>`;
  const body = pick.nodes.length ? graphSvg(pick, width)
    : `<div class="empty-hint">${f.cat || f.zone || f.exposed
        ? "Nothing matches these filters."
        : "No links yet — map the hosts below, then re-derive links."}</div>`;
  return bar + `<div class="gscroll">${body}</div>` + legend;
}

function drawGraph() {
  const box = $("#graphBox");
  if (!box || !GRAPH_DATA) return;
  const entries = ALL.length ? ALL : ENTRIES;
  try {
    box.innerHTML = graphHtml(entries, GRAPH_DATA, Math.max(320, box.clientWidth - 4));
  } catch (err) {
    box.innerHTML = `<div class="empty-hint">The graph could not be drawn: ${esc(String(err))}</div>`;
    return;
  }
  const set = (k, v) => { GRAPH_F[k] = v; graphSave(); drawGraph(); };
  $("#gCat").onchange = ev => set("cat", ev.target.value);
  $("#gZone").onchange = ev => set("zone", ev.target.value);
  $("#gExposed").onchange = ev => set("exposed", ev.target.checked);
  $("#gUnlinked").onchange = ev => set("unlinked", ev.target.checked);
  // Pointing at a node lights up its links.
  const svg = $("#graphSvg");
  if (!svg) return;
  svg.addEventListener("mouseover", ev => {
    const g = ev.target.closest("[data-gid]");
    if (!g) return;
    const id = g.dataset.gid;
    svg.classList.add("focus");
    svg.querySelectorAll(".ge").forEach(p =>
      p.classList.toggle("hot", p.dataset.src === id || p.dataset.dst === id));
  });
  svg.addEventListener("mouseout", ev => {
    if (ev.relatedTarget?.closest?.("[data-gid]")) return;     // on to another node
    svg.classList.remove("focus");
    svg.querySelectorAll(".ge.hot").forEach(p => p.classList.remove("hot"));
  });
}

let GRAPH_RESIZE = null;
window.addEventListener("resize", () => {
  clearTimeout(GRAPH_RESIZE);
  GRAPH_RESIZE = setTimeout(() => { if (view === "network" && $("#graphBox")) drawGraph(); }, 200);
});
