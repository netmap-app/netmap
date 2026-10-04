/* NetMap front end - network.js: the Network view: topology, derived links, deep scan.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

/* ================= network view ================= */
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function subnets(rows) {
  const nets = {};
  for (const e of rows) {
    const m = (e.ip || "").trim().match(IPV4);
    if (!m) continue;
    const net = `${m[1]}.${m[2]}.${m[3]}.0/24`;
    (nets[net] ||= {}).addrs ||= {};
    (nets[net].addrs[+m[4]] ||= []).push(e);
  }
  // A subnet whose every entry is on the WAN side belongs to the ISP: the
  // modem's own management subnet is one address that will never be allocated
  // here, and drawing "1 used · 253 free" invites planning that is not this
  // network's to do.
  for (const [net, v] of Object.entries(nets)) {
    const here = Object.values(v.addrs).flat();
    if (here.length && here.every(e => (e.zone || "").toUpperCase() === "WAN"))
      delete nets[net];
  }
  return Object.entries(nets).map(([net, v]) => {
    const used = Object.keys(v.addrs).length;
    const dup = Object.values(v.addrs).filter(a => a.length > 1).length;
    // Occupied-but-untracked addresses are not free, and saying they are is
    // the bug this layer exists to fix.
    let seen = 0;
    for (let i = 1; i <= 254; i++)
      if (!v.addrs[i] && SEEN[net.replace(/0\/24$/, "") + i]) seen++;
    return { net, used, dup, seen, free: 254 - used, addrs: v.addrs };
  }).sort((a, b) => b.used - a.used);
}

function portTable(rows) {
  const ports = {};
  for (const e of rows) {
    for (const m of (e.ports || "").matchAll(/\b(\d{1,5})\b/g)) {
      const p = +m[1];
      if (!(p > 0 && p < 65536)) continue;
      (ports[p] ||= []).push(e);
    }
  }
  return Object.entries(ports).map(([p, es]) => ({
    port: +p, entries: es,
    hosts: new Set(es.map(e => e.ip).filter(Boolean)).size,
  })).sort((a, b) => b.entries.length - a.entries.length || a.port - b.port);
}

// Which branches the reader has folded away. Kept per browser: a tree is
// something you arrange to suit what you are looking at, and having to
// re-arrange it on every visit is the reason nobody collapses anything.
const TFOLD = new Set((() => {
  try { return JSON.parse(localStorage.getItem("netmap.tree") || "[]"); }
  catch { return []; }
})());

function tsave() {
  try { localStorage.setItem("netmap.tree", JSON.stringify([...TFOLD])); }
  catch { /* private mode */ }
}

function tcount(n) {
  return n.children.reduce((a, c) => a + 1 + tcount(c), 0);
}

function treeHtml(nodes, depth = 0) {
  return nodes.map(n => {
    const kids = n.children.length;
    const open = !TFOLD.has(String(n.id));
    // The address, ports and cable annotation are reference, not structure. On
    // every row they turned the shape of the tree into a wall of text; on
    // hover they are still one gesture away. `via` arrives already normalised
    // - db.topology() reduces four phrasings of "plugged into a port" to one
    // and drops provenance.
    //
    // The address is no longer hidden when it matches the parent's. That
    // suppression saved a repetition nobody could see anyway, and cost every
    // container on a shared host its tooltip entirely: same address as its
    // host, provenance-only `via`, nothing left to show. On a shared address
    // it is the ports beside it that identify the row.
    const tip = [n.kind || "", n.criticality === "critical" ? "critical" : "",
                 n.ip || "", n.ports || "", n.via || ""]
      .filter(Boolean).join("  ·  ");
    // Status and the product's mark are the two things worth seeing on every
    // row - a glance down the tree shows what is up and what each thing is.
    // The address sits in a faint column at the far right: available without
    // a hover, but out of the tree's shape, which is what the comment above
    // protects. It goes away on narrow screens.
    const e = entryById(n.id) || n;
    const port = (n.ports || "").match(/\d{1,5}/);
    return `
    <div class="tn${kids ? " has" : ""}" style="--d:${depth}" data-open="${open}"
         ${tip ? `title="${esc(tip)}"` : ""}>
      ${kids ? `<button class="tcar" data-tog="${n.id}" aria-expanded="${open}"
                  aria-label="${open ? "Collapse" : "Expand"} ${esc(n.name)}"></button>`
             : `<span class="tcar"></span>`}
      ${dot(e)}${entGlyph(e)}
      <span class="tname" data-card="${n.id}">${esc(n.name)}</span>
      ${kids ? `<span class="tnum">${tcount(n)}</span>` : ""}
      ${n.ip ? `<span class="tmeta mono">${esc(n.ip)}${port ? ":" + port[0] : ""}</span>` : ""}
    </div>${kids ? `<div class="tkids">${treeHtml(n.children, depth + 1)}</div>` : ""}`;
  }).join("");
}

/* ================= watching ================= */
/* Devices a person is keeping an eye on without adding them to the
   inventory (app/watch.py). Each says what the sources know, whether it is
   on the network now, and the note; it ends with Create entry, Ignore or
   Stop watching - or by itself after 90 days unseen. */
let WATCH = { watching: [], drop_days: 90 };
// A note being typed survives the re-render a landing scan causes.
const WNOTE_DRAFT = {};

function watchHtml() {
  const ws = WATCH.watching || [];
  if (!ws.length) return "";
  const day = (ts) => ts ? whenScan(ts) : "-";
  return `<div class="ovsec" id="watchSec">
    <div class="ovhead"><h2>Watching</h2>
      <span class="hint">${ws.length} device${ws.length === 1 ? "" : "s"} · ${
        ws.filter(w => w.online).length} on the network now</span>
      <span class="hint" data-tip>Devices you are not ready to add or ignore. They stay
        out of Needs you; a notification says when one is back. Dropped after
        ${WATCH.drop_days} days unseen.</span></div>
    <div class="cflist">${ws.map(w => {
      const ip = (w.ips || []).find(x => IPV4.test(x)) || "";
      return `<div class="cf wcard ${w.online ? "f-new" : "f-stopped"}" data-wkey="${esc(w.key)}">
        <div class="cfh"><span class="sev">${w.online ? "online" : "away"}</span>
          <b>${esc(w.name)}</b></div>
        <div class="cfd">${[
          w.mac ? `<span class="mono">${esc(w.mac)}</span>` : "",
          w.randomised ? "randomised MAC" : esc(w.vendor || ""),
          (w.ips || []).length ? `at <span class="mono">${esc(w.ips.join(", "))}</span>` : "",
          w.sources.length ? `seen by ${esc(w.sources.map(srcLabel).join(", "))}` : "",
        ].filter(Boolean).join(" · ")}</div>
        <div class="cfd">first seen ${esc(day(w.first_seen))} · last seen ${
          esc(w.online ? "now" : day(w.last_seen))}${w.online ? ""
          : ` · dropped on ${esc((w.drop_on || "").split("-").reverse().join("."))} if not seen again`}</div>
        <div class="setrow wnote">
          <input class="wnoteIn" maxlength="500" value="${esc(w.key in WNOTE_DRAFT
            ? WNOTE_DRAFT[w.key] : w.note || "")}"
                 placeholder="Note - what you know so far" aria-label="Note on ${esc(w.name)}">
          <button class="btn sm" data-wsave="${esc(w.key)}">Save note</button>
        </div>
        <div class="setrow">
          ${ip ? `<button class="btn sm" data-wscan="${esc(ip)}">Scan its ports</button>` : ""}
          <button class="btn primary sm" data-wcreate="${esc(w.key)}">Create entry</button>
          <button class="btn sm" data-wignore="${esc(w.key)}">Ignore</button>
          <button class="btn sm" data-wstop="${esc(w.key)}">Stop watching</button>
        </div>
      </div>`;
    }).join("")}</div>
  </div>`;
}

function wireWatch(box) {
  const find = (key) => (WATCH.watching || []).find(w => w.key === key);
  const again = async () => { await load(); if (view === "network") renderNetwork(); };
  box.querySelectorAll("[data-wsave]").forEach(b => {
    b.onclick = async () => {
      const inp = b.closest(".wcard").querySelector(".wnoteIn");
      try {
        await api("/api/watch", {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ key: b.dataset.wsave, note: inp.value }),
        });
        delete WNOTE_DRAFT[b.dataset.wsave];
        const w = find(b.dataset.wsave);
        if (w) w.note = inp.value.trim();
        toast("Note saved");
      } catch { /* api() already toasted why */ }
    };
  });
  box.querySelectorAll(".wnoteIn").forEach(inp => {
    inp.oninput = () => { WNOTE_DRAFT[inp.closest(".wcard").dataset.wkey] = inp.value; };
    inp.onkeydown = (ev) => {
      if (ev.key === "Enter") inp.closest(".wcard").querySelector("[data-wsave]").click();
    };
  });
  box.querySelectorAll("[data-wscan]").forEach(b => {
    b.onclick = () => {
      $("#dsIp").value = b.dataset.wscan;
      dsStart(b.dataset.wscan);
      $("#dsbox").scrollIntoView({ block: "center", behavior: "smooth" });
    };
  });
  box.querySelectorAll("[data-wcreate]").forEach(b => {
    b.onclick = () => {
      const w = find(b.dataset.wcreate);
      if (!w) return;
      openEdit(null);
      const set = (id, v) => {
        const f = $("#" + id);
        if (f && v) { f.value = v; f.dispatchEvent(new Event("input")); }
      };
      set("f_name", w.name);
      set("f_ip", (w.ips || [])[0] || "");
      set("f_mac", w.mac);
      set("f_kind", "hardware");
      set("f_notes", [`First seen ${(w.first_seen || "").slice(0, 10)}`,
                      w.vendor, w.note].filter(Boolean).join("; ") + ".");
      $("#f_verified").checked = false;
      $("#f_name").focus();
    };
  });
  box.querySelectorAll("[data-wignore],[data-wstop]").forEach(b => {
    b.onclick = async () => {
      const ignore = !!b.dataset.wignore;
      const key = b.dataset.wignore || b.dataset.wstop;
      try {
        await api(`/api/watch?key=${encodeURIComponent(key)}${ignore ? "&ignore=true" : ""}`,
                  { method: "DELETE" });
      } catch { return; }
      toast(ignore ? "Ignored - it will not come back" : "No longer watched");
      const src = ((find(key) || {}).finding || "").split(":")[0];
      if (src && !ignore) await scanOne(src);
      await again();
    };
  });
}

async function renderNetwork() {
  const box = $("#network");
  // Only show a placeholder the first time; a refresh swaps the finished
  // markup in instead of flashing "Loading…" over what is already there.
  if (!box.firstChild) box.innerHTML = `<div class="empty-hint">Loading…</div>`;
  api("/api/presence").then(r => {
    SEEN = {};
    for (const x of (r.presence || [])) SEEN[x.ip] = x;
  }).catch(() => {});
  // The live sweep - eight sources, one of them ~2,000 port probes - runs
  // behind the page instead of in front of it. Reconciliation renders from
  // whatever is cached (nothing, on a first-ever visit) and fills in, with
  // the rail's "checked" time along with it, once the scan lands.
  if (!SCAN) scanAll(false).then(() => {
    renderOverview(ALL);
    if (view === "network") renderNetwork();
  });
  // The graph needs width; a phone gets the tree, with a note saying so.
  const graph = topoMode === "graph";
  const narrow = matchMedia("(max-width: 640px)").matches;
  const [topo, plan] = await Promise.all([
    graph && !narrow
      ? api("/api/graph").then(g => { GRAPH_DATA = g; return []; })
      : api("/api/topology?mode=" + encodeURIComponent(graph ? "tree" : topoMode)),
    api("/api/edges/derive?dry_run=true", { method: "POST" }).catch(() => null),
    // Never scans - safe to re-read on every visit, same as the nav badge does.
    api("/api/discovery/summary").then(s => { SRC_HEALTH = s; }).catch(() => {}),
    api("/api/watch").then(w => { WATCH = w; }).catch(() => {}),
  ]);
  const rows = ALL.length ? ALL : ENTRIES;
  const roots = topo.filter(n => n.children.length);
  const loose = topo.filter(n => !n.children.length);

  const unmapped = (plan && plan.unmapped || []);
  const unmappedHtml = !unmapped.length ? "" : `
    <div class="ovsec">
      <div class="ovhead"><h2>Unmapped hosts</h2>
        <span class="hint">${unmapped.length} host names NetMap cannot place</span></div>
      <div class="cflist">${unmapped.map(u => `
        <div class="cf">
          <div class="cfh"><b class="mono">${esc(u.host)}</b>
            <span class="cfd">${u.count} entr${u.count === 1 ? "y" : "ies"} - ${esc(u.examples.join(", "))}</span></div>
          <div class="setrow">
            <input class="hmIn" list="entrylist2" data-host="${esc(u.host)}" placeholder="which entry is this?">
            <button class="btn hmSet" data-host="${esc(u.host)}">Map</button>
          </div>
        </div>`).join("")}</div>
      <datalist id="entrylist2">${rows.map(x => `<option value="${esc(x.name)}">`).join("")}</datalist>
    </div>`;

  const nets = subnets(rows);
  const ports = portTable(rows);
  // A port used once is a fact; a port used twice is a question. Lead with the
  // questions and keep the long tail as chips.
  const shared = ports.filter(p => p.entries.length > 1);
  const single = ports.filter(p => p.entries.length === 1);

  const ae = document.activeElement;
  const typing = ae && ae.classList.contains("wnoteIn") ? ae.closest(".wcard").dataset.wkey : null;
  box.innerHTML = discoveryHtml() + watchHtml() + `
    <div class="ovsec">
      <div class="ovhead"><h2>Topology</h2>
        <span class="tabs">${["tree", "physical", "deps", "graph"].map(m =>
          `<button class="tab${m === topoMode ? " on" : ""}" data-topo="${m}">${
            m === "deps" ? "Dependencies" : m[0].toUpperCase() + m.slice(1)}</button>`).join("")}</span>
        <span class="hint" data-tip>${esc(TOPO_HINT[topoMode])}</span>
        ${graph ? "" : `<span class="more" id="tfoldall">Collapse all</span>`}
        <span class="more" id="rederive">Re-derive links</span></div>
      ${graph && !narrow ? `<div class="card2 gwrap" id="graphBox"></div>` : `
      ${graph ? `<div class="empty-hint gnarrow">The graph needs a wider screen - here is the tree.</div>` : ""}
      <div class="card2 tree">${roots.length ? treeHtml(roots)
        : `<div class="empty-hint">${topoMode === "deps"
            ? "Nothing declares a dependency yet - add <code>depends on</code> links on a service card."
            : topoMode === "physical"
            ? "No cabling recorded yet - UniFi derives it; re-derive links."
            : "No <code>runs on</code> links yet - map the hosts below, then re-derive."}</div>`}
        ${loose.length && topoMode === "tree" ? `<div class="loose"><span class="lh">Not placed (${loose.length})</span>
          ${loose.map(n => `<span class="lchip" data-card="${n.id}">${esc(n.name)}</span>`).join("")}</div>` : ""}
      </div>`}
    </div>
    ${unmappedHtml}
    <div class="ovsec">
      <div class="ovhead"><h2>Addresses</h2><span class="hint" data-tip>Every /24 in the inventory.</span></div>
      <div class="card2">${nets.map(n => `
        <div class="subnet">
          <div class="snh"><b class="mono">${esc(n.net)}</b>
            <span class="hint">${n.used} used · ${n.free - n.seen} free${
              n.seen ? ` · <span class="seenw">${n.seen} seen, not tracked</span>` : ""}${
              n.dup ? ` · <span class="dupw">${n.dup} shared</span>` : ""}</span></div>
          <div class="snbar" data-net="${esc(n.net)}">${Array.from({ length: 254 }, (_, i) => {
            const a = n.addrs[i + 1];
            const cls = a ? (a.length > 1 ? "dup" : "on")
              : (SEEN[addrOf(n.net, i + 1)] ? "seen" : "free");
            return `<i class="${cls}" data-a="${i + 1}"></i>`;
          }).join("")}</div>
          <div class="snread" data-read="${esc(n.net)}"><span class="hint">Hover or tap an address for detail - or Tab here and use the arrow keys</span></div>
        </div>`).join("")}
      </div>
    </div>

    <div class="ovsec">
      <div class="ovhead"><h2>Ports</h2>
        <span class="hint">${shared.length} used by more than one entry · ${single.length} used once</span>
        <span class="more" id="portToggle">${portsAll ? "Show shared only" : "Show all"}</span></div>
      <div class="card2">
        <div class="ptable">${(portsAll ? ports : shared).map(p => `
          <div class="prow">
            <span class="pp mono" data-port="${p.port}">${p.port}</span>
            <span class="pe">${p.entries.slice(0, 6).map(e =>
              `<span class="lchip" data-card="${e.id}">${esc(e.name)}</span>`).join("")}
              ${p.entries.length > 6 ? `<span class="pmore">+${p.entries.length - 6}</span>` : ""}</span>
            <span class="pc">${p.hosts} host${p.hosts === 1 ? "" : "s"}</span>
          </div>`).join("") || `<div class="empty-hint">No port is used twice.</div>`}
        </div>
        ${portsAll ? "" : `<div class="singles">${single.map(p =>
          `<span class="lchip"><b class="mono" data-port="${p.port}">${p.port}</b> <span data-card="${p.entries[0].id}">${esc(p.entries[0].name)}</span></span>`).join("")}</div>`}
      </div>
    </div>

    <div class="ovsec">
      <div class="ovhead"><h2>Deep scan</h2>
        <span class="hint" data-tip>All 65535 ports of one address, on demand.</span></div>
      <div class="card2">
        <div class="setrow">
          <input id="dsIp" list="dsips" placeholder="10.0.0.22"
                 autocomplete="off" spellcheck="false">
          <button class="btn" id="dsGo">Scan</button>
        </div>
        <datalist id="dsips">${[...new Set(rows.map(x => (x.ip || "").trim())
          .filter(x => IPV4.test(x)))].sort().map(x =>
          `<option value="${esc(x)}">`).join("")}</datalist>
        <div id="dsbox"></div>
      </div>
    </div>`;

  if (graph && !narrow) drawGraph();
  $("#dsGo").onclick = () => dsStart($("#dsIp").value.trim());
  $("#dsIp").onkeydown = (ev) => { if (ev.key === "Enter") $("#dsGo").click(); };
  dsPaint();
  if (DS && DS.state === "running") dsPoll();
  else api("/api/scan/deep").then(j => { DS = j; dsPaint();
    if (j && j.state === "running") dsPoll(); }).catch(() => {});

  $("#portToggle").onclick = () => { portsAll = !portsAll; renderNetwork(); };
  box.querySelectorAll("[data-topo]").forEach(b => {
    b.onclick = () => {
      topoMode = b.dataset.topo;
      try { localStorage.setItem("netmap.topo", topoMode); } catch { /* private mode */ }
      renderNetwork();
    };
  });
  wireStrip(box, nets);
  wireWatch(box);
  if (typing) {
    const inp = box.querySelector(`.wcard[data-wkey="${CSS.escape(typing)}"] .wnoteIn`);
    if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
  }

  box.querySelectorAll("[data-rescan]").forEach(el => {
    el.onclick = async () => {
      toast("Scanning…"); await scanOne(el.dataset.rescan); renderNetwork();
    };
  });
  box.querySelectorAll("[data-fmore],[data-fless]").forEach(el => {
    const src = el.dataset.fmore || el.dataset.fless;
    el.onclick = () => { findingsAll[src] = !!el.dataset.fmore; renderNetwork(); };
  });
  $("#rederive").onclick = async () => {
    const r = await api("/api/edges/derive?dry_run=false", { method: "POST" });
    toast(`${r.counts.added} links derived`);
    await load(); renderNetwork();
  };
  box.querySelectorAll(".hmSet").forEach(btn => {
    btn.onclick = async () => {
      const host = btn.dataset.host;
      const inp = box.querySelector(`.hmIn[data-host="${CSS.escape(host)}"]`);
      const target = rows.find(x => x.name.toLowerCase() === inp.value.trim().toLowerCase());
      if (!target) { toast("Pick an entry from the list"); return; }
      await api("/api/hostmap", {
        method: "PUT", headers: { "content-type": "application/json" },
        body: JSON.stringify({ host, entry_id: target.id }),
      });
      const r = await api("/api/edges/derive?dry_run=false", { method: "POST" });
      toast(`Mapped - ${r.counts.added} links`);
      await load(); renderNetwork();
    };
  });
}


/* ================= deep scan ================= */
/* The scheduled sweep checks 111 ports on every address. This checks all
   65535 on one, because a person asked a question about one machine. It takes
   minutes, so it is a job with progress rather than a request that hangs. */
let DS = null, DSPOLL = null;

function dsRows(j) {
  if (!j.results || !j.results.length) return "";
  return `<div class="ptable dsres">${j.results.map(r => `
    <div class="prow">
      <span class="pp mono" data-port="${r.port}">${r.port}</span>
      <span class="pe">${r.url && /^https?:\/\//.test(r.url)
        ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.service || r.url)}</a>`
        : esc(r.service || "")}${r.service && !r.identified
        ? ` <span class="hint" title="Named from the port number alone - nothing answered that said what it is">(guess)</span>` : ""}</span>
      <span class="pc">${r.declared
        ? `<span class="hint">declared</span>`
        : `<span class="dupw">not declared</span>`}</span>
    </div>`).join("")}</div>`;
}

function dsInner() {
  const j = DS;
  if (!j || j.state === "none")
    return `<div class="empty-hint">Nothing scanned yet. Private addresses
      only - this probes machines, it does not read a record.</div>`;
  if (j.state === "running") {
    return `
      <div class="dshead"><b class="mono">${esc(j.ip)}</b>
        <span class="hint">${j.done} of ${j.total} ports · ${j.percent}% ·
          ${j.open.length} open so far</span>
        <span class="more" id="dsCancel">Stop</span></div>
      <div class="dsbar"><i style="width:${j.percent}%"></i></div>`;
  }
  if (j.state === "error")
    return `<div class="empty-hint">Scan of ${esc(j.ip)} failed -
      ${esc(j.error || "no reason given")}.</div>`;
  // A silent host is not a host with 65535 closed ports. Say which it was.
  const verdict = j.silent
    ? `<span class="dupw">${esc(j.ip)} answered nothing at all</span> - no
       refusals either, so it is unreachable or dropping every packet. That is
       not evidence that its ports are closed.`
    : `<b>${j.open.length}</b> open of ${j.total} scanned in ${j.seconds}s`
      + (j.undeclared.length
        ? ` - <span class="dupw">${j.undeclared.length} nothing in the
            inventory accounts for</span>` : `, all of them declared`);
  return `
    <div class="dshead"><b class="mono">${esc(j.ip)}</b>
      <span class="hint">${j.state === "cancelled" ? "stopped early · " : ""}${verdict}</span></div>
    ${(j.owners || []).length ? `<div class="exchips">${j.owners.map(o =>
      `<span class="lchip" data-card="${o.id}">${esc(o.name)}</span>`).join("")}</div>` : ""}
    ${dsRows(j)}`;
}

function dsPaint() {
  const box = document.getElementById("dsbox");
  if (!box) return;
  box.innerHTML = dsInner();
  const c = document.getElementById("dsCancel");
  if (c) c.onclick = async () => {
    await api("/api/scan/deep", { method: "DELETE" });
    toast("Stopping…");
  };
}

function dsPoll() {
  clearInterval(DSPOLL);
  DSPOLL = setInterval(async () => {
    try { DS = await api("/api/scan/deep"); } catch { return; }
    dsPaint();
    if (!DS || DS.state !== "running") { clearInterval(DSPOLL); DSPOLL = null; }
  }, 1500);
}

async function dsStart(ip) {
  if (!ip) { toast("Enter an address"); return; }
  try { DS = await api("/api/scan/deep", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ ip }),
  }); }
  catch { return; }               // api() already reported the reason
  dsPaint(); dsPoll();
}
