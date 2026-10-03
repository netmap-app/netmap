/* NetMap front end — overview.js: the Overview: verdict, the attention queue, exposure, tiles.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines — tests/test_frontend.py checks. */

/* ================= overview ================= */
// The control room. What this page owes the reader is one sentence — is
// anything wrong — and then the queue, worst first. The counts that used to
// lead it (entries tracked, a bar chart of categories) answered "how much is
// there", which never changes and never asks anything of you; they live on
// Inventory now, where you go when you actually want to look something up.
//
// The server decides the verdict and the ranking (app/overview.py), so that
// this page and the MCP client cannot disagree about whether the house is on
// fire.
let OV = null;
let OVSHOW = false;                     // is the "set aside" list expanded

const LEVEL_WORD = { critical: "critical", warn: "attention", note: "later" };

/* The banner. A state you read from across the room — a glyph and two or
   three words — then the numbers, each led by its own mark. The full
   sentence (app/overview.py, the same one MCP answers with) is the hover. */
const TILE_ICON = {
  assets: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
  responding: '<path d="M2 12h4l2.5-6 4 13 3-9 2 2h4.5"/>',
  sources: '<path d="M12 3v9"/><path d="M8 8.5L12 12l4-3.5"/><path d="M4 15v3.5A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V15"/>',
  observations: '<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/><circle cx="12" cy="12" r="8.5"/>',
};
const STATE_ICON = {
  ok: '<circle cx="12" cy="12" r="10"/><path d="M7 12.5l3.5 3.5L17 9"/>',
  warn: '<path d="M12 3.2L22 20.5H2z"/><path d="M12 10v4.5M12 17.6v.1"/>',
  critical: '<path d="M8.2 2.5h7.6l5.7 5.7v7.6l-5.7 5.7H8.2l-5.7-5.7V8.2z"/><path d="M12 7.5v5.5M12 16.3v.1"/>',
  down: '<circle cx="12" cy="12" r="10"/><path d="M8.5 8.5l7 7M15.5 8.5l-7 7"/>',
};
// The queue by level, one glyph each — what the rows below are, counted.
const LEVEL_ICON = {
  critical: '<circle cx="12" cy="12" r="6"/>',
  warn: '<path d="M12 5l8 14H4z"/>',
  note: '<circle cx="12" cy="12" r="8"/><path d="M12 7.5V12l3 2"/>',
};
const LEVEL_TIP = { critical: "critical", warn: "to look at", note: "for later" };
const svgi = (paths, cls) => `<svg viewBox="0 0 24 24" class="ico ${cls}" aria-hidden="true">${paths}</svg>`;
const tile = (icon, value, label, tone = "", tip = "") => `
  <span class="vfact ${tone}" title="${esc(tip || label)}">
    ${svgi(TILE_ICON[icon] || "", "tico")}
    <b class="num">${value}</b><small>${label}</small>
  </span>`;

function verdictHtml(all, c) {
  const items = OV.attention || [];
  const n = (lv) => items.filter(it => it.level === lv).length;
  const [state, head] = c.critical_down ? ["down", `${c.critical_down} down`]
    : OV.level === "critical" ? ["critical", `${n("critical")} critical`]
    : OV.level === "warn" ? ["warn", `${n("warn")} to check`]
    : ["ok", "All clear"];
  const levels = ["critical", "warn", "note"].filter(lv => n(lv)).map(lv =>
    `<span class="vlv ${lv}" title="${n(lv)} ${LEVEL_TIP[lv]}">${svgi(LEVEL_ICON[lv], "lvico")}${n(lv)}<span class="vh"> ${LEVEL_TIP[lv]}</span></span>`).join("");
  const srcTone = !OV.sources.total ? "" : OV.sources.ok === OV.sources.total ? "good" : "bad";
  return `
    <div class="verdict ${esc(state)}">
      <div class="vstate" title="${esc(OV.verdict)}">
        ${svgi(STATE_ICON[state], "vglyph")}
        <div class="vwords"><div class="vhead">${esc(head)}</div>
          ${levels ? `<div class="vlevels">${levels}</div>` : ""}</div>
      </div>
      <div class="vfacts">
        ${tile("responding", `${c.up}/${c.monitored}`, "up", c.up === c.monitored ? "good" : "bad",
               `${c.up} of ${c.monitored} monitored entries answering`)}
        ${tile("sources", `${OV.sources.ok}/${OV.sources.total}`, "sources", srcTone,
               `${OV.sources.ok} of ${OV.sources.total} sources reporting`)}
        ${tile("assets", all.length, "entries", "", `${all.length} entries, ${c.monitored} monitored`)}
        ${tile("observations", OV.sightings.rows, "seen", "",
               `${OV.sightings.rows} observations from the sources`)}
      </div>
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

function attnHtml(items) {
  if (!items.length) return "";
  return `<div class="attn">${items.map(it => `
    <div class="at ${esc(it.level)}"${it.entry_id ? ` data-card="${it.entry_id}"` : ""}${
      it.goto ? ` data-goto="${esc(it.goto)}"` : ""}>
      <span class="atl">${esc(LEVEL_WORD[it.level] || it.level)}</span>
      <div class="att">
        <span class="atn">${esc(it.title)}${
          it.changed_since_dismissed
            ? `<span class="again" title="You set this aside; it has changed since">changed</span>` : ""}${
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
      ${it.since ? `<span class="atage" title="${esc(it.since_exact
          ? "since " + when(it.since)
          : "first seen by NetMap " + when(it.since) +
            " — nothing records when this actually began")}">${
          it.since_exact || ago(it.since) === "now" ? "" : "~"}${ago(it.since)}</span>` : ""}
      <button class="iconbtn atx" title="${esc(it.level === "critical"
          ? "Set aside for a day"
          : "Set aside until this changes")}"
        data-dismiss="${esc(it.key)}"
        data-fp="${esc(it.fingerprint || "")}"
        data-title="${esc(it.title)}">\u2715</button>
    </div>`).join("")}</div>`;
}

// Set-aside items stay one click away. A dismissal that cannot be seen or
// undone is indistinguishable from a bug.
function dismissedHtml(hidden) {
  if (!hidden || !hidden.length) return "";
  const open = OVSHOW;
  return `
    <div class="ovsec">
      <div class="ovhead"><h2>Set aside</h2>
        <span class="hint" data-tip>They return if the situation changes.</span>
        <span class="hint">${hidden.length} hidden</span>
        <span class="more" id="ovShowDis">${open ? "Hide" : "Show"}</span></div>
      ${open ? `<div class="attn dis">${hidden.map(it => `
        <div class="at ${esc(it.level)}">
          <span class="atl">${esc(LEVEL_WORD[it.level] || it.level)}</span>
          <div class="att">
            <span class="atn">${esc(it.title)}</span>
            <span class="atd">set aside ${esc(when(it.dismissed_at || ""))}</span>
          </div>
          <button class="iconbtn atx" title="Bring this back"
            data-undismiss="${esc(it.key)}">\u21ba</button>
        </div>`).join("")}</div>` : ""}
    </div>`;
}

/* Open hostnames split two ways: ones nobody has looked at (red — a real
   question) and ones ignored with a reason (neutral — a decision on record,
   the reason on hover). */
function exOpenCaption(naked) {
  const open = naked.filter(n => !n.accepted).length;
  const ok = naked.length - open;
  if (!open) return `<div class="excap">no Access application — open on purpose</div>`;
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
      <span class="hint">The server did not answer as expected — it may be restarting.</span>
      <button class="btn" data-retry-load>Try again</button></div>`;
    return;
  }

  // The address card calls an address free only if nothing is living on it,
  // which needs the presence layer — normally loaded by the Network view. On
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

  const pinned = all.filter(e => e.pinned);
  const c = OV.counts;
  const ok = OV.level === "ok";

  // Everything below is one template literal, and an exception anywhere in it
  // leaves the "Loading…" placeholder standing — a fault that looks exactly
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

function overviewHtml(all, pinned, c, ok) {
  return `
    ${verdictHtml(all, c)}

    ${OV.attention.length ? `
    <div class="ovsec">
      <div class="ovhead"><h2>Needs you</h2>
        <span class="hint" data-tip>Worst first.</span></div>
      ${attnHtml(OV.attention)}
    </div>` : ""}

    ${dismissedHtml(OV.dismissed)}

    <div class="ovsec">
      <div class="ovhead"><h2>Reachable from outside</h2>
        <span class="hint" data-tip>What the edge actually says — the firewall, proxy and
          tunnel sources, not the inventory.</span></div>
      ${exposureHtml(OV.exposure)}
    </div>

    <div class="ovgrid">
      <div class="ovsec wide2">
        <div class="ovhead"><h2>Quick links</h2><span class="hint" data-tip>Pinned services.</span></div>
        ${pinned.length ? `<div class="qgrid">${pinned.map(qlink).join("")}</div>`
        : `<div class="empty-hint">Nothing pinned yet — open any entry and tick
             <strong>Pin to Quick links</strong> to put it here.</div>`}
      </div>

      <div class="ovsec">
        <div class="ovhead"><h2>Recent changes</h2><span class="more" id="ovHist">View all</span></div>
        <div class="card2"><div class="feed" id="ovFeed"><div class="empty-hint">Loading…</div></div></div>
      </div>

      <div class="ovsec">
        <div class="ovhead"><h2>Inventory by category</h2>
          <span class="hint">${all.length} tracked</span></div>
        <div class="card2">${catCardHtml(all)}</div>
      </div>

      <div class="ovsec wide2">
        <div class="ovhead"><h2>Address space</h2>
          <span class="hint" data-tip>Every /24 in the inventory.</span></div>
        <div class="card2">${addrCardHtml(all)}</div>
      </div>
    </div>`;

}

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
  // "Not verified": the person has checked them — say so for all at once.
  box.querySelectorAll("[data-verify]").forEach(b => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      const ids = b.dataset.verify.split(",").filter(Boolean);
      if (ids.length > 1 && !(await confirmDialog({
        title: `Mark ${ids.length} entries verified?`,
        body: "Only if their values are checked — each change is in the history.",
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
  const sd = $("#ovShowDis");
  if (sd) sd.onclick = () => { OVSHOW = !OVSHOW; renderOverview(ALL.length ? ALL : ENTRIES); };

  box.querySelectorAll("[data-goto]").forEach(el => {
    el.onclick = (ev) => {
      if (ev.target.closest("[data-card]")) return;
      view = el.dataset.goto; applyView(); renderNetwork();
    };
  });

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
   category, not to the total — with nine categories a share-of-total bar is
   nine slivers, and the question this answers is "which of these is big",
   not "what fraction of everything is it". */
function catCardHtml(all) {
  const n = {};
  for (const e of all) n[(e.category || "").trim() || "Uncategorised"] =
    (n[(e.category || "").trim() || "Uncategorised"] || 0) + 1;
  const rows = Object.entries(n).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (!rows.length) return `<div class="empty-hint">Nothing tracked yet.</div>`;
  const max = rows[0][1];
  return `<div class="cats">${rows.map(([cat, k]) => `
    <div class="catrow" data-cat="${esc(cat)}" title="Show only ${esc(cat)}">
      ${catGlyph(cat)}
      <span class="cn">${esc(cat)}</span>
      <span class="catbar"><i class="${catKey(cat)}" style="width:${Math.round(100 * k / max)}%"></i></span>
      <span class="cc num">${k}</span>
    </div>`).join("")}</div>`;
}

/* Address space, in proportion. The Network view draws all 254 addresses one
   cell each, which is the right tool for "is .41 free"; this one answers the
   only question the front page should ask, which is whether a subnet is
   filling up. Seen-but-untracked is drawn as its own band because those
   addresses are occupied — counting them as free is the error this layer was
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
    // section — the proportion is the information, and the proportion is the
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
    <span class="t"><span class="n">${esc(e.name)}</span><span class="a mono">${esc(addr || "—")}</span></span>
  </a>`;
}
