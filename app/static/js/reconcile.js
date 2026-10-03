/* NetMap front end — reconcile.js: reconciliation: source health, findings, ignoring.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines — tests/test_frontend.py checks. */

/* ================= reconciliation ================= */
/* One shape for every source. A finding says what it saw; which buttons it
   gets follows from what it carries — a draft can be created, a suggest can be
   accepted, an entry can be opened — so adding a source needs no UI work. */
let SCAN = null;                 // the whole /api/discovery result
let SRC_HEALTH = { health: [] }; // /api/discovery/summary — never scans, always free
const findingsAll = {};          // per-source "show the tail" flag

/* The sources, as one line: green once a source has answered inside the
   staleness window, amber once its last good answer is older than that, red
   when its most recent attempt failed outright.

   The window is a setting (Settings › Sources, default five hours), sent with
   the summary. It once followed the scan interval — one and a half of them —
   so a daily scan stayed green for 36 hours, and a source ten hours behind
   looked as good as one that answered a minute ago. */
const SRC_STALE_DEFAULT_H = 5;
const srcStaleMs = (sources) =>
  (sources && sources.stale_hours || SRC_STALE_DEFAULT_H) * 60 * 60 * 1000;

function srcState(h, staleMs = srcStaleMs(null)) {
  if (h.pending) return "stale";              // waiting for its first scan
  if (!h.ok) return "bad";
  const last = h.last_ok ? new Date(h.last_ok.endsWith("Z") ? h.last_ok : h.last_ok + "Z") : null;
  if (!last || isNaN(last) || Date.now() - last.getTime() > staleMs) return "stale";
  return "good";
}

// While a sweep runs, each source's name is gray until its own scan answers,
// then green or red — the sweep is one request per source, so each lands on
// its own. Outside a sweep (null) the colours are the sources' health.
let SCAN_PROGRESS = null;      // { id: {st: "wait" | "good" | "bad", error} }
let SCAN_RUN = null;           // the sweep in flight, so two never overlap

function srcChip(h, staleMs) {
  const p = SCAN_PROGRESS && SCAN_PROGRESS[h.source];
  const st = p ? p.st : srcState(h, staleMs);
  const title = p ? (p.st === "wait" ? "scanning…"
                     : p.st === "bad" ? (p.error || "not answering") : "answered just now")
    : h.pending ? "not scanned yet"
    : st === "bad" ? (h.error || "not answering")
    : st === "stale" ? "last answered " + whenScan(h.last_ok || "") + " (stale)"
    : "last answered " + whenScan(h.last_ok || "");
  return `<span class="s ${st}" data-srcchip="${esc(h.source)}" title="${esc(title)}">${
    esc(h.label || h.source)}</span>`;
}

function srcHtml(sources) {
  const hs = (sources.health || []).filter(h => h.configured);
  if (!hs.length) return "";
  const staleMs = srcStaleMs(sources);
  return `<div class="srcline mono">${hs.map(h => srcChip(h, staleMs)).join('<i>·</i>')}</div>`;
}

// Every name again, against the clock: a source crosses into "stale" while
// the page sits there, and no new data has to arrive for that to show.
function repaintSrcChips() {
  if (SCAN_PROGRESS) return;
  const staleMs = srcStaleMs(SRC_HEALTH);
  for (const h of SRC_HEALTH.health || []) {
    const el = document.querySelector(`[data-srcchip="${CSS.escape(h.source)}"]`);
    if (el) el.outerHTML = srcChip(h, staleMs);
  }
}

// Repaint one name in place as its scan lands — not the whole view, which
// would re-fetch the topology on every answer.
function paintSrcChip(id) {
  const h = (SRC_HEALTH.health || []).find(x => x.source === id);
  const el = document.querySelector(`[data-srcchip="${CSS.escape(id)}"]`);
  if (h && el) el.outerHTML = srcChip(h, srcStaleMs(SRC_HEALTH));
  const hint = $("#reconHint");
  if (hint && SCAN_PROGRESS) {
    const all = Object.values(SCAN_PROGRESS);
    const done = all.filter(p => p.st !== "wait").length;
    hint.textContent = `scanning… ${done}/${all.length}`;
  }
}

const FTYPE = {
  new:                  { label: "not in NetMap", cls: "f-new" },
  gone:                 { label: "no container", cls: "f-gone" },
  ports:                { label: "ports differ", cls: "f-ports" },
  stopped:              { label: "stopped", cls: "f-stopped" },
  "nat-unknown":        { label: "exposed", cls: "f-new" },
  "nat-stale":          { label: "no such rule", cls: "f-gone" },
  "nat-drift":          { label: "ports differ", cls: "f-ports" },
  "addr-unreserved":    { label: "not reserved", cls: "f-ports" },
  "reservation-orphan": { label: "untracked", cls: "f-new" },
  "lease-unknown":      { label: "unknown host", cls: "f-new" },
  "mac-mismatch":       { label: "other MAC", cls: "f-ports" },
  "ip-moved":           { label: "moved", cls: "f-ports" },
  "new-device":         { label: "new device", cls: "f-new" },
  "netbox-untracked":   { label: "in NetBox only", cls: "f-new" },
  "netbox-ip":          { label: "in NetBox only", cls: "f-new" },
  "netbox-missing":     { label: "not in NetBox", cls: "f-gone" },
  "netbox-ip-drift":    { label: "address differs", cls: "f-ports" },
  "netbox-mac-drift":   { label: "MAC differs", cls: "f-ports" },
};
// "The inventory describes something that is no longer there" — the only
// findings where offering to delete an entry is sane.
const F_ABSENT = new Set(["gone", "nat-stale"]);
const FORDER = ["new", "nat-unknown", "gone", "nat-stale", "ports", "nat-drift",
  "addr-unreserved", "reservation-orphan", "stopped", "lease-unknown", "mac-mismatch", "ip-moved", "new-device", "netbox-untracked", "netbox-ip", "netbox-missing",
  "netbox-ip-drift", "netbox-mac-drift"];

function suggestLabel(sg) {
  return Object.entries(sg).map(([k, v]) => `${k} ${v}`).join(", ");
}

function findingHtml(f) {
  const t = FTYPE[f.type] || { label: f.type, cls: "" };
  const a = [];
  if (f.draft) a.push(`<button class="btn primary sm" data-fcreate="${esc(f.key)}">Create entry</button>`);
  if (f.suggest) a.push(`<button class="btn primary sm" data-fapply="${esc(f.key)}">Accept ${esc(suggestLabel(f.suggest))}</button>`);
  if (f.entry && F_ABSENT.has(f.type)) {
    a.push(`<button class="btn sm" data-funver="${esc(f.key)}">Mark unverified</button>`);
    a.push(`<button class="btn danger sm" data-fdel="${esc(f.key)}">Delete entry</button>`);
  } else if (f.entry) {
    a.push(`<button class="btn sm" data-fopen="${f.entry.id}">Open entry</button>`);
  }
  // Not ready to add it, not willing to ignore it: keep it in sight.
  if (f.type === "new-device")
    a.push(`<button class="btn sm" data-fwatch="${esc(f.key)}">Watch</button>`);
  a.push(`<button class="btn sm" data-fignore="${esc(f.key)}">Ignore</button>`);
  return `<div class="cf ${t.cls}">
    <div class="cfh"><span class="sev">${esc(t.label)}</span><b>${esc(f.label)}</b></div>
    <div class="cfd">${esc(f.detail || "")}</div>
    <div class="setrow">${a.join("")}</div>
  </div>`;
}

function tallyHtml(r) {
  const c = r.counts || {};
  // Every count that is not a finding count, in a fixed order, then the rest.
  const scale = ["containers", "leases", "reservations", "rules", "addresses", "devices", "vms"]
    .filter(k => c[k] !== undefined)
    .map(k => `${c[k]} ${c[k] === 1 ? k.replace(/s$/, "") : k}`);
  if (c.matched !== undefined) scale.push(`${c.matched} matched`);
  const found = r.findings.length
    ? `${r.findings.length} finding${r.findings.length === 1 ? "" : "s"}`
    : "agrees with NetMap";
  return [...scale, found, c.ignored ? `${c.ignored} ignored` : ""]
    .filter(Boolean).join(" · ");
}

function sourceHtml(r) {
  const head = (body) => `<div class="ovsec">
    <div class="ovhead"><h2>${esc(r.label || r.source)}</h2>
      ${r.hint ? `<span class="hint" data-tip>${esc(r.hint)}</span>` : ""}
      <span class="more" data-rescan="${esc(r.source)}">Scan</span></div>
    ${body}</div>`;
  if (r.skipped) {
    return head(`<div class="empty-hint">Not fully configured, or disabled —
      <a href="#" data-goto-sources>see Settings › Sources</a>.</div>`);
  }
  if (r.error) return head(`<div class="empty-hint">${esc(r.error)}</div>`);

  const fs = [...r.findings].sort((a, b) =>
    FORDER.indexOf(a.type) - FORDER.indexOf(b.type) || a.label.localeCompare(b.label));
  // A first scan against a drifted inventory can produce dozens of findings.
  // Showing all of them buries the rest of the view, so cap it and let the
  // reader ask for the tail.
  const all = findingsAll[r.source];
  const shown = all ? fs : fs.slice(0, 8);
  const tail = fs.length > shown.length
    ? `<div class="empty-hint moreline" data-fmore="${esc(r.source)}">Show ${fs.length - shown.length} more</div>`
    : (all && fs.length > 8
      ? `<div class="empty-hint moreline" data-fless="${esc(r.source)}">Show fewer</div>` : "");
  return `<div class="ovsec">
    <div class="ovhead"><h2>${esc(r.label || r.source)}</h2>
      <span class="hint">${esc(tallyHtml(r))}</span>
      ${fs.length > 2 ? `<span class="more" data-fignoreall="${esc(r.source)}">Ignore all</span>` : ""}
      <span class="more" data-rescan="${esc(r.source)}">Scan again</span></div>
    ${fs.length
      ? `<div class="cflist">${shown.map(findingHtml).join("")}</div>${tail}`
      : `<div class="empty-hint">Nothing to report — everything this source can
         see is already described, and described correctly.</div>`}
  </div>`;
}

function discoveryHtml() {
  if (!SCAN) {
    // The sweep is still running behind the page (see renderNetwork). Say so
    // rather than leaving a gap where Reconciliation is about to appear —
    // but only once there is something to reconcile against.
    const hs = (SRC_HEALTH.health || []).filter(h => h.configured);
    return hs.length ? `
    <div class="ovsec quietsec">
      <div class="ovhead"><h2>Reconciliation</h2>
        <span class="hint" id="reconHint">scanning…</span></div>
      ${srcHtml(SRC_HEALTH)}
    </div>` : "";
  }
  const live = SCAN.sources.filter(r => !r.skipped);
  if (!live.length) {
    return `<div class="ovsec">
      <div class="ovhead"><h2>Reconciliation</h2>
        <span class="hint">no source configured</span></div>
      <div class="empty-hint">NetMap can reconcile itself against Docker,
        OPNsense, Pi-hole, AdGuard Home, a DHCP lease file, router ARP over SNMP,
        UniFi, Home Assistant, NPM, Traefik, Cloudflare, Proxmox VE, NetBox and an
        open-port sweep. None is added yet —
        <a href="#" data-goto-sources>add one under Settings › Sources</a>.</div></div>`;
  }
  // A source with nothing to say gets one word, not a card. But it still gets
  // the word: "agrees" and "has not run" must not look the same, or a source
  // that quietly stops scanning reads as good news.
  const noisy = live.filter(r => r.error || (r.findings || []).length);
  const oldest = live.map(r => r.scanned_at).filter(Boolean).sort()[0];
  // "Agrees" and "could not be read" both produce zero findings, and the
  // difference is the whole point: NPM's token expired and the Overview
  // showed nothing wrong for days. So the count of *working* sources is
  // stated first, and any that are not working are named. This line — and
  // who they are, below it — used to live at the top of the Overview; it
  // reads better here, next to what the sources actually found.
  const broken = live.filter(r => r.error);
  const health = `${live.length - broken.length}/${live.length} sources`;
  const header = `
    <div class="ovsec quietsec">
      <div class="ovhead"><h2>Reconciliation</h2>
        <span class="hint ${broken.length ? "shealth bad" : "shealth"}" id="reconHint">${
          SCAN_PROGRESS ? "scanning…" : `${health}
          ${broken.length ? `— ${broken.map(r => esc(r.label || r.source)).join(", ")} failing`
                          : "reporting"}${oldest ? ` · checked ${esc(whenScan(oldest))}` : ""}`}</span>
      </div>
      ${srcHtml(SRC_HEALTH)}
    </div>`;
  return header + noisy.map(sourceHtml).join("");
}

async function scanAll(force) {
  if (SCAN && !force) return;
  if (SCAN_RUN) return SCAN_RUN;
  SCAN_RUN = (async () => {
    if (!(SRC_HEALTH.health || []).length)
      SRC_HEALTH = await api("/api/discovery/summary").catch(() => SRC_HEALTH);
    const ids = (SRC_HEALTH.health || []).filter(h => h.configured).map(h => h.source);
    if (!ids.length) {                 // nothing added: the one call says so
      SCAN = await api("/api/discovery").catch(() => null);
      return;
    }
    SCAN_PROGRESS = Object.fromEntries(ids.map(id => [id, { st: "wait" }]));
    ids.forEach(paintSrcChip);
    // All at once, each answering on its own. Not forced, a result under 30s
    // old is reused, as the single sweep did — refreshing the page is not a
    // reason to knock on every system again.
    const results = await Promise.all(ids.map(id =>
      api(`/api/discovery/${encodeURIComponent(id)}?max_age=${force ? 0 : 30}`)
        .then(r => { SCAN_PROGRESS[id] = { st: r.error ? "bad" : "good", error: r.error };
                     paintSrcChip(id); return r; })
        .catch(() => { SCAN_PROGRESS[id] = { st: "bad", error: "no answer from NetMap" };
                       paintSrcChip(id); return null; })));
    const got = results.filter(Boolean);
    SCAN = { sources: got, configured: ids,
             findings: got.reduce((n, r) => n + (r.findings || []).length, 0),
             errors: got.filter(r => r.error).length };
    SRC_HEALTH = await api("/api/discovery/summary").catch(() => SRC_HEALTH);
  })().finally(() => { SCAN_PROGRESS = null; SCAN_RUN = null; });
  return SCAN_RUN;
}

async function scanOne(source) {
  // A live scan, which also refreshes the server's cache — so the badge and
  // the Overview are correct straight after an action, without waiting for
  // the next background sweep.
  try {
    const r = await api("/api/discovery/" + encodeURIComponent(source));
    if (SCAN) SCAN.sources = SCAN.sources.map(x => x.source === source ? r : x);
  } catch { /* leave the previous result standing rather than blanking it */ }
}

function findFinding(key) {
  // Two places hold findings: the Network view's own scan, and the cached set
  // the Overview renders. An action can be fired from either, and the Network
  // view may never have been opened.
  for (const r of (SCAN ? SCAN.sources : [])) {
    const f = (r.findings || []).find(x => x.key === key);
    if (f) return f;
  }
  return (FINDINGS.findings || []).find(x => x.key === key) || null;
}

async function ignoreAll(source) {
  const r = SCAN && SCAN.sources.find(x => x.source === source);
  if (!r || !r.findings.length) return;
  if (!(await confirmDialog({
    title: `Ignore all ${r.findings.length} findings from ${r.label || source}?`,
    body: "They will not be reported again until you un-ignore them.",
    ok: "Ignore all", danger: false }))) return;
  const labels = {};
  r.findings.forEach(f => { labels[f.key] = f.label; });
  await api("/api/discovery/ignores", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ keys: r.findings.map(f => f.key), labels }),
  });
  toast(`${r.findings.length} ignored`);
  await scanOne(source); await load();
  if (view === "network") renderNetwork();
}

async function findingAction(key, what) {
  const f = findFinding(key);
  if (!f && what !== "ignore") return;
  const src = f ? f.source : key.split(":")[0];
  if (what === "create") {
    await api("/api/entries", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(f.draft),
    });
    toast(`Added ${f.draft.name}`);
  } else if (what === "apply") {
    await api("/api/entries/" + f.entry.id, {
      method: "PATCH", headers: { "content-type": "application/json" },
      body: JSON.stringify(f.suggest),
    });
    toast("Entry updated");
  } else if (what === "unver") {
    await api("/api/entries/" + f.entry.id, {
      method: "PATCH", headers: { "content-type": "application/json" },
      body: JSON.stringify({ verified: false }),
    });
    toast("Marked for verification");
  } else if (what === "delete") {
    if (!(await confirmDialog({ title: `Delete "${f.label}"?`,
                                 body: "It stays in the change history." }))) return;
    await api("/api/entries/" + f.entry.id, { method: "DELETE" });
    toast("Deleted");
  } else if (what === "watch") {
    await api("/api/watch", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ key }),
    });
    toast("Watching — see Network › Watching");
  } else if (what === "ignore") {
    await api("/api/discovery/ignores", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ key, label: f ? f.label : key }),
    });
    toast("Ignored — it will not come back");
  }
  await scanOne(src);
  await load();
  if (view === "network") renderNetwork();
}
