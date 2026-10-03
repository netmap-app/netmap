/* NetMap front end — palette.js: quick open (Cmd/Ctrl+K).
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines — tests/test_frontend.py checks. */

/* ================= quick open (Cmd/Ctrl+K) ================= */
const entryById = (id) => ENTRIES.find(x => x.id == id) || ALL.find(x => x.id == id);
let palRows = [], palAt = 0;

function palScore(e, q) {
  const name = e.name.toLowerCase();
  if (name === q) return 100;
  if (name.startsWith(q)) return 85;
  // initials: "ha" finds Home Assistant, "npm" finds Nginx Proxy Manager
  const ini = e.name.split(/[^A-Za-z0-9]+/).filter(Boolean)
    .map(w => w[0].toLowerCase()).join("");
  if (ini.startsWith(q)) return 78;
  if (name.includes(q)) return 65;
  const hay = [e.ip, e.host, e.category, e.kind, e.ports, e.protocol,
    (e.tags || []).join(" ")].join(" ").toLowerCase();
  if (hay.includes(q)) return 40;
  // Loose subsequence, so "sonr" still finds Sonarr — but only when the
  // letters sit close together. Scattered over a long name, any four letters
  // match something ("plex" found "Philips Pedestal Fan cx3550").
  let best = Infinity;
  for (let s = name.indexOf(q[0]); s !== -1; s = name.indexOf(q[0], s + 1)) {
    let i = 0, k = s;
    for (; k < name.length && i < q.length; k++) if (name[k] === q[i]) i++;
    if (i === q.length) best = Math.min(best, k - s);
  }
  return best <= Math.max(q.length + 2, Math.ceil(q.length * 1.6)) ? 12 : -1;
}

function palSearch(q) {
  q = q.trim().toLowerCase();
  const pool = ALL.length ? ALL : ENTRIES;
  if (!q) {
    return [...pool].sort((a, b) =>
      (b.pinned - a.pinned) || String(b.updated_at || "").localeCompare(a.updated_at || "")
    ).slice(0, 8);
  }
  return pool.map(e => [palScore(e, q), e]).filter(([sc]) => sc >= 0)
    .sort((a, b) => b[0] - a[0] || a[1].name.localeCompare(b[1].name))
    .slice(0, 8).map(([, e]) => e);
}

function palRender() {
  const box = $("#palResults");
  if (!palRows.length) {
    box.innerHTML = `<div class="palempty">Nothing matches.</div>`; return;
  }
  box.innerHTML = palRows.map((e, i) => {
    const port = (e.ports || "").match(/\b\d{1,5}\b/);
    const addr = [e.ip, port ? port[0] : ""].filter(Boolean).join(":");
    return `<div class="palrow ${i === palAt ? "cur" : ""}" data-i="${i}" role="option" aria-selected="${i === palAt}">
      ${dot(e)}
      <span class="pn">${esc(e.name)}</span>
      ${e.kind ? `<span class="kind ${esc(e.kind)}">${esc(e.kind)}</span>` : ""}
      <span class="pa mono">${esc(addr || "")}</span>
      <span class="pc">${esc(e.category)}</span>
      ${linkFor(e) ? ICON.ext : ""}
    </div>`;
  }).join("");
  const at = box.querySelector(".palrow.cur");
  if (at) at.scrollIntoView({ block: "nearest" });
}

function palOpen() {
  $("#palModal").hidden = false;
  const i = $("#palInput");
  i.value = ""; palAt = 0; palRows = palSearch("");
  palRender(); i.focus();
}
const palClose = () => ($("#palModal").hidden = true);

function palGo(e, edit) {
  if (!e) return;
  palClose();
  if (edit) { showCard(e.id); return; }
  const href = linkFor(e);
  if (href) window.open(href, "_blank", "noopener");
  else showCard(e.id);
}

$("#palInput").addEventListener("input", ev => {
  palRows = palSearch(ev.target.value); palAt = 0; palRender();
});
$("#palInput").addEventListener("keydown", ev => {
  // stopPropagation matters: without it ⌘↵ here also reaches the global
  // handler, which sees the edit dialog the palette just opened and saves it.
  if (ev.key === "ArrowDown") { ev.preventDefault(); palAt = Math.min(palAt + 1, palRows.length - 1); palRender(); }
  else if (ev.key === "ArrowUp") { ev.preventDefault(); palAt = Math.max(palAt - 1, 0); palRender(); }
  else if (ev.key === "Enter") {
    ev.preventDefault(); ev.stopPropagation();
    palGo(palRows[palAt], ev.metaKey || ev.ctrlKey);
  }
});
$("#palResults").addEventListener("click", ev => {
  const r = ev.target.closest(".palrow"); if (!r) return;
  palGo(palRows[+r.dataset.i], ev.metaKey || ev.ctrlKey);
});

const fmtBytes = (b) => b == null ? "—"
  : b > 1048576 ? (b / 1048576).toFixed(1) + " MB"
  : b > 1024 ? (b / 1024).toFixed(0) + " kB" : b + " B";
const fmtDur = (s) => {
  if (s == null) return "—";
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
};

/* Settings is one page with sub-tabs rather than one long scroll — the
   Sources tab alone can run long once a few sources are added. */
function readSetTab() {
  try { return localStorage.getItem("netmap.settab") || "about"; } catch { return "about"; }
}
function applySetTab(tab) {
  try { localStorage.setItem("netmap.settab", tab); } catch { /* private mode */ }
  document.querySelectorAll("#setTabs [data-settab]").forEach(b =>
    b.classList.toggle("on", b.dataset.settab === tab));
  document.querySelectorAll(".setpanel").forEach(p =>
    p.hidden = p.dataset.panel !== tab);
}
$("#setTabs").addEventListener("click", ev => {
  const b = ev.target.closest("[data-settab]"); if (!b) return;
  applySetTab(b.dataset.settab);
});

async function renderSettingsPage() {
  applySetTab(readSetTab());
  applyTheme(readTheme());
  if (!IMPORT) $("#impPlan").innerHTML = "";
  $("#srcForm").innerHTML = "";
  $("#notifyForm").innerHTML = "";
  loadSources();
  loadNotify();
  loadScanSchedule();
  loadCertDays();
  loadNewDev();
  loadUptimeRule();
  loadStaleDays();
  loadProfile();
  const b = $("#aboutBody");
  try {
    const a = await api("/api/about");
    const rv = $("#railVer"); if (rv) rv.textContent = "v" + a.version;
    const rows = [
      ["Version", `${esc(a.version)} · <a href="#" class="inlink" id="changelogLink">what's new</a>`, true],
      ["Entries", `${a.entries} in ${a.categories} categories`],
      ["Monitored", `${a.monitored} · ${a.pinned} pinned`],
      ["Needs attention", `${a.unverified} to verify · ${a.unclassified} without a kind`],
      ["Conflicts", a.conflicts ? `${a.conflicts} — see the Overview` : "none"],
      ["Links", `${a.links} recorded · ${a.unlinked} entries unlinked`],
      ["Reconciliation", (() => {
        const on = (a.discovery_sources || []).filter(x => x.configured);
        if (!on.length) return "no source configured";
        return on.map(x => x.label).join(", ")
          + (a.ignored_findings ? ` · ${a.ignored_findings} findings ignored` : "");
      })()],
      ["Last status sweep", a.last_sweep ? when(a.last_sweep) : "not yet"],
      ["Check interval", `${a.check_interval}s · ${a.check_timeout}s timeout`],
      ["App uptime", fmtDur(a.uptime_seconds)],
      ["Database", `${fmtBytes(a.db_bytes)} — ${a.db_path}`],
      ["MCP endpoint", (a.mcp_path_is_default ? "default path /mcp — not secret" : "private path")
        + (a.mcp_token_required ? " + bearer token" : " · NO bearer token")],
      ["MCP accepts Host", (a.mcp_allowed_hosts || []).join(", ")],
      ["API access", !a.auth ? "—" : a.auth.disabled
        ? "OPEN — NETMAP_AUTH=off, anyone who can reach the port"
        : [a.auth.cf_access && "Cloudflare Access (verified JWT)",
           a.auth.api_token && "API token",
           a.auth.summary_token && "read-only summary token",
           a.auth.metrics_token && "read-only metrics token",
           a.auth.password && "password login"].filter(Boolean).join(" or ")],
      ["Secret key", a.secret_key === "environment"
        ? "in NETMAP_SECRET_KEY — the database holds ciphertext only"
        : "in the database — set NETMAP_SECRET_KEY to move it out"],
      ...(a.secrets_undecryptable ? [["Undecryptable secrets",
        `${a.secrets_undecryptable} — NETMAP_SECRET_KEY does not match; see the Overview`]] : []),
      ["Python", a.python],
    ];
    b.innerHTML = rows.map(([k, v, raw]) =>
      `<dt>${esc(k)}</dt><dd>${raw ? v : esc(String(v))}</dd>`).join("");
    $("#changelogLink").onclick = (ev) => { ev.preventDefault(); showChangelog(); };
  } catch {
    b.innerHTML = `<dd>Could not load.</dd>`;
  }
}
