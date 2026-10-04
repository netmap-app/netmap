/* NetMap front end - sources.js: Settings › Sources.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

/* ================= Settings > Sources ================= */
// A source id is its type, or "<type>-<n>" for another source of that type.
const srcType = id => String(id || "").split("-")[0];

let SOURCES = [];
let SRC_DRIVERS = null;

let SRC_ROLES = {};
async function srcDriversList() {
  if (!SRC_DRIVERS) {
    const r = await api("/api/sources/drivers");
    SRC_DRIVERS = r.drivers;
    SRC_ROLES = r.roles;
  }
  return SRC_DRIVERS;
}

function srcRowHtml(inst) {
  const dotCls = !inst.enabled ? "na" : inst.error ? "down" : inst.ok ? "up" : "na";
  const dotTitle = !inst.enabled ? "Disabled" : inst.error ? inst.error
    : inst.ok ? "Last scan OK" : inst.configured ? "Not scanned yet" : "Not fully configured";
  return `<div class="srcrow" data-id="${esc(inst.id)}">
    <span class="dot ${dotCls}" title="${esc(dotTitle)}"></span>
    <div class="srcinfo">
      <div class="srcname">${esc(inst.name)}${inst.name !== inst.label
        ? ` <span class="hint">· ${esc(inst.label)}</span>` : ""}</div>
      <div class="srcmeta">${esc(inst.config.url || inst.hint)}${inst.enabled ? "" : " · disabled"}</div>
      ${inst.error ? `<div class="srcerr">${esc(inst.error)}</div>` : ""}
    </div>
    <div class="btns">
      <button class="btn sm" data-src-edit="${esc(inst.id)}">Edit</button>
      <button class="btn sm danger" data-src-del="${esc(inst.id)}">Delete</button>
    </div>
  </div>`;
}

/* ---- how often every source is scanned by itself ---- */
function fmtEvery(s) {
  const h = Math.floor(s / 3600), m = Math.round((s % 3600) / 60);
  return [h ? `${h} h` : "", m ? `${m} min` : ""].filter(Boolean).join(" ") || "0 min";
}

async function loadScanSchedule() {
  try {
    const r = await api("/api/settings/scan");
    $("#scanH").value = Math.floor(r.interval / 3600);
    $("#scanM").value = Math.round((r.interval % 3600) / 60);
    $("#srcStaleH").value = r.stale_hours;
    const next = r.next_scan ? new Date(r.next_scan) : null;
    const left = next ? Math.max(0, Math.round((next - Date.now()) / 60000)) : null;
    $("#scanNext").textContent =
      (next ? `Next automatic scan ${left < 1 ? "any moment" : "in " + fmtEvery(left * 60)}`
                + ` (${next.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hourCycle: "h23" })}). `
            : "The first automatic scan runs a few seconds after NetMap starts. ") +
      "";
    $("#scanTip").textContent = `Between 5 minutes and 7 days; the default is ${fmtEvery(r.default)}. `
      + "Every pass includes the port sweep. The refresh button scans now, whatever this says.";
  } catch { $("#scanNext").textContent = "Could not load the schedule."; }
}

$("#scanForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  const h = parseInt($("#scanH").value || "0", 10), m = parseInt($("#scanM").value || "0", 10);
  if (!(h >= 0 && m >= 0 && m < 60)) { toast("Hours and minutes (0–59), please"); return; }
  const sh = parseInt($("#srcStaleH").value || "0", 10);
  try {
    const r = await api("/api/settings/scan", {
      method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ interval: h * 3600 + m * 60, stale_hours: sh }),
    });
    toast(`Sources will be scanned every ${fmtEvery(r.interval)}, stale after ${r.stale_hours} h`);
    SRC_HEALTH.stale_hours = r.stale_hours;
    repaintSrcChips();
    // The server just worked out the new deadline; read it back.
    setTimeout(loadScanSchedule, 300);
  } catch { /* api() already toasted why */ }
});

/* ---- when an unseen entry is flagged ---- */
async function loadStaleDays() {
  try { $("#staleDays").value = (await api("/api/settings/stale")).days; }
  catch { /* the field stays empty; saving still works */ }
}
$("#staleForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  try {
    const r = await api("/api/settings/stale", {
      method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ days: parseInt($("#staleDays").value || "0", 10) }),
    });
    toast(`Entries unseen for ${r.days} days are flagged`);
  } catch { /* api() already toasted why */ }
});

/* ---- where uptime is shown ---- */
async function loadUptimeRule() {
  const box = $("#uptimeRule");
  try {
    const [r, m] = await Promise.all([api("/api/settings/uptime"), api("/api/meta")]);
    const group = (key, label, vals) => vals.length ? `<div class="upg"><span class="pickhead">${esc(label)}</span>${
      vals.map(v => `<label class="ckf"><input type="checkbox" data-up="${key}" value="${esc(v)}"${
        r[key].includes(v) ? " checked" : ""}> ${esc(v)}</label>`).join("")}</div>` : "";
    box.innerHTML = group("criticalities", "Criticality", m.all_criticalities || [])
      + group("kinds", "Kind", m.all_kinds || [])
      + group("categories", "Category", m.categories || []);
  } catch { box.innerHTML = `<span class="hint">Could not load.</span>`; }
}
$("#uptimeForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  const pick = k => [...document.querySelectorAll(`[data-up="${k}"]`)].filter(b => b.checked).map(b => b.value);
  try {
    await api("/api/settings/uptime", {
      method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ criticalities: pick("criticalities"), kinds: pick("kinds"),
                             categories: pick("categories") }),
    });
    toast("Uptime rule saved");
  } catch { /* api() already toasted why */ }
});

/* ---- what counts as new on the network ---- */
async function loadNewDev() {
  try {
    const r = await api("/api/settings/newdevices");
    $("#ndDays").value = r.days; $("#ndKeep").value = r.keep_days;
    $("#ndRandom").checked = r.include_random;
  } catch { /* the fields stay empty; saving still works */ }
}
$("#newdevForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  try {
    const r = await api("/api/settings/newdevices", {
      method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ days: parseInt($("#ndDays").value || "0", 10),
                             keep_days: parseInt($("#ndKeep").value || "0", 10),
                             include_random: $("#ndRandom").checked }),
    });
    toast(`New for ${r.days} days, history kept ${r.keep_days} days`
          + (r.include_random ? ", randomised MACs included" : ""));
  } catch { /* api() already toasted why */ }
});

/* ---- when a checked certificate is worth a warning ---- */
async function loadCertDays() {
  try { $("#certDays").value = (await api("/api/settings/checks")).tls_warn_days; }
  catch { /* the field stays empty; saving still works */ }
}
$("#certForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  try {
    const r = await api("/api/settings/checks", {
      method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ tls_warn_days: parseInt($("#certDays").value || "0", 10) }),
    });
    toast(`Certificates warn ${r.tls_warn_days} days before they expire`);
  } catch { /* api() already toasted why */ }
});

async function loadSources() {
  const box = $("#srcList");
  box.innerHTML = "Loading…";
  try {
    SOURCES = await api("/api/sources/instances");
    box.innerHTML = SOURCES.length ? SOURCES.map(srcRowHtml).join("")
      : `<div class="srcempty">No sources yet - add the systems NetMap should read.</div>`;
  } catch {
    box.innerHTML = `<div class="srcempty">Could not load.</div>`;
  }
}

// Also the form of a notification channel (notify.js), with its own prefix.
function srcFieldHtml(f, existing, prefix = "srcf_") {
  const id = `${prefix}${f.key}`;
  if (f.type === "checkbox") {
    const checked = existing && f.key in existing.config ? !!existing.config[f.key] : !!f.default;
    return `<label class="ckf"><input type="checkbox" id="${id}" ${checked ? "checked" : ""}> ${esc(f.label)}</label>`;
  }
  if (f.secret) {
    const prev = existing && existing.secrets[f.key];
    // Required is a "*" after the label, as in the entry form; the line under
    // the field only says what is stored.
    const set = prev && prev.set;
    return `<div class="f"><label for="${id}">${esc(f.label)}${f.required && !set ? " *" : ""}</label>
      <input type="password" id="${id}" autocomplete="new-password" placeholder="${esc(f.placeholder || "")}"${
        f.required && !set ? ' aria-required="true"' : ""}${set ? ` aria-describedby="${id}_h"` : ""}>
      ${set ? `<span class="hint" id="${id}_h">${esc(`currently set (${prev.preview}) - leave blank to keep it`)}</span>` : ""}</div>`;
  }
  // A blank saved value means "the default", so an edit shows the default as
  // the placeholder rather than as a value typed in.
  const val = existing ? (existing.config[f.key] ?? "") : (f.default ?? "");
  const ph = f.placeholder || (f.default ?? "");
  const mode = f.type === "number" ? ` inputmode="${f.integer ? "numeric" : "decimal"}"` : "";
  return `<div class="f"><label for="${id}">${esc(f.label)}${f.required ? " *" : ""}</label>
    <input id="${id}" value="${esc(val)}" placeholder="${esc(ph)}"${mode}${f.required ? ' aria-required="true"' : ""}></div>`;
}

function srcGather(driver, prefix = "srcf_") {
  const fields = {};
  for (const f of driver.fields) {
    const el = $("#" + prefix + f.key);
    if (!el) continue;
    fields[f.key] = f.type === "checkbox" ? el.checked : el.value.trim();
  }
  return fields;
}

// The form opens below a list that can be longer than the screen, so opening
// it brings it into view and puts the cursor in it - otherwise "Edit" looks
// like it did nothing. Cancel hands focus back to whatever opened it.
let SRC_OPENER = null;
function showSrcForm(focus) {
  const f = $("#srcForm .srcform");
  if (!f) return;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  f.scrollIntoView({ behavior: still ? "auto" : "smooth", block: "start" });
  const el = focus ? f.querySelector(focus) : null;
  if (el) el.focus({ preventScroll: true });
}
function closeSrcForm() {
  $("#srcForm").innerHTML = "";
  if (SRC_OPENER && document.contains(SRC_OPENER)) SRC_OPENER.focus();
  SRC_OPENER = null;
}

function openSrcForm(driver, existing) {
  const box = $("#srcForm");
  box.innerHTML = `<div class="srcform">
    <div class="flabel"><h3>${existing ? "Edit" : "Add"} ${esc(driver.label)}</h3>
      <span class="hint" data-tip>${esc(driver.hint)}</span></div>
    <div class="flabel"><label class="ckf formon"><input type="checkbox" id="srcEnabled"
      ${!existing || existing.enabled ? "checked" : ""}> Enabled</label>
      <span class="hint" data-tip>Off pauses the source: it is not scanned and leaves the
        sources line, but its settings and stored secrets are kept.</span></div>
    <div class="f"><label for="srcf__name">Name</label>
      <input id="srcf__name" value="${esc(existing ? existing.name : "")}"
        placeholder="${esc(existing ? "" : driver.label + (SOURCES.some(i => i.type === driver.type) ? " 2, 3…" : ""))}"></div>
    ${driver.fields.map(f => srcFieldHtml(f, existing)).join("")}
    <div id="srcTestOut" class="hint"></div>
    <div class="setrow">
      <button class="btn primary" id="srcSaveBtn">Save</button>
      <button class="btn" id="srcTestBtn">Test connection</button>
      <button class="btn" id="srcCancelBtn">Cancel</button>
    </div>
  </div>`;
  $("#srcCancelBtn").onclick = closeSrcForm;
  // Editing starts at the first setting; adding at the name.
  showSrcForm(existing ? '[id^="srcf_"]:not(#srcf__name)' : "#srcf__name");
  $("#srcTestBtn").onclick = async () => {
    const out = $("#srcTestOut");
    out.textContent = "Testing…";
    try {
      const r = existing
        ? await api(`/api/sources/instances/${existing.id}/test`, { method: "POST" })
        : await api("/api/sources/test", {
            method: "POST", headers: { "content-type": "application/json" },
            body: JSON.stringify({ type: driver.type, fields: srcGather(driver) }),
          });
      out.textContent = r.ok
        ? "Reachable" + (r.nodes ? ` - nodes: ${r.nodes.join(", ")}` : "")
        : "Failed: " + (r.error || "unknown error");
    } catch { out.textContent = "Could not run the test."; }
  };
  $("#srcSaveBtn").onclick = async () => {
    const name = $("#srcf__name").value.trim();   // blank: the server names it
    try {
      if (existing) {
        await api(`/api/sources/instances/${existing.id}`, {
          method: "PUT", headers: { "content-type": "application/json" },
          body: JSON.stringify({ name, fields: srcGather(driver), enabled: $("#srcEnabled").checked }),
        });
        toast("Source updated");
      } else {
        await api("/api/sources/instances", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ type: driver.type, name, fields: srcGather(driver),
                                 enabled: $("#srcEnabled").checked }),
        });
        toast("Source added");
      }
      box.innerHTML = "";
      SRC_DRIVERS = null;               // "can add" has changed
      await loadSources();
    } catch { /* api() already toasted the error */ }
  };
}

$("#srcAddBtn").onclick = async () => {
  SRC_OPENER = $("#srcAddBtn");
  const drivers = await srcDriversList().catch(() => []);
  if (!drivers.length) { toast("No source types available"); return; }
  const box = $("#srcForm");
  // Always a type picker first, even with one option - the form for a type
  // is a second step, not the default. Otherwise "Add source" quietly means
  // "add Proxmox" until a second driver exists, which is the wrong mental
  // model to teach.
  // Grouped by what a source is for - "DNS", "Reverse proxy" - so the list
  // reads as the parts of a network rather than a list of products.
  const groups = Object.keys(SRC_ROLES).map(role => [role,
    drivers.filter(d => (d.roles || [])[0] === role)]).filter(([, ds]) => ds.length);
  box.innerHTML = `<div class="srcform"><h3>Add a source</h3>
    ${groups.map(([role, ds]) => `<div class="pickgroup">
      <div class="pickhead">${esc(SRC_ROLES[role].label)}</div>
      <div class="picklist">${ds.map(d => `
      <button class="pickrow" data-src-pick="${esc(d.type)}"${d.can_add ? "" : " disabled"}>
        <span class="picklabel">${esc(d.label)}${d.can_add ? "" : ' <span class="hint">· already added</span>'}</span>
        <span class="hint">${esc(d.hint)}</span>
      </button>`).join("")}</div></div>`).join("")}
    <div class="setrow"><button class="btn" id="srcPickCancel">Cancel</button></div>
  </div>`;
  box.querySelectorAll("[data-src-pick]").forEach(b => {
    b.onclick = () => openSrcForm(drivers.find(d => d.type === b.dataset.srcPick), null);
  });
  $("#srcPickCancel").onclick = closeSrcForm;
  showSrcForm(".pickrow:not([disabled])");
};

$("#srcList").addEventListener("click", async ev => {
  const editBtn = ev.target.closest("[data-src-edit]");
  const delBtn = ev.target.closest("[data-src-del]");
  if (editBtn) {
    const inst = SOURCES.find(s => s.id === editBtn.dataset.srcEdit);
    const drivers = await srcDriversList().catch(() => []);
    const driver = drivers.find(d => d.type === inst.type);
    SRC_OPENER = editBtn;
    if (driver) openSrcForm(driver, inst);
    return;
  }
  if (delBtn) {
    const inst = SOURCES.find(s => s.id === delBtn.dataset.srcDel);
    if (!inst || !(await confirmDialog({
      title: `Remove "${inst.name}"?`,
      body: "Its stored credentials are deleted, and what it saw with them. "
          + "Findings you ignored stay, in case it is added back.",
      ok: "Remove" }))) return;
    await api(`/api/sources/instances/${inst.id}`, { method: "DELETE" });
    SRC_DRIVERS = null;
    toast("Source removed");
    await loadSources();
  }
});

async function showChangelog() {
  $("#changelogBody").innerHTML = "Loading…";
  $("#changelogModal").hidden = false;
  try {
    const { entries } = await api("/api/changelog");
    $("#changelogBody").innerHTML = entries.length ? entries.map(e => `
      <div class="clentry">
        <h4>${esc(e.version)}${e.date ? ` <span class="when">${esc(e.date)}</span>` : ""}</h4>
        <ul>${e.notes.map(n => `<li>${
          // `names` in the changelog as code; escaped first, so it stays text.
          esc(n).replace(/`([^`]+)`/g, "<code>$1</code>")}</li>`).join("")}</ul>
      </div>`).join("") : `<div class="empty-hint">No changelog yet.</div>`;
  } catch {
    $("#changelogBody").innerHTML = `<div class="empty-hint">Could not load.</div>`;
  }
}
$("#changelogClose").onclick = () => ($("#changelogModal").hidden = true);
