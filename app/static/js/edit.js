/* NetMap front end - edit.js: the entry form, and the header and rail controls.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

/* ================= edit ================= */
const FIELDS = ["name", "category", "host", "ip", "mac", "ports", "protocol", "url",
  "tags", "notes", "zone", "secret_ref", "healthcheck"];
function openEdit(e) {
  editingId = e ? e.id : null;
  $("#editTitle").textContent = e ? "Edit entry" : "New entry";
  for (const f of FIELDS) $("#f_" + f).value = e ? (f === "tags" ? (e.tags || []).join(", ") : e[f] || "") : "";
  if (!e && filter.category) $("#f_category").value = filter.category;
  $("#f_kind").value = e ? (e.kind || "") : "";
  $("#f_criticality").value = e ? (e.criticality || "") : "";
  $("#f_monitor").checked = e ? !!e.monitor : true;
  $("#f_verified").checked = e ? !!e.verified : true;
  $("#f_pinned").checked = e ? !!e.pinned : false;
  $("#delBtn").style.visibility = e ? "visible" : "hidden";
  $("#editModal").hidden = false;
  $("#f_name").focus();
}
function closeEdit() { $("#editModal").hidden = true; editingId = null; }

async function save() {
  const body = {};
  for (const f of FIELDS) body[f] = $("#f_" + f).value.trim();
  if (!body.name) { toast("Name is required"); return; }
  body.tags = body.tags.split(",").map(s => s.trim()).filter(Boolean);
  body.kind = $("#f_kind").value;
  body.criticality = $("#f_criticality").value;
  body.monitor = $("#f_monitor").checked;
  body.verified = $("#f_verified").checked;
  body.pinned = $("#f_pinned").checked;
  const opts = { headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  try {
    if (editingId) await api("/api/entries/" + editingId, { method: "PATCH", ...opts });
    else await api("/api/entries", { method: "POST", ...opts });
  } catch { return; }      // api() toasted why; the form stays open with the input
  closeEdit(); toast("Saved"); await load();
}

async function del() {
  if (!editingId) return;
  if (!(await confirmDialog({ title: "Delete this entry?",
                               body: "It stays in the change history." }))) return;
  await api("/api/entries/" + editingId, { method: "DELETE" });
  closeEdit(); toast("Deleted"); await load();
}

const dayLabel = (ts) => {
  const d = new Date(ts.endsWith("Z") ? ts : ts + "Z");
  if (isNaN(d)) return ts;
  const today = new Date(), y = new Date(Date.now() - 86400000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === y.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { day: "numeric", month: "long", year: "numeric" });
};

/* Changes, full page. The modal is still there for the narrow-screen toolbar
   button, but a log you read is not a dialog you dismiss - it wants width and
   a place in the nav, which is what the rail gives it. */
async function renderChanges() {
  const box = $("#changes");
  if (!box.firstChild) box.innerHTML = `<div class="empty-hint">Loading…</div>`;
  let rows = [];
  const logins = readLogins();
  try { rows = await api("/api/audit?limit=200" + (logins ? "&logins=1" : "")); }
  catch { box.innerHTML = `<div class="empty-hint">Could not load.</div>`; return; }
  let day = null;
  box.innerHTML = `
    <div class="ovsec">
      <div class="ovhead"><h2>Changes</h2>
        <span class="hint" data-tip>Every edit, newest first.</span>
        <span class="hint">${rows.length} shown</span>
        <label class="more ckf"><input type="checkbox" id="chLogins" ${logins ? "checked" : ""}>
          Include sign-ins</label></div>
      <div class="card2 histpage">${rows.length ? rows.map(h => {
        const label = dayLabel(h.ts);
        const head = label === day ? "" : `<div class="dayhead">${esc(label)}</div>`;
        day = label;
        return head + histRow(h);
      }).join("") : `<div class="empty-hint">No changes recorded yet.</div>`}</div>
    </div>`;
}

/* Sign-ins are recorded in the change log but are not changes to anything -
   hidden by default so they do not push real edits off the page. */
function readLogins() {
  try { return localStorage.getItem("netmap.logins") === "1"; } catch { return false; }
}
document.addEventListener("change", ev => {
  if (ev.target.id !== "chLogins") return;
  try { localStorage.setItem("netmap.logins", ev.target.checked ? "1" : "0"); } catch { /* private */ }
  renderChanges().catch(() => {});
});

async function showHistory() {
  const rows = await api("/api/audit?limit=80");
  let day = null;
  $("#histBody").innerHTML = rows.length ? rows.map(h => {
    const label = dayLabel(h.ts);
    const head = label === day ? "" : `<div class="dayhead">${esc(label)}</div>`;
    day = label;
    return head + histRow(h);
  }).join("") : `<div class="empty">No changes yet.</div>`;
  $("#histModal").hidden = false;
}

/* What changed inside a value. Short values read best as "old → new"; for
   text (notes above all) that showed the first 40 characters of both, which
   for an edit at the end of a note was the same 40 characters twice. Longer
   values get a word diff instead: removed words struck through, added words
   highlighted, and unchanged runs cut down to a few words of context. */
function wordDiff(a, b) {
  const A = a.split(/(\s+)/), B = b.split(/(\s+)/);
  // Trim the common start and end first - most edits touch one place.
  let s = 0;
  while (s < A.length && s < B.length && A[s] === B[s]) s++;
  let e = 0;
  while (e < A.length - s && e < B.length - s && A[A.length - 1 - e] === B[B.length - 1 - e]) e++;
  const a2 = A.slice(s, A.length - e), b2 = B.slice(s, B.length - e);
  let mid = [];
  if (a2.length * b2.length <= 250000) {           // LCS for what remains
    const L = Array.from({ length: a2.length + 1 }, () => new Uint16Array(b2.length + 1));
    for (let i = a2.length - 1; i >= 0; i--)
      for (let j = b2.length - 1; j >= 0; j--)
        L[i][j] = a2[i] === b2[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
    let i = 0, j = 0;
    while (i < a2.length || j < b2.length) {
      if (i < a2.length && j < b2.length && a2[i] === b2[j]) { mid.push(["=", a2[i]]); i++; j++; }
      else if (j < b2.length && (i === a2.length || L[i][j + 1] > L[i + 1][j])) mid.push(["+", b2[j++]]);
      else mid.push(["-", a2[i++]]);
    }
  } else mid = [["-", a2.join("")], ["+", b2.join("")]];
  // A rewrite reads better as "this, then that" than as a patchwork: if under
  // 40% of the words in the changed stretch survived, show both whole.
  const words = t => t.filter(x => x.trim()).length;
  const kept = mid.filter(([op, t]) => op === "=" && t.trim()).length;
  if (kept && kept < 0.4 * Math.max(words(a2), words(b2)))
    mid = [["-", a2.join("")], ["+", b2.join("")]];
  // One part per run, not per word - and within a changed run, what went
  // before what came in, the order a reader expects.
  const runs = [];
  for (const [op, t] of [["=", A.slice(0, s).join("")], ...mid, ["=", A.slice(A.length - e).join("")]]) {
    const last = runs[runs.length - 1];
    if (last && last[0] === op) last[1] += t; else runs.push([op, t]);
  }
  const parts = [];
  for (let k = 0; k < runs.length; k++) {
    if (runs[k][0] === "+" && runs[k + 1]?.[0] === "-") { parts.push(runs[k + 1], runs[k]); k++; }
    else parts.push(runs[k]);
  }
  // Unchanged text keeps about six words next to each change and drops the
  // rest: before the first change only its end matters, after the last only
  // its start, and between two changes both ends.
  const N = 12;                                   // tokens: ~6 words + spaces
  const ctx = (t, where) => {
    const w = t.split(/(\s+)/);
    if (w.length <= (where === "mid" ? 2 * N + 1 : N + 1)) return esc(t);
    if (where === "first") return "…" + esc(w.slice(-N).join(""));
    if (where === "last") return esc(w.slice(0, N).join("")) + "…";
    return esc(w.slice(0, N).join("")) + " … " + esc(w.slice(-N).join(""));
  };
  return parts.map(([op, t], k) => !t ? ""
    : op === "+" ? `<ins>${esc(t)}</ins>`
    : op === "-" ? `<del>${esc(t)}</del>`
    : ctx(t, k === 0 ? "first" : k === parts.length - 1 ? "last" : "mid")).join("");
}

function fieldChange(k, before, after) {
  const a = before == null ? "" : String(before), b = after == null ? "" : String(after);
  const long = a.length > 40 || b.length > 40;
  return `<div class="chg"><code>${esc(k)}</code> ${long && a && b
    ? `<span class="wdiff">${wordDiff(a, b)}</span>`
    : `${esc(a.slice(0, 60)) || "∅"} → ${esc(b.slice(0, 60)) || "∅"}`}</div>`;
}

function histRow(h) {
  let detail = "";
  if (h.action === "update" && h.detail && typeof h.detail === "object")
    detail = Object.entries(h.detail).map(([k, v]) => fieldChange(k, v[0], v[1])).join("");
  return `<div class="hist"${h.entry_id ? ` data-card="${h.entry_id}"` : ""}>
    <b>${esc(h.action)}</b> ${esc(h.name || "")}
    <span class="when">· ${esc(when(h.ts))} · ${esc(h.actor)}</span>${detail}</div>`;
}

/* ================= events ================= */
let t;
$("#search").addEventListener("input", (ev) => {
  clearTimeout(t); filter.q = ev.target.value.trim();
  if (filter.q && view !== "inventory") { view = "inventory"; applyView(); }
  t = setTimeout(load, 200);
});
$("#viewtabs").addEventListener("click", (ev) => {
  const b = ev.target.closest(".vtab"); if (!b) return;
  view = b.dataset.view; applyView();
});
/* Collapsing the rail. Icons only rather than gone: a rail you cannot see is
   one you cannot get back without knowing where to click, and 60px of glyphs
   still answers "where am I". The choice is remembered per browser. */
function applyRail() {
  const min = localStorage.getItem("netmap.rail") === "min";
  document.body.classList.toggle("railmin", min);
  const b = $("#railTog");
  if (b) b.title = min ? "Expand the sidebar" : "Collapse the sidebar";
}
$("#railTog").onclick = () => {
  localStorage.setItem("netmap.rail",
    document.body.classList.contains("railmin") ? "full" : "min");
  applyRail();
};
applyRail();
