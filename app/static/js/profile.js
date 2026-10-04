/* NetMap front end - profile.js: Settings › Profile: the local account, appearance.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

/* ---- Settings > Profile - the local account (app/accounts.py) ---- */
const VIA = { access: "Cloudflare Access", password: "the password login",
              token: "the API token", off: "nothing - NETMAP_AUTH=off" };

function showPwBanner(p) { $("#pwBanner").hidden = !(p && p.must_change); }

async function loadProfile() {
  let p;
  try { p = await api("/api/profile"); } catch { $("#profWho").textContent = "Could not load."; return; }
  showPwBanner(p);
  $("#profWho").innerHTML = `Signed in as <b>${esc(p.signed_in_as)}</b> through ${esc(VIA[p.via] || p.via)}.`
    + (p.must_change ? ` <span class="warntext">The local login still uses its starting password.</span>` : "")
    + (p.password_changed_at ? ` <span class="hint">Password last set ${esc(when(p.password_changed_at))}.</span>` : "");
  $("#profUser").value = p.username;
  $("#profPwUser").value = p.username;
  const pw = p.via === "password";
  $("#signOut").hidden = !pw;
  $("#signOutHint").textContent = pw ? ""
    : `This browser is signed in through ${VIA[p.via] || p.via}, not the password login - there is nothing to sign out of here.`;
}

$("#profNameForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  await api("/api/profile", {
    method: "PUT", headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: $("#profUser").value.trim() }),
  });
  toast("Username saved");
  loadProfile();
});

$("#profPwForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  if ($("#pwNew").value !== $("#pwNew2").value) { toast("The two new passwords differ"); return; }
  const r = await fetch("/api/profile/password", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ current: $("#pwCur").value, new: $("#pwNew").value }),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    toast(d.detail || `Error ${r.status}`); return;
  }
  ev.target.reset();
  toast("Password changed");
  loadProfile();
});

$("#signOut").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  location.href = "/login";
});

$("#pwBanner").addEventListener("click", () => {
  view = "settings"; applySetTab("profile"); applyView();
});

/* The version in the rail used to arrive only when Settings was opened, which
   is the one place it is already written. Ask once at boot instead. */
api("/api/about").then(a => {
  const rv = $("#railVer"); if (rv) rv.textContent = "v" + a.version;
}).catch(() => {});

$("#railnav").addEventListener("click", (ev) => {
  const b = ev.target.closest(".rnav[data-view]"); if (!b) return;
  view = b.dataset.view; applyView();
});
$("#groupSeg").addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-group]"); if (!b) return;
  groupBy = b.dataset.group;
  localStorage.setItem("netmap.groupby", groupBy);
  renderChips(); renderList();
});
// On the whole row: the strip and the Filters panel share this handler.
$("#chipsrow").addEventListener("click", (ev) => {
  const c = ev.target.closest(".chip:not(#filterBtn)"); if (!c) return;
  const only = (key, val) => {
    for (const k of ["category", "tag", "kind", "criticality", "zone", "ip"]) filter[k] = "";
    if (key) filter[key] = val;
  };
  const d = c.dataset;
  if (d.tagchip !== undefined) only(filter.tag === d.tagchip ? null : "tag", d.tagchip);
  else if (d.kindchip !== undefined) only(filter.kind === d.kindchip ? null : "kind", d.kindchip);
  else if (d.critchip !== undefined) only(filter.criticality === d.critchip ? null : "criticality", d.critchip);
  else if (d.zonechip !== undefined) only(filter.zone === d.zonechip ? null : "zone", d.zonechip);
  else if (d.ipchip !== undefined) only(null);
  else only(d.cat ? "category" : null, d.cat);
  closeFilterPop();
  load();
});

function closeFilterPop(focusBtn = false) {
  $("#filterPop").hidden = true;
  $("#filterBtn").setAttribute("aria-expanded", "false");
  if (focusBtn) $("#filterBtn").focus();
}
$("#filterBtn").addEventListener("click", ev => {
  ev.stopPropagation();
  const open = $("#filterPop").hidden;
  $("#filterPop").hidden = !open;
  $("#filterBtn").setAttribute("aria-expanded", String(open));
  if (open) $("#filterPop .chip")?.focus();
});
document.addEventListener("click", ev => {
  if (!$("#filterPop").hidden && !ev.target.closest("#filterPop, #filterBtn")) closeFilterPop();
});
document.addEventListener("keydown", ev => {
  if (ev.key === "Escape" && !$("#filterPop").hidden) closeFilterPop(true);
});
document.addEventListener("click", async (ev) => {
  const cat = ev.target.closest("[data-cat]");
  if (cat && (cat.classList.contains("cn") || cat.classList.contains("catrow"))) {
    filter.category = cat.dataset.cat; filter.tag = ""; filter.ip = ""; view = "inventory"; applyView(); load(); return;
  }
  const tg = ev.target.closest("[data-tag]");
  if (tg) { filter.tag = tg.dataset.tag; filter.category = ""; filter.ip = ""; view = "inventory"; applyView(); load(); return; }
  if (ev.target.closest("#ovHist")) { view = "changes"; applyView(); return; }
  const bulk = ev.target.closest("[data-fignoreall]");
  if (bulk) { await ignoreAll(bulk.dataset.fignoreall); return; }
  for (const [attr, what] of [["fcreate", "create"], ["fapply", "apply"],
                             ["funver", "unver"], ["fdel", "delete"],
                             ["fignore", "ignore"], ["fwatch", "watch"]]) {
    const el = ev.target.closest(`[data-${attr}]`);
    if (el) { await findingAction(el.dataset[attr], what); return; }
  }
  const fo = ev.target.closest("[data-fopen]");
  if (fo && fo.dataset.fopen) { showCard(fo.dataset.fopen); return; }
  const head0 = ev.target.closest(".groupname");
  const gt = head0 ? head0.querySelector("[data-gtog]") : null;
  if (gt) {
    const head = head0;
    const open = head.dataset.open !== "true";
    head.dataset.open = String(open);
    gt.setAttribute("aria-expanded", String(open));
    const body = head.nextElementSibling;
    if (body && body.classList.contains("gbody")) body.hidden = !open;
    if (open) GFOLD.delete(gkey(gt.dataset.gtog)); else GFOLD.add(gkey(gt.dataset.gtog));
    gsave();
    return;
  }
  const tog = ev.target.closest("[data-tog]");
  if (tog) {
    const row = tog.closest(".tn");
    const open = row.dataset.open !== "true";
    row.dataset.open = String(open);
    tog.setAttribute("aria-expanded", String(open));
    if (open) TFOLD.delete(tog.dataset.tog); else TFOLD.add(tog.dataset.tog);
    tsave();
    return;
  }
  const fa = ev.target.closest("#tfoldall");
  if (fa) {
    const rows = [...document.querySelectorAll(".tree .tn.has")];
    // One switch, and it does whichever is not already true of everything.
    const collapse = rows.some(r => r.dataset.open === "true");
    for (const r of rows) {
      r.dataset.open = String(!collapse);
      const b = r.querySelector("[data-tog]");
      if (b) {
        b.setAttribute("aria-expanded", String(!collapse));
        if (collapse) TFOLD.add(b.dataset.tog); else TFOLD.delete(b.dataset.tog);
      }
    }
    fa.textContent = collapse ? "Expand all" : "Collapse all";
    tsave();
    return;
  }
  const pt = ev.target.closest("[data-port]");
  if (pt) { showPort(pt.dataset.port); return; }
  const cd = ev.target.closest("[data-card]");
  if (cd) { showCard(cd.dataset.card); return; }
  const ul = ev.target.closest("[data-unlink]");
  if (ul) {
    const [src, dst, type] = ul.dataset.unlink.split(":");
    await api(`/api/edges?src=${src}&dst=${dst}&type=${encodeURIComponent(type)}`,
              { method: "DELETE" });
    toast("Link removed");
    if (cardId) showCard(cardId);
    return;
  }
  const ed = ev.target.closest("[data-edit]");
  if (ed) { const e = entryById(ed.dataset.edit); if (e) openEdit(e); return; }
  const row = ev.target.closest("tr[data-id], .card[data-id]");
  if (row && !ev.target.closest("a, button, .tag")) { showCard(row.dataset.id); return; }
  const rc = ev.target.closest("[data-recheck]");
  if (rc) {
    const id = rc.dataset.recheck;
    const st = await api("/api/status/refresh?entry_id=" + id, { method: "POST" });
    const e = ENTRIES.find(x => x.id == id); if (e) { e.status = st; renderList(); }
    toast(st.up === true ? `Up (${st.latency_ms}ms)` : st.up === false ? "No answer" : "Not monitored");
  }
});
