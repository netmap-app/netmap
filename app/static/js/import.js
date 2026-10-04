/* NetMap front end - import.js: Settings › Data: JSON import.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

/* ================= JSON import ================= */
let IMPORT = null;   // the parsed file, held between preview and apply

function planHtml(plan) {
  const c = plan.counts;
  const line = (n, what, cls) => n ? `<span class="${cls}">${n} ${what}</span>` : "";
  const names = (arr, f) => arr.length
    ? `<div class="impnames">${arr.slice(0, 12).map(x => esc(f(x))).join(", ")}${
        arr.length > 12 ? ` +${arr.length - 12} more` : ""}</div>` : "";
  return `<div class="impplan">
    <div class="impsum">
      ${line(c.create, "new", "ic")}${line(c.update, "changed", "iu")}
      ${line(c.delete, "to delete", "id")}${line(c.unchanged, "unchanged", "in")}
      ${c.create + c.update + c.delete === 0 && !(plan.relations
        && (plan.relations.links || plan.relations.hosts_mapped))
        ? `<span class="in">nothing to do</span>` : ""}
    </div>
    ${plan.relations && (plan.relations.links || plan.relations.hosts_mapped)
      ? `<div class="impnames">${plan.relations.links} links · ${plan.relations.hosts_mapped} host mappings${
          plan.relations.links_skipped ? ` · ${plan.relations.links_skipped} links skipped` : ""}</div>` : ""}
    ${names(plan.create, x => x)}
    ${names(plan.update, x => `${x.name} (${x.fields.join(", ")})`)}
    ${plan.delete.length ? `<div class="impnames warnrow">deletes: ${
      plan.delete.slice(0, 12).map(x => esc(x.name)).join(", ")}</div>` : ""}
    ${plan.problems.length ? `<div class="impnames warnrow">skipped: ${
      plan.problems.map(p => esc(p.name) + " - " + esc(p.why)).join("; ")}</div>` : ""}
    <div class="setrow">
      <button class="btn ${c.delete ? "danger" : "primary"}" id="impApply"
        ${c.create + c.update + c.delete === 0 && !(plan.relations
          && (plan.relations.links || plan.relations.hosts_mapped)) ? "disabled" : ""}>Apply</button>
      <button class="btn" id="impCancel">Cancel</button>
    </div>
  </div>`;
}

async function importPreview() {
  const mode = $("#impReplace").checked ? "replace" : "merge";
  const plan = await api(`/api/import?mode=${mode}&dry_run=true`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(IMPORT),
  });
  $("#impPlan").innerHTML = planHtml(plan);
  $("#impApply").onclick = async () => {
    if (plan.counts.delete && !(await confirmDialog({
        title: `Delete ${plan.counts.delete} entries?`,
        body: "Replace mode deletes every entry the file does not contain. "
            + "Each stays in the change history.", ok: "Replace" }))) return;
    const res = await api(`/api/import?mode=${mode}&dry_run=false`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(IMPORT),
    });
    const c = res.counts;
    $("#impPlan").innerHTML = `<div class="impplan"><div class="impsum">
      <span class="in">Imported - ${c.create} new, ${c.update} changed, ${c.delete} deleted.</span>
      </div></div>`;
    IMPORT = null;
    toast("Import applied");
    await load();
    renderSettingsPage();
  };
  $("#impCancel").onclick = () => { IMPORT = null; $("#impPlan").innerHTML = ""; };
}

$("#impBtn").onclick = () => $("#impFile").click();
$("#impFile").addEventListener("change", async ev => {
  const f = ev.target.files[0];
  ev.target.value = "";                       // let the same file be picked twice
  if (!f) return;
  try { IMPORT = JSON.parse(await f.text()); }
  catch { toast("That file is not valid JSON"); return; }
  if (Array.isArray(IMPORT)) IMPORT = { entries: IMPORT };
  if (!IMPORT || !Array.isArray(IMPORT.entries)) {
    toast("No 'entries' list in that file"); IMPORT = null; return;
  }
  await importPreview();
});
$("#impReplace").addEventListener("change", () => { if (IMPORT) importPreview(); });
