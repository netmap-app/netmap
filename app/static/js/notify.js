/* NetMap front end - notify.js: Settings › Notifications.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines - tests/test_frontend.py checks. */

/* ================= Settings > Notifications ================= */
// Where Overview news goes when nobody is looking: ntfy, Gotify, Telegram or
// a webhook. The form reuses the source form's field helpers (sources.js)
// with its own id prefix, so both forms can exist at once.
let NOTIFY = [];
let NOTIFY_TYPES = null;
let NOTIFY_OPENER = null;

// Short names for the row; the form shows the full sentence from the server.
const NOTIFY_EVENT_SHORT = {
  finding: "new findings", entry: "entries down or back",
  source: "sources down or back", cert: "certificates", critical: "critical items",
  watch: "watched devices",
};
// What a summary channel still sends at once (critical level only).
const NOTIFY_URGENT = {
  entry: "A critical entry going down", source: "A source not answering",
  cert: "A certificate expired", critical: "Any other critical item",
};
const NOTIFY_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const hh = h => String(h).padStart(2, "0") + ":00";

function notifyDeliveryText(d) {
  if (!d || d.mode === "off") return "";
  return d.mode === "daily" ? `daily summary at ${hh(d.hour)}`
    : `weekly summary, ${NOTIFY_DAYS[d.day]} ${hh(d.hour)}`;
}

async function notifyTypes() {
  if (!NOTIFY_TYPES) NOTIFY_TYPES = await api("/api/notify/types");
  return NOTIFY_TYPES;
}

function notifyWhere(ch) {
  const c = ch.config || {};
  if (ch.type === "ntfy") return `${c.topic || "?"} on ${c.url || "ntfy.sh"}`;
  if (ch.type === "gotify") return c.url || "";
  if (ch.type === "telegram") return `chat ${c.chat_id || "?"}`;
  const u = (ch.secrets || {}).url;
  return u && u.set ? `URL ${u.preview.slice(-8)}` : "";
}

function notifyRowHtml(ch) {
  const dotCls = !ch.enabled ? "na" : ch.error ? "down" : ch.last_ok ? "up" : "na";
  const dotTitle = !ch.enabled ? "Disabled" : ch.error ? ch.error
    : ch.last_ok ? "Last delivery OK" : "Nothing sent yet";
  const events = (ch.events || []).map(e => NOTIFY_EVENT_SHORT[e] || e).join(", ") || "no events";
  return `<div class="srcrow" data-nid="${esc(ch.id)}">
    <span class="dot ${dotCls}" title="${esc(dotTitle)}"></span>
    <div class="srcinfo">
      <div class="srcname">${esc(ch.name)}${ch.name !== ch.label
        ? ` <span class="hint">· ${esc(ch.label)}</span>` : ""}</div>
      <div class="srcmeta">${esc(notifyWhere(ch))} · ${esc(events)}${ch.enabled ? "" : " · disabled"}</div>
      ${notifyDeliveryText(ch.delivery) ? `<div class="srcmeta">${esc(notifyDeliveryText(ch.delivery))}${
        ch.waiting ? ` · ${ch.waiting} waiting` : ""}</div>` : ""}
      ${ch.held ? `<div class="srcmeta">${ch.held} held back by the rate limit</div>` : ""}
      ${ch.error ? `<div class="srcerr">${esc(ch.error)}</div>` : ""}
    </div>
    <div class="btns">
      <button class="btn sm" data-n-test="${esc(ch.id)}">Test</button>
      <button class="btn sm" data-n-edit="${esc(ch.id)}">Edit</button>
      <button class="btn sm danger" data-n-del="${esc(ch.id)}">Delete</button>
    </div>
  </div>`;
}

async function loadNotify() {
  loadTimezone();
  const box = $("#notifyList");
  box.innerHTML = "Loading…";
  try {
    NOTIFY = await api("/api/notify/channels");
    box.innerHTML = NOTIFY.length ? NOTIFY.map(notifyRowHtml).join("")
      : `<div class="srcempty">No channels yet - add one to hear about problems
         when NetMap is not open.</div>`;
  } catch {
    box.innerHTML = `<div class="srcempty">Could not load.</div>`;
  }
}

/* ---- the time zone summaries are scheduled in ---- */
async function loadTimezone() {
  try { $("#tzName").value = (await api("/api/settings/timezone")).timezone; }
  catch { /* the field stays empty; saving still works */ }
}
$("#tzForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  try {
    const r = await api("/api/settings/timezone", {
      method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ timezone: $("#tzName").value.trim() }),
    });
    $("#tzName").value = r.timezone;
    toast(`Summaries use ${r.timezone} time`);
  } catch { /* api() already toasted why */ }
});

function closeNotifyForm() {
  $("#notifyForm").innerHTML = "";
  if (NOTIFY_OPENER && document.contains(NOTIFY_OPENER)) NOTIFY_OPENER.focus();
  NOTIFY_OPENER = null;
}

function showNotifyForm(focus) {
  const f = $("#notifyForm .srcform");
  if (!f) return;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  f.scrollIntoView({ behavior: still ? "auto" : "smooth", block: "start" });
  const el = focus ? f.querySelector(focus) : null;
  if (el) el.focus({ preventScroll: true });
}

function notifyDeliveryHtml(d) {
  const opt = (v, label, cur) => `<option value="${v}"${String(v) === String(cur) ? " selected" : ""}>${esc(label)}</option>`;
  return `<div class="ndeliv" role="group" aria-labelledby="ntfDelHead">
    <div class="pickhead" id="ntfDelHead">Delivery</div>
    <div class="ndrow">
      <select id="ntff__mode" aria-label="Delivery">${
        [["off", "Immediately"], ["daily", "Daily summary"], ["weekly", "Weekly summary"]]
          .map(([v, l]) => opt(v, l, d.mode)).join("")}</select>
      <select id="ntff__day" aria-label="Day">${
        NOTIFY_DAYS.map((n, i) => opt(i, n, d.day)).join("")}</select>
      <select id="ntff__hour" aria-label="Hour">${
        Array.from({ length: 24 }, (_, h) => opt(h, hh(h), d.hour)).join("")}</select>
    </div>
    <div class="nurgent">
      <span class="hint">Send at once even in a summary:</span>
      ${Object.entries(NOTIFY_URGENT).map(([k, label]) => `<label class="ckf">
        <input type="checkbox" data-n-urgent="${k}" ${d.urgent.includes(k) ? "checked" : ""}>
        <span>${esc(label)}</span></label>`).join("")}
    </div>
  </div>`;
}

function syncNotifyDelivery() {
  const mode = $("#ntff__mode").value;
  $("#ntff__day").hidden = mode !== "weekly";
  $("#ntff__hour").hidden = mode === "off";
  $(".nurgent").hidden = mode === "off";
}

function openNotifyForm(type, events, existing) {
  const on = existing ? existing.events : Object.keys(events);
  const deliv = (existing && existing.delivery)
    || { mode: "off", hour: 8, day: 0, urgent: Object.keys(NOTIFY_URGENT) };
  $("#notifyForm").innerHTML = `<div class="srcform">
    <div class="flabel"><h3>${existing ? "Edit" : "Add"} ${esc(type.label)}</h3>
      <span class="hint" data-tip>${esc(type.hint)}</span></div>
    <label class="ckf formon"><input type="checkbox" id="ntffEnabled"
      ${!existing || existing.enabled ? "checked" : ""}> Enabled</label>
    <div class="f"><label for="ntff__name">Name</label>
      <input id="ntff__name" value="${esc(existing ? existing.name : "")}"
        placeholder="${esc(type.label)}"></div>
    ${type.fields.map(f => srcFieldHtml(f, existing, "ntff_")).join("")}
    <div class="nevents" role="group" aria-labelledby="ntfEvHead">
      <div class="pickhead" id="ntfEvHead">Tell this channel about</div>
      ${Object.entries(events).map(([k, label]) => `<label class="ckf">
        <input type="checkbox" data-n-event="${esc(k)}" ${on.includes(k) ? "checked" : ""}>
        <span>${esc(label)}</span></label>`).join("")}
    </div>
    ${notifyDeliveryHtml(deliv)}
    <div id="notifyTestOut" class="hint"></div>
    <div class="setrow">
      <button class="btn primary" id="notifySaveBtn">Save</button>
      <button class="btn" id="notifyTestBtn">Send test</button>
      <button class="btn" id="notifyCancelBtn">Cancel</button>
    </div>
  </div>`;
  const gather = () => ({
    name: $("#ntff__name").value.trim(),
    fields: srcGather(type, "ntff_"),
    events: [...document.querySelectorAll("[data-n-event]")]
      .filter(b => b.checked).map(b => b.dataset.nEvent),
    enabled: $("#ntffEnabled").checked,
    delivery: {
      mode: $("#ntff__mode").value,
      hour: parseInt($("#ntff__hour").value, 10),
      day: parseInt($("#ntff__day").value, 10),
      urgent: [...document.querySelectorAll("[data-n-urgent]")]
        .filter(b => b.checked).map(b => b.dataset.nUrgent),
    },
  });
  syncNotifyDelivery();
  $("#ntff__mode").onchange = syncNotifyDelivery;
  $("#notifyCancelBtn").onclick = closeNotifyForm;
  showNotifyForm(existing ? '[id^="ntff_"]:not(#ntff__name)' : "#ntff__name");
  $("#notifyTestBtn").onclick = async () => {
    const out = $("#notifyTestOut");
    out.textContent = "Sending…";
    try {
      // An edit tests what is saved - its secrets never come back to the
      // browser to be sent along. Save first to test a change.
      const r = existing
        ? await api(`/api/notify/channels/${existing.id}/test`, { method: "POST" })
        : await api("/api/notify/test", {
            method: "POST", headers: { "content-type": "application/json" },
            body: JSON.stringify({ type: type.type, fields: gather().fields }),
          });
      out.textContent = r.ok ? "Sent - check that it arrived" + (existing ? " (the saved settings)" : "")
        : "Failed: " + (r.error || "unknown error");
    } catch { out.textContent = "Could not send the test."; }
  };
  $("#notifySaveBtn").onclick = async () => {
    const body = gather();
    try {
      if (existing) {
        await api(`/api/notify/channels/${existing.id}`, {
          method: "PUT", headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        toast("Channel updated");
      } else {
        await api("/api/notify/channels", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ type: type.type, ...body }),
        });
        toast("Channel added");
      }
      $("#notifyForm").innerHTML = "";
      await loadNotify();
    } catch { /* api() already toasted why */ }
  };
}

$("#notifyAddBtn").onclick = async () => {
  NOTIFY_OPENER = $("#notifyAddBtn");
  const t = await notifyTypes().catch(() => null);
  if (!t) { toast("Could not load the channel types"); return; }
  $("#notifyForm").innerHTML = `<div class="srcform"><h3>Add a channel</h3>
    <div class="picklist">${t.types.map(d => `
      <button class="pickrow" data-n-pick="${esc(d.type)}">
        <span class="picklabel">${esc(d.label)}</span>
        <span class="hint">${esc(d.hint)}</span>
      </button>`).join("")}</div>
    <div class="setrow"><button class="btn" id="notifyPickCancel">Cancel</button></div>
  </div>`;
  document.querySelectorAll("[data-n-pick]").forEach(b => {
    b.onclick = () => openNotifyForm(t.types.find(d => d.type === b.dataset.nPick), t.events, null);
  });
  $("#notifyPickCancel").onclick = closeNotifyForm;
  showNotifyForm(".pickrow");
};

$("#notifyList").addEventListener("click", async ev => {
  const b = ev.target.closest("[data-n-test], [data-n-edit], [data-n-del]");
  if (!b) return;
  const ch = NOTIFY.find(c => c.id === (b.dataset.nTest || b.dataset.nEdit || b.dataset.nDel));
  if (!ch) return;
  if (b.dataset.nTest) {
    b.disabled = true;
    try {
      const r = await api(`/api/notify/channels/${ch.id}/test`, { method: "POST" });
      toast(r.ok ? `Test sent to ${ch.name}` : `${ch.name}: ${r.error}`);
    } catch { /* api() already toasted why */ }
    await loadNotify();
    return;
  }
  if (b.dataset.nEdit) {
    const t = await notifyTypes().catch(() => null);
    const type = t && t.types.find(d => d.type === ch.type);
    NOTIFY_OPENER = b;
    if (type) openNotifyForm(type, t.events, ch);
    return;
  }
  if (!(await confirmDialog({
    title: `Remove "${ch.name}"?`,
    body: "Its stored token or URL is deleted with it.",
    ok: "Remove" }))) return;
  await api(`/api/notify/channels/${ch.id}`, { method: "DELETE" });
  toast("Channel removed");
  await loadNotify();
});
