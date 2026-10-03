/* NetMap front end — addresses.js: the address strip — one /24 at a time.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines — tests/test_frontend.py checks. */

/* ================= address strip ================= */
/* 254 cells per /24. A native `title` was the cheap answer and the wrong one:
   it waits a second, truncates a long list, cannot be clicked, and never
   appears on the free cells — which are the ones you are looking at when the
   question is "what address can I use next". So: a readout that follows the
   pointer, and a popover on click whose entries are links. */
let popNet = null;
// Addresses a source has seen that no entry claims. Not inventory — a layer
// over the map, because a strip that draws an occupied address as free is
// wrong exactly when someone is looking for a free one.
let SEEN = {};

function addrPop() {
  let el = document.getElementById("addrpop");
  if (!el) {
    el = document.createElement("div");
    el.id = "addrpop";
    el.hidden = true;
    document.body.appendChild(el);
  }
  return el;
}

let popReturn = null;       // the strip to hand keyboard focus back to
function closeAddrPop() {
  addrPop().hidden = true; popNet = null;
  if (popReturn?.isConnected) popReturn.focus();
  popReturn = null;
}

function addrOf(net, i) { return net.replace(/0\/24$/, "") + i; }

// Who made it, and since when it has been around — from the server's device
// history (app/newdevices.py). A randomised MAC has no vendor to name.
function seenWho(x) {
  return x.randomised ? "randomised MAC" : (x.vendor || "");
}
function seenWhen(x) {
  if (!x.first_seen) return "";
  const d = ts => dayLabel(ts).replace(/^(Today|Yesterday)$/, s => s.toLowerCase());
  return `first seen ${d(x.first_seen)}` + (x.last_seen ? `, last ${when(x.last_seen)}` : "");
}

function wireStrip(box, nets) {
  closeAddrPop();
  const byNet = {};
  for (const n of nets) byNet[n.net] = n;

  box.querySelectorAll(".snbar").forEach(bar => {
    const n = byNet[bar.dataset.net];
    const read = box.querySelector(`.snread[data-read="${CSS.escape(bar.dataset.net)}"]`);
    if (!n || !read) return;
    const idle = read.innerHTML;

    const describe = cell => {
      const i = +cell.dataset.a, here = n.addrs[i] || [];
      const ipHere = addrOf(n.net, i), sawIt = SEEN[ipHere];
      read.innerHTML = here.length
        ? `<b class="mono">${esc(ipHere)}</b> <span class="rn">${
            here.map(x => esc(x.name)).join(", ")}</span>${
            here.length > 1 ? ` <span class="dupw">shared by ${here.length}</span>` : ""}`
        : sawIt
        ? `<b class="mono">${esc(ipHere)}</b> <span class="seenw">${
            esc(sawIt.label || sawIt.mac || "seen")}</span> <span class="hint">${
            esc([sawIt.detail, seenWho(sawIt), seenWhen(sawIt),
                 (sawIt.sources || []).map(srcLabel).join(", ")].filter(Boolean).join(" · "))}</span>`
        : `<b class="mono">${esc(ipHere)}</b> <span class="hint">free</span>`;
    };
    bar.addEventListener("mousemove", ev => {
      const cell = ev.target.closest("i[data-a]");
      if (cell) describe(cell);
    });
    bar.addEventListener("mouseleave", () => {
      if (document.activeElement !== bar) read.innerHTML = idle;
    });

    /* The keyboard reaches the strip as one stop, not 254: Tab lands on the
       bar, the arrow keys move through its addresses (Shift+arrow skips to the
       next one that is in use or seen, Home/End go to the ends), the read-out
       below follows and is announced, and Enter or Space opens the detail. */
    bar.tabIndex = 0;
    bar.setAttribute("role", "group");
    bar.setAttribute("aria-label", `Addresses in ${n.net}. Arrow keys move, `
      + "Shift+arrow skips to the next one in use, Enter shows detail.");
    read.setAttribute("aria-live", "polite");
    const cells = [...bar.querySelectorAll("i[data-a]")];
    let cur = -1;
    const move = to => {
      cur = Math.max(0, Math.min(cells.length - 1, to));
      cells.forEach((c, k) => c.classList.toggle("kcur", k === cur));
      describe(cells[cur]);
    };
    bar.addEventListener("focus", () => move(cur < 0 ? 0 : cur));
    bar.addEventListener("blur", () => {
      cells.forEach(c => c.classList.remove("kcur"));
      read.innerHTML = idle;
    });
    bar.addEventListener("keydown", ev => {
      const used = k => !cells[k].classList.contains("free");
      const skip = dir => { let k = cur + dir;
        while (k >= 0 && k < cells.length && !used(k)) k += dir;
        return k >= 0 && k < cells.length ? k : cur; };
      const to = { ArrowRight: ev.shiftKey ? skip(1) : cur + 1,
                   ArrowLeft: ev.shiftKey ? skip(-1) : cur - 1,
                   Home: 0, End: cells.length - 1 }[ev.key];
      if (to !== undefined) { ev.preventDefault(); move(to); return; }
      if ((ev.key === "Enter" || ev.key === " ") && cur >= 0) {
        ev.preventDefault();
        cells[cur].click();
      }
    });

    bar.addEventListener("click", ev => {
      const cell = ev.target.closest("i[data-a]");
      if (!cell) return;
      ev.stopPropagation();
      const i = +cell.dataset.a, here = n.addrs[i] || [];
      const ip = addrOf(n.net, i);
      const el = addrPop();
      el.innerHTML = `
        <div class="aph"><b class="mono">${esc(ip)}</b>
          <span class="apx" id="apClose">✕</span></div>
        ${here.length
          ? `<div class="apl">${here.map(x => {
              // Only the first port. Free text like "8123 (default, verify)"
              // makes every chip a full line and the list unreadable.
              const p = (x.ports || "").match(/\d{1,5}/);
              return `<span class="lchip" data-card="${x.id}">${esc(x.name)}${
                p ? `<i class="mono">${p[0]}</i>` : ""}</span>`;
            }).join("")}</div>
             ${here.length > 1
               ? `<div class="apw">${here.length} entries at this address. Normal for
                  containers on one host — the Overview flags the pairs that actually
                  conflict.</div>` : ""}`
          : SEEN[ip]
          ? `<div class="apseen"><b>${esc(SEEN[ip].label || "unnamed device")}</b>
               <span class="hint">${esc(SEEN[ip].detail || "")}</span>
               ${SEEN[ip].mac ? `<span class="mono">${esc(SEEN[ip].mac)}</span>` : ""}
               ${seenWho(SEEN[ip]) ? `<span class="hint">${esc(seenWho(SEEN[ip]))}</span>` : ""}
               ${seenWhen(SEEN[ip]) ? `<span class="hint apwhen">${esc(seenWhen(SEEN[ip]))}</span>` : ""}
               <span class="hint">seen by ${esc((SEEN[ip].sources || []).map(srcLabel).join(", "))}</span></div>
             <div class="apf">On the network, not in the inventory.</div>
             <button class="btn primary sm" id="apAdd">Add to inventory</button>`
          : `<div class="apf">Nothing in the inventory claims this address.</div>
             <button class="btn primary sm" id="apAdd">Add an entry here</button>`}`;
      const r = cell.getBoundingClientRect();
      el.hidden = false;
      // Measure after unhiding, then keep it inside the viewport — the cell
      // may be at either edge of a 254-wide strip.
      const w = el.offsetWidth;
      el.style.left = Math.max(8, Math.min(window.innerWidth - w - 8,
                                           r.left + r.width / 2 - w / 2)) + "px";
      el.style.top = (r.bottom + 8) + "px";
      popNet = ip;
      popReturn = document.activeElement === bar ? bar : null;
      const close = el.querySelector("#apClose");
      if (close) {
        close.onclick = closeAddrPop;
        close.setAttribute("role", "button");
        close.setAttribute("aria-label", "Close");
        close.tabIndex = 0;
      }
      if (popReturn) (el.querySelector("#apAdd, .lchip, #apClose") || el).focus();
      const add = el.querySelector("#apAdd");
      if (add) add.onclick = () => {
        const x = SEEN[ip] || {};
        closeAddrPop();
        openEdit(null);
        const set = (id, v) => {
          const f = $("#" + id);
          if (f && v) { f.value = v; f.dispatchEvent(new Event("input")); }
        };
        // Everything the sources already know, so promoting a device is a
        // decision rather than a retyping exercise.
        set("f_ip", ip);
        set("f_name", x.label || "");
        set("f_mac", x.mac || "");
        set("f_notes", x.detail ? `Seen on the network: ${x.detail}.` : "");
        $("#f_name").focus();
      };
    });
  });
}

document.addEventListener("click", ev => {
  if (addrPop().hidden) return;
  // A chip opens the service card, which would otherwise appear behind a
  // popover still sitting over the strip.
  if (ev.target.closest("#addrpop .lchip")) { closeAddrPop(); return; }
  if (!ev.target.closest("#addrpop")) closeAddrPop();
});
document.addEventListener("keydown", ev => {
  if (ev.key === "Escape" && !addrPop().hidden) closeAddrPop();
});
