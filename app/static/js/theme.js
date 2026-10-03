/* NetMap front end — theme.js: light / dark / auto.
   One of the plain scripts index.html loads in order; they share one
   global scope. Code that runs at load may only use what an earlier
   file (or this one) defines — tests/test_frontend.py checks. */

/* ---- theme: "auto" leaves the OS media query in charge ---- */
function readTheme() {
  try { return localStorage.getItem("netmap.theme") || "auto"; } catch { return "auto"; }
}
function applyTheme(t) {
  if (t === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem("netmap.theme", t); } catch { /* private mode */ }
  // Marks are painted server-side per theme, so a switch has to re-request
  // them. Rewriting the src is enough; the browser has both cached.
  document.querySelectorAll("img.svc").forEach(i => {
    i.src = i.src.replace(/([?&]t=)(dark|light)/, "$1" + inkNow());
  });
  document.querySelectorAll("[data-theme-set]").forEach(b =>
    b.classList.toggle("on", b.dataset.themeSet === t));
}
applyTheme(readTheme());

const toast = (msg) => {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(t._t); t._t = setTimeout(() => (t.hidden = true), 2200);
};

async function api(path, opts) {
  const r = await fetch(path, opts);
  // Signed out — an expired session, or a password changed elsewhere. The
  // login form is the only useful thing to show.
  if (r.status === 401 && !path.startsWith("/api/profile/password")) {
    location.href = "/login"; throw new Error(401);
  }
  if (!r.ok) { toast("Error: " + r.status + " " + (await r.text()).slice(0, 240)); throw new Error(r.status); }
  return r.status === 204 ? null : r.json();
}

function linkFor(e) {
  // Only web addresses become links — never `javascript:` or `data:`. The
  // server refuses those on write; this covers anything stored before it did.
  if (e.url) return /^https?:\/\//i.test(e.url.trim()) ? e.url.trim() : null;
  const ip = (e.ip || "").trim();
  if (!ip || !/^[A-Za-z0-9_.:-]+$/.test(ip)) return null;
  const m = (e.ports || "").match(/\b(\d{1,5})\b/);
  if (!m) return null;
  const port = parseInt(m[1], 10);
  if (!(port > 0 && port < 65536)) return null;
  const proto = /https|dsm|8443|9443|8006|8007|8123/i.test((e.protocol || "") + " " + port)
    && !/^\s*http\b/i.test(e.protocol || "") ? "https" : "http";
  return `${proto}://${ip}:${port}`;
}

// What the last check did and what answered — the server writes it
// ("HTTPS 10.0.0.5:443/health → 200 in 42 ms"); older results lack it.
function statusWhy(st) {
  if (st.summary) return st.summary;
  return st.up === true ? `Reachable ${st.target || ""} ${st.latency_ms ?? ""}ms`
    : st.up === false ? `No answer on ${st.target || "?"}` : "Not monitored";
}
function dot(e) {
  const st = e.status || {};
  const cls = st.up === true ? "up" : st.up === false ? "down" : "na";
  // The 30-day figure, where the uptime rule shows it (app/uptime.py).
  const up = e.uptime != null ? ` · ${e.uptime}% up over 30 days` : "";
  return `<span class="dot ${cls}" title="${esc(statusWhy(st) + up)}"></span>`;
}

function when(ts) {
  if (!ts) return "";
  const d = new Date(ts.endsWith("Z") ? ts : ts + "Z");
  if (isNaN(d)) return ts;
  const today = new Date().toDateString() === d.toDateString();
  // 24-hour, whatever the browser's locale — the same clock as whenScan().
  const hm = { hour: "2-digit", minute: "2-digit", hourCycle: "h23" };
  return today ? d.toLocaleTimeString([], hm)
               : d.toLocaleDateString([], { day: "numeric", month: "short" }) + " " +
                 d.toLocaleTimeString([], hm);
}

/* A scan's timestamp is read once, days later, next to sources that may have
   gone stale — "today at 9 PM" is useless once today has passed, so unlike
   `when()` this always carries the date, in dd.mm.yyyy + 24h so it reads the
   same regardless of locale. */
function whenScan(ts) {
  if (!ts) return "";
  const d = new Date(ts.endsWith("Z") ? ts : ts + "Z");
  if (isNaN(d)) return ts;
  const p2 = (n) => String(n).padStart(2, "0");
  return `${p2(d.getDate())}.${p2(d.getMonth() + 1)}.${d.getFullYear()} `
       + `${p2(d.getHours())}:${p2(d.getMinutes())}`;
}

/* Only the two levels that change what you do about an outage earn a badge;
   "normal" on sixty rows is decoration. */
const critBadge = (e) => (e.criticality === "critical" || e.criticality === "important")
  ? `<span class="crit ${esc(e.criticality)}">${esc(e.criticality)}</span>` : "";

const tagHtml = (tags) => (tags || [])
  .map(t => `<span class="tag" data-tag="${esc(t)}">${esc(t)}</span>`).join("");
