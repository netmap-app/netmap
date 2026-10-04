/* The local sign-in form - see app/accounts.py. A separate file rather than
   an inline <script>: the Content-Security-Policy allows no inline script. */
(() => {
  try {
    const t = localStorage.getItem("netmap.theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch { /* private mode */ }

  const form = document.getElementById("loginForm");
  const err = document.getElementById("lErr");
  const go = document.getElementById("lGo");
  document.getElementById("lUser").focus();

  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    err.hidden = true;
    go.disabled = true;
    try {
      const r = await fetch("/api/auth/login", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({
          username: document.getElementById("lUser").value,
          password: document.getElementById("lPass").value,
        }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || `sign-in failed (${r.status})`);
      // Straight to the password form while the starting password is in use.
      location.replace(d.must_change ? "/#settings" : "/");
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
      document.getElementById("lPass").select();
    } finally {
      go.disabled = false;
    }
  });
})();
