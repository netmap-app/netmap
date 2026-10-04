# Contributing to NetMap

NetMap is a self-hosted inventory and reconciliation app for a home or
small-office network. Single container: FastAPI + SQLite + an MCP server, no
build step, no framework. `app/db.py` is meant to be readable in one sitting -
keep it that way.

Issues and pull requests are welcome. Security problems go through
[SECURITY.md](SECURITY.md), not a public issue. How a release is cut:
[RELEASING.md](RELEASING.md).

## Rules the code keeps

- **Credentials never appear in chat, the repository, an issue, a log, a test
  fixture or a tool call.** Every source is an instance added in Settings › Sources and
  stored in `source_instances` (drivers: `app/sources/dynamic.py`; field
  schema: `app/sources/fields.py`). The old `NETMAP_*` source variables are a
  one-time seed (`sources.migrate_legacy()`, guarded by the `sources_seeded`
  kv row) and ignored afterwards. Never ask for a credential or echo one; a
  credential pasted into a chat or somewhere public by mistake is
  regenerated, not reused.
- **Every secret is encrypted at rest.** A source's `secrets` column goes
  through `app/crypto.py`. With `NETMAP_SECRET_KEY` set, the key lives only in
  the container's environment and the database holds ciphertext alone - a
  copy of `netmap.db` cannot be decrypted by itself. Without it, a key
  generated on first boot is stored in the database. Setting the variable
  later re-encrypts everything at start-up and deletes the stored key; a key
  that opens nothing is a critical Overview item, never a silent blank. The
  Settings UI shows at most a last-four-characters preview, never the value;
  a blank secret field on save means "keep what is stored", not "clear it".
- **Every source is read-only.** Four are read-only by enforcement (Docker's
  socket proxy, UniFi's View Only role, NPM's View Only user, Cloudflare's
  scoped token); OPNsense, Pi-hole and Home Assistant are read-only *by
  promise* - the module contains no code path able to construct a write, and
  that promise is checkable by reading one file. Keep it true. Every driver
  holds itself to the same promise - Proxmox issues GETs only, and a token
  built from its built-in "PVEAuditor" role cannot write even if the code
  tried.
- **Drivers keep no module state.** Configuration arrives as `cfg`; login
  sessions live in `cfg["_state"]`, which is per instance and dropped on
  every edit. A type can have several instances: ids are the type, then
  `<type>-2`…; drivers write sightings/presence under `cfg["_id"]` and start
  finding keys with `cfg["_key"]`. Never compare a source id to a type name -
  use `dynamic.type_of()`. Code outside a scan that needs another source's
  answer uses `sources.by_role(role)` (or `bound_all(type)` for a
  product-specific need); a driver's `ABSENCE` set names findings a sibling
  instance can shadow.
- **Shared code asks for a role, never a product.** Roles live in
  `dynamic.ROLES` (dns, proxy, edge, firewall, layer2, scanner…); a driver
  declaring a role keeps that role's contract, which `tests/test_roles.py`
  checks. The checks a role implies live once, in `_dns.py` / `_proxy.py`; a
  new DNS server or proxy maps its API onto records/routes and calls them.
- **Nothing assumes one installation** - not a domain, an address or a naming
  convention. Derive it from a source or make it a field.
- **Discovery never writes to the inventory.** A scan reports; a person
  decides. Firewall changes are made by the person, never by the app.
- **Nothing is reachable without a credential by default.** The web UI and
  API require a login; the MCP endpoint is off until `NETMAP_MCP_TOKEN` is
  set. A path is never a credential.
- **Entry notes are short.** Essential technical facts only.

## Working on it

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m playwright install chromium     # for the browser tests
.venv/bin/pytest -q
```

- **A fix comes with a test that fails without it.** `tests/conftest.py`'s
  `make_app(**env)` re-imports the app under a given environment with an empty
  temporary database - configuration is read at import, so that is the way to
  test a different auth mode.
- **A UI change comes with a browser test** in `tests/ui` (Playwright, a real
  server per test; CI runs them and fails if the browser is missing),
  including a check at phone width (375 px, no horizontal scroll).
- **Test the states the seed data does not produce** - sources reporting, a
  queue with rows, the all-clear - by intercepting `/api/overview` in the
  test. A build once shipped broken because an empty source list meant the
  code path that referenced a deleted constant never ran.
- **Run it locally** against a scratch database:

  ```bash
  NETMAP_DB=/tmp/nm.db NETMAP_AUTH=off NETMAP_ALLOWED_HOSTS=localhost \
    .venv/bin/uvicorn app.main:application --port 8099
  ```

  `NETMAP_AUTH=off` because the API otherwise refuses requests without a login;
  `application`, not `app`, so the MCP dispatcher is in front, as in the
  container. Drive it headless and assert on the DOM, not on a screenshot
  alone.

### Front end

Hand-written, no bundler: `app/static/index.html`, `style.css`, and the plain
scripts in `app/static/js/`, loaded by `index.html` in order and sharing one
global scope (core, theme, overview, inventory, edit, profile, network, graph,
addresses, reconcile, card, palette, sources, notify, import, boot - boot
last). Code that runs at load may only use what the same or an earlier file
defines; `tests/test_frontend.py` checks that, and that every file is loaded
once. A new file goes into `index.html` in the right place. `renderOverview`
builds its HTML in `overviewHtml()` and swaps it in, so a render exception
shows an error instead of a permanent "Loading…".

### Icons

Icons come from dashboard-icons (apps) and simple-icons (hardware brands),
fetched once by the server and cached on disk. A rules change needs
`CACHE_GEN` bumped in `app/icons.py`, or stale files and `.miss` markers hide
the fix. An entry can override with a tag: `icon:<slug>`, `icon:none`.

## The shape of the data

Four tables carry the meaning: `entries` (what exists), `edges` (how things
hang together, `derived=1` rebuilt on demand), `sightings` (what each source
currently says, latest only), `presence` (addresses seen but not tracked).
Plus `observations` (status transitions only), `audit`, `ignores`,
`attention_age`, `host_map`.

Two distinctions worth preserving:

- A **finding** is a disagreement; a **sighting** is a positive observation.
  Recording only disagreements meant the app could say what was wrong and
  never what was true.
- A **derived** edge is rebuilt by `derive_links`; a hand-made edge is never
  overwritten by a guess - and permanently blocks the derived one, because
  `db.link` is `INSERT OR IGNORE`.

Data lives in the container's `/data` volume: `netmap.db` and `icons-v2/`. The
app runs as UID 1000, so the host folder mounted there must be owned by 1000;
start-up says so if it is not.
