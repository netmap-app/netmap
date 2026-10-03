# NetMap — working notes for Claude

A self-hosted inventory and reconciliation app for a home or small-office
network. Single container: FastAPI + SQLite + an MCP server, no build step,
no framework. `app/db.py` is meant to be readable in one sitting — keep it
that way.

## How it is released

- **CI/CD** (`.github/workflows/tests.yml`): every push and pull request runs
  `pytest`. A push to `main` with a bumped `VERSION` publishes the image to
  `ghcr.io/<owner>/<repo>` (amd64 and arm64). An optional deploy job asks a
  Dockhand instance to recreate the container — only when the repository
  variable `DOCKHAND_URL` is set; the workflow header lists what it needs.
- Data lives in the container's `/data` volume: `netmap.db` and `icons-v2/`.
  The app runs as UID 1000 (not root), so the host folder mounted there must
  be owned by 1000; start-up says so if it is not.
- Deployment-specific notes (hosts, paths, standing instructions for one
  installation) do not belong here: keep them in `CLAUDE.local.md`, which is
  git-ignored.

**Bump `VERSION` in `app/main.py` on every release.** It cache-busts
the front-end scripts and `style.css` (`?v=__V__`) and is the only way to
tell what is live.
Add a matching entry to `CHANGELOG.md` (`## <version> — <date>` heading, `- `
bullets) in the same commit — Settings > "what's new" reads it via
`/api/changelog`, and the Dockerfile only ships it if it stays at the repo
root next to `app/`.

## Rules that are not negotiable

- **Credentials never appear in chat, in the repo, or in a tool call,
  regardless of where they're configured.** Since 1.75.0 every source is an
  instance added in Settings › Sources and stored in `source_instances`
  (drivers: `app/sources/dynamic.py`; field schema: `app/sources/fields.py`).
  The old `NETMAP_*` source variables are a one-time seed
  (`sources.migrate_legacy()`, guarded by the `sources_seeded` kv row) and
  ignored afterwards. Do not ask for a credential, do not echo one — not even
  one pasted into chat unprompted, which should end with "please regenerate
  that", not with using it.
- **Every secret is encrypted at rest.** A source's `secrets` column goes
  through `app/crypto.py`. With `NETMAP_SECRET_KEY` set the key lives only in `docker-compose.yml` and the database holds
  ciphertext alone — a copy of `netmap.db` cannot be decrypted by itself.
  Without it, a key generated on first boot is stored in the database.
  Setting the variable later re-encrypts everything at start-up and deletes
  the stored key; a key that opens nothing is a critical Overview item, never
  a silent blank. Lose the variable and every stored secret must be re-entered. The Settings UI shows at most a last-four-
  characters preview, never the value; a blank secret field on save means
  "keep what's already stored", not "clear it".
- **Every source is read-only.** Four are read-only by enforcement (Docker's
  socket proxy, UniFi's View Only role, NPM's View Only user, Cloudflare's
  scoped token); OPNsense, Pi-hole and Home Assistant are read-only *by
  promise* — the module contains no code path able to construct a write, and
  that promise is checkable by reading one file. Keep it true. Every driver
  holds itself to the same promise — Proxmox issues
  GETs only, and a token built from Proxmox's built-in "PVEAuditor" role
  cannot write even if the code tried.
- **Drivers keep no module state.** Configuration arrives as `cfg`; login
  sessions live in `cfg["_state"]`, which is per instance and dropped on
  every edit. Since 1.76.0 a type can have several instances: ids are the
  type, then `<type>-2`…; drivers write sightings/presence under
  `cfg["_id"]` and start finding keys with `cfg["_key"]` (the legacy prefix
  for the first instance, e.g. `ha`). Never compare a source id to a type
  name — use `dynamic.type_of()`. Code outside a scan that needs another
  source's answer uses `sources.by_role(role)` (or `bound_all(type)` for a
  product-specific need); a driver's `ABSENCE` set names findings a sibling
  instance can shadow. Shared code asks for a **role** (`dynamic.ROLES`:
  dns, proxy, edge, firewall, layer2, scanner…) and never names a product;
  a driver declaring a role keeps that role's contract, which
  `tests/test_roles.py` checks. The checks a role implies live once, in
  `_dns.py` / `_proxy.py`; a new DNS server or proxy maps its API onto
  records/routes and calls them. Nothing in the code may assume one
  installation (a domain, an address, a naming convention) — derive it from a
  source or make it a field.
- **Discovery never writes to the inventory.** A scan reports; a person
  decides. Firewall changes are made by the person, never by the app.
- **Entry notes are short.** Essential technical facts only — no background
  commentary, no observations about the observation.

## How to work on it

- **Run the tests before every release:** `.venv/bin/pytest -q` (install once
  with `.venv/bin/pip install -r requirements.txt -r requirements-dev.txt`).
  `tests/conftest.py`'s `make_app(**env)` re-imports the app under a given
  environment with an empty temp database — configuration is read at import,
  so that is the only way to test a different auth mode. A fix gets a test
  that fails without it. The front end has browser tests in `tests/ui`
  (Playwright, a real server per test; CI runs them): a UI change gets one,
  and a phone-width check is part of the suite. Install the browser once with
  `.venv/bin/python -m playwright install chromium`.
- Verify before shipping. `mcp` needs Python >=3.10; use a venv at `.venv`
  (`python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt -r
  requirements-dev.txt`). The app runs locally against a scratch database:
  `NETMAP_DB=/tmp/nm.db NETMAP_AUTH=off NETMAP_ALLOWED_HOSTS=localhost .venv/bin/uvicorn app.main:application --port 8099`
  (`NETMAP_AUTH=off` because the API otherwise refuses requests without a
  Cloudflare Access JWT or `NETMAP_API_TOKEN`; `application`, not `app`, so
  the MCP dispatcher is in front, as in the container)
  then drive it headless (Playwright) and assert on the DOM, not on a
  screenshot alone.
- **Test the states the seed data does not produce.** A build shipped broken
  because the container had no source credentials, so `sources.health` was
  empty, so the loop that referenced a deleted constant never ran. Inject the
  states — sources reporting, a queue with rows, the all-clear — by
  intercepting `/api/overview` in the test.
- The front end is hand-written, no bundler: `app/static/index.html`,
  `style.css`, and the plain scripts in `app/static/js/`, loaded by
  index.html in order and sharing one global scope (core, theme, overview,
  inventory, edit, profile, network, graph, addresses, reconcile, card, palette,
  sources, notify, import, boot — boot last). Code that runs at load may only use
  what the same or an earlier file defines; `tests/test_frontend.py` checks
  that, and that every file is loaded once. A new file goes into index.html
  in the right place. `renderOverview` builds its HTML in
  `overviewHtml()` and swaps it in, so a render exception shows an error
  instead of a permanent "Loading…".
- Icons come from dashboard-icons (apps) and simple-icons (hardware brands),
  fetched once by the server and cached on disk. A rules change needs
  `CACHE_GEN` bumped in `app/icons.py`, or stale files and `.miss` markers
  hide the fix. An entry can override with a tag: `icon:<slug>`, `icon:none`.

## The shape of the data

Four tables carry the meaning: `entries` (what exists), `edges` (how things
hang together, `derived=1` rebuilt on demand), `sightings` (what each source
currently says, latest-only), `presence` (addresses seen but not tracked).
Plus `observations` (status transitions only), `audit`, `ignores`,
`attention_age`, `host_map`.

Two distinctions worth preserving:
- A **finding** is a disagreement; a **sighting** is a positive observation.
  Recording only disagreements meant the app could say what was wrong and
  never what was true.
- A **derived** edge is rebuilt by `derive_links`; a hand-made edge is never
  overwritten by a guess — and permanently blocks the derived one, because
  `db.link` is INSERT OR IGNORE.
