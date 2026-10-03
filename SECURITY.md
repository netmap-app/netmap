# Security

NetMap holds a map of your network and credentials to read-only accounts on
your infrastructure, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security › Report a vulnerability** on this repository. Include the version
(Settings › About), how to reproduce it, and what an attacker gains.

You will get an answer within a week. Fixes ship as a new release and are
named in `CHANGELOG.md` once users have had a chance to update.

## What NetMap promises

- Login is required for the web UI and API by default; `NETMAP_AUTH=off` is
  for local development only.
- Every source is read-only: drivers issue reads only, and the README names the
  read-only credential to create for each.
- Source and notification secrets are encrypted at rest; set
  `NETMAP_SECRET_KEY` to keep the key out of the database.
- The MCP endpoint is off unless `NETMAP_MCP_TOKEN` is set, and then requires
  that bearer token.
- Only host names listed in `NETMAP_ALLOWED_HOSTS` are answered (DNS
  rebinding).
- The container runs as an unprivileged user.

Supported versions: the latest release.
