#!/usr/bin/env bash
# Print the GitHub Release notes for one version: its CHANGELOG.md bullets,
# then the pull command and the upgrade line. Fails if the version has no
# entry or the entry has no bullets — a release never goes out empty.
#
#   release-notes.sh <version> [CHANGELOG.md] [image]
set -euo pipefail
v=${1:?usage: release-notes.sh <version> [CHANGELOG.md] [image]}
file=${2:-CHANGELOG.md}
image=${3:-ghcr.io/netmap-app/netmap}

# The entry: from "## <version> — <date>" to the next "## " heading. The same
# shape /api/changelog parses (app/main.py), so one format serves both.
notes=$(awk -v v="$v" '
  /^## / { on = ($2 == v); next }
  on && /^- / { print }
' "$file")
[ -n "$notes" ] || { echo "no CHANGELOG.md bullets for $v" >&2; exit 1; }

printf '%s\n\n' "$notes"
printf '```bash\ndocker pull %s:%s\n```\n\n' "$image" "$v"
printf 'Upgrade: `docker compose pull && docker compose up -d`. Anything else an upgrade needs is in the notes above.\n'
