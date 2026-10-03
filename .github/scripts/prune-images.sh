#!/usr/bin/env bash
# Keep the newest KEEP tagged releases of the NetMap image on GHCR, and
# everything they reference; delete every other package version.
#
# "Everything they reference" is the point. Each push creates three package
# versions: the tagged image index, and the untagged manifests it points to —
# one image per architecture and their build attestations. A cleanup that deletes untagged
# versions as garbage deletes the image under a tag that is still there, and
# the next pull of that tag fails. So the untagged versions to keep are read
# from the kept indexes themselves, and nothing is deleted by age or by being
# untagged alone.
#
#   GH_TOKEN   a token that may read and delete the package (GITHUB_TOKEN in CI)
#   KEEP       tagged releases to keep (default 10)
#   DRY_RUN=1  print what would be deleted, delete nothing
set -euo pipefail
# GITHUB_REPOSITORY (owner/name) is set in Actions; the package is named
# after the repository, in lower case.
REPO=${GITHUB_REPOSITORY:-}
OWNER=${OWNER:-${REPO%%/*}}
PKG=${PKG:-${REPO##*/}}
PKG=${PKG,,}
[ -n "$OWNER" ] && [ -n "$PKG" ] || { echo "set OWNER and PKG (or GITHUB_REPOSITORY)"; exit 1; }
KEEP=${KEEP:-10}
API="/users/$OWNER/packages/container/$PKG/versions"
ACCEPT="application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

versions=$(gh api --paginate "$API?per_page=100" | jq -s 'add')
# Newest first; a version with any tag counts as a release.
kept_tagged=$(jq -r --argjson n "$KEEP" \
  '[.[] | select(.metadata.container.tags | length > 0)] | sort_by(.created_at) | reverse | .[:$n][] | .name' <<<"$versions")
[ -n "$kept_tagged" ] || { echo "no tagged versions found — refusing to prune"; exit 1; }

# The registry's own view of what each kept index points to.
bearer=$(printf %s "$GH_TOKEN" | base64 | tr -d '\n')
keep=$kept_tagged
for digest in $kept_tagged; do
  refs=$(curl -fsS -H "Authorization: Bearer $bearer" -H "Accept: $ACCEPT" \
         "https://ghcr.io/v2/$OWNER/$PKG/manifests/$digest" | jq -r '.manifests[]?.digest')
  keep=$(printf '%s\n%s\n' "$keep" "$refs")
done

doomed=$(jq -r --arg keep "$keep" \
  '($keep | split("\n") | map(select(. != ""))) as $k
   | .[] | select(.name as $d | $k | index($d) | not)
   | "\(.id)\t\(.metadata.container.tags | join(",") | if . == "" then "(untagged)" else . end)"' <<<"$versions")

echo "package versions: $(jq length <<<"$versions"), keeping $(grep -c . <<<"$keep") ($KEEP releases)"
if [ -z "$doomed" ]; then echo "nothing to delete"; exit 0; fi
while IFS=$'\t' read -r id tags; do
  if [ "${DRY_RUN:-}" = 1 ]; then
    echo "would delete $id $tags"
  else
    gh api -X DELETE "$API/$id" >/dev/null && echo "deleted $id $tags"
  fi
done <<<"$doomed"
