# Releasing NetMap

A release is a version bump on `main`. CI does the rest.

## 1. Prepare

On a branch, in the same commit:

- Bump `VERSION` in `app/main.py`. It cache-busts the front-end scripts and
  `style.css` (`?v=__V__`) and is the only way to tell what is live.
- Add a `CHANGELOG.md` entry: a `## <version> - <YYYY-MM-DD>` heading and one
  `- ` bullet per change, each on a single line. Settings › "what's new" reads
  the file through `/api/changelog`, and the Dockerfile ships it from the repo
  root next to `app/`.

Version numbers: patch (`2.0.1`) for fixes and dependency updates, minor
(`2.1.0`) for new features, major (`3.0.0`) when an upgrade needs the user to
change something.

## 2. Test

```bash
.venv/bin/pytest -q
```

Open a pull request; CI runs the same suite, browser tests included. `main`
accepts a change only with the `pytest` check passing.

## 3. Merge

Fast-forward `main` to the reviewed commits, so they land exactly as tested:

```bash
git push origin <branch>:main
```

GitHub marks the pull request as merged. Commits are authored as
`NetMap <dev@netmap-app.invalid>` (`git config user.name NetMap` and
`git config user.email dev@netmap-app.invalid` in the clone).

## 4. What CI does

On a push to `main` whose `VERSION` is not yet published,
`.github/workflows/tests.yml`:

1. runs `pytest`;
2. builds the image for linux/amd64 and linux/arm64 and pushes it to
   `ghcr.io/netmap-app/netmap` as `:<version>`, `:latest` and `:sha-<commit>`;
3. keeps the newest 10 releases and deletes older image versions
   (`.github/scripts/prune-images.sh`);
4. creates the GitHub Release `v<version>` on the commit that set that
   `VERSION`, with that version's `CHANGELOG.md` bullets and the pull command
   (`.github/scripts/release-notes.sh`) - unless it already exists;
5. optionally asks a Dockhand instance to recreate the container - only when
   the repository secret `DOCKHAND_URL` is set. The workflow header lists the
   variables and secrets it needs; none of them belong in the code.

A push that does not change `VERSION` runs the tests and publishes nothing; it
still creates the release for the current version if that one is missing.

## 5. Announce

CI writes the release. If an upgrade needs anything beyond `docker compose pull
&& docker compose up -d`, say so in a `CHANGELOG.md` bullet - that is where the
release notes come from. Edit the release on GitHub afterwards if needed.

## 6. Check

```bash
docker buildx imagetools inspect ghcr.io/netmap-app/netmap:<version>
```

Both platforms should be listed, and a running instance should report the new
version in Settings › About.
