"""The GitHub Release notes CI writes (.github/scripts/release-notes.sh) and the
job that writes them (.github/workflows/tests.yml, job `release`)."""
import os
import re
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, ".github", "scripts", "release-notes.sh")
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "tests.yml")


def _notes(version: str, changelog: str, image: str = "ghcr.io/o/r"):
    return subprocess.run(["bash", SCRIPT, version, changelog, image],
                          capture_output=True, text=True)


def test_the_current_version_has_release_notes():
    src = open(os.path.join(ROOT, "app", "main.py"), encoding="utf-8").read()
    version = re.search(r'^VERSION = "(.*)"', src, re.M).group(1)
    r = _notes(version, os.path.join(ROOT, "CHANGELOG.md"))
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("- ")
    assert f"docker pull ghcr.io/o/r:{version}" in r.stdout


def test_notes_are_one_entry_only(tmp_path):
    cl = tmp_path / "CHANGELOG.md"
    cl.write_text("# Changelog\n\n- not a release\n\n"
                  "## 2.0.10 - 2026-10-05\n\n- ten\n\n"
                  "## 2.0.1 - 2026-10-03\n\n- one\n- one, again\n\n"
                  "## 2.0.0 - 2026-10-01\n\n- zero\n", encoding="utf-8")
    out = _notes("2.0.1", str(cl)).stdout
    assert "- one\n- one, again\n" in out
    assert "ten" not in out and "zero" not in out and "not a release" not in out


def test_a_version_without_bullets_fails(tmp_path):
    cl = tmp_path / "CHANGELOG.md"
    cl.write_text("## 2.0.1 - 2026-10-03\n\n- one\n\n## 2.0.2 - 2026-10-04\n\n", encoding="utf-8")
    for v in ("2.0.2", "2.0", "9.9.9"):
        r = _notes(v, str(cl))
        assert r.returncode != 0 and r.stdout == ""


def test_the_release_job_runs_after_publish_with_write_access_to_contents_only():
    text = open(WORKFLOW, encoding="utf-8").read()
    # The job's block: from "  release:" to the next two-space-indented key.
    job = re.search(r"^  release:\n(.*?)(?=^  \S)", text, re.M | re.S).group(1)
    assert re.search(r"^    needs: publish$", job, re.M)
    assert "refs/heads/main" in job
    perms = re.search(r"^    permissions:\n((?:      .*\n)+)", job, re.M).group(1)
    assert [ln.split("#")[0].strip() for ln in perms.splitlines()] == ["contents: write"]
    assert "release-notes.sh" in job and "gh release view" in job
