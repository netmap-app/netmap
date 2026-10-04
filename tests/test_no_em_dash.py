"""The project writes plain dashes. The changelog headings are '## <version> -
<date>', which /api/changelog and the release-notes script both parse."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_no_em_dash_in_the_repository():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                           text=True, check=True).stdout.split()
    bad = []
    for f in files:
        try:
            text = (ROOT / f).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue                                   # binary, or deleted in the tree
        bad += [f"{f}:{n}" for n, line in enumerate(text.splitlines(), 1) if chr(0x2014) in line]
    assert not bad, bad


def test_changelog_headings_parse(make_app):
    _, c = make_app(NETMAP_AUTH="off")
    entries = c.get("/api/changelog").json()["entries"]
    assert entries
    for e in entries:
        assert re.fullmatch(r"\d+\.\d+\.\d+", e["version"]), e["version"]
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", e["date"]), e["date"]
        assert e["notes"]
