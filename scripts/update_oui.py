"""Refresh app/oui.txt.gz - the vendor of every IEEE MA-L block, for
"who made this device" on the address map.

Run by hand, never by the app: NetMap does not fetch this at run time.

    .venv/bin/python scripts/update_oui.py                 # from IEEE
    .venv/bin/python scripts/update_oui.py path/oui.txt    # from a copy

The input is IEEE's own oui.txt (https://standards-oui.ieee.org/oui/oui.txt;
netaddr ships the same file as netaddr/eui/oui.txt). Output: one
"AABBCC<TAB>Vendor" line per block, sorted, gzipped.
"""
import gzip
import pathlib
import re
import sys
import urllib.request

URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUT = pathlib.Path(__file__).resolve().parent.parent / "app" / "oui.txt.gz"
LINE = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$")


def main(src: str | None) -> None:
    if src:
        text = pathlib.Path(src).read_text(encoding="utf-8", errors="replace")
    else:
        req = urllib.request.Request(URL, headers={"user-agent": "NetMap OUI refresh"})
        text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
    rows = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if m and m.group(2):
            rows[m.group(1)] = " ".join(m.group(2).split())
    if len(rows) < 10000:
        raise SystemExit(f"only {len(rows)} blocks parsed - not an IEEE oui.txt?")
    body = "".join(f"{k}\t{v}\n" for k, v in sorted(rows.items()))
    OUT.write_bytes(gzip.compress(body.encode(), 9, mtime=0))
    print(f"{len(rows)} blocks -> {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
