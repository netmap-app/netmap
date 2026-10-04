"""Who made a network card: the IEEE MA-L registry, shipped as app/oui.txt.gz
and refreshed by scripts/update_oui.py - never fetched at run time.

A locally administered address (the second-lowest bit of the first octet set)
belongs to no vendor: phones and laptops make these up per network ("private
Wi-Fi address"), so saying who made one would be a guess.
"""
import gzip
import os

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.txt.gz")
_TABLE: dict[str, str] | None = None


def _table() -> dict[str, str]:
    global _TABLE
    if _TABLE is None:
        try:
            with gzip.open(_PATH, "rt", encoding="utf-8") as fh:
                _TABLE = dict(line.rstrip("\n").split("\t", 1) for line in fh if "\t" in line)
        except OSError:
            _TABLE = {}
    return _TABLE


def _hex(mac: str) -> str:
    return "".join(c for c in str(mac or "").upper() if c in "0123456789ABCDEF")


def randomised(mac: str) -> bool:
    h = _hex(mac)
    return len(h) == 12 and bool(int(h[:2], 16) & 0x02)


def vendor(mac: str) -> str:
    """The registered vendor, "" when unknown or randomised."""
    h = _hex(mac)
    if len(h) != 12 or randomised(mac):
        return ""
    return _table().get(h[:6], "")
