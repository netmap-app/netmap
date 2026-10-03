"""The front end is plain scripts that index.html loads in order, sharing one
global scope (app/static/js/). That works only while two rules hold, and
neither shows up until a page fails to load, so they are checked here:

  * every file is loaded, once, and nothing loaded is missing;
  * code that runs at load time (a top-level statement, or a top-level
    const/let initialiser) only uses names defined in the same file or an
    earlier one. Inside one big file every function was hoisted to the top;
    across files it is not, and a forward reference is a ReferenceError at
    load — a blank page. Function bodies run later and may use anything.

The file is consistently indented, so "top level" is "starts at column 0".
The browser tests (tests/ui) catch the same failure in practice; this names
the file and the line."""
import pathlib
import re

STATIC = pathlib.Path(__file__).resolve().parent.parent / "app" / "static"
DECL = re.compile(r"(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)"
                  r"|(?:const|let|var|class)\s+([A-Za-z_$][\w$]*)")


def _order() -> list[str]:
    html = (STATIC / "index.html").read_text()
    return re.findall(r'<script src="/static/js/([\w-]+\.js)\?v=__V__"></script>', html)


def _files():
    return [(n, (STATIC / "js" / n).read_text().split("\n")) for n in _order()]


def test_every_script_is_loaded_once():
    order = _order()
    on_disk = sorted(p.name for p in (STATIC / "js").glob("*.js"))
    assert sorted(order) == on_disk
    assert len(order) == len(set(order))
    assert order[-1] == "boot.js"              # start-up runs after everything exists


def test_no_top_level_name_is_declared_twice():
    seen: dict[str, str] = {}
    for name, lines in _files():
        for i, line in enumerate(lines, 1):
            m = re.match(r"(?:const|let|class)\s+([A-Za-z_$][\w$]*)", line)
            if m:
                where = f"{name}:{i}"
                assert m.group(1) not in seen, f"{m.group(1)} at {where} and {seen[m.group(1)]}"
                seen[m.group(1)] = where


def test_load_time_code_only_uses_what_is_already_defined():
    files = _files()
    defined_in: dict[str, int] = {}
    for k, (_, lines) in enumerate(files):
        for line in lines:
            m = DECL.match(line)
            if m:
                defined_in.setdefault(m.group(1) or m.group(2), k)
    bad = []
    for k, (name, lines) in enumerate(files):
        for i, line in enumerate(lines, 1):
            if not line or line[0].isspace() or line.startswith(("}", "//", "/*", "*", ")", "]")):
                continue
            if re.match(r"(async\s+)?function\b", line):
                continue
            code = re.split(r"=>|\bfunction\b", line, maxsplit=1)[0]  # bodies run later
            if re.match(r"(const|let|var|class)\b", line):
                code = code.split("=", 1)[1] if "=" in code else ""
            code = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", "", code)       # not inside strings
            for ident in set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)", code)):
                if defined_in.get(ident, -1) > k:
                    bad.append(f"{name}:{i} uses {ident} from {files[defined_in[ident]][0]}")
    assert not bad, "load-time forward references:\n" + "\n".join(bad)
