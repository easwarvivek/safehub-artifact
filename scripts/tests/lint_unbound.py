#!/usr/bin/env python3
"""Find variables a shell function reads that nothing in scope assigns.

These scripts run under `set -u`, where reading an unset variable is fatal --
and fatal even inside `set +e`, so it kills a whole run rather than failing one
cell. That is exactly how three E13 experiments died after fifteen minutes of
work each: a rename left `arm_clone` reading `$url`, which is a `local` of
`arm_setup` and therefore unset by the time `arm_clone` runs.

Scope rules this encodes, which are bash's:
  * `local`/`declare` inside a function scopes a name to that function;
  * a plain assignment inside a function creates a GLOBAL, visible everywhere;
  * so reading in function A a name that is `local` only to function B is the
    bug, and is what this reports.

Usage: lint_unbound.py [--also <file-scanned-for-globals-only>] <script.sh>...
Exits non-zero on any finding.
"""
from __future__ import annotations

import re
import sys

ENV_OK = {
    "HOME", "PATH", "PWD", "USER", "SHELL", "TMPDIR", "LANG", "LC_ALL", "IFS",
    "BASH_SOURCE", "BASH_VERSION", "FUNCNAME", "OLDPWD", "RANDOM", "SECONDS",
    "LINENO", "PIPESTATUS", "REPLY", "GNUPGHOME", "XDG_CONFIG_HOME",
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_DIR", "GIT_TERMINAL_PROMPT",
    "COPYFILE_DISABLE", "SSH_AUTH_SOCK",
}

FUNC = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{")
REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
ASSIGN = re.compile(r"^\s*(?:export\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+?=|\()")
DECL = re.compile(r"^\s*(?:local|declare|typeset)\s+((?:-\w+\s+)*)(.*)$")
FORVAR = re.compile(r"^\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\b")
ARITHFOR = re.compile(r"^\s*for\s+\(\(\s*([A-Za-z_][A-Za-z0-9_]*)")
READVAR = re.compile(r"\bread\s+((?:-\w+\s+)*)(.+)$")


def names_in(decl: str) -> set[str]:
    out = set()
    for tok in re.split(r"\s+", decl.strip()):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", tok.strip("\"'"))
        if m:
            out.add(m.group(1))
    return out


def depth_delta(ln: str) -> int:
    """Brace depth change, ignoring braces in quotes and in ${...}."""
    out, i, q = 0, 0, None
    while i < len(ln):
        c = ln[i]
        if q:
            if c == q:
                q = None
            elif c == "\\":
                i += 1
        elif c in "\"'":
            q = c
        elif c == "$" and i + 1 < len(ln) and ln[i + 1] == "{":
            j, d = i + 2, 1
            while j < len(ln) and d:
                d += (ln[j] == "{") - (ln[j] == "}")
                j += 1
            i = j - 1
        elif c == "{":
            out += 1
        elif c == "}":
            out -= 1
        i += 1
    return out


def assigned_names(ln: str) -> set[str]:
    """Names this line assigns, across `;` `&&` `||` and `case` patterns."""
    out: set[str] = set()
    for stmt in re.split(r"[;&|)(]+", ln):
        if not stmt.strip():
            continue
        s = " " + stmt.strip()
        m = ASSIGN.match(s)
        if m:
            out.add(m.group(1))
        m = FORVAR.match(s) or ARITHFOR.match(s)
        if m:
            out.add(m.group(1))
        m = READVAR.search(s)
        if m:
            out |= names_in(m.group(2))
    return out


def scan(path: str):
    """-> (globals, {fn: locals}, [(line_no, fn_or_None, name)])"""
    lines = open(path, encoding="utf-8").read().splitlines()
    glob: set[str] = set()
    loc: dict[str, set[str]] = {}
    refs = []
    fn, depth = None, 0
    for i, ln in enumerate(lines, 1):
        st = ln.strip()
        if not st or st.startswith("#"):
            continue
        if fn is None:
            m = FUNC.match(ln)
            if m:
                fn = m.group(1)
                loc.setdefault(fn, set())
                depth = depth_delta(ln)
                if depth <= 0:
                    _absorb(ln, fn, loc, glob)
                    fn, depth = None, 0
                else:
                    _absorb(ln, fn, loc, glob)
                for r in _refs(ln):
                    refs.append((i, fn, r))
                continue
            d = DECL.match(ln)
            if d:
                glob |= names_in(d.group(2))
            glob |= assigned_names(ln)
            for r in _refs(ln):
                refs.append((i, None, r))
        else:
            _absorb(ln, fn, loc, glob)
            for r in _refs(ln):
                refs.append((i, fn, r))
            depth += depth_delta(ln)
            if depth <= 0:
                fn, depth = None, 0
    return glob, loc, refs


def _absorb(ln: str, fn: str, loc: dict, glob: set) -> None:
    d = DECL.match(ln)
    if d:
        loc[fn] |= names_in(d.group(2))
        return
    # A plain assignment inside a function creates a global -- UNLESS the name
    # was already declared local in this function, in which case it assigns
    # that local and the name stays function-scoped. Missing this made the
    # check useless: `local url` followed by `url=$(...)` looked like a global,
    # so reading $url from another function was accepted.
    names = assigned_names(ln)
    glob |= (names - loc.get(fn, set()))


def _refs(ln: str):
    for m in REF.finditer(ln):
        after = ln[m.end():]
        # ${VAR:-x} / ${VAR-x} / ${VAR:+x} etc. are safe under set -u
        if after[:2] in (":-", ":=", ":?", ":+") or after[:1] in ("-", "+", "=", "?"):
            continue
        yield m.group(1)


def main() -> int:
    args = sys.argv[1:]
    also, targets = [], []
    i = 0
    while i < len(args):
        if args[i] == "--also":
            also.append(args[i + 1]); i += 2
        else:
            targets.append(args[i]); i += 1

    pooled: set[str] = set()
    for p in also + targets:
        g, lc, _ = scan(p)
        pooled |= g
        # A name declared local anywhere is still a name the author controls;
        # only cross-function reads matter, handled per file below.

    findings = []
    for p in targets:
        g, loc, refs = scan(p)
        for line, fn, name in refs:
            if name in ENV_OK or name in pooled:
                continue
            if fn and name in loc.get(fn, ()):
                continue
            owners = sorted(o for o, v in loc.items() if name in v and o != fn)
            where = f"in {fn}()" if fn else "at top level"
            extra = f"; it is local to {', '.join(o + '()' for o in owners)}" if owners else ""
            findings.append(f"{p}:{line}: ${name} read {where}, never assigned in scope{extra}")

    for f in findings:
        print("  " + f)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
