#!/usr/bin/env python3
"""Static audit of the evaluation harnesses for silent-failure patterns.

Every rule encodes a defect that reached published numbers. The unifying shape:
an operation fails or does not happen, and a plausible value is recorded anyway.
A crash is cheap; a wrong number that looks measured is expensive.

Run: python3 scripts/tests/audit_harness.py
Exit non-zero if any rule fires.
"""
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
findings = []


def add(rule, path, line, text, why, sev="ERROR"):
    findings.append((sev, rule, f"{path.name}:{line}", text.strip()[:96], why))


def read(p):
    try:
        return p.read_text().splitlines()
    except Exception:
        return []


# --- rule 1: server-side paths operated on locally ---------------------------
# In split-host mode GIT_BASE and SH_DATA live on the server box. A local
# command against them fails instantly and still returns a timing. This is how
# `git gc` silently no-opped, leaving the git arm cloned from 100 packfiles.
REMOTE_PATHS = re.compile(r'(git\s+-C\s+"\$(GIT_BASE|SH_DATA)|rm\s+-rf\s+"\$(GIT_BASE|SH_DATA))')
for p in [SCRIPTS / "parity_sweep.sh"]:
    lines = read(p)
    for i, ln in enumerate(lines, 1):
        if REMOTE_PATHS.search(ln):
            window = "\n".join(lines[max(0, i - 8): i])
            if "PARITY_REMOTE" not in window:
                add("local-op-on-server-path", p, i, ln,
                    "runs locally against a path that is remote in split mode; "
                    "fails instantly and still yields a timing")

# --- rule 2: epsilon division guards ----------------------------------------
# max(den, 1e-9) turns an undefined ratio into ~1e10 and publishes it.
EPS = re.compile(r'max\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*1e-\d+\s*\)')
for p in list(SCRIPTS.glob("*.py")) + list(SCRIPTS.glob("*.sh")) + list((SCRIPTS / "lib").glob("*")):
    if not p.is_file():
        continue
    for i, ln in enumerate(read(p), 1):
        if EPS.search(ln):
            if "throughput" in ln and "wall" in ln:
                continue  # wall is a measured duration, never zero in practice
            add("epsilon-division", p, i, ln,
                "an undefined ratio becomes ~1e10 and is indistinguishable from a measurement")

# --- rule 3: reading 'median' off an analytic_point --------------------------
# analytic_point carries 'value'. ['median'] raises; .get('median') silently
# publishes None. dispersion() DOES carry median, so only flag a read whose key
# is assigned from analytic_point in the same file.
for p in SCRIPTS.glob("gen_*.py"):
    lines = read(p)
    src = "\n".join(lines)
    if "analytic_point" not in src:
        continue
    analytic_keys = set(re.findall(r'"([A-Za-z_0-9]+)":\s*analytic_point\(', src))
    analytic_vars = set(re.findall(r'^\s*([A-Za-z_0-9]+)\s*=\s*analytic_point\(', src, re.M))
    for i, ln in enumerate(lines, 1):
        m = re.search(r'\["([A-Za-z_0-9]+)"\]\[["\']median["\']\]', ln)
        v = re.search(r'\b([A-Za-z_0-9]+)\[["\']median["\']\]', ln)
        key = m.group(1) if m else None
        var = v.group(1) if v else None
        if (key and key in analytic_keys) or (var and var in analytic_vars):
            add("analytic-point-median", p, i, ln,
                "this key is assigned from analytic_point elsewhere in the file; a "
                "['median'] read on it raises, and .get() would publish None",
                sev="WARN")

# --- rule 4: timed command whose status is never inspected -------------------
# Only meaningful in scripts without errexit, where a failed op is simply fast.
TIMED = re.compile(r'\$\(\s*time_(cmd_)?ms\s')
for p in SCRIPTS.glob("*.sh"):
    lines = read(p)
    head = "\n".join(lines[:40])
    m = re.search(r'^set -([a-zA-Z]+)', head, re.M)
    errexit = bool(m) and "e" in m.group(1)
    # A file-level `set -e` is not enough. `set +e` regions inside an errexit
    # script are exactly where this defect hid: the depth-clone harness timed
    # `shub repo consolidate` under `set +e` and published 19 ms without ever
    # reading its status, so a consolidation that never ran looked measured.
    plus_e = False
    for i, ln in enumerate(lines, 1):
        stripped = ln.strip()
        if re.match(r'^set \+e\b', stripped):
            plus_e = True
        elif re.match(r'^set -e\b', stripped) or re.match(r'^set -[a-zA-Z]*e', stripped):
            plus_e = False
        if errexit and not plus_e:
            continue  # errexit aborts on failure, so the value is never used
        if TIMED.search(ln):
            # `$?` refers to the previous command, so a status capture is only
            # a capture of *this* command on the same line or the very next
            # one. A wider window lets a neighbouring command's rc= stand in
            # for a check that was never written.
            # A command substitution may span lines; the status capture can
            # only follow the line that closes it, so extend the window to
            # there before looking.
            j = i - 1
            depth = lines[j].count("$(") - lines[j].count(")")
            while depth > 0 and j + 1 < len(lines):
                j += 1
                depth += lines[j].count("$(") - lines[j].count(")")
            near = "\n".join(lines[i - 1: j + 2])
            # `$?` is only this command's status on the line that closes the
            # substitution or the one after it. TIMED_RC is different: the
            # helper persists it in a global, so a check a few lines down --
            # after an if/fi that wraps two spellings of the same call -- is
            # still a check of this command.
            wide = "\n".join(lines[i - 1: j + 10])
            if not (re.search(r'[Rr][Cc]=\$\?|\|\||&&|FAILED=', near)
                    or "TIMED_RC" in wide):
                add("unchecked-timed-command", p, i, ln,
                    "a timed command with no status check: outside errexit, or "
                    "inside a set +e region, a failed operation is recorded as a "
                    "fast one")

# --- rule 5: assertions against endpoints the host does not serve ------------
# The untrusted host registers no plaintext tree routes; asserting 403 there
# yields 404 for everyone and the check can never pass.
exempt = 0
for p in SCRIPTS.glob("*.sh"):
    lines = read(p)
    for i, ln in enumerate(lines, 1):
        if any(r in ln for r in ("/git/tree", "/contents", "/commits")) and "SAFEHUB_HOST" in ln:
            # An assertion may deliberately require 404 to prove the host serves
            # no plaintext. That is a security property, not a vacuous check, so
            # it must be annotated -- and the exemption is reported, never silent.
            if "intentional-host-404" in "\n".join(lines[max(0, i - 4): i]):
                exempt += 1
                continue
            add("host-route-assumption", p, i, ln,
                "router_host serves no plaintext tree/contents/commits route "
                "(router_local_ui only); every caller gets 404, so a positive "
                "check cannot pass and a status check asserting 404 would be vacuous")

errors = [f for f in findings if f[0] == "ERROR"]
warns = [f for f in findings if f[0] == "WARN"]
for sev, rule, loc, text, why in errors + warns:
    print(f"  [{sev}] [{rule}] {loc}")
    print(f"      {text}")
    print(f"      -> {why}\n")
print(f"harness audit: {len(errors)} error(s), {len(warns)} warning(s), "
      f"{exempt} annotated exemption(s)")
sys.exit(1 if errors else 0)
