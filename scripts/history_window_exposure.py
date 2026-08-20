#!/usr/bin/env python3
"""Eval E17 — what a forward-only grant actually withholds.

A forward-only member receives a grafted snapshot of the repository as of its
join epoch, so it sees the current tree. The confidentiality benefit of a
history window is therefore over content reachable from history but *not* from
the tip: superseded blob versions and deleted paths. This measures that
quantity on real repositories instead of asserting it.

The measurement is structural, so it cannot come back empty for an
uninteresting reason. A secret-pattern count is also reported, but as a
secondary signal: public repositories are routinely scrubbed, so a low count
here is evidence about public corpora, not about the mechanism. The motivating
evidence for the secrets case is Meli et al. (2019).

Usage: history_window_exposure.py <repo.git> [<repo.git> ...]
Publishes: code/eval/published/history-window-exposure-latest.json
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import PUB_DIR, meta_block, write_published  # noqa: E402

SCRIPT = "scripts/history_window_exposure.py"

# High-confidence, low-false-positive markers only. A broad entropy sweep would
# inflate the count with minified assets and test vectors.
SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key_block", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY")),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
]


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=True
    )
    return out.stdout.decode("utf-8", "replace")


def blobs_in_tip(repo: Path) -> tuple[set[str], set[str]]:
    """(blob oids, paths) reachable from HEAD's tree."""
    oids: set[str] = set()
    paths: set[str] = set()
    for line in git(repo, "ls-tree", "-r", "HEAD").splitlines():
        if not line.strip():
            continue
        meta, path = line.split("\t", 1)
        fields = meta.split()
        if len(fields) >= 3 and fields[1] == "blob":
            oids.add(fields[2])
            paths.add(path)
    return oids, paths


def blobs_in_history(repo: Path) -> tuple[set[str], set[str]]:
    """(blob oids, paths) reachable from every commit."""
    names: dict[str, str] = {}
    for line in git(repo, "rev-list", "--objects", "--all").splitlines():
        parts = line.split(" ", 1)
        if not parts[0]:
            continue
        names[parts[0]] = parts[1] if len(parts) > 1 else ""

    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch-check"],
        input="\n".join(names).encode(),
        capture_output=True,
        check=True,
    )
    oids: set[str] = set()
    paths: set[str] = set()
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        f = line.split()
        if len(f) >= 2 and f[1] == "blob":
            oids.add(f[0])
            if names.get(f[0]):
                paths.add(names[f[0]])
    return oids, paths


def scan_secrets(repo: Path, oids: list[str]) -> dict[str, int]:
    """Count high-confidence secret markers across the given blobs.

    Writes every request up front and reads the whole response, rather than
    interleaving on one process's pipes: feeding thousands of object ids to
    `cat-file --batch` while nothing drains its stdout deadlocks once the
    output pipe buffer fills.
    """
    hits = {name: 0 for name, _ in SECRET_PATTERNS}
    if not oids:
        return hits
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input=("\n".join(oids) + "\n").encode(),
        capture_output=True,
        check=False,
    )
    buf = proc.stdout
    i = 0
    n = len(buf)
    while i < n:
        nl = buf.find(b"\n", i)
        if nl == -1:
            break
        header = buf[i:nl].split()
        i = nl + 1
        if len(header) < 3:
            continue
        try:
            size = int(header[2])
        except ValueError:
            continue
        body = buf[i : i + size]
        i += size + 1  # skip trailing newline
        if b"\x00" in body[:1024]:
            continue  # binary; skip
        for name, pat in SECRET_PATTERNS:
            if pat.search(body):
                hits[name] += 1
    return hits


def measure(repo: Path, secret_scan_cap: int = 20000) -> dict:
    name = repo.name.removesuffix(".git")
    commits = int(git(repo, "rev-list", "--count", "--all").strip())
    tip_oids, tip_paths = blobs_in_tip(repo)
    hist_oids, hist_paths = blobs_in_history(repo)

    history_only = hist_oids - tip_oids
    deleted_paths = hist_paths - tip_paths

    scanned = sorted(history_only)[:secret_scan_cap]
    hist_secrets = scan_secrets(repo, scanned)
    tip_secrets = scan_secrets(repo, sorted(tip_oids)[:secret_scan_cap])

    return {
        "repository": name,
        "commits": commits,
        "blobs_in_tip": len(tip_oids),
        "blobs_in_history": len(hist_oids),
        "blobs_history_only": len(history_only),
        "fraction_of_blobs_withheld_by_forward_only": (
            round(len(history_only) / len(hist_oids), 4) if hist_oids else None
        ),
        "paths_in_tip": len(tip_paths),
        "paths_ever_present": len(hist_paths),
        "paths_deleted_before_tip": len(deleted_paths),
        "fraction_of_paths_withheld_by_forward_only": (
            round(len(deleted_paths) / len(hist_paths), 4) if hist_paths else None
        ),
        "secret_markers_history_only": hist_secrets,
        "secret_markers_in_tip": tip_secrets,
        "secret_markers_scanned_blobs": len(scanned),
        "secret_scan_capped": len(history_only) > secret_scan_cap,
        "measured": True,
        "status": "measured",
    }


def main() -> None:
    repos = [Path(a) for a in sys.argv[1:]]
    if not repos:
        print(__doc__)
        raise SystemExit(2)
    cells = []
    for r in repos:
        if not r.exists():
            print(f"    skip {r} (missing)")
            continue
        print(f"==> measuring {r.name}")
        cell = measure(r)
        cells.append(cell)
        print(
            "    {}: {} commits, {:.1%} of blobs and {:.1%} of paths exist "
            "only in history".format(
                cell["repository"],
                cell["commits"],
                cell["fraction_of_blobs_withheld_by_forward_only"] or 0,
                cell["fraction_of_paths_withheld_by_forward_only"] or 0,
            )
        )

    doc = {
        "id": "E17",
        "title": "What a forward-only grant withholds, measured on real repositories",
        "meta": meta_block(
            SCRIPT,
            "object-graph reachability over real corpora: blobs and paths "
            "reachable from history but not from the tip tree",
            1,
        ),
        "definition": {
            "withheld": (
                "A forward-only member receives a grafted snapshot of the tip, "
                "so it sees every blob and path reachable from HEAD. What the "
                "window withholds is the complement: superseded blob versions "
                "and paths deleted before the join epoch."
            ),
            "not_withheld": (
                "Current code, current secrets, and the present directory "
                "structure are all disclosed by the grafted snapshot. A history "
                "window bounds historical exposure, not present exposure."
            ),
        },
        "cells": cells,
        "notes": [
            "Structural counts are the primary result and cannot be empty for "
            "an uninteresting reason.",
            "Secret-marker counts are secondary: public repositories are "
            "routinely scrubbed, so a low count is evidence about public "
            "corpora rather than about the mechanism. Meli et al. (2019) is "
            "the motivating evidence for the secrets case.",
            "Only high-confidence patterns are counted; a broad entropy sweep "
            "would inflate the count with minified assets and test vectors.",
        ],
    }
    write_published(PUB_DIR / "history-window-exposure-latest.json", doc)


if __name__ == "__main__":
    main()
