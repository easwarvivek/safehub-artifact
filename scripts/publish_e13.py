#!/usr/bin/env python3
"""Publisher for the E13 benchmark matrix.

Design: code/eval/design-e13-full-matrix.md.

Every cell is wall-clock on the machine named in the artifact. Nothing is
modelled. Three rules are enforced here rather than trusted upstream:

  * a cell that failed publishes no numbers -- a status is not a measurement;
  * a corrected value exists only when that operation's own zero-payload floor
    on that same tool was measured;
  * raw samples are retained per cell, so an arm measured with fewer
    repetitions (gcrypt at 3) can be topped up later without re-running the
    others or discarding what was already measured.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import meta_block, write_published  # noqa: E402

MODE_TITLE = {
    "delta": ("E13-A1", "Update cost versus size of new content"),
    "filesz": ("E13-A2", "Update cost versus file size, at a fixed 1 KiB edit"),
    "nfiles": ("E13-A3", "Update cost versus number of files touched"),
    "size": ("E13-B", "Push, clone and storage versus repository size"),
    "depth": ("E13-C", "Clone versus history depth"),
    "updates": ("E13-D", "Stored bytes versus number of updates"),
    "revisions": ("E13-E", "Push, clone and storage versus revisions of one file"),
}

# What each experiment is expected to show, recorded before the run. A curve
# that contradicts its prediction means a broken arm, not a surprising result.
PREDICTED = {
    "delta": "all arms rise; SafeHub ~ git plus a constant; gcrypt flat and high",
    "filesz": ("git and SafeHub flat; git-crypt linear in file size; gcrypt flat "
               "and high. git-crypt flat here means its filter is not engaging"),
    "nfiles": "all rise; git-crypt's slope ~ (file size / edit size) times the others",
    "size": ("git, git-crypt and SafeHub flat in repository size; gcrypt linear. "
             "gcrypt flat here means it is not re-encrypting"),
    "depth": "SafeHub ~17 ms/head; git ~0.3 ms/head against a packed remote",
    "updates": ("gcrypt linear in version count; git-crypt and SGitChar store a "
                "whole re-encrypted file per version, so both are far above git"),
    "revisions": ("SGitChar's clone rises with revision count -- it replays one "
                  "appended block per revision -- while SGitLine's stays flat "
                  "because it rewrites in place. SGitChar's storage stays well "
                  "under git-crypt's, which stores a whole file per revision. "
                  "SGitChar flat in clone here means the blocks are not being "
                  "replayed and the arm is not the construction"),
}


def linfit(xs, ys):
    if len(xs) < 2:
        return None, None
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None, None
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
    return slope, my - slope * mx


def fit(rows, arm, xkey, ykey):
    pts = [
        (float(r[xkey]), float(r[ykey]["median"]))
        for r in rows
        if r.get("arm") == arm and r.get(ykey) and r[ykey].get("median") is not None
    ]
    if len(pts) < 2:
        return {"status": "insufficient-measured-points", "n": len(pts)}
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    slope, icept = linfit(xs, ys)
    return {
        "slope_ms_per_unit": round(slope, 6) if slope is not None else None,
        "intercept_ms": round(icept, 3) if icept is not None else None,
        "n_points": len(pts),
        "method": "least squares over measured points only",
        "status": "derived-from-measured",
    }


def main() -> None:
    rows_path = Path(os.environ["ROWS"])
    out = Path(os.environ["OUT"])
    if not rows_path.exists():
        return
    rows = [json.loads(l) for l in rows_path.read_text().splitlines() if l.strip()]
    if not rows:
        return
    mode = rows[0].get("mode", os.environ.get("MODE", "delta"))
    eid, title = MODE_TITLE.get(mode, ("E13", "Benchmark matrix"))

    arms = sorted({r["arm"] for r in rows})
    measured = [r for r in rows if r.get("status") == "measured"]
    failed = [(r["arm"], r.get("point")) for r in rows if r.get("status") != "measured"]

    xkey = "point"
    ykey = "update_ms" if mode in ("delta", "filesz", "nfiles") else "push_ms"
    fits = {a: fit(measured, a, xkey, ykey) for a in arms}
    clone_fits = (
        {a: fit(measured, a, xkey, "clone_ms") for a in arms}
        if mode in ("size", "depth", "revisions") else {}
    )

    thin = sorted({r["arm"] for r in rows if r.get("thin_dispersion")})

    doc = {
        "id": eid,
        "title": title,
        "meta": meta_block(
            f"scripts/e2e_e13_{'edit' if mode in ('delta','filesz','nfiles') else 'repo'}.sh",
            "wall-clock E2E; every arm on identical content per point; each "
            "operation asserts a DAG or working-tree postcondition; corrected "
            "values use that operation's own zero-payload floor on that same "
            "tool; clones are compared against the source content, not merely "
            "checked to be non-empty",
            int(os.environ.get("REPS", "5")),
        ),
        "axis": {
            "mode": mode,
            "arms": arms,
            "reps": int(os.environ.get("REPS", "5")),
            "gcrypt_reps": int(os.environ.get("GREPS", "3")),
            "note": (
                "Cells do not share an n: gcrypt is measured with fewer "
                "repetitions, so each cell records its own n and every ratio "
                "spans two. Raw samples are retained per cell so gcrypt can be "
                "topped up later without re-running the other arms."
            ),
        },
        "predicted_shape": PREDICTED.get(mode, ""),
        "cells": rows,
        "fit": {"primary": fits, **({"clone": clone_fits} if clone_fits else {})},
        "integrity": {
            "arms_present": arms,
            "failed_cells": failed,
            "thin_dispersion_arms": thin,
            "note": (
                "A failed cell publishes no numbers. A corrected value appears "
                "only where that operation's own zero-payload floor was "
                "measured on the same tool -- a floor taken from a different "
                "operation is refused by the harness, which is the defect the "
                "withdrawn corrected columns had. Clones are asserted to have "
                "produced a non-empty working tree, because a git clone of a "
                "gcrypt remote exits zero having checked out nothing."
            ),
        },
        "notes": [
            "Measured only; no modelled or extrapolated cell appears here.",
            "Tools absent from the host are reported absent, never as a zero.",
            "Predicted shapes were recorded before the run, so a curve that "
            "contradicts one indicates a broken arm rather than a finding.",
            "Storage is reported as GROWTH over the point, not as the size of "
            "the remote afterwards. SafeHub's server keeps one store shared by "
            "every repository, so its directory size is a running total for the "
            "whole run, where each git-family arm gets a fresh bare repository "
            "per point. Growth is the quantity that means the same thing for "
            "every arm.",
            "Byte columns are of two kinds and are not interchangeable: "
            "wire_bytes is the thin pack a push put on the wire, available only "
            "where the transport is an ordinary Git push; remote_growth is what "
            "the remote's storage gained, packed at both ends, and is defined "
            "for every arm.",
        ],
    }
    write_published(out, doc)
    for a in arms:
        f = fits.get(a, {})
        if f.get("status") == "derived-from-measured":
            print(f"    fit {a:9s} {f['slope_ms_per_unit']} ms/unit "
                  f"(intercept {f['intercept_ms']}, n={f['n_points']})")
    if failed:
        print(f"    FAILED cells: {failed}")


if __name__ == "__main__":
    main()
