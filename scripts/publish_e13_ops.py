#!/usr/bin/env python3
"""Publisher for E13 sweep 2 — the operations sweep 1 does not cover.

Plan: code/eval/SWEEP2-PLAN.md. Same three rules the sweep-1 publisher enforces:
a failed cell publishes no numbers, a corrected value exists only where that
operation's own zero-payload floor was measured on that same tool, and raw
samples are retained per cell so an arm measured with fewer repetitions can be
topped up later.

One rule is added here. A cell that is *undefined* for an arm is published as
such, with the reason, and is never a zero: an operation a design cannot express
and an operation that costs nothing are opposite claims.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import meta_block, write_published  # noqa: E402

# Recorded before running. A curve that contradicts its row indicates a broken
# arm rather than a finding.
PREDICTED = {
    "fetch": "flat in depth for every arm; the protocol floor only",
    "pull": ("flat for git; SafeHub cheaper than git, since it serves sealed "
             "writer-side ciphertext instead of rebuilding a pack"),
    "merge": "dominated by local Git; arms differ only in the push that follows",
    "rebase": "as merge, plus a force-push per repetition",
    "forcepush": ("git flat; SafeHub pays an admin co-signature per push; gcrypt "
                  "re-encrypts the repository. Undefined for the SGit arms, whose "
                  "ciphertext repository only appends, so a host cannot "
                  "distinguish a rewrite from an ordinary push"),
    "rotate": "flat in depth; MLS epoch cost only. SafeHub alone",
    "consolidate": ("rises with the span consolidated; per-epoch compaction, so no "
                    "window widens. SafeHub alone"),
}


# Predictions that measurement contradicted, recorded rather than rewritten.
# Editing PREDICTED after seeing the data would defeat the point of recording it
# beforehand, so the original stays above and the correction is stated here with
# its cause.
CONTRADICTED = {
    "pull": ("Predicted SafeHub cheaper than git; measured ~2.2x git at depth 10 "
             "(200 ms against 89). The prediction mis-attributed the push-side "
             "advantage to the read direction. `sit fetch` and `sit pull` share "
             "one code path and SafeHub has no ref-advertisement-only operation: "
             "a client cannot learn what changed without decrypting, so fetch "
             "downloads, verifies and replays bundles. The write direction is "
             "cheaper than git because the host serves sealed writer-side "
             "ciphertext; the read direction is dearer because the client "
             "decrypts. Both follow from the same design."),
    "fetch": ("Predicted 'the protocol floor only'. True for the git-family arms; "
              "false for SafeHub, whose fetch is a decrypt-and-replay and lands "
              "within 3 ms of its own pull. Whether it is flat in depth is the "
              "separate question the axis answers: fetch_bundles_since asks only "
              "for heads after the last applied sequence, so flat is expected."),
    "merge": ("Predicted 'dominated by local Git'. The 47-399 ms spread across "
              "arms at one depth shows it is dominated by the push that follows, "
              "since the local merge is identical work on every arm. The "
              "measurements stand; the emphasis was wrong."),
    "forcepush": ("Predicted SafeHub 'pays an admin co-signature per push'. It "
                  "pays it and is still the fastest arm (43 ms against git's 97). "
                  "One ML-DSA-87 signature is small next to the transport it "
                  "saves. The force path is confirmed taken by the postcondition, "
                  "not assumed."),
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


def fit(rows, op, arm):
    pts = [(float(r["point"]), float(r["op_ms"]["median"]))
           for r in rows
           if r.get("op") == op and r.get("arm") == arm
           and r.get("op_ms") and r["op_ms"].get("median") is not None]
    if len(pts) < 2:
        return {"status": "insufficient-measured-points", "n": len(pts)}
    slope, icept = linfit([p[0] for p in pts], [p[1] for p in pts])
    return {"slope_ms_per_head": round(slope, 6) if slope is not None else None,
            "intercept_ms": round(icept, 3) if icept is not None else None,
            "n_points": len(pts), "status": "derived-from-measured"}


def main() -> None:
    rows_path = Path(os.environ["ROWS"])
    out = Path(os.environ["OUT"])
    if not rows_path.exists():
        return
    rows = [json.loads(l) for l in rows_path.read_text().splitlines() if l.strip()]
    if not rows:
        return

    ops = sorted({r["op"] for r in rows})
    arms = sorted({r["arm"] for r in rows})
    measured = [r for r in rows if r.get("status") == "measured"]
    failed = [(r["arm"], r["op"], r.get("point")) for r in rows
              if r.get("status") == "failed"]
    undefined = sorted({(r["arm"], r["op"]) for r in rows
                        if r.get("status") == "undefined-for-arm"})

    doc = {
        "id": "E13-OPS",
        "title": "Pull, fetch, merge, rebase, force-push, rotate and consolidation versus history depth",
        "meta": meta_block(
            "scripts/e2e_e13_ops.sh",
            "wall-clock E2E; every arm on identical history per point; each "
            "operation asserts its own postcondition and is corrected only by "
            "its own zero-payload floor on the same tool; clients and remotes "
            "on separate hosts with every arm over HTTP",
            int(os.environ.get("REPS", "5")),
        ),
        "axis": {
            "axis": "history depth (heads)",
            "ops": ops,
            "arms": arms,
            "reps": int(os.environ.get("REPS", "5")),
            "gcrypt_reps": int(os.environ.get("GREPS", "3")),
            "note": ("Cells do not share an n: gcrypt is measured with fewer "
                     "repetitions, so each cell records its own and every ratio "
                     "spans two."),
        },
        "predicted_shape": PREDICTED,
        "predictions_contradicted": CONTRADICTED,
        "cells": rows,
        # An undefined pair is reported as undefined, not as
        # "insufficient-measured-points": labelling a design's inability to
        # express an operation as a shortfall of measurement is the exact
        # conflation this publisher exists to prevent.
        "fit": {op: {a: ({"status": "undefined-for-arm"} if (a, op) in set(undefined)
                         else fit(measured, op, a))
                     for a in arms} for op in ops},
        "integrity": {
            "failed_cells": failed,
            "undefined_cells": [{"arm": a, "op": o} for a, o in undefined],
            "note": ("An undefined cell is published as undefined, with the "
                     "reason, and is never a zero: an operation a design cannot "
                     "express and an operation that costs nothing are opposite "
                     "claims. force-push is undefined for the SGit arms because "
                     "their ciphertext repository only appends, so a host cannot "
                     "distinguish a history rewrite from an ordinary push and "
                     "therefore cannot enforce branch protection. rotate and "
                     "consolidation exist only for SafeHub; git-crypt has no "
                     "rekey mechanism at all."),
        },
        "notes": [
            "Measured only; no modelled or extrapolated cell appears here.",
            "This sweep covers the operations absent from the push/clone/storage "
            "matrix; the two are read together, not merged.",
            "Predicted shapes were recorded before the run and are preserved "
            "verbatim; where measurement contradicted one, the contradiction and "
            "its cause are recorded alongside rather than by editing the "
            "prediction.",
        ],
    }
    write_published(out, doc)
    for op in ops:
        for a in arms:
            f = doc["fit"][op][a]
            if f.get("status") == "derived-from-measured":
                print(f"    fit {op:<12}{a:<10}{f['slope_ms_per_head']} ms/head "
                      f"(intercept {f['intercept_ms']}, n={f['n_points']})")
    if failed:
        print(f"    FAILED cells: {failed}")
    if undefined:
        print(f"    undefined cells: {len(undefined)}")


if __name__ == "__main__":
    main()
