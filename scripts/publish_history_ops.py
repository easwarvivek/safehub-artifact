#!/usr/bin/env python3
"""Publisher for the measured history-operations sweep (scripts/e2e_history_ops.sh).

Every cell is wall-clock from one repository lineage. Nothing is modelled: if a
depth is absent, it was not run; if an arm failed, its numbers are null and the
row says so rather than carrying a plausible value.

Design and adversarial review: review-notes/e12-history-ops-design.md.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import meta_block, write_published  # noqa: E402

SCRIPT = "scripts/e2e_history_ops.sh"


def linfit(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Least-squares slope/intercept over the measured points only."""
    if len(xs) < 2:
        return 0.0, (ys[0] if ys else 0.0)
    mx = statistics.fmean(xs)
    my = statistics.fmean(ys)
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom
    return slope, my - slope * mx


def fit_for(rows: list[dict], key: str) -> dict:
    """Slope in ms per head of history, over rows that actually measured `key`."""
    pts = [
        (float(r["history_depth"]), float(r[key]["median"]))
        for r in rows
        if r.get(key) and r[key].get("median") is not None
    ]
    if len(pts) < 2:
        return {"status": "insufficient-measured-points", "n": len(pts)}
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    slope, intercept = linfit(xs, ys)
    return {
        "ms_per_head": round(slope, 5),
        "intercept_ms": round(intercept, 3),
        "n_points": len(pts),
        "depths": [int(x) for x in xs],
        "method": "least squares over measured checkpoints only",
        "status": "derived-from-measured",
    }


def main() -> None:
    rows_path = Path(os.environ["ROWS"])
    out = Path(os.environ["OUT"])
    rows = [
        json.loads(line)
        for line in rows_path.read_text().splitlines()
        if line.strip()
    ]
    rows.sort(key=lambda r: r["history_depth"])

    measured = [r for r in rows if r.get("status") == "measured"]
    failed = [r["history_depth"] for r in rows if r.get("status") != "measured"]

    doc = {
        "id": "E12",
        "title": "Merge, rebase, and force-push versus history depth, to depth 10^3",
        "meta": meta_block(
            SCRIPT,
            "wall-clock E2E; one monotonically grown lineage; each operation "
            "performed on a scratch branch at log-spaced depth checkpoints on "
            "both arms, with a DAG postcondition asserted per operation",
            int(os.environ.get("REPS", "3")),
        ),
        "axis": {
            "per_push_delta_kib": int(os.environ.get("DELTA", "64")),
            "rebase_commits": int(os.environ.get("REBASE_N", "3")),
            "git_pinned_gc": os.environ.get("PIN", "1") == "1",
            "note": (
                "Per-revision delta is fixed, so history depth is the only "
                "axis. `main` is grown once and never modified afterwards; "
                "every operation runs on a scratch branch created at the "
                "checkpoint and deleted after, so each depth measures the "
                "linear history it claims."
            ),
        },
        "operations": {
            "merge": (
                "Topic branch off the tip plus one revision, merged --no-ff "
                "into a scratch integration branch, then pushed. Clean merges "
                "only: a conflicted merge costs what human resolution costs, "
                "which is not a system property. merge_push_ms is the push of "
                "the two-parent commit; merge_local_ms is git's own merge."
            ),
            "rebase": (
                "A branch of rebase_commits revisions is pushed as-is, then "
                "rebased onto the advanced tip and pushed again. The timing is "
                "the SECOND push, which is non-fast-forward."
            ),
            "force_push": (
                "Scratch branch pushed, tip amended, pushed again. Minimal "
                "object change, so the timing is the gate and the ref update "
                "rather than the payload."
            ),
        },
        "cells": rows,
        "fit": {
            "merge_push": fit_for(measured, "merge_push_ms"),
            "git_merge_push": fit_for(measured, "git_merge_push_ms"),
            "rebase_push": fit_for(measured, "rebase_push_ms"),
            "git_rebase_push": fit_for(measured, "git_rebase_push_ms"),
            "force_push": fit_for(measured, "force_push_ms"),
            "git_force_push": fit_for(measured, "git_force_push_ms"),
        },
        "integrity": {
            "every_operation_asserted_its_postcondition": True,
            "checkpoints_measured": [r["history_depth"] for r in measured],
            "checkpoints_failed": failed,
            "note": (
                "A merge must produce a two-parent commit, a rebase must "
                "rewrite commit ids onto the new base, and a force-push's old "
                "tip must not be an ancestor of the new one; the SafeHub side "
                "additionally confirms from the pushed head's own metadata "
                "that it was sent as forced. An operation that fails its "
                "postcondition publishes no timing. Guards are in "
                "scripts/lib/history_ops_lib.sh and tested by "
                "scripts/tests/test_history_ops.sh."
            ),
        },
        "notes": [
            "Measured only. A failed arm nulls its numbers and the row is "
            "marked failed; a status is not a measurement.",
            "The arms are not symmetric on the non-fast-forward operations: "
            "SafeHub's rebase and force-push carry an ML-DSA-87 admin "
            "co-signature and git's carry nothing comparable. That is the cost "
            "of the branch-protection guarantee, so the ratio columns should be "
            "read as including it rather than as like-for-like.",
            "SafeHub's head log is append-only and per repository, so the "
            "scratch-branch pushes lengthen it even though `main` is untouched. "
            "head_log_seq_added_by_ops reports that footprint per checkpoint.",
            "git's arm is measured against a freshly packed bare repository "
            "when git_pinned_gc is true, because receive.autogc firing between "
            "checkpoints otherwise makes git's cost non-monotonic in depth.",
        ],
    }
    write_published(out, doc)

    def show(label: str, key: str) -> None:
        f = doc["fit"][key]
        if f.get("status") == "derived-from-measured":
            print(f"    {label}: {f['ms_per_head']:.4f} ms/head "
                  f"(intercept {f['intercept_ms']:.1f} ms, n={f['n_points']})")
        else:
            print(f"    {label}: {f['status']}")

    show("merge  sit", "merge_push")
    show("merge  git", "git_merge_push")
    show("rebase sit", "rebase_push")
    show("rebase git", "git_rebase_push")
    show("force  sit", "force_push")
    show("force  git", "git_force_push")
    if failed:
        print(f"    FAILED checkpoints: {failed}")


if __name__ == "__main__":
    main()
