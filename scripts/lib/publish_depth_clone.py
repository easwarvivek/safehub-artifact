#!/usr/bin/env python3
"""Publisher for the measured depth-clone sweep (scripts/e2e_depth_clone.sh).

Every cell here is wall-clock from one repository lineage. Nothing is modelled
and nothing is extrapolated: if a depth is not in the JSON, it was not run.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from eval_publish import meta_block, write_published  # noqa: E402

SCRIPT = "scripts/e2e_depth_clone.sh"


def linfit(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Least-squares slope/intercept, used only to summarise measured points."""
    n = len(xs)
    mx = statistics.fmean(xs)
    my = statistics.fmean(ys)
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom
    return slope, my - slope * mx


def main() -> None:
    rows_path = Path(os.environ["ROWS"])
    out = Path(os.environ["OUT"])
    rows = [json.loads(line) for line in rows_path.read_text().splitlines() if line.strip()]
    rows.sort(key=lambda r: r["history_depth"])

    depths = [float(r["history_depth"]) for r in rows]
    sit_clone = [float(r["clone_ms"]["median"]) for r in rows]
    git_clone = [float(r["git_clone_ms"]["median"]) for r in rows]
    sit_slope, sit_intercept = linfit(depths, sit_clone)
    git_slope, git_intercept = linfit(depths, git_clone)

    mismatched = [r["history_depth"] for r in rows if not r.get("clone_tree_matches")]

    doc = {
        "id": "E03",
        "title": "Measured clone latency versus history depth, to depth 10^4",
        "meta": meta_block(
            SCRIPT,
            "wall-clock E2E; one monotonically grown lineage; clone timed at "
            "log-spaced depth checkpoints on both arms",
            int(os.environ.get("REPS", "3")),
        ),
        "axis": {
            "per_push_delta_kib": int(os.environ.get("DELTA", "64")),
            "base_tree_mib": int(os.environ.get("BASE_MIB", "4")),
            "max_depth": int(os.environ.get("MAXDEPTH", "0")),
            "note": (
                "Per-push delta and base tree are held fixed, so depth is the "
                "only axis. Both arms carry byte-identical revisions."
            ),
        },
        "cells": rows,
        "fit": {
            "safehub_clone_ms_per_head": round(sit_slope, 4),
            "safehub_clone_intercept_ms": round(sit_intercept, 3),
            "git_clone_ms_per_head": round(git_slope, 4),
            "git_clone_intercept_ms": round(git_intercept, 3),
            "method": "least squares over the measured checkpoints only",
            "status": "derived-from-measured",
        },
        "consolidation": json.loads(os.environ.get("CONSOL", '{"status":"not-run"}')),
        "integrity": {
            "clone_tree_hash_matched_at_every_depth": not mismatched,
            "depths_with_mismatched_trees": mismatched,
            "note": (
                "Each checkpoint compares the SafeHub clone's HEAD tree hash "
                "against the plain-git clone's. An exit status of zero is not "
                "accepted as evidence that the clone carried the repository."
            ),
        },
        "notes": [
            "Measured only. No modelled or extrapolated cell appears in this "
            "file; the previous AEAD-rate model and its synthesized dispersion "
            "were removed rather than relabelled.",
            "One lineage is grown once and cloned at each checkpoint, so every "
            "depth compares the same history instead of a freshly generated one.",
            "Clone is the operation that does not amortize: a blind host cannot "
            "repack, so cost tracks head count rather than bytes.",
        ],
    }
    write_published(out, doc)
    print(
        "    fit: SafeHub {:.2f} ms/head, Git {:.2f} ms/head over depths {}".format(
            sit_slope, git_slope, [int(d) for d in depths]
        )
    )


if __name__ == "__main__":
    main()
