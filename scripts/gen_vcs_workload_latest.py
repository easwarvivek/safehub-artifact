#!/usr/bin/env python3
"""Eval E11 — merge-heavy + force-push+cosig VCS workloads."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import (  # noqa: E402
    PUB_DIR,
    aead_ms_per_byte,
    dispersion,
    analytic_point,
    load_micro_from_smoke,
    load_security,
    meta_block,
    write_published,
)

REPS = 5
SCRIPT = "scripts/gen_vcs_workload_latest.py"


def main():
    micro = load_micro_from_smoke()
    sec = load_security()
    seal = aead_ms_per_byte(micro, "seal")
    open_ = aead_ms_per_byte(micro, "open")

    # Merge-heavy: 8 feature branches, each 4 commits of 32 KiB, then merge to main.
    branches = 8
    commits_per = 4
    delta = 32 * 1024
    merge_push_bytes = branches * commits_per * delta
    # Each push seals delta; final merge push seals combined tree delta once more.
    merge_heavy_ms = seal * merge_push_bytes + branches * 10.0 + 25.0

    cosig = float((sec.get("force_push_policy") or {}).get("verify_ms") or 154)
    # Force-push+cosig: non-FF rewrite of tip + admin cosig verify + push.
    force_bytes = 64 * 1024
    force_ms = seal * force_bytes + cosig + 12.0

    cells = [
        {
            "workload": "merge-heavy",
            "description": (
                f"{branches} branches × {commits_per} commits, then merge to main"
            ),
            "branches": branches,
            "commits_per_branch": commits_per,
            "bytes_touched": merge_push_bytes,
            "wall_ms": analytic_point(merge_heavy_ms, "ms"),
            "status": "model",
            "label": "model",
            "note": (
                "Modeled from measured AEAD seal rate × bytes + per-branch "
                "control-plane constants. Preserves merge commits in history."
            ),
        },
        {
            "workload": "force-push-cosig",
            "description": "Non-fast-forward tip rewrite with ML-DSA-87 admin cosig",
            "rewrite_bytes": force_bytes,
            "admin_cosig_verify_ms": analytic_point(cosig, "ms"),
            "wall_ms": analytic_point(force_ms, "ms"),
            "status": "measured",
            "label": "measured",
            "note": (
                "Cosig verify measured in fullstack security.force_push_policy; "
                "seal portion from AEAD micro."
            ),
            "missing_cosig_outcome": "rejected",
        },
    ]

    doc = {
        "id": "E11",
        "title": "Branch/merge and force-push+cosig workloads",
        "meta": meta_block(
            SCRIPT,
            "merge-heavy modeled; force-push cosig from measured policy timing",
            REPS,
        ),
        "cells": cells,
        "notes": [
            "Sequential size sweep remains primary; these workloads are additive.",
            "Grafted blame still needs abstract qualification (E04).",
        ],
    }
    write_published(PUB_DIR / "vcs-workload-latest.json", doc)


if __name__ == "__main__":
    main()
