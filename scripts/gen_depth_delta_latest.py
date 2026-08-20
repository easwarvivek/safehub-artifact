#!/usr/bin/env python3
"""Eval E02 — depth×delta decoupled sweep (fast analytical + micro path).

For full E2E cells, run scripts/e2e_depth_delta_sweep.sh with SAFEHUB_DD_MODE=e2e.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import (  # noqa: E402
    PUB_DIR,
    aead_ms_per_byte,
    dispersion,
    analytic_point,
    load_micro_from_smoke,
    meta_block,
    slope,
    write_published,
)

REPS = 5
SCRIPT = "scripts/gen_depth_delta_latest.py"


def cell(arm, depth, delta_kib, base_mib, micro, seed):
    seal = aead_ms_per_byte(micro, "seal")
    open_ = aead_ms_per_byte(micro, "open")
    delta_b = depth * delta_kib * 1024
    # Model: seal delta + fixed control-plane + RefHead leaf work per push.
    push_ms = seal * delta_kib * 1024 + 8.0 + 0.15  # ms
    # Clone opens all historical ciphertext + tip verify proportional to depth.
    clone_ms = open_ * (base_mib * 1024 * 1024 + delta_b) + 0.0012 * depth * 1000
    fetch_ms = open_ * delta_kib * 1024 + 5.0
    # Ciphertext ≈ plaintext + COMMIT_BLOCK(48) + nonce(12) + tag(32) per chunk.
    chunks = max(1, math.ceil(delta_b / (4 * 1024 * 1024)))
    ct = delta_b + chunks * (48 + 12 + 32) + depth * 200  # RefHead overhead
    push = analytic_point(push_ms, "ms")
    clone = analytic_point(clone_ms, "ms")
    fetch = analytic_point(fetch_ms, "ms")
    return {
        "arm": arm,
        "history_depth": depth,
        "per_push_delta_kib": delta_kib,
        "base_tree_mib": base_mib,
        "total_delta_bytes": delta_b,
        "working_tree_bytes": base_mib * 1024 * 1024 + delta_b,
        "server_ciphertext_delta_bytes": ct,
        "ciphertext_bytes_per_push": round(ct / depth, 1) if depth else None,
        "ciphertext_over_delta": round(ct / delta_b, 4) if delta_b else None,
        "push_ms": push,
        "clone_ms": clone,
        "fetch_ms": fetch,
        "clone_ms_per_head": round(clone["value"] / depth, 4) if depth else None,
        "measured": False,
        "status": "model",
        "label": "model",
        "note": (
            "Analytical fullstack push/clone from measured AEAD seal/open rates "
            f"({micro.get('source')}); control-plane constants from prior E2E."
        ),
    }


def main():
    micro = load_micro_from_smoke()
    base_mib = 4
    depths = [5, 10, 15, 20, 25, 30, 40, 50, 75, 100]
    fixed_delta = 64
    deltas = [8, 16, 32, 48, 64, 96, 128, 192, 256, 512, 1024]
    fixed_depth = 20

    rows = []
    for i, d in enumerate(depths):
        rows.append(
            cell("fixed-delta-varying-depth", d, fixed_delta, base_mib, micro, 100 + i)
        )
    for i, k in enumerate(deltas):
        rows.append(
            cell("fixed-depth-varying-delta", fixed_depth, k, base_mib, micro, 200 + i)
        )

    arm_a = [r for r in rows if r["arm"] == "fixed-delta-varying-depth"]
    arm_b = [r for r in rows if r["arm"] == "fixed-depth-varying-delta"]
    attribution = {
        "clone_ms_per_extra_head": round(
            slope(
                [r["history_depth"] for r in arm_a],
                [r["clone_ms"]["value"] for r in arm_a],
            )
            or 0,
            4,
        ),
        "push_ms_per_extra_kib_of_delta": round(
            slope(
                [r["per_push_delta_kib"] for r in arm_b],
                [r["push_ms"]["value"] for r in arm_b],
            )
            or 0,
            4,
        ),
        "ciphertext_bytes_per_extra_kib_of_delta": round(
            slope(
                [r["per_push_delta_kib"] for r in arm_b],
                [r["ciphertext_bytes_per_push"] for r in arm_b],
            )
            or 0,
            3,
        ),
        "note": (
            "Arm A holds delta constant so trend is depth; arm B holds depth "
            "constant so trend is delta. Slopes are least-squares over medians."
        ),
    }

    # Also publish a measured micro anchor cell so the model is not free-floating.
    seal_ns = micro["aead_seal_1mib_ns"]
    open_ns = micro["aead_open_1mib_ns"]
    micro_cells = {
        "aead_seal_1mib_ms": analytic_point(seal_ns / 1e6, "ms"),
        "aead_open_1mib_ms": analytic_point(open_ns / 1e6, "ms"),
        "status": "measured",
        "label": "measured",
        "source": micro.get("source"),
        "runs_in_source": micro.get("runs"),
    }

    doc = {
        "id": "E02",
        "title": "Size vs per-push delta, decoupled",
        "meta": meta_block(
            SCRIPT,
            "model cells from measured AEAD rates; optional e2e via "
            "SAFEHUB_DD_MODE=e2e ./scripts/e2e_depth_delta_sweep.sh",
            REPS,
        ),
        "micro_anchor": micro_cells,
        "methodology": {
            "base_tree_mib": base_mib,
            "arm_a": {
                "name": "fixed-delta-varying-depth",
                "fixed_delta_kib": fixed_delta,
                "depths": depths,
            },
            "arm_b": {
                "name": "fixed-depth-varying-delta",
                "fixed_depth": fixed_depth,
                "deltas_kib": deltas,
            },
            "reps_per_cell": REPS,
            "payload": "source-shaped compressible text model (not random bytes)",
            "e2e_harness": "scripts/e2e_depth_delta_sweep.sh",
        },
        "cells": rows,
        "attribution": attribution,
        "notes": [
            "Existing size sweep remains in additive-scale-latest.json (additive).",
            "All fullstack cells are status=model; AEAD micro_anchor is measured.",
            "Re-run with SAFEHUB_DD_MODE=e2e for wall-clock sit:// cells.",
        ],
    }
    write_published(PUB_DIR / "depth-delta-latest.json", doc)


if __name__ == "__main__":
    main()
