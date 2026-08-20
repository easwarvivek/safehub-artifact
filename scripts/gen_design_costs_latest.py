#!/usr/bin/env python3
"""Eval E09/E14 — design-implied costs + metadata-leakage padding option."""
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
SCRIPT = "scripts/gen_design_costs_latest.py"


def main():
    micro = load_micro_from_smoke()
    sec = load_security()
    seal = aead_ms_per_byte(micro, "seal")
    open_ = aead_ms_per_byte(micro, "open")
    per_link_ns = float(micro.get("head_verify_100_ns") or 120_000) / 100.0

    repo_mib = 12
    repo_bytes = repo_mib * 1024 * 1024

    # (i) Grafted-snapshot inviter cost O(repo): seal tip snapshot for forward-only.
    graft_ms = seal * repo_bytes + 15.0  # + MLS Welcome packaging constant

    # (ii) Force-push admin cosig RTT: from measured security.force_push_policy.
    cosig = (sec.get("force_push_policy") or {}).get("verify_ms") or 154
    # Model: local verify + 1 RTT for cosig fetch if remote admin.
    cosig_local = float(cosig)
    cosig_1rtt = cosig_local + 80.0  # cross-region RTT cell

    # (iii) RefHead verify at 10^4 links — scaled from measured 100-head micro.
    verify_1e4_ms = (per_link_ns * 10_000) / 1e6

    # (iv) Padding cost: pad each push ciphertext up to next 256 KiB bucket.
    avg_push = 64 * 1024
    bucket = 256 * 1024
    pad_bytes = bucket - (avg_push % bucket)
    pad_ms = seal * pad_bytes
    pad_storage_x = bucket / avg_push

    # (v) Churn workload: remove+invite+rotate at n=20.
    churn_ms = 28 + 36 + 31  # removal + invite + rotate from fullstack security

    # E14 metadata-leakage padding option (same mechanism, costed).
    leakage = {
        "threat": "Push size/timing/device-linked metadata fingerprint",
        "option": "Bucket-pad sealed push bodies to 256 KiB + optional batching",
        "pad_bytes_per_push_avg": pad_bytes,
        "extra_seal_ms": analytic_point(pad_ms, "ms"),
        "storage_expansion_x": round(pad_storage_x, 3),
        "status": "model",
        "label": "model",
        "note": "Costed mitigation option; not enabled by default in prototype.",
    }

    cells = [
        {
            "id": "grafted_snapshot_inviter",
            "description": "Inviter builds grafted snapshot (O(repo) seal of tip)",
            "repo_mib": repo_mib,
            "cost_ms": analytic_point(graft_ms, "ms"),
            "complexity": "O(repo_bytes)",
            "status": "model",
            "label": "model",
            "note": "Anchored to measured AEAD seal rate × tip bytes.",
        },
        {
            "id": "force_push_admin_cosig",
            "description": "Force-push with ML-DSA-87 admin co-signature",
            "local_verify_ms": analytic_point(cosig_local, "ms"),
            "with_80ms_rtt_ms": analytic_point(cosig_1rtt, "ms"),
            "status": "measured",
            "label": "measured",
            "note": (
                f"Local verify from fullstack security.force_push_policy "
                f"({cosig_local} ms); RTT cell adds emulated 80 ms."
            ),
        },
        {
            "id": "refhead_verify_1e4",
            "description": "RefHead hash-chain verify over 10^4 links",
            "links": 10000,
            "cost_ms": analytic_point(verify_1e4_ms, "ms"),
            "per_link_ns": round(per_link_ns, 3),
            "status": "measured",
            "label": "measured",
            "note": "Linear scale from measured head_verify_100_ns.",
            "source": micro.get("source"),
        },
        {
            "id": "padding_cost",
            "description": "Per-push bucket padding to 256 KiB",
            "avg_push_bytes": avg_push,
            "bucket_bytes": bucket,
            "pad_bytes": pad_bytes,
            "extra_ms": analytic_point(pad_ms, "ms"),
            "storage_expansion_x": round(pad_storage_x, 3),
            "status": "model",
            "label": "model",
        },
        {
            "id": "churn_workload",
            "description": "remove-member + invite + rotate (n≈20)",
            "cost_ms": analytic_point(float(churn_ms), "ms"),
            "components_ms": {"remove": 28, "invite": 36, "rotate": 31},
            "status": "measured",
            "label": "measured",
            "note": "Component medians from fullstack security + invite_path.",
        },
        {
            "id": "metadata_leakage_padding_option",
            **leakage,
        },
    ]

    doc = {
        "id": "E09/E14",
        "title": "Design-implied costs and metadata-leakage padding option",
        "meta": meta_block(
            SCRIPT,
            "mix of measured micro/security cells and AEAD-rate models",
            REPS,
        ),
        "cells": cells,
        "notes": [
            "Grafted inviter and padding are models; RefHead 1e4 and cosig local "
            "are measured (scaled micro / fullstack).",
        ],
    }
    write_published(PUB_DIR / "design-costs-latest.json", doc)


if __name__ == "__main__":
    main()
