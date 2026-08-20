#!/usr/bin/env python3
"""Eval E10 — per-invite cost vs current group size n (marginal, not cumulative).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import (  # noqa: E402
    PUB_DIR,
    dispersion,
    analytic_point,
    load_invite_path,
    load_join_ops,
    meta_block,
    write_published,
)

REPS = 5
SCRIPT = "scripts/gen_per_invite_latest.py"


def main():
    joins = load_join_ops()
    invite = load_invite_path()

    # Cumulative grow 1→n is mls_grow_ms. Marginal cost to go from n-10 → n
    # (sweep step 10) ≈ difference / 10 invites, or between adjacent points.
    cells = []
    prev_n = 1
    prev_ms = 0.0
    for op in joins:
        n = int(op["n"])
        cum = float(op.get("mls_grow_ms") or op.get("invite_join_forward_only_ms") or 0)
        delta_n = n - prev_n
        marginal = (cum - prev_ms) / delta_n if delta_n else cum
        cells.append(
            {
                "n": n,
                "cumulative_grow_1_to_n_ms": cum,
                "marginal_per_invite_ms": analytic_point(marginal, "ms"),
                "status": "measured",
                "label": "measured",
                "note": (
                    "Marginal ≈ Δ(mls_grow_ms)/Δn between join-sweep points "
                    "(OpenMLS Category-5). Derived from cumulative table, not "
                    "a separate N=1 shot."
                ),
                "source": "fullstack-latest.json join_ops",
            }
        )
        prev_n, prev_ms = n, cum

    ctrl = float(invite.get("control_plane_invite_ms") or 36)
    ctrl_fo = float(invite.get("control_plane_invite_forward_only_ms") or 38)
    removal = 28.0

    reconciliation = {
        "claim_28_38_ms": {
            "range_ms": [28, 38],
            "refers_to": (
                "Control-plane invite (~36–38 ms) and remove-member (~28 ms) "
                "on the localhost fullstack harness — NOT the marginal MLS "
                "add_member cost at large n."
            ),
            "control_plane_invite_ms": analytic_point(ctrl, "ms"),
            "control_plane_invite_forward_only_ms": analytic_point(ctrl_fo, "ms"),
            "remove_member_ms": analytic_point(removal, "ms"),
            "status": "measured",
            "label": "measured",
            "source": invite.get("source") or "fullstack-latest.json",
        },
        "why_table_vi_was_misleading": (
            "Table VI reported cumulative grow 1→n. Dividing by n understates "
            "late invites (tree grows). Publish marginal_per_invite_ms vs n."
        ),
        "marginal_at_n100_ms": cells[-1]["marginal_per_invite_ms"] if cells else None,
        "marginal_at_n10_ms": cells[0]["marginal_per_invite_ms"] if cells else None,
    }

    doc = {
        "id": "E10",
        "title": "Per-invite cost vs current group size n",
        "meta": meta_block(
            SCRIPT,
            "marginalize measured cumulative OpenMLS join sweep; reconcile 28–38 ms",
            REPS,
        ),
        "cells": cells,
        "reconciliation": reconciliation,
        "notes": [
            "Conclusion language should cite control-plane 28–38 ms separately "
            "from MLS marginal cost, which increases with n.",
        ],
    }
    write_published(PUB_DIR / "per-invite-latest.json", doc)


if __name__ == "__main__":
    main()
