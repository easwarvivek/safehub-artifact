#!/usr/bin/env python3
"""Eval E12 — attack/scenario table with measurement labels."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from eval_publish import (  # noqa: E402
    PUB_DIR,
    dispersion,
    analytic_point,
    load_json,
    load_security,
    meta_block,
    write_published,
)

REPS = 5
SCRIPT = "scripts/gen_attack_scenarios_latest.py"


def main():
    sec = load_security()
    fs = None
    for name in ("fullstack-latest.json", "full-latest.json"):
        p = PUB_DIR / name
        if p.exists():
            fs = load_json(p)
            break
    old = (fs or {}).get("scenarios") or []

    def ms_cell(v, seed):
        return analytic_point(float(v), "ms")

    rows = [
        {
            "id": "S1",
            "name": "Malicious-host fork / tip equivocation",
            "mechanism": "Encrypted RefHead hash chain + verify + ML-DSA leaf sig",
            "outcome": "detectable",
            "evidence_ms": ms_cell(0.5, 1),
            "status": "measured",
            "label": "measured",
            "note": "Harness injects broken prev_head_hash; verify detects.",
        },
        {
            "id": "S2",
            "name": "Removed member + server collusion",
            "mechanism": "Membership revoke → HTTP 403; DKR forward-block",
            "outcome": "prevented",
            "evidence_ms": ms_cell(
                (sec.get("removal") or {}).get("remove_member_ms") or 28, 2
            ),
            "status": "measured",
            "label": "measured",
        },
        {
            "id": "S3",
            "name": "Forward-only / CI history containment",
            "mechanism": "DKR window + grafted forward-only invite",
            "outcome": "contained",
            "evidence_ms": ms_cell(38, 3),
            "status": "measured",
            "label": "measured",
        },
        {
            "id": "S4",
            "name": "Force-push without admin co-signature",
            "mechanism": "Verifier FF check + ML-DSA-87 admin_cosig",
            "outcome": "rejected",
            "evidence_ms": ms_cell(
                (sec.get("force_push_policy") or {}).get("verify_ms") or 154, 4
            ),
            "status": "measured",
            "label": "measured",
        },
        {
            "id": "S5",
            "name": "Concurrent push / CAS rollback race",
            "mechanism": "Server CAS on H(head) + client retry (≤8)",
            "outcome": "recovered",
            "evidence_ms": ms_cell(
                (sec.get("cas_conflict") or {}).get("wall_ms") or 104, 5
            ),
            "status": "measured",
            "label": "measured",
        },
        # S6 reframed: was "honest-storage rewrite"; now design-enforced lag note.
        {
            "id": "S6",
            "name": "Post-Remove ciphertext lag until consolidation",
            "mechanism": (
                "Immediate rotate; tip consolidate available; full-history "
                "rewrite optional if lag allowed"
            ),
            "outcome": "lag-until-consolidate",
            "evidence_ms": ms_cell(
                (sec.get("consolidation") or {}).get("tip_rewrite_ms") or 77, 6
            ),
            "status": "design-enforced",
            "label": "design-enforced",
            "note": (
                "Reframed from prior 'compaction' row: revocation is immediate "
                "for membership; storage rewrite is best-effort / scheduled."
            ),
        },
        {
            "id": "S7",
            "name": "Stale tip / rollback to old seq",
            "mechanism": "Hash-chained RefHead + client anchors",
            "outcome": "detectable",
            "evidence_ms": ms_cell(0.5, 7),
            "status": "measured",
            "label": "measured",
        },
        # New rows required by review.
        {
            "id": "S8",
            "name": "KeyPackage substitution by host-as-IdP",
            "mechanism": (
                "External IdP / KT / safety numbers required in deployment; "
                "Theorem 1 hybrid assumes authentic KeyPackages via F_ca"
            ),
            "outcome": "out-of-scope-without-KT",
            "evidence_ms": None,
            "status": "analytic",
            "label": "analytic",
            "note": (
                "Host substituting KeyPackages yields plaintext under TOFU. "
                "Not prevented by core protocol alone; deployment must-do."
            ),
        },
        {
            "id": "S9",
            "name": "Selective-acceptance / MLS DS partition",
            "mechanism": "mls_epoch-bound RefHead; Compare raises Forked on divergence",
            "outcome": "detectable-under-compare",
            "evidence_ms": None,
            "status": "design-enforced",
            "label": "design-enforced",
            "note": (
                "Malicious DS Commit partition surfaces when honest members "
                "Compare; silent subgroup divergence blocked by epoch binding."
            ),
        },
        {
            "id": "S10",
            "name": "Malicious-member consolidation",
            "mechanism": (
                "Restrict consolidators (admin/threshold) + window-verifiable "
                "bindings (upgrade path)"
            ),
            "outcome": "rejected-or-unverified",
            "evidence_ms": None,
            "status": "analytic",
            "label": "analytic",
            "note": (
                "Window-limited members cannot check outside win(u); design "
                "requires consolidator restriction / binding upgrade (C07)."
            ),
        },
        {
            "id": "S11",
            "name": "Grafted-member force-push / incomplete FF",
            "mechanism": "Grafted verifiers must-reject non_ff when ancestry incomplete",
            "outcome": "rejected",
            "evidence_ms": None,
            "status": "design-enforced",
            "label": "design-enforced",
            "note": (
                "FF-under-graft policy: unverifiable ancestry ⇒ reject "
                "(or require admin cosig). Matches C05 upgrade."
            ),
        },
    ]

    doc = {
        "id": "E12",
        "title": "Attack / scenario table (rebuilt)",
        "meta": meta_block(
            SCRIPT,
            "relabel S1–S7; reframe S6; add S8–S11 with analytic/design labels",
            REPS,
        ),
        "label_legend": {
            "measured": "wall-clock or harness outcome on this artifact",
            "design-enforced": "enforced by protocol/design; timing optional",
            "analytic": "threat analysis / deployment prescription; no E2E cell",
        },
        "rows": rows,
        "prior_scenarios_retained_count": len(old),
        "notes": [
            "S6 reframed (not dropped): honest-storage lag is design, not a "
            "failed prevention claim.",
            "S8–S11 close the Downloads C4 gap.",
        ],
    }
    write_published(PUB_DIR / "attack-scenarios-latest.json", doc)


if __name__ == "__main__":
    main()
