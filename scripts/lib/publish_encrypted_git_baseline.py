#!/usr/bin/env python3
"""Publisher for the measured encrypted-Git baseline (E08).

Arms that could not run are published as `tool-absent` with no numbers. The
previous version of this file emitted analytic bars for the unavailable tools;
a bar a reader cannot distinguish from a measurement is worse than no bar.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from eval_publish import meta_block, write_published  # noqa: E402

SCRIPT = "scripts/e2e_encrypted_git_baseline.sh"

# What each arm leaves visible to the host. Measured latency is only half the
# comparison: the arms do not protect the same things.
PROTECTION = {
    "plain-git": {
        "file_contents": False,
        "paths": False,
        "commit_messages": False,
        "ref_names": False,
        "graph_shape": False,
        "dynamic_membership_pcs": False,
        "history_windows": False,
        "ref_rollback_detection": False,
        "post_quantum": False,
    },
    "git-crypt": {
        "file_contents": True,
        "paths": False,
        "commit_messages": False,
        "ref_names": False,
        "graph_shape": False,
        "dynamic_membership_pcs": False,
        "history_windows": False,
        "ref_rollback_detection": False,
        "post_quantum": False,
    },
    "git-remote-gcrypt": {
        "file_contents": True,
        "paths": True,
        "commit_messages": True,
        "ref_names": True,
        "graph_shape": True,
        "dynamic_membership_pcs": False,
        "history_windows": False,
        "ref_rollback_detection": False,
        "post_quantum": False,
    },
    "safehub": {
        "file_contents": True,
        "paths": True,
        "commit_messages": True,
        "ref_names": True,
        "graph_shape": True,
        "dynamic_membership_pcs": True,
        "history_windows": True,
        "ref_rollback_detection": True,
        "post_quantum": True,
    },
}


def main() -> None:
    rows = [
        json.loads(line)
        for line in Path(os.environ["ROWS"]).read_text().splitlines()
        if line.strip()
    ]
    for r in rows:
        r["protects"] = PROTECTION.get(r["arm"], {})

    by_arm = {r["arm"]: r for r in rows}
    plain = by_arm.get("plain-git") or {}
    base_push = (plain.get("push_ms") or {}).get("median")
    base_clone = (plain.get("clone_ms") or {}).get("median")
    base_store = plain.get("remote_bytes")
    for r in rows:
        pm = (r.get("push_ms") or {}).get("median")
        cm = (r.get("clone_ms") or {}).get("median")
        st = r.get("remote_bytes")
        r["vs_plain_git"] = {
            "push": round(pm / base_push, 3) if pm and base_push else None,
            "clone": round(cm / base_clone, 3) if cm and base_clone else None,
            "remote_bytes": round(st / base_store, 3) if st and base_store else None,
        }

    absent = [r["arm"] for r in rows if not r["available"]]

    doc = {
        "id": "E08",
        "title": "Encrypted-Git baselines, measured: sit vs plain git vs git-crypt vs git-remote-gcrypt",
        "meta": meta_block(
            SCRIPT,
            "wall-clock E2E; byte-identical working tree across arms; local "
            "remotes so the comparison is transport+crypto rather than network",
            int(os.environ.get("REPS", "3")),
        ),
        "fixture": {
            "kind": os.environ.get("FIXTURE_KIND", "unspecified"),
            "working_tree_bytes": int(os.environ.get("SRC_BYTES", "0")) or None,
            "working_tree_mib": int(os.environ.get("TREE_MIB", "16")),
            "incremental_pushes": int(os.environ.get("PUSHES", "8")),
            "content": (
                "one working tree, generated or copied once and then copied "
                "into each arm so all arms transfer identical bytes"
            ),
            "why_this_matters": (
                "The storage comparison against git-crypt is bounded by how "
                "compressible the corpus is: git-crypt encrypts each file "
                "before git packs it, so its remote lands at ~1x the raw tree "
                "whatever the content, while SafeHub compresses (git bundle) "
                "and then seals, keeping most of git's compression. The ratio "
                "between them is therefore approximately the corpus's own "
                "compression ratio, and a highly compressible synthetic "
                "fixture will overstate it."
            ),
        },
        "arms": rows,
        "arms_not_measured": absent,
        "notes": [
            "Latency is not the whole comparison: the arms do not protect the "
            "same properties. The `protects` map on each arm records what its "
            "host still sees, so a faster arm that leaks paths is not a "
            "cheaper version of the same guarantee.",
            "git-crypt encrypts file contents under a static symmetric key via "
            "path filters; the object graph, paths and ref names stay readable.",
            "git-remote-gcrypt encrypts the whole remote under PGP, but has no "
            "per-member epochs, no history windows, and no protection against "
            "ref rollback by the remote.",
            "Arms whose binaries are absent are reported as tool-absent with no "
            "numbers rather than as modelled bars.",
        ],
    }
    write_published(Path(os.environ["OUT"]), doc)
    print(f"    published {len(rows)} arms; not measured: {absent or 'none'}")


if __name__ == "__main__":
    main()
